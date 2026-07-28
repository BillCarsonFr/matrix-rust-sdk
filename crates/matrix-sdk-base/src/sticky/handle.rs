// Copyright 2025 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The per-room sticky-events handle: a shareable, in-memory
//! [`EphemeralMap`] of sticky events (with their encryption data), fed from
//! sync and expired by a background task.

use std::sync::{Arc, Mutex, OnceLock};

use matrix_sdk_common::{
    deserialized_responses::{EncryptionInfo, TimelineEventKind},
    executor::AbortOnDrop,
};
use ruma::{OwnedEventId, OwnedRoomId, events::AnySyncTimelineEvent, serde::Raw};
use tokio::sync::{Notify, broadcast};

use super::{
    Clock, EphemeralMap, MAX_STICKY_DURATION_MS, StickyCandidate, StickyEventsUpdate, StickyKey,
    SystemClock,
    eviction::{Persister, spawn_eviction},
};
use crate::store::{PersistedPendingStickyEvent, PersistedStickyEvent, SaveLockedStateStore};

/// A parked encrypted sticky event with the local time it was first received.
type ParkedEvent = (u64, Raw<AnySyncTimelineEvent>);

/// A single currently-live sticky event, as returned to consumers.
#[derive(Clone, Debug)]
pub struct StickyLiveEvent {
    /// The `(sender, type, sticky_key)` key of this entry.
    pub key: StickyKey,
    /// The event id.
    pub event_id: OwnedEventId,
    /// The sticky event, together with its encryption data (see
    /// [`Self::encryption_info`]).
    ///
    /// Only [`TimelineEventKind::PlainText`] and
    /// [`TimelineEventKind::Decrypted`] occur here: the map key of an encrypted
    /// sticky event (its type and `content.sticky_key`) lives in the encrypted
    /// content, so an event we cannot decrypt is parked rather than filed in
    /// the map, and only shows up once its room key arrives.
    pub kind: TimelineEventKind,
    /// Absolute expiry time in milliseconds since the Unix epoch.
    pub expires_at_ms: u64,
}

impl StickyLiveEvent {
    /// The raw sticky event; the decrypted one, if it was sent encrypted.
    pub fn raw(&self) -> &Raw<AnySyncTimelineEvent> {
        self.kind.raw()
    }

    /// The encryption data of this event, or `None` if it was sent in the
    /// clear.
    pub fn encryption_info(&self) -> Option<&Arc<EncryptionInfo>> {
        self.kind.encryption_info()
    }
}

/// The per-room store of currently-live sticky events.
///
/// This is a cheap-to-clone handle: clones share the same underlying map and
/// the single background maintenance task (TTL eviction plus write-through
/// persistence), which is aborted once the last clone is dropped. It is held on
/// [`Room`](crate::Room), persisted to the state store, and reloaded on
/// startup.
#[derive(Clone, Debug)]
pub struct StickyEvents {
    inner: Arc<StickyEventsInner>,
}

#[derive(Debug)]
struct StickyEventsInner {
    map: Arc<Mutex<EphemeralMap<TimelineEventKind>>>,
    /// Encrypted sticky events awaiting decryption, with the local time each
    /// was first received (so a retry does not reset its TTL). Drained and
    /// retried by the redecryptor when room keys arrive; without encryption
    /// support nothing reads it (parked events can never be decrypted). Shared
    /// via `Arc` so the persistence task can snapshot it without a cycle back
    /// to this inner.
    pending: Arc<Mutex<Vec<ParkedEvent>>>,
    /// Notified when `pending` changes (park / take_pending), so the
    /// maintenance task persists it (those don't go through the map's
    /// change broadcast).
    pending_changed: Arc<Notify>,
    /// The store + room this map persists to, if any. `None` in unit tests that
    /// exercise the map without a store.
    persist: Option<PersistContext>,
    /// The maintenance task (TTL eviction + write-through persistence), spawned
    /// lazily on first ingest/load (so constructing a `Room` doesn't require
    /// an async runtime), aborted on drop.
    eviction: OnceLock<AbortOnDrop<()>>,
}

/// Where a room's sticky events are persisted.
#[derive(Debug)]
struct PersistContext {
    store: SaveLockedStateStore,
    room_id: OwnedRoomId,
}

impl StickyEvents {
    /// Create a new, empty handle driven by the real system clock, persisting
    /// to `store` under `room_id`.
    pub(crate) fn new(store: SaveLockedStateStore, room_id: OwnedRoomId) -> Self {
        Self::build(Arc::new(SystemClock), Some(PersistContext { store, room_id }))
    }

    /// Create a new, empty, non-persisting handle driven by `clock` (used in
    /// tests).
    #[cfg(test)]
    pub(crate) fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self::build(clock, None)
    }

    fn build(clock: Arc<dyn Clock>, persist: Option<PersistContext>) -> Self {
        Self {
            inner: Arc::new(StickyEventsInner {
                map: Arc::new(Mutex::new(EphemeralMap::new(clock))),
                pending: Arc::new(Mutex::new(Vec::new())),
                pending_changed: Arc::new(Notify::new()),
                persist,
                eviction: OnceLock::new(),
            }),
        }
    }

    /// Ensure the background maintenance task is running (idempotent).
    fn ensure_task(&self) {
        self.inner.eviction.get_or_init(|| {
            let persist = self.inner.persist.as_ref().map(|ctx| {
                // Capture the shared `map`/`pending` (not `inner`) so the task
                // holds no strong reference back to the inner it lives on.
                let map = self.inner.map.clone();
                let pending = self.inner.pending.clone();
                Persister {
                    store: ctx.store.clone(),
                    room_id: ctx.room_id.clone(),
                    live_snapshot: Arc::new(move || live_snapshot(&map)),
                    pending_snapshot: Arc::new(move || pending_snapshot(&pending)),
                    pending_changed: self.inner.pending_changed.clone(),
                }
            });
            spawn_eviction(self.inner.map.clone(), persist)
        });
    }

    /// Load the map from persisted events, dropping any that have already
    /// expired. Starts the maintenance task (so the loaded entries expire and
    /// further changes are persisted) only when something live was loaded, so
    /// rooms with no live stickies don't spawn an idle task.
    pub(crate) fn load(&self, events: Vec<PersistedStickyEvent>) {
        let now = self.now_ms();
        let batch: Vec<_> = events
            .into_iter()
            .filter(|e| e.end_time > now)
            .map(|e| {
                (
                    StickyKey::new(e.sender, e.event_type, e.sticky_key),
                    e.kind,
                    e.event_id,
                    e.end_time,
                    false,
                )
            })
            .collect();

        if !batch.is_empty() {
            self.ensure_task();
            self.inner.map.lock().unwrap().apply_batch(batch);
        }
    }

    /// Load the parked (encrypted) buffer from persisted events, dropping any
    /// whose maximum possible lifetime (`received_ts` + the max TTL) has
    /// already passed, so a UTD event whose keys never arrived isn't kept
    /// forever. Starts the maintenance task when anything was loaded.
    pub(crate) fn load_pending(&self, events: Vec<PersistedPendingStickyEvent>) {
        let now = self.now_ms();
        let restored: Vec<_> = events
            .into_iter()
            .filter(|e| e.received_ts.saturating_add(MAX_STICKY_DURATION_MS) > now)
            .map(|e| (e.received_ts, e.event))
            .collect();

        if !restored.is_empty() {
            self.ensure_task();
            self.inner.pending.lock().unwrap().extend(restored);
        }
    }

    /// The current time in milliseconds, per the map's clock.
    pub(crate) fn now_ms(&self) -> u64 {
        self.inner.map.lock().unwrap().now_ms()
    }

    /// Apply a batch of already-resolved sticky candidates (plaintext, or
    /// decrypted) to the map. `value` is the event stored for each candidate,
    /// together with its encryption data.
    pub(crate) fn ingest_candidates(
        &self,
        items: impl IntoIterator<Item = (StickyCandidate, TimelineEventKind)>,
    ) {
        let batch: Vec<_> = items
            .into_iter()
            .map(|(c, value)| (c.key, value, c.event_id, c.end_time, c.is_removal))
            .collect();

        if !batch.is_empty() {
            // Start the maintenance task only now that we hold real data, so a
            // sync touching a room with no sticky events spawns nothing.
            self.ensure_task();
            self.inner.map.lock().unwrap().apply_batch(batch);
        }
    }

    /// Take (drain) the encrypted sticky events parked awaiting decryption.
    ///
    /// Only the (encryption-gated) redecryptor drains the buffer; without
    /// encryption, parked events simply remain parked.
    #[cfg(feature = "e2e-encryption")]
    pub(crate) fn take_pending(&self) -> Vec<ParkedEvent> {
        let drained = std::mem::take(&mut *self.inner.pending.lock().unwrap());
        if !drained.is_empty() {
            // The parked buffer shrank; persist the new (smaller) set.
            self.inner.pending_changed.notify_one();
        }
        drained
    }

    /// Append encrypted sticky events to the parking buffer (awaiting
    /// decryption). Atomic under the buffer lock, so it never clobbers events
    /// parked concurrently.
    pub(crate) fn park(&self, mut pending: Vec<ParkedEvent>) {
        if pending.is_empty() {
            return;
        }
        // Make sure the maintenance task is running so the parked events get
        // persisted (and retried after a restart).
        self.ensure_task();
        self.inner.pending.lock().unwrap().append(&mut pending);
        self.inner.pending_changed.notify_one();
    }

    /// Subscribe to batched change notifications for this room.
    pub fn subscribe(&self) -> broadcast::Receiver<StickyEventsUpdate> {
        self.inner.map.lock().unwrap().subscribe()
    }

    /// A snapshot of all currently-live sticky events.
    pub fn live(&self) -> Vec<StickyLiveEvent> {
        let map = self.inner.map.lock().unwrap();
        map.iter_live()
            .map(|(key, entry)| StickyLiveEvent {
                key: key.clone(),
                event_id: entry.event_id.clone(),
                kind: entry.value.clone(),
                expires_at_ms: entry.end_time,
            })
            .collect()
    }
}

/// Build a serializable snapshot of the map's currently-live entries, for
/// write-through persistence.
fn live_snapshot(map: &Mutex<EphemeralMap<TimelineEventKind>>) -> Vec<PersistedStickyEvent> {
    let guard = map.lock().unwrap();
    guard
        .iter_live()
        .map(|(key, entry)| PersistedStickyEvent {
            sender: key.sender.clone(),
            event_type: key.event_type.clone(),
            sticky_key: key.sticky_key.clone(),
            event_id: entry.event_id.clone(),
            end_time: entry.end_time,
            kind: entry.value.clone(),
        })
        .collect()
}

/// Build a serializable snapshot of the parked (encrypted) buffer.
fn pending_snapshot(pending: &Mutex<Vec<ParkedEvent>>) -> Vec<PersistedPendingStickyEvent> {
    pending
        .lock()
        .unwrap()
        .iter()
        .map(|(received_ts, event)| PersistedPendingStickyEvent {
            received_ts: *received_ts,
            event: event.clone(),
        })
        .collect()
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
    use std::{sync::Arc, time::Duration};

    use matrix_sdk_common::deserialized_responses::TimelineEventKind;
    use matrix_sdk_test::async_test;
    use ruma::{
        RoomId, events::AnySyncTimelineEvent, owned_event_id, owned_user_id, room_id, serde::Raw,
    };
    use serde_json::json;

    use super::StickyEvents;
    use crate::{
        sticky::{MAX_STICKY_DURATION_MS, MockClock, StickyCandidate, StickyKey},
        store::{
            IntoStateStore, MemoryStore, PersistedPendingStickyEvent, PersistedStickyEvent,
            SaveLockedStateStore, StateStore, StateStoreDataKey,
        },
    };

    fn raw_event() -> Raw<AnySyncTimelineEvent> {
        serde_json::from_value(json!({
            "type": "m.rtc.member",
            "sender": "@alice:localhost",
            "event_id": "$sticky:localhost",
            "origin_server_ts": 1,
            "content": { "sticky_key": "slot" },
        }))
        .unwrap()
    }

    /// The plaintext event kind stored for a sticky event that was sent in the
    /// clear.
    fn plaintext_event() -> TimelineEventKind {
        TimelineEventKind::PlainText { event: raw_event() }
    }

    fn persisted(end_time: u64) -> PersistedStickyEvent {
        PersistedStickyEvent {
            sender: owned_user_id!("@alice:localhost"),
            event_type: "m.rtc.member".to_owned(),
            sticky_key: Some("slot".to_owned()),
            event_id: owned_event_id!("$sticky:localhost"),
            end_time,
            kind: plaintext_event(),
        }
    }

    #[async_test]
    async fn test_load_drops_expired_keeps_live() {
        let clock = MockClock::new(1_000);
        let handle = StickyEvents::with_clock(Arc::new(clock));

        let expired = PersistedStickyEvent {
            sticky_key: Some("gone".to_owned()),
            end_time: 500,
            ..persisted(500)
        };
        let live = persisted(5_000);
        handle.load(vec![expired, live]);

        let live_events = handle.live();
        assert_eq!(live_events.len(), 1, "only the non-expired entry should survive loading");
        assert_eq!(live_events[0].key.sticky_key.as_deref(), Some("slot"));
        assert_eq!(live_events[0].expires_at_ms, 5_000);
        // It was sent in the clear, so it carries no encryption data.
        assert!(live_events[0].encryption_info().is_none());
        assert_eq!(
            live_events[0].raw().get_field::<String>("type").unwrap().as_deref(),
            Some("m.rtc.member")
        );
    }

    #[async_test]
    async fn test_write_through_persists_on_ingest() {
        let room_id: &RoomId = room_id!("!persist:localhost");
        let store = SaveLockedStateStore::new(MemoryStore::new().into_state_store());
        let handle = StickyEvents::new(store.clone(), room_id.to_owned());

        // Ingest a single, long-lived sticky event.
        let end_time = handle.now_ms() + 3_600_000;
        let candidate = StickyCandidate {
            key: StickyKey::new(
                owned_user_id!("@alice:localhost"),
                "m.rtc.member".to_owned(),
                Some("slot".to_owned()),
            ),
            event_id: owned_event_id!("$sticky:localhost"),
            end_time,
            is_removal: false,
        };
        handle.ingest_candidates([(candidate, plaintext_event())]);

        // The background maintenance task writes the live set through to the
        // store; wait for it to appear.
        let persisted = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let value = store
                    .get_kv_data(StateStoreDataKey::StickyEvents(room_id))
                    .await
                    .expect("store read should succeed");
                if let Some(events) = value.and_then(|v| v.into_sticky_events())
                    && !events.is_empty()
                {
                    break events;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("sticky events should be persisted within the timeout");

        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].sticky_key.as_deref(), Some("slot"));
        assert_eq!(persisted[0].end_time, end_time);

        // The persisted entry survives a JSON round-trip (the on-disk encoding of
        // the sticky kv data) and reloads into a fresh map.
        let json = serde_json::to_string(&persisted).expect("persisted events should serialize");
        let restored: Vec<PersistedStickyEvent> =
            serde_json::from_str(&json).expect("persisted events should deserialize");

        let reloaded = StickyEvents::new(store, room_id.to_owned());
        reloaded.load(restored);

        let live = reloaded.live();
        assert_eq!(live.len(), 1);
        assert!(live[0].encryption_info().is_none());
        assert_eq!(
            live[0].raw().get_field::<String>("type").unwrap().as_deref(),
            Some("m.rtc.member")
        );
    }

    #[async_test]
    async fn test_load_pending_drops_stale_keeps_recent() {
        // "now" far enough that a received-long-ago entry is past its max TTL.
        let clock = MockClock::new(2 * MAX_STICKY_DURATION_MS);
        let handle = StickyEvents::with_clock(Arc::new(clock));

        // received_ts = 0 → 0 + max TTL <= now → dropped; the recent one is kept.
        let stale = PersistedPendingStickyEvent { received_ts: 0, event: raw_event() };
        let recent = PersistedPendingStickyEvent {
            received_ts: 2 * MAX_STICKY_DURATION_MS - 1,
            event: raw_event(),
        };
        handle.load_pending(vec![stale, recent]);

        let restored = std::mem::take(&mut *handle.inner.pending.lock().unwrap());
        assert_eq!(restored.len(), 1, "only the still-live parked event should survive");
        assert_eq!(restored[0].0, 2 * MAX_STICKY_DURATION_MS - 1);
    }

    #[async_test]
    async fn test_write_through_persists_parked_events() {
        let room_id: &RoomId = room_id!("!park:localhost");
        let store = SaveLockedStateStore::new(MemoryStore::new().into_state_store());
        let handle = StickyEvents::new(store.clone(), room_id.to_owned());

        handle.park(vec![(handle.now_ms(), raw_event())]);

        let persisted = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let value = store
                    .get_kv_data(StateStoreDataKey::StickyPendingEvents(room_id))
                    .await
                    .expect("store read should succeed");
                if let Some(events) = value.and_then(|v| v.into_sticky_pending_events())
                    && !events.is_empty()
                {
                    break events;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("parked events should be persisted within the timeout");

        assert_eq!(persisted.len(), 1);
    }
}
