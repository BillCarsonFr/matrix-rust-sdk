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

//! The background task that proactively evicts expired sticky events so that
//! expiry reaches subscribers without waiting for the next sync, and (when
//! configured) persists the live set to the store on every change.

use std::{
    future::pending,
    sync::{Arc, Mutex},
    time::Duration,
};

use matrix_sdk_common::{
    executor::{AbortOnDrop, JoinHandleExt as _, spawn},
    sleep::sleep,
};
use ruma::OwnedRoomId;
use tokio::sync::{Notify, broadcast};
use tracing::warn;

use super::{EphemeralMap, StickyEventsUpdate};
use crate::store::{
    PersistedPendingStickyEvent, PersistedStickyEvent, SaveLockedStateStore, StateStore,
    StateStoreDataKey, StateStoreDataValue,
};

/// Produces a serializable snapshot of the map's currently-live entries.
///
/// Locks the map internally and returns owned data, so the caller never holds
/// the map lock across the (async) store write.
pub(crate) type SnapshotFn = Arc<dyn Fn() -> Vec<PersistedStickyEvent> + Send + Sync>;

/// Produces a serializable snapshot of the parked (encrypted) sticky events.
pub(crate) type PendingSnapshotFn = Arc<dyn Fn() -> Vec<PersistedPendingStickyEvent> + Send + Sync>;

/// Everything the maintenance task needs to write a room's sticky sets through
/// to the store.
pub(crate) struct Persister {
    pub store: SaveLockedStateStore,
    pub room_id: OwnedRoomId,
    pub live_snapshot: SnapshotFn,
    pub pending_snapshot: PendingSnapshotFn,
    /// Notified when the parked buffer changes (park / take_pending), since those
    /// don't go through the map's change broadcast.
    pub pending_changed: Arc<Notify>,
}

impl Persister {
    /// Re-serialize the full live set and write it to the store. We always
    /// persist the complete set (rather than a delta), so a lagged change
    /// notification simply means we write current truth once.
    async fn persist_live(&self) {
        let events = (self.live_snapshot)();
        if let Err(error) = self
            .store
            .set_kv_data(
                StateStoreDataKey::StickyEvents(&self.room_id),
                StateStoreDataValue::StickyEvents(events),
            )
            .await
        {
            warn!(?error, room_id = %self.room_id, "failed to persist sticky events");
        }
    }

    /// Re-serialize the parked (encrypted) buffer and write it to the store.
    async fn persist_pending(&self) {
        let events = (self.pending_snapshot)();
        if let Err(error) = self
            .store
            .set_kv_data(
                StateStoreDataKey::StickyPendingEvents(&self.room_id),
                StateStoreDataValue::StickyPendingEvents(events),
            )
            .await
        {
            warn!(?error, room_id = %self.room_id, "failed to persist pending sticky events");
        }
    }
}

/// Spawn the eviction task for `map`, returning a guard that aborts the task
/// when dropped (so it never outlives the map's owner). When `persist` is set,
/// the same task also writes the live set through to the store on every change.
pub(crate) fn spawn_eviction<V>(
    map: Arc<Mutex<EphemeralMap<V>>>,
    persist: Option<Persister>,
) -> AbortOnDrop<()>
where
    V: Send + 'static,
{
    // Subscribe here (synchronously, before the caller applies its first batch)
    // so the task doesn't miss the change that prompted it to spawn.
    let updates = persist.as_ref().map(|_| map.lock().unwrap().subscribe());
    spawn(run_eviction(map, persist, updates)).abort_on_drop()
}

/// The eviction loop: sleep until the earliest expiry, evict, repeat; wake
/// early whenever the map changes (a new, sooner-expiring entry may have
/// arrived). When persisting, it also writes the live set through on every map
/// broadcast (including eviction removals, which the map broadcasts) and the
/// parked buffer through whenever `pending_changed` fires.
///
/// The persistence arms are driven by `updates`/`pending_changed`, which are
/// only `Some` when a `Persister` is configured; otherwise those `select!` arms
/// park forever and the loop behaves as a pure eviction task.
async fn run_eviction<V>(
    map: Arc<Mutex<EphemeralMap<V>>>,
    persist: Option<Persister>,
    mut updates: Option<broadcast::Receiver<StickyEventsUpdate>>,
) where
    V: Send + 'static,
{
    let pending_changed = persist.as_ref().map(|p| p.pending_changed.clone());

    loop {
        // Peek the next expiry and grab a fresh change-notification handle.
        // The guard is dropped before any `.await`.
        let (next_expiry, changed) = {
            let guard = map.lock().unwrap();
            (guard.next_expiry(), guard.change_notify())
        };

        tokio::select! {
            // Time to evict whatever has expired.
            _ = sleep_until_expiry(next_expiry, &map) => { map.lock().unwrap().evict_expired(); }
            // Entries changed; loop to recompute the next expiry.
            _ = changed.notified() => {}
            // A map change (add/update/remove/eviction) — persist the live set.
            res = recv_or_pending(&mut updates) => persist_live_on_update(&persist, res).await,
            // The parked buffer changed — persist it.
            _ = notified_or_pending(&pending_changed) => {
                if let Some(persister) = &persist {
                    persister.persist_pending().await;
                }
            }
        }
    }
}

/// Sleep until `next_expiry` (relative to the map's clock), or park forever when
/// nothing is scheduled.
async fn sleep_until_expiry<V>(next_expiry: Option<u64>, map: &Mutex<EphemeralMap<V>>) {
    match next_expiry {
        Some(end_time) => {
            let duration = {
                let now = map.lock().unwrap().now_ms();
                Duration::from_millis(end_time.saturating_sub(now))
            };
            sleep(duration).await;
        }
        None => pending::<()>().await,
    }
}

/// Await the next change broadcast, or park forever when not persisting.
async fn recv_or_pending(
    updates: &mut Option<broadcast::Receiver<StickyEventsUpdate>>,
) -> Result<StickyEventsUpdate, broadcast::error::RecvError> {
    match updates {
        Some(rx) => rx.recv().await,
        None => pending().await,
    }
}

/// Await the next `pending_changed` notification, or park forever when absent.
async fn notified_or_pending(notify: &Option<Arc<Notify>>) {
    match notify {
        Some(n) => n.notified().await,
        None => pending::<()>().await,
    }
}

/// React to a change broadcast by persisting the live set. A `Lagged` error is
/// treated like any other change (we persist the full current set anyway); a
/// `Closed` channel can only happen once the map is gone, so there is nothing
/// left to persist.
async fn persist_live_on_update(
    persist: &Option<Persister>,
    res: Result<StickyEventsUpdate, broadcast::error::RecvError>,
) {
    if matches!(res, Err(broadcast::error::RecvError::Closed)) {
        return;
    }
    if let Some(persister) = persist {
        persister.persist_live().await;
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    use matrix_sdk_test::async_test;
    use ruma::{owned_event_id, owned_user_id};

    use super::spawn_eviction;
    use crate::sticky::{EphemeralMap, MockClock, RemovalReason, StickyKey};

    #[async_test]
    async fn test_active_eviction_notifies_subscriber() {
        let clock = MockClock::new(1_000_000);
        let map = Arc::new(Mutex::new(EphemeralMap::<u32>::new(Arc::new(clock.clone()))));

        // Keep the eviction task alive for the duration of the test.
        let _guard = spawn_eviction(map.clone(), None);

        let mut rx = map.lock().unwrap().subscribe();
        let key = StickyKey::new(
            owned_user_id!("@alice:localhost"),
            "m.rtc.member".to_owned(),
            Some("slot".to_owned()),
        );

        // Insert an entry that expires 50ms from "now", then move the clock past
        // its expiry. The eviction task must drop it and broadcast a removal
        // without any further upsert.
        map.lock().unwrap().upsert(
            key.clone(),
            0,
            owned_event_id!("$a:localhost"),
            1_000_050,
            false,
        );
        clock.advance(1000);

        let removed = loop {
            let update = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .expect("eviction should notify within the timeout")
                .expect("channel should not close");
            if !update.removed.is_empty() {
                break update.removed;
            }
        };

        assert_eq!(removed, vec![(key, RemovalReason::Expired)]);
    }
}
