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

//! The generic sticky-events ephemeral map.

use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap},
    sync::Arc,
};

use ruma::OwnedEventId;
use tokio::sync::{Notify, broadcast};

use super::{
    clock::Clock,
    key::{RemovalReason, StickyEntry, StickyEventsUpdate, StickyKey},
};

/// The largest sticky duration allowed by [MSC4354]: one hour.
///
/// [MSC4354]: https://github.com/matrix-org/matrix-spec-proposals/pull/4354
pub const MAX_STICKY_DURATION_MS: u64 = 3_600_000;

/// Capacity of the broadcast channel used to notify subscribers of changes.
const UPDATES_CHANNEL_CAPACITY: usize = 16;

/// Compute the absolute expiry time of a sticky event, per the MSC4354 rule:
///
/// ```text
/// start_time = min(received_ts, origin_server_ts)
/// end_time   = start_time + min(duration_ms, 3_600_000)
/// ```
///
/// Taking the minimum of the two timestamps prevents a malicious future
/// `origin_server_ts` from extending stickiness.
pub fn compute_end_time(origin_server_ts: u64, received_ts: u64, duration_ms: u32) -> u64 {
    let start_time = origin_server_ts.min(received_ts);
    start_time.saturating_add(u64::from(duration_ms).min(MAX_STICKY_DURATION_MS))
}

/// A node in the expiry min-heap. Ordered by `end_time` then `key` so that
/// [`BinaryHeap`] wrapped in [`Reverse`] yields the earliest expiry first.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ExpiryNode {
    end_time: u64,
    key: StickyKey,
}

/// The classification of a single applied change, before it is batched into a
/// [`StickyEventsUpdate`].
enum Change {
    Added(StickyKey),
    Updated(StickyKey),
    Removed(StickyKey, RemovalReason),
}

/// A generic, in-memory map of currently-live sticky events for a single room.
///
/// Keyed by [`StickyKey`] (`sender`, `type`, optional `sticky_key`), the map
/// keeps at most one live entry per key, resolving conflicts with the MSC4354
/// tie-break (last-to-expire wins, then highest lexicographic event id). Expiry
/// is evaluated lazily on read via [`iter_live`](Self::iter_live) /
/// [`get`](Self::get), and proactively by
/// [`evict_expired`](Self::evict_expired) (driven by a background task).
/// Changes are broadcast to [`subscribe`](Self::subscribe)rs.
///
/// It is generic over the stored value `V` so it can be unit-tested in
/// isolation; in production `V` is
/// [`TimelineEventKind`](matrix_sdk_common::deserialized_responses::TimelineEventKind).
#[derive(Debug)]
pub struct EphemeralMap<V> {
    /// The live entries, one per key.
    entries: HashMap<StickyKey, StickyEntry<V>>,
    /// Min-heap of `(end_time, key)` used to schedule and perform eviction.
    /// May contain stale nodes (a key updated to a later `end_time` leaves its
    /// old node behind); these are discarded when popped.
    expiry_heap: BinaryHeap<Reverse<ExpiryNode>>,
    /// Broadcasts batched changes to external subscribers.
    updates: broadcast::Sender<StickyEventsUpdate>,
    /// Notifies the eviction task that entries changed and it should
    /// reschedule.
    change: Arc<Notify>,
    /// Source of "now".
    clock: Arc<dyn Clock>,
}

impl<V> EphemeralMap<V> {
    /// Create a new, empty map driven by `clock`.
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        let (updates, _) = broadcast::channel(UPDATES_CHANNEL_CAPACITY);
        Self {
            entries: HashMap::new(),
            expiry_heap: BinaryHeap::new(),
            updates,
            change: Arc::new(Notify::new()),
            clock,
        }
    }

    /// The current time in milliseconds, per the map's clock.
    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    /// Subscribe to batched change notifications.
    pub fn subscribe(&self) -> broadcast::Receiver<StickyEventsUpdate> {
        self.updates.subscribe()
    }

    /// A handle the eviction task awaits to learn that entries changed.
    pub(super) fn change_notify(&self) -> Arc<Notify> {
        self.change.clone()
    }

    /// The number of currently-live entries.
    pub fn len_live(&self) -> usize {
        self.iter_live().count()
    }

    /// Get the live entry for `key`, if any (expired entries are hidden).
    pub fn get(&self, key: &StickyKey) -> Option<&StickyEntry<V>> {
        let now = self.now_ms();
        self.entries.get(key).filter(|entry| entry.end_time > now)
    }

    /// Iterate over currently-live (non-expired) entries.
    pub fn iter_live(&self) -> impl Iterator<Item = (&StickyKey, &StickyEntry<V>)> {
        let now = self.now_ms();
        LiveIter { inner: self.entries.iter(), now }
    }

    /// The earliest expiry time currently scheduled, if any.
    ///
    /// May reflect a stale heap node (its `end_time` is still a valid lower
    /// bound on the next real expiry, so it only ever wakes the eviction task
    /// too early, never too late).
    pub fn next_expiry(&self) -> Option<u64> {
        self.expiry_heap.peek().map(|Reverse(node)| node.end_time)
    }

    /// Upsert a single sticky event, emitting an update and waking the eviction
    /// task if anything changed. Returns whether the map changed.
    ///
    /// See [`compute_end_time`] for how `end_time` is derived. When
    /// `is_removal` is set the entry for `key` is removed (a replacement event
    /// carrying only `sticky_key`).
    pub fn upsert(
        &mut self,
        key: StickyKey,
        value: V,
        event_id: OwnedEventId,
        end_time: u64,
        is_removal: bool,
    ) -> bool {
        match self.apply_one(key, value, event_id, end_time, is_removal) {
            Some(change) => {
                let mut update = StickyEventsUpdate::default();
                self.record(&mut update, change);
                self.publish(update);
                true
            }
            None => false,
        }
    }

    /// Apply a batch of upserts, emitting a single combined update at the end.
    /// Returns whether the map changed.
    pub fn apply_batch(
        &mut self,
        items: impl IntoIterator<Item = (StickyKey, V, OwnedEventId, u64, bool)>,
    ) -> bool {
        let mut update = StickyEventsUpdate::default();
        for (key, value, event_id, end_time, is_removal) in items {
            if let Some(change) = self.apply_one(key, value, event_id, end_time, is_removal) {
                self.record(&mut update, change);
            }
        }

        let changed = !update.is_empty();
        self.publish(update);
        changed
    }

    /// Explicitly remove the entry for `key`, if present.
    pub fn remove(&mut self, key: &StickyKey) -> Option<StickyEntry<V>> {
        let entry = self.entries.remove(key)?;
        let mut update = StickyEventsUpdate::default();
        update.removed.push((key.clone(), RemovalReason::ExplicitRemoval));
        self.publish(update);
        Some(entry)
    }

    /// Drop every entry whose expiry time has passed, broadcasting a single
    /// `removed` update. Returns the evicted keys.
    pub fn evict_expired(&mut self) -> Vec<StickyKey> {
        let now = self.now_ms();
        let mut removed = Vec::new();

        while let Some(Reverse(node)) = self.expiry_heap.peek() {
            if node.end_time > now {
                break;
            }

            let Reverse(node) = self.expiry_heap.pop().expect("peeked node must pop");

            // Discard stale nodes: only evict if the live entry still has this
            // exact end_time (and is therefore expired, since end_time <= now).
            if self.entries.get(&node.key).is_some_and(|e| e.end_time == node.end_time) {
                self.entries.remove(&node.key);
                removed.push(node.key);
            }
        }

        if !removed.is_empty() {
            let update = StickyEventsUpdate {
                removed: removed.iter().cloned().map(|k| (k, RemovalReason::Expired)).collect(),
                ..Default::default()
            };
            self.publish(update);
        }

        removed
    }

    /// Apply one change to the entry map (no broadcasting), returning what
    /// changed.
    fn apply_one(
        &mut self,
        key: StickyKey,
        value: V,
        event_id: OwnedEventId,
        end_time: u64,
        is_removal: bool,
    ) -> Option<Change> {
        if is_removal {
            return match self.entries.get(&key) {
                // A removal is subject to the same convergent tie-break as an
                // add: it only supersedes the current entry if it is
                // last-to-expire, then by highest lexicographic event id. A
                // stale/older removal is ignored, so it can't wipe a newer live
                // sticky (e.g. a superseded disconnect deleting a fresh connect).
                Some(current) if (end_time, &event_id) <= (current.end_time, &current.event_id) => {
                    None
                }
                Some(_) => {
                    self.entries.remove(&key);
                    Some(Change::Removed(key, RemovalReason::Replaced))
                }
                // Nothing to remove.
                None => None,
            };
        }

        // Ignore events that are already expired on arrival.
        if end_time <= self.now_ms() {
            return None;
        }

        match self.entries.get(&key) {
            // Tie-break: the incoming event wins only if it is last-to-expire,
            // then by highest lexicographic event id.
            Some(current) if (end_time, &event_id) <= (current.end_time, &current.event_id) => None,
            existing => {
                let is_update = existing.is_some();
                self.entries.insert(key.clone(), StickyEntry { value, event_id, end_time });
                self.expiry_heap.push(Reverse(ExpiryNode { end_time, key: key.clone() }));
                Some(if is_update { Change::Updated(key) } else { Change::Added(key) })
            }
        }
    }

    /// Fold a single [`Change`] into the batched update.
    fn record(&self, update: &mut StickyEventsUpdate, change: Change) {
        match change {
            Change::Added(key) => update.added.push(key),
            Change::Updated(key) => update.updated.push(key),
            Change::Removed(key, reason) => update.removed.push((key, reason)),
        }
    }

    /// Broadcast `update` (if non-empty) and wake the eviction task when an
    /// entry was added or updated (which may bring the next expiry forward).
    fn publish(&self, update: StickyEventsUpdate) {
        if update.is_empty() {
            return;
        }

        if !update.added.is_empty() || !update.updated.is_empty() {
            self.change.notify_one();
        }

        // A send error just means there are no subscribers; that's fine.
        let _ = self.updates.send(update);
    }
}

/// Iterator over live entries, filtering out expired ones lazily.
struct LiveIter<'a, V> {
    inner: std::collections::hash_map::Iter<'a, StickyKey, StickyEntry<V>>,
    now: u64,
}

impl<'a, V> Iterator for LiveIter<'a, V> {
    type Item = (&'a StickyKey, &'a StickyEntry<V>);

    fn next(&mut self) -> Option<Self::Item> {
        for (key, entry) in self.inner.by_ref() {
            if entry.end_time > self.now {
                return Some((key, entry));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ruma::{OwnedEventId, owned_event_id, owned_user_id};

    use super::{EphemeralMap, MAX_STICKY_DURATION_MS, compute_end_time};
    use crate::sticky::{MockClock, RemovalReason, StickyKey};

    fn key(sticky_key: Option<&str>) -> StickyKey {
        StickyKey::new(
            owned_user_id!("@alice:localhost"),
            "m.rtc.member".to_owned(),
            sticky_key.map(ToOwned::to_owned),
        )
    }

    fn map_at(now_ms: u64) -> EphemeralMap<u32> {
        EphemeralMap::new(Arc::new(MockClock::new(now_ms)))
    }

    fn upsert(map: &mut EphemeralMap<u32>, k: &StickyKey, id: OwnedEventId, end_time: u64) -> bool {
        map.upsert(k.clone(), 0, id, end_time, false)
    }

    #[test]
    fn test_compute_end_time_uses_earliest_start() {
        // Normal case: origin before received.
        assert_eq!(compute_end_time(1000, 2000, 500), 1500);
        // A future origin_server_ts cannot extend stickiness: start = received.
        assert_eq!(compute_end_time(5000, 1000, 500), 1500);
    }

    #[test]
    fn test_compute_end_time_clamps_duration() {
        assert_eq!(compute_end_time(0, 0, u32::MAX), MAX_STICKY_DURATION_MS);
    }

    #[test]
    fn test_insert_get_and_iter_live() {
        let mut map = map_at(0);
        let k = key(Some("slot"));
        assert!(upsert(&mut map, &k, owned_event_id!("$a:localhost"), 1000));

        assert!(map.get(&k).is_some());
        assert_eq!(map.len_live(), 1);
        assert_eq!(map.iter_live().count(), 1);
    }

    #[test]
    fn test_lazy_expiry_boundary() {
        let clock = MockClock::new(0);
        let mut map = EphemeralMap::<u32>::new(Arc::new(clock.clone()));
        let k = key(Some("slot"));
        upsert(&mut map, &k, owned_event_id!("$a:localhost"), 1500);

        clock.set(1499);
        assert!(map.get(&k).is_some(), "live while now < end_time");

        clock.set(1500);
        assert!(map.get(&k).is_none(), "expired once now >= end_time");
        assert_eq!(map.len_live(), 0);
    }

    #[test]
    fn test_tiebreak_prefers_later_end_time() {
        let mut map = map_at(0);
        let k = key(Some("slot"));
        assert!(upsert(&mut map, &k, owned_event_id!("$a:localhost"), 100));
        // Later end_time wins.
        assert!(upsert(&mut map, &k, owned_event_id!("$b:localhost"), 200));
        assert_eq!(map.get(&k).unwrap().end_time, 200);
        // Earlier end_time loses; the stored entry is unchanged.
        assert!(!upsert(&mut map, &k, owned_event_id!("$c:localhost"), 150));
        assert_eq!(map.get(&k).unwrap().end_time, 200);
    }

    #[test]
    fn test_tiebreak_by_event_id_on_equal_end_time() {
        let mut map = map_at(0);
        let k = key(Some("slot"));
        upsert(&mut map, &k, owned_event_id!("$a:localhost"), 100);
        // Higher lexicographic event id wins at equal end_time.
        assert!(upsert(&mut map, &k, owned_event_id!("$b:localhost"), 100));
        assert_eq!(map.get(&k).unwrap().event_id, owned_event_id!("$b:localhost"));
        // Lower event id loses.
        assert!(!upsert(&mut map, &k, owned_event_id!("$a:localhost"), 100));
    }

    #[test]
    fn test_keyed_and_unkeyed_are_distinct() {
        let mut map = map_at(0);
        let keyed = key(Some("slot"));
        let unkeyed = key(None);
        upsert(&mut map, &keyed, owned_event_id!("$a:localhost"), 100);
        upsert(&mut map, &unkeyed, owned_event_id!("$b:localhost"), 100);
        assert_eq!(map.len_live(), 2);
        assert!(map.get(&keyed).is_some());
        assert!(map.get(&unkeyed).is_some());
    }

    #[test]
    fn test_removal_marker_drops_entry() {
        let mut map = map_at(0);
        let k = key(Some("slot"));
        upsert(&mut map, &k, owned_event_id!("$a:localhost"), 1000);

        let mut rx = map.subscribe();
        // A removal that wins the tie-break (equal end_time, higher event id)
        // supersedes the entry.
        let removed = map.upsert(k.clone(), 0, owned_event_id!("$b:localhost"), 1000, true);
        assert!(removed);
        assert!(map.get(&k).is_none());

        let update = rx.try_recv().unwrap();
        assert_eq!(update.removed, vec![(k, RemovalReason::Replaced)]);
    }

    #[test]
    fn test_stale_removal_does_not_wipe_newer_entry() {
        let mut map = map_at(0);
        let k = key(Some("slot"));
        // A fresh connect, last-to-expire.
        upsert(&mut map, &k, owned_event_id!("$b:localhost"), 2000);

        // An older, superseded removal (earlier end_time) must be ignored rather
        // than deleting the live entry.
        assert!(!map.upsert(k.clone(), 0, owned_event_id!("$a:localhost"), 1000, true));
        assert!(map.get(&k).is_some(), "the newer live entry must survive a stale removal");
    }

    #[test]
    fn test_explicit_remove() {
        let mut map = map_at(0);
        let k = key(Some("slot"));
        upsert(&mut map, &k, owned_event_id!("$a:localhost"), 1000);

        let mut rx = map.subscribe();
        assert!(map.remove(&k).is_some());
        assert!(map.get(&k).is_none());

        let update = rx.try_recv().unwrap();
        assert_eq!(update.removed, vec![(k, RemovalReason::ExplicitRemoval)]);
    }

    #[test]
    fn test_evict_expired_and_next_expiry() {
        let clock = MockClock::new(0);
        let mut map = EphemeralMap::<u32>::new(Arc::new(clock.clone()));
        let (k1, k2, k3) = (key(Some("1")), key(Some("2")), key(Some("3")));
        upsert(&mut map, &k1, owned_event_id!("$a:localhost"), 100);
        upsert(&mut map, &k2, owned_event_id!("$b:localhost"), 200);
        upsert(&mut map, &k3, owned_event_id!("$c:localhost"), 300);

        clock.set(250);
        let mut removed = map.evict_expired();
        removed.sort();
        let mut expected = vec![k1, k2];
        expected.sort();
        assert_eq!(removed, expected);
        assert_eq!(map.next_expiry(), Some(300));
        assert_eq!(map.len_live(), 1);
    }

    #[test]
    fn test_stale_heap_node_is_discarded() {
        let clock = MockClock::new(0);
        let mut map = EphemeralMap::<u32>::new(Arc::new(clock.clone()));
        let k = key(Some("slot"));
        // First a short-lived entry, then extend it to a much later end_time.
        upsert(&mut map, &k, owned_event_id!("$a:localhost"), 100);
        upsert(&mut map, &k, owned_event_id!("$b:localhost"), 500);

        clock.set(150);
        // The stale node (end_time 100) must not evict the live entry (500).
        assert!(map.evict_expired().is_empty());
        assert!(map.get(&k).is_some());
    }

    #[test]
    fn test_subscribe_fans_out_to_multiple_receivers() {
        let mut map = map_at(0);
        let mut rx1 = map.subscribe();
        let mut rx2 = map.subscribe();
        let k = key(Some("slot"));
        upsert(&mut map, &k, owned_event_id!("$a:localhost"), 1000);

        assert_eq!(rx1.try_recv().unwrap().added, vec![k.clone()]);
        assert_eq!(rx2.try_recv().unwrap().added, vec![k]);
    }
}
