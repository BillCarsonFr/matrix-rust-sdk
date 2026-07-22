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

//! Key, entry and update types for the sticky-events [`EphemeralMap`].
//!
//! [`EphemeralMap`]: super::EphemeralMap

use ruma::{OwnedEventId, OwnedUserId};

/// The key identifying a sticky-event slot in a single room.
///
/// Per [MSC4354] the ephemeral map is keyed by the 4-tuple
/// `(room_id, sender, type, content.sticky_key)`. The room is implied by the
/// per-room map that owns this key, so the key itself carries the remaining
/// three components. `sticky_key` is optional: events without a
/// `content.sticky_key` are still tracked, keyed only by `(sender, type)`.
///
/// [MSC4354]: https://github.com/matrix-org/matrix-spec-proposals/pull/4354
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StickyKey {
    /// The event sender.
    pub sender: OwnedUserId,
    /// The event type, e.g. `m.rtc.member`.
    pub event_type: String,
    /// The `content.sticky_key`, if the event carried one.
    pub sticky_key: Option<String>,
}

impl StickyKey {
    /// Create a new sticky key.
    pub fn new(sender: OwnedUserId, event_type: String, sticky_key: Option<String>) -> Self {
        Self { sender, event_type, sticky_key }
    }
}

/// A currently-tracked sticky event, together with the metadata needed to
/// expire it and to break ties against competing events for the same key.
#[derive(Clone, Debug)]
pub struct StickyEntry<V> {
    /// The stored value (in production, the raw sticky event).
    pub value: V,
    /// The event id, used as the tie-breaker of last resort.
    pub event_id: OwnedEventId,
    /// The absolute time, in milliseconds since the Unix epoch, at which this
    /// entry stops being sticky. The entry is live while `now < end_time`.
    pub end_time: u64,
}

/// The reason a sticky entry was removed from the map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemovalReason {
    /// The entry reached its expiry time.
    Expired,
    /// The entry was replaced by a removal event (empty content carrying only
    /// the `sticky_key`).
    Replaced,
    /// The entry was removed via an explicit local API call.
    ExplicitRemoval,
}

/// A batch of changes to an [`EphemeralMap`], broadcast to subscribers.
///
/// One update is emitted per ingested batch and once per eviction pass, so a
/// subscriber sees the net effect of a sync (or an expiry tick) at once.
///
/// [`EphemeralMap`]: super::EphemeralMap
#[derive(Clone, Debug, Default)]
pub struct StickyEventsUpdate {
    /// Keys that were newly added.
    pub added: Vec<StickyKey>,
    /// Keys whose entry was replaced by a newer/longer-lived event.
    pub updated: Vec<StickyKey>,
    /// Keys that were removed, with the reason why.
    pub removed: Vec<(StickyKey, RemovalReason)>,
}

impl StickyEventsUpdate {
    /// Whether this update carries no changes.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.updated.is_empty() && self.removed.is_empty()
    }
}
