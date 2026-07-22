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

//! Support for sticky events, as defined in [MSC4354] and delivered via the
//! [MSC4480] sliding-sync extension.
//!
//! Sticky events are message-like events with a temporary, per-user lifetime
//! (a TTL of up to one hour). Clients materialize them into an *ephemeral map*
//! keyed by `(room_id, sender, type, content.sticky_key)`, keeping the
//! last-to-expire event per key and dropping entries when they expire.
//!
//! The core of this module is the generic, in-memory [`EphemeralMap`], which is
//! store-agnostic and unit-tested in isolation. Ingestion from sync and the
//! per-room wiring live alongside the room model.
//!
//! [MSC4354]: https://github.com/matrix-org/matrix-spec-proposals/pull/4354
//! [MSC4480]: https://github.com/matrix-org/matrix-spec-proposals/pull/4480

mod clock;
mod eviction;
mod extract;
mod handle;
mod key;
mod manager;
mod map;

#[cfg(any(test, feature = "testing"))]
pub use clock::MockClock;
pub use clock::{Clock, SystemClock};
#[cfg(feature = "e2e-encryption")]
pub(crate) use extract::resolve;
pub(crate) use extract::{StickyCandidate, StickyExtract, classify};
pub use handle::{StickyEvents, StickyLiveEvent};
pub use key::{RemovalReason, StickyEntry, StickyEventsUpdate, StickyKey};
pub(crate) use manager::StickyManager;
pub use map::{EphemeralMap, MAX_STICKY_DURATION_MS, compute_end_time};
