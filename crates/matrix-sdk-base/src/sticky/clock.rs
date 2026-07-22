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

//! A minimal clock abstraction so the sticky-events [`EphemeralMap`] can be
//! tested deterministically.
//!
//! [`EphemeralMap`]: super::EphemeralMap

use ruma::MilliSecondsSinceUnixEpoch;

/// Source of "now" used to compute sticky-event expiry.
pub trait Clock: std::fmt::Debug + Send + Sync {
    /// The current time, in milliseconds since the Unix epoch.
    fn now_ms(&self) -> u64;
}

/// The real system clock, used in production.
#[derive(Debug, Clone, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        MilliSecondsSinceUnixEpoch::now().get().into()
    }
}

#[cfg(any(test, feature = "testing"))]
pub use mock::MockClock;

#[cfg(any(test, feature = "testing"))]
mod mock {
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };

    use super::Clock;

    /// A manually-driven clock for tests.
    ///
    /// Cloning shares the same underlying time, so a clone handed to an
    /// eviction task and the handle used by the test observe the same value.
    #[derive(Debug, Clone)]
    pub struct MockClock {
        now_ms: Arc<AtomicU64>,
    }

    impl MockClock {
        /// Create a new mock clock set to `now_ms`.
        pub fn new(now_ms: u64) -> Self {
            Self { now_ms: Arc::new(AtomicU64::new(now_ms)) }
        }

        /// Set the current time to `now_ms`.
        pub fn set(&self, now_ms: u64) {
            self.now_ms.store(now_ms, Ordering::SeqCst);
        }

        /// Advance the current time by `delta_ms`.
        pub fn advance(&self, delta_ms: u64) {
            self.now_ms.fetch_add(delta_ms, Ordering::SeqCst);
        }
    }

    impl Clock for MockClock {
        fn now_ms(&self) -> u64 {
            self.now_ms.load(Ordering::SeqCst)
        }
    }
}
