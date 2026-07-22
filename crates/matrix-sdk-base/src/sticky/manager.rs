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

//! Client-level coordination of sticky events ([MSC4354]).
//!
//! [`StickyManager`] is held on [`BaseClient`](crate::BaseClient) and owns all
//! *client-scoped* sticky processing: ingesting sticky events from the sync
//! response into the per-room maps ([`dispatch`](StickyManager::dispatch)) and
//! the background *redecryptor* that re-decrypts parked encrypted sticky events
//! when their room keys arrive. The per-room maps themselves live on each
//! [`Room`](crate::Room).
//!
//! [MSC4354]: https://github.com/matrix-org/matrix-spec-proposals/pull/4354

use std::collections::BTreeMap;

use ruma::{
    OwnedRoomId, RoomId, api::client::sync::sync_events::v5 as http,
    events::AnySyncTimelineEvent, serde::Raw,
};

use super::{StickyCandidate, StickyExtract, classify};
#[cfg(feature = "e2e-encryption")]
use crate::response_processors::e2ee;
use crate::{error::Result, store::BaseStateStore};

/// A raw sticky event awaiting resolution, with the local time it was first
/// received (so a decryption retry does not reset its TTL).
type PendingEvent = (u64, Raw<AnySyncTimelineEvent>);

/// A resolved sticky event, ready to upsert into the map.
type ResolvedEvent = (StickyCandidate, Raw<AnySyncTimelineEvent>);

/// What the manager needs to decrypt encrypted sticky events: a (shared) handle
/// to the client's `OlmMachine` and the decryption settings. An
/// [`E2EE`](e2ee::E2EE) is built from this on demand — it borrows an
/// `OlmMachine` read-guard and so can't itself be stored.
#[cfg(feature = "e2e-encryption")]
#[derive(Clone)]
struct DecryptionContext {
    olm_machine: std::sync::Arc<tokio::sync::RwLock<Option<crate::crypto::OlmMachine>>>,
    decryption_settings: crate::crypto::DecryptionSettings,
}

/// Client-level manager for sticky events, held on
/// [`BaseClient`](crate::BaseClient).
#[derive(Clone, Default)]
pub(crate) struct StickyManager {
    /// The decryption context, injected once after client construction via
    /// [`set_decryption_context`](Self::set_decryption_context). Empty until
    /// then (and always empty without encryption support). A `OnceLock` because
    /// it is set exactly once and only read afterwards — so it can be set
    /// through `&self`, without making the whole `BaseClient` mutable.
    #[cfg(feature = "e2e-encryption")]
    decryption: std::sync::OnceLock<DecryptionContext>,

    /// The running redecryptor task; dropping it aborts the task. Bound to a
    /// specific `OlmMachine`'s room-keys stream, so it is replaced whenever the
    /// machine is (re)created.
    #[cfg(feature = "e2e-encryption")]
    redecryptor:
        std::sync::Arc<std::sync::Mutex<Option<matrix_sdk_common::executor::AbortOnDrop<()>>>>,
}

impl StickyManager {
    /// Inject the decryption context (the client's shared `OlmMachine` handle
    /// and decryption settings). Called once from the `BaseClient`
    /// constructors; the olm handle is stable across `regenerate_olm` (which
    /// swaps the machine *inside* the lock), so it never needs re-injecting.
    #[cfg(feature = "e2e-encryption")]
    pub(crate) fn set_decryption_context(
        &self,
        olm_machine: std::sync::Arc<tokio::sync::RwLock<Option<crate::crypto::OlmMachine>>>,
        decryption_settings: crate::crypto::DecryptionSettings,
    ) {
        // Set exactly once (at construction); ignore a redundant re-set.
        let _ = self.decryption.set(DecryptionContext { olm_machine, decryption_settings });
    }

    /// Ingest sticky events (MSC4354) into each room's in-memory ephemeral map.
    ///
    /// Reads from both the dedicated `msc4354_sticky` section and the room
    /// timeline (recent sticky events are deduplicated *out* of the section, so
    /// they only arrive via the timeline).
    ///
    /// Plaintext sticky events are resolved immediately;
    /// encrypted ones are decrypted to recover their real type and
    /// `sticky_key`, or **parked** (so they are never mistakenly filed as
    /// unkeyed `m.room.encrypted` entries). Parked events are retried by the
    /// redecryptor when the room keys arrive.
    pub(crate) async fn dispatch(
        &self,
        sticky_events: &http::response::StickyEvents,
        rooms: &BTreeMap<OwnedRoomId, http::response::Room>,
        state_store: &BaseStateStore,
    ) -> Result<()> {
        // Gather, per room, *references* to the raw candidate events from both
        // sources. We only clone the ones that turn out to be sticky, below.
        let mut per_room: BTreeMap<OwnedRoomId, Vec<&Raw<AnySyncTimelineEvent>>> = BTreeMap::new();
        for (room_id, sticky) in &sticky_events.rooms {
            per_room.entry(room_id.clone()).or_default().extend(sticky.events.iter());
        }
        for (room_id, room_response) in rooms {
            per_room.entry(room_id.clone()).or_default().extend(room_response.timeline.iter());
        }

        if per_room.is_empty() {
            return Ok(());
        }

        for (room_id, raws) in per_room {
            let Some(room) = state_store.room(&room_id) else { continue };
            let sticky = room.sticky_events();
            let now = sticky.now_ms();

            // Classify by reference (a cheap field probe) and clone only the
            // events that are actually sticky, so the bulk of a room's non-sticky
            // timeline events aren't deep-cloned on every sync.
            let inputs: Vec<PendingEvent> = raws
                .into_iter()
                .filter(|raw| !matches!(classify(now, raw), StickyExtract::NotSticky))
                .map(|raw| (now, raw.clone()))
                .collect();

            if inputs.is_empty() {
                continue;
            }

            let (resolved, pending) = self.resolve_room(inputs, &room_id).await;

            sticky.ingest_candidates(resolved);
            // Append newly-undecryptable events to the parking buffer; the
            // redecryptor retries them on key arrival.
            sticky.park(pending);
        }

        Ok(())
    }

    /// Resolve one room's inputs, building an [`E2EE`](e2ee::E2EE) from our
    /// decryption context to decrypt any encrypted sticky events.
    async fn resolve_room(
        &self,
        inputs: Vec<PendingEvent>,
        room_id: &RoomId,
    ) -> (Vec<ResolvedEvent>, Vec<PendingEvent>) {
        #[cfg(feature = "e2e-encryption")]
        {
            let Some(context) = self.decryption.get() else {
                return resolve_inputs(inputs, room_id, None).await;
            };
            let guard = context.olm_machine.read().await;
            let e2ee = e2ee::E2EE::new(guard.as_ref(), &context.decryption_settings, false);
            resolve_inputs(inputs, room_id, Some(&e2ee)).await
        }

        #[cfg(not(feature = "e2e-encryption"))]
        resolve_inputs(inputs, room_id).await
    }

    /// (Re)start the redecryptor task for a freshly-(re)created `OlmMachine`,
    /// aborting any previously-running one.
    ///
    /// Called from
    /// [`BaseClient::regenerate_olm`](crate::BaseClient::regenerate_olm) with
    /// the new machine's room-keys stream; the olm handle and decryption
    /// settings come from the manager's own context.
    #[cfg(feature = "e2e-encryption")]
    pub(crate) fn start_redecryptor<S, E>(&self, room_keys_stream: S, state_store: BaseStateStore)
    where
        S: futures_util::Stream<
                Item = std::result::Result<Vec<crate::crypto::store::types::RoomKeyInfo>, E>,
            > + Send
            + 'static,
        E: Send + 'static,
    {
        use matrix_sdk_common::executor::{JoinHandleExt as _, spawn};

        // Without a decryption context there is nothing to decrypt.
        let Some(context) = self.decryption.get().cloned() else { return };

        let task =
            spawn(run_redecryptor(room_keys_stream, context, state_store)).abort_on_drop();

        // Replacing the handle drops (and thus aborts) the previous task.
        *self.redecryptor.lock().unwrap() = Some(task);
    }
}

/// Classify and (for encrypted events) decrypt a batch of raw events into
/// resolved candidates and a still-to-decrypt remainder.
///
/// Never fails: a missing decryption context or a decryption error parks the
/// event rather than aborting.
// `room_id` is only read, and the `.await` only reached, on the decryption path.
#[cfg_attr(not(feature = "e2e-encryption"), allow(unused_variables, clippy::unused_async))]
async fn resolve_inputs(
    inputs: Vec<PendingEvent>,
    room_id: &RoomId,
    #[cfg(feature = "e2e-encryption")] e2ee: Option<&e2ee::E2EE<'_>>,
) -> (Vec<ResolvedEvent>, Vec<PendingEvent>) {
    let mut resolved = Vec::new();
    let mut pending = Vec::new();

    for (received_ts, raw) in inputs {
        match classify(received_ts, &raw) {
            StickyExtract::NotSticky => {}
            StickyExtract::Sticky(candidate) => resolved.push((candidate, raw)),
            StickyExtract::NeedsDecryption(_meta) => {
                #[cfg(feature = "e2e-encryption")]
                if let Some(e2ee) = e2ee {
                    let event =
                        matrix_sdk_common::deserialized_responses::TimelineEvent::from_plaintext(
                            raw.clone(),
                        );
                    match e2ee::decrypt::sync_timeline_event(e2ee, &event, room_id).await {
                        Ok(Some(decrypted)) => {
                            let decrypted_raw = decrypted.raw().clone();
                            // A UTD keeps the outer `m.room.encrypted` type; a
                            // real decryption exposes the content.
                            let still_encrypted =
                                decrypted_raw.get_field::<String>("type").ok().flatten().as_deref()
                                    == Some("m.room.encrypted");
                            if still_encrypted {
                                pending.push((received_ts, raw));
                            } else if let Some(candidate) = super::resolve(_meta, &decrypted_raw) {
                                resolved.push((candidate, decrypted_raw));
                            }
                        }
                        // No olm machine (yet): park.
                        Ok(None) => pending.push((received_ts, raw)),
                        Err(error) => {
                            tracing::warn!(?error, "Failed to decrypt a sticky event; parking it");
                            pending.push((received_ts, raw));
                        }
                    }
                } else {
                    // No decryption context: park.
                    pending.push((received_ts, raw));
                }

                #[cfg(not(feature = "e2e-encryption"))]
                pending.push((received_ts, raw));
            }
        }
    }

    (resolved, pending)
}

/// Background task: re-decrypt parked encrypted sticky events as soon as their
/// room keys arrive, instead of waiting for the next sync.
///
/// Subscribes to the crypto store's `room_keys_received_stream` (the same
/// signal the event cache's `Redecryptor` uses). Generic over the stream error
/// so we don't depend on `tokio_stream`'s error type; on any lag/error we
/// conservatively sweep every room with parked events.
#[cfg(feature = "e2e-encryption")]
async fn run_redecryptor<S, E>(
    room_keys_stream: S,
    context: DecryptionContext,
    state_store: BaseStateStore,
) where
    S: futures_util::Stream<
            Item = std::result::Result<Vec<crate::crypto::store::types::RoomKeyInfo>, E>,
        >,
{
    use std::collections::BTreeSet;

    use futures_util::StreamExt as _;

    let mut stream = std::pin::pin!(room_keys_stream);

    while let Some(item) = stream.next().await {
        // Which rooms to retry: the ones named in the batch, or (on lag/error)
        // every room that currently has parked sticky events.
        let room_ids: BTreeSet<OwnedRoomId> = match item {
            Ok(room_keys) => room_keys.into_iter().map(|info| info.room_id).collect(),
            Err(_) => {
                state_store.rooms().into_iter().map(|room| room.room_id().to_owned()).collect()
            }
        };

        for room_id in room_ids {
            let Some(room) = state_store.room(&room_id) else { continue };
            let sticky = room.sticky_events();

            let pending = sticky.take_pending();
            if pending.is_empty() {
                continue;
            }

            let guard = context.olm_machine.read().await;
            let e2ee = e2ee::E2EE::new(guard.as_ref(), &context.decryption_settings, false);
            let (resolved, still_pending) = resolve_inputs(pending, &room_id, Some(&e2ee)).await;
            drop(guard);

            sticky.ingest_candidates(resolved);
            sticky.park(still_pending);
        }
    }
}
