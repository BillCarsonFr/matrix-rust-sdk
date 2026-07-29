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

//! Extraction of sticky-event metadata from raw sync events.
//!
//! Sticky events arrive both in the dedicated `msc4354_sticky` sync section and
//! (deduplicated out of that section) in the room timeline. Both are
//! `Raw<AnySyncTimelineEvent>`, so a single extractor handles them.
//!
//! Encryption needs care: for an encrypted sticky event the server annotates
//! the *outer* `m.room.encrypted` event with `msc4354_sticky`, but the
//! `type` and `content.sticky_key` we key on live in the *decrypted* content.
//! So [`classify`] separates the two: it reads the sticky metadata from the
//! outer event and, for encrypted events, defers to [`resolve`] once the
//! content has been decrypted. This avoids mistakenly filing an encrypted
//! event as an *unkeyed* `m.room.encrypted` sticky.

use ruma::{
    OwnedEventId, OwnedUserId,
    events::{AnySyncTimelineEvent, sticky::StickyObject},
    serde::Raw,
};
use serde::Deserialize;

use super::{key::StickyKey, map::compute_end_time};

/// The metadata extracted from a sticky event, ready to feed into
/// [`EphemeralMap::upsert`](super::EphemeralMap::upsert).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StickyCandidate {
    /// The `(sender, type, sticky_key)` key.
    pub key: StickyKey,
    /// The event id (tie-breaker).
    pub event_id: OwnedEventId,
    /// The absolute expiry time in milliseconds since the Unix epoch.
    pub end_time: u64,
    /// Whether this event removes its map entry (empty content besides
    /// `sticky_key`).
    pub is_removal: bool,
}

/// Sticky metadata read from the *outer* event, independent of the (possibly
/// encrypted) content. Combined with the decrypted content by [`resolve`].
///
/// `sender`/`event_id` are only read when resolving a decrypted event, so
/// without encryption support they are set but never used.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(not(feature = "e2e-encryption"), allow(dead_code))]
pub(crate) struct StickyMeta {
    sender: OwnedUserId,
    event_id: OwnedEventId,
    end_time: u64,
}

/// The result of classifying a raw sync event.
pub(crate) enum StickyExtract {
    /// Not a sticky event.
    NotSticky,
    /// A sticky event whose content is encrypted; decrypt it and call
    /// [`resolve`] with the decrypted event.
    NeedsDecryption(StickyMeta),
    /// A plaintext sticky event, fully resolved.
    Sticky(StickyCandidate),
}

/// Probe for the fields of `content` we care about, plus a catch-all so we can
/// tell whether the content carries anything beyond `sticky_key`.
#[derive(Default, Deserialize)]
struct ContentProbe {
    /// The unstable name MSC4354 gives `content.sticky_key`, and the one we
    /// prefer.
    #[serde(default, rename = "msc4354_sticky_key")]
    unstable_sticky_key: Option<String>,
    /// The stable name, which ruma's sticky event contents (e.g.
    /// `RtcMemberEventContent`) already use. Read as a named field rather than
    /// left to `rest`, so that it doesn't count as content of its own and
    /// hide a removal.
    #[serde(default)]
    sticky_key: Option<String>,
    #[serde(flatten)]
    rest: serde_json::Map<String, serde_json::Value>,
}

impl ContentProbe {
    /// The sticky key under either spelling.
    fn sticky_key(self) -> Option<String> {
        self.unstable_sticky_key.or(self.sticky_key)
    }
}

/// Probe for the remaining-ttl hint the server may attach in `unsigned`.
#[derive(Deserialize)]
struct UnsignedProbe {
    #[serde(default, rename = "msc4354_sticky_duration_ttl_ms")]
    sticky_duration_ttl_ms: Option<u64>,
}

/// Classify a raw sync event as a sticky candidate.
///
/// `received_ts` is the local time the event was (first) received, in
/// milliseconds since the Unix epoch; it feeds the expiry `start_time` and the
/// base for a server-provided remaining ttl. For a parked event awaiting
/// decryption this must be the *original* receive time, so its TTL does not
/// reset on retry.
pub(crate) fn classify(received_ts: u64, raw: &Raw<AnySyncTimelineEvent>) -> StickyExtract {
    let Some(meta) = read_meta(received_ts, raw) else {
        return StickyExtract::NotSticky;
    };

    // An encrypted event hides its real type and `sticky_key`; defer to
    // `resolve` after decryption rather than filing it as an unkeyed entry.
    if raw.get_field::<String>("type").ok().flatten().as_deref() == Some("m.room.encrypted") {
        return StickyExtract::NeedsDecryption(meta);
    }

    match read_content(raw) {
        Some((event_type, sticky_key, is_removal)) => StickyExtract::Sticky(StickyCandidate {
            key: StickyKey::new(meta.sender, event_type, sticky_key),
            event_id: meta.event_id,
            end_time: meta.end_time,
            is_removal,
        }),
        None => StickyExtract::NotSticky,
    }
}

/// Resolve a sticky candidate from the outer [`StickyMeta`] and the decrypted
/// content event. Returns `None` if the decrypted event lacks a `type`.
#[cfg(feature = "e2e-encryption")]
pub(crate) fn resolve(
    meta: StickyMeta,
    content: &Raw<AnySyncTimelineEvent>,
) -> Option<StickyCandidate> {
    let (event_type, sticky_key, is_removal) = read_content(content)?;
    Some(StickyCandidate {
        key: StickyKey::new(meta.sender, event_type, sticky_key),
        event_id: meta.event_id,
        end_time: meta.end_time,
        is_removal,
    })
}

/// Read the sticky metadata from the outer event, or `None` if it is not
/// sticky.
fn read_meta(received_ts: u64, raw: &Raw<AnySyncTimelineEvent>) -> Option<StickyMeta> {
    let sticky: StickyObject = raw.get_field("msc4354_sticky").ok().flatten()?;
    let sender: OwnedUserId = raw.get_field("sender").ok().flatten()?;
    let event_id: OwnedEventId = raw.get_field("event_id").ok().flatten()?;
    let origin_server_ts: u64 = raw.get_field("origin_server_ts").ok().flatten()?;

    // Prefer the server-provided remaining ttl (received_ts + ttl); otherwise
    // use the declared duration via the MSC4354 start/end formula.
    let ttl_ms = raw
        .get_field::<UnsignedProbe>("unsigned")
        .ok()
        .flatten()
        .and_then(|u| u.sticky_duration_ttl_ms);

    let end_time = match ttl_ms {
        Some(ttl) => received_ts.saturating_add(ttl.min(super::map::MAX_STICKY_DURATION_MS)),
        None => compute_end_time(origin_server_ts, received_ts, sticky.duration_ms.get()),
    };

    Some(StickyMeta { sender, event_id, end_time })
}

/// Read `(type, sticky_key, is_removal)` from a plaintext event's content.
fn read_content(raw: &Raw<AnySyncTimelineEvent>) -> Option<(String, Option<String>, bool)> {
    let event_type: String = raw.get_field("type").ok().flatten()?;
    let content: ContentProbe = raw.get_field("content").ok().flatten().unwrap_or_default();
    // A removal carries nothing beyond `sticky_key`.
    let is_removal = content.rest.is_empty();
    Some((event_type, content.sticky_key(), is_removal))
}

#[cfg(test)]
mod tests {
    use ruma::{events::AnySyncTimelineEvent, owned_event_id, owned_user_id, serde::Raw};
    use serde_json::{Value, json};

    use super::{StickyExtract, classify};

    const RECEIVED_TS: u64 = 10_000;

    fn raw(value: Value) -> Raw<AnySyncTimelineEvent> {
        serde_json::from_value(value).unwrap()
    }

    fn expect_sticky(extract: StickyExtract) -> super::StickyCandidate {
        match extract {
            StickyExtract::Sticky(candidate) => candidate,
            StickyExtract::NotSticky => panic!("expected sticky, got NotSticky"),
            StickyExtract::NeedsDecryption(_) => panic!("expected sticky, got NeedsDecryption"),
        }
    }

    #[test]
    fn test_connect_event_is_a_sticky_candidate() {
        let event = raw(json!({
            "type": "m.rtc.member",
            "sender": "@alice:localhost",
            "event_id": "$a:localhost",
            "origin_server_ts": 1000,
            "content": { "msc4354_sticky_key": "slot", "application": "m.call" },
            "msc4354_sticky": { "duration_ms": 500 },
        }));

        let candidate = expect_sticky(classify(RECEIVED_TS, &event));
        assert_eq!(candidate.key.sender, owned_user_id!("@alice:localhost"));
        assert_eq!(candidate.key.event_type, "m.rtc.member");
        assert_eq!(candidate.key.sticky_key.as_deref(), Some("slot"));
        assert_eq!(candidate.event_id, owned_event_id!("$a:localhost"));
        assert!(!candidate.is_removal);
        // start_time = min(1000, 10_000) = 1000; end = 1000 + 500.
        assert_eq!(candidate.end_time, 1500);
    }

    #[test]
    fn test_removal_event_when_content_only_carries_sticky_key() {
        let event = raw(json!({
            "type": "m.rtc.member",
            "sender": "@alice:localhost",
            "event_id": "$b:localhost",
            "origin_server_ts": 1000,
            "content": { "msc4354_sticky_key": "slot" },
            "msc4354_sticky": { "duration_ms": 500 },
        }));

        let candidate = expect_sticky(classify(RECEIVED_TS, &event));
        assert!(candidate.is_removal);
        assert_eq!(candidate.key.sticky_key.as_deref(), Some("slot"));
    }

    /// Sticky event contents may spell the key either way (ruma's own contents
    /// use the stable name), and both spellings at once must still read as a
    /// removal rather than as content of their own.
    #[test]
    fn test_removal_event_with_the_stable_sticky_key_spelling() {
        for content in [
            json!({ "sticky_key": "slot" }),
            json!({ "msc4354_sticky_key": "slot", "sticky_key": "slot" }),
        ] {
            let event = raw(json!({
                "type": "m.rtc.member",
                "sender": "@alice:localhost",
                "event_id": "$b:localhost",
                "origin_server_ts": 1000,
                "content": content,
                "msc4354_sticky": { "duration_ms": 500 },
            }));

            let candidate = expect_sticky(classify(RECEIVED_TS, &event));
            assert!(candidate.is_removal);
            assert_eq!(candidate.key.sticky_key.as_deref(), Some("slot"));
        }
    }

    #[test]
    fn test_unsigned_ttl_takes_precedence_over_duration() {
        let event = raw(json!({
            "type": "m.rtc.member",
            "sender": "@alice:localhost",
            "event_id": "$c:localhost",
            "origin_server_ts": 1000,
            "content": { "msc4354_sticky_key": "slot", "application": "m.call" },
            "msc4354_sticky": { "duration_ms": 500 },
            "unsigned": { "msc4354_sticky_duration_ttl_ms": 250_000 },
        }));

        let candidate = expect_sticky(classify(RECEIVED_TS, &event));
        // Uses received_ts + ttl, not origin + duration.
        assert_eq!(candidate.end_time, RECEIVED_TS + 250_000);
    }

    #[test]
    fn test_non_sticky_event_is_ignored() {
        let event = raw(json!({
            "type": "m.room.message",
            "sender": "@alice:localhost",
            "event_id": "$d:localhost",
            "origin_server_ts": 1000,
            "content": { "body": "hello", "msgtype": "m.text" },
        }));

        assert!(matches!(classify(RECEIVED_TS, &event), StickyExtract::NotSticky));
    }

    #[test]
    fn test_encrypted_sticky_event_needs_decryption_not_unkeyed() {
        // An encrypted sticky event must NOT be filed as an unkeyed
        // `m.room.encrypted` entry; it needs decryption first.
        let event = raw(json!({
            "type": "m.room.encrypted",
            "sender": "@alice:localhost",
            "event_id": "$e:localhost",
            "origin_server_ts": 1000,
            "content": { "algorithm": "m.megolm.v1.aes-sha2", "ciphertext": "AAA" },
            "msc4354_sticky": { "duration_ms": 500 },
        }));

        assert!(matches!(classify(RECEIVED_TS, &event), StickyExtract::NeedsDecryption(_)));
    }
}
