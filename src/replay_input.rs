//! Q6's narrow payload-retention exception: evidence identity remains immutable,
//! but a captured replay input expires with its memory. No signed state is changed.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{hygiene::HygienePolicy, signal::Signal, signal::SignalKind, ReedeError};

/// Retained after payload expiry, so its identity and original deadline survive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputRetention {
    pub sha256: String,
    pub expires_at: DateTime<Utc>,
}

impl InputRetention {
    pub fn matches(&self, input: &str) -> bool {
        self.sha256 == hex::encode(Sha256::digest(input.as_bytes()))
    }

    pub fn available(&self, input: &str, now: DateTime<Utc>) -> bool {
        self.expires_at > now && self.matches(input)
    }
}

/// Capture once, before append, and only on a correction with a corrected answer.
/// An actual empty input is allowed; absence never becomes an empty input.
pub fn capture_replay_input(
    signal: &mut Signal,
    input: &str,
    captured_at: DateTime<Utc>,
    policy: &HygienePolicy,
) -> Result<(), ReedeError> {
    let expires_at = memory_deadline(captured_at, policy)?;
    capture_with_expiry(signal, input, expires_at)
}

/// A source may require an earlier deadline than memory's TTL. Its original
/// capture clock and fixed deadline must never be reset by an approval/retry.
pub fn capture_replay_input_with_deadline(
    signal: &mut Signal,
    input: &str,
    captured_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    policy: &HygienePolicy,
) -> Result<(), ReedeError> {
    let now = Utc::now();
    if captured_at > now
        || expires_at <= captured_at
        || expires_at <= now
        || expires_at > memory_deadline(captured_at, policy)?
    {
        return Err(ReedeError::SpecValidationFailed {
            reason: "replay input requires an available original, nonextended deadline".into(),
        });
    }
    capture_with_expiry(signal, input, expires_at)
}

fn memory_deadline(
    captured_at: DateTime<Utc>,
    policy: &HygienePolicy,
) -> Result<DateTime<Utc>, ReedeError> {
    captured_at
        .checked_add_signed(policy.default_ttl)
        .filter(|deadline| *deadline > captured_at)
        .ok_or_else(|| ReedeError::SpecValidationFailed {
            reason: "replay input requires a finite positive memory TTL".into(),
        })
}

fn capture_with_expiry(
    signal: &mut Signal,
    input: &str,
    expires_at: DateTime<Utc>,
) -> Result<(), ReedeError> {
    let corrected = signal
        .raw
        .get("after")
        .or_else(|| signal.raw.get("corrected_output"));
    if signal.kind != SignalKind::Correction
        || !signal.value.is_finite()
        || signal.value >= 0.0
        || corrected
            .and_then(serde_json::Value::as_str)
            .is_none_or(|s| s.trim().is_empty())
    {
        return Err(ReedeError::SpecValidationFailed {
            reason: "replay input belongs only to an actual corrected output".into(),
        });
    }
    let raw = signal
        .raw
        .as_object_mut()
        .ok_or_else(|| ReedeError::SpecValidationFailed {
            reason: "a correction payload must be an object".into(),
        })?;
    if raw.contains_key("input") || raw.contains_key("input_retention") {
        return Err(ReedeError::SpecValidationFailed {
            reason: "a replay input and its deadline cannot be replaced or extended".into(),
        });
    }
    let retention = InputRetention {
        sha256: hex::encode(Sha256::digest(input.as_bytes())),
        expires_at,
    };
    raw.insert("input".into(), input.into());
    raw.insert(
        "input_retention".into(),
        serde_json::to_value(retention).expect("retention serializes"),
    );
    Ok(())
}

/// Legacy or malformed metadata is not trustworthy replay evidence. Its history
/// can still be read/appended; no deadline is invented for it.
pub fn input_retention(signal: &Signal) -> Option<InputRetention> {
    let retention: InputRetention =
        serde_json::from_value(signal.raw.get("input_retention")?.clone()).ok()?;
    (retention.sha256.len() == 64
        && retention
            .sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then_some(retention)
}

pub fn retained_input(signal: &Signal, now: DateTime<Utc>) -> Option<(&str, InputRetention)> {
    let retention = input_retention(signal)?;
    let input = signal.raw.get("input")?.as_str()?;
    retention
        .available(input, now)
        .then_some((input, retention))
}

/// Only the input is removed. Digest, deadline and all evidence metadata remain.
pub fn redact_signal_input(signal: &mut Signal, now: DateTime<Utc>) -> bool {
    if input_retention(signal).is_some_and(|r| r.expires_at <= now) {
        return signal
            .raw
            .as_object_mut()
            .is_some_and(|raw| raw.remove("input").is_some());
    }
    false
}

/// A retry names the same case, without relying on a fresh random id. Length
/// framing prevents tenant/key separator collisions.
pub fn signal_case_id(signal: &Signal) -> String {
    let framed =
        crate::receipt::encode_fields_injective(&[&signal.tenant_id, &signal.idempotency_key]);
    format!("gld_{:x}", Sha256::digest(framed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn correction() -> Signal {
        let mut signal = Signal::builder("subject")
            .tenant("tenant")
            .idempotency("edit")
            .run("run")
            .kind(SignalKind::Correction)
            .value(-0.5)
            .build();
        signal.raw = serde_json::json!({"before": "wrong", "after": "right"});
        signal
    }

    #[test]
    fn leading_zero_digest_survives_capture_and_golden_replay() {
        let input = "leading-zero-182";
        let expected = "00db57de56c23d7616da1961591ce0878cd14fe1102db36dcd54f389e6356ed6";
        let now = Utc::now();
        let mut signal = correction();
        capture_replay_input(&mut signal, input, now, &HygienePolicy::default()).unwrap();

        let retention = input_retention(&signal).unwrap();
        assert_eq!(retention.sha256.len(), 64);
        assert_eq!(retention.sha256, expected);
        assert!(retention.available(input, now));
        assert_eq!(retained_input(&signal, now).unwrap().0, input);

        let mut case = crate::honesty::golden_case_from_signal(&signal).unwrap();
        assert_eq!(case.input, input);
        assert_eq!(case.input_retention, Some(retention));
        assert!(case.replay_available(now));
        case.input.push('!');
        assert!(!case.replay_available(now));
    }

    #[test]
    fn empty_captured_input_expires_without_extending_or_erasing_evidence() {
        let now = Utc::now();
        let policy = HygienePolicy {
            default_ttl: Duration::seconds(2),
            ..HygienePolicy::default()
        };
        let mut signal = correction();
        capture_replay_input(&mut signal, "", now, &policy).unwrap();
        assert_eq!(
            input_retention(&signal).unwrap().expires_at,
            now + policy.default_ttl
        );
        assert_eq!(retained_input(&signal, now).unwrap().0, "");
        let original = signal.clone();
        assert!(capture_replay_input(&mut signal, "replacement", now, &policy).is_err());
        assert_eq!(signal, original);
        assert!(retained_input(&signal, now + Duration::seconds(2)).is_none());
        assert!(redact_signal_input(&mut signal, now + Duration::seconds(2)));
        assert!(signal.raw.get("input").is_none());
        assert_eq!(input_retention(&signal), input_retention(&original));
        assert_eq!(signal.idempotency_key, original.idempotency_key);
        assert_eq!(signal.raw["after"], "right");
        assert!(capture_replay_input(&mut signal, "replacement", now, &policy).is_err());
        assert!(!redact_signal_input(
            &mut signal,
            now + Duration::seconds(3)
        ));
    }

    #[test]
    fn missing_unbounded_or_tampered_input_is_unavailable() {
        let now = Utc::now();
        let mut signal = correction();
        assert!(retained_input(&signal, now).is_none());
        signal.raw["input"] = "legacy".into();
        assert!(retained_input(&signal, now).is_none());
        signal.raw.as_object_mut().unwrap().remove("input");
        capture_replay_input(&mut signal, "original", now, &HygienePolicy::default()).unwrap();
        signal.raw["input"] = "tampered".into();
        assert!(retained_input(&signal, now).is_none());
    }

    #[test]
    fn capture_refuses_routine_approvals_and_noncorrections() {
        for (kind, value, after) in [
            (SignalKind::Correction, 0.0, "right"),
            (SignalKind::Outcome, -1.0, "right"),
            (SignalKind::Correction, -0.5, " "),
        ] {
            let mut signal = correction();
            signal.kind = kind;
            signal.value = value;
            signal.raw["after"] = after.into();
            assert!(capture_replay_input(
                &mut signal,
                "request",
                Utc::now(),
                &HygienePolicy::default()
            )
            .is_err());
            assert!(signal.raw.get("input").is_none());
        }
    }

    #[test]
    fn source_deadline_can_shorten_but_not_reset_or_extend_memory_ttl() {
        let now = Utc::now();
        let policy = HygienePolicy {
            default_ttl: Duration::seconds(10),
            ..HygienePolicy::default()
        };
        let deadline = now + Duration::seconds(2);
        let mut signal = correction();
        capture_replay_input_with_deadline(&mut signal, "original", now, deadline, &policy)
            .unwrap();
        assert_eq!(input_retention(&signal).unwrap().expires_at, deadline);
        assert!(capture_replay_input_with_deadline(
            &mut signal,
            "replacement",
            now,
            now + Duration::seconds(3),
            &policy
        )
        .is_err());
        assert_eq!(retained_input(&signal, now).unwrap().0, "original");
        for invalid in [now - Duration::seconds(1), now, now + Duration::seconds(11)] {
            let mut signal = correction();
            assert!(capture_replay_input_with_deadline(
                &mut signal,
                "original",
                now,
                invalid,
                &policy
            )
            .is_err());
            assert!(signal.raw.get("input").is_none());
        }
    }

    #[test]
    fn case_identity_is_stable_and_length_framed() {
        let mut a = correction();
        a.tenant_id = "a:b".into();
        a.idempotency_key = "c".into();
        let mut b = a.clone();
        b.tenant_id = "a".into();
        b.idempotency_key = "b:c".into();
        assert_eq!(signal_case_id(&a), signal_case_id(&a.clone()));
        assert_ne!(signal_case_id(&a), signal_case_id(&b));
    }
}
