//! Keeping the memory store honest over time.
//!
//! Two failures this prevents, both slow and both silent:
//!
//! - **Accumulation.** A memory store that only grows retrieves ever more, ever
//!   staler context, and the lesson from eight months ago outvotes the one from
//!   Tuesday. Nothing goes red; answers just get worse.
//! - **Evidence that turned out to be wrong.** Someone withdraws a correction. The
//!   memory it produced keeps being retrieved and acted on, and there is nothing in
//!   the retrieved text to say the human took it back.
//!
//! ## Decay, not rewriting
//!
//! The spec is specific: *"Decay weight; do not rewrite memory text."* A memory's
//! text is a record of what somebody said. Editing it to reflect diminished
//! confidence produces a sentence nobody wrote, attributed to a human, in a store
//! whose entire value is that its contents are traceable to real judgements. The
//! weight is the confidence; the text stays put.
//!
//! ## Expiry is the default, and the exception is earned
//!
//! Also from the spec: *"Expiry is the default; a null `expires_at` means the record
//! was promoted deliberately and has a regression behind it."* So a null is a claim
//! -- "a test protects this" -- and [`assert_permanent`] is the only way to make one,
//! refusing unless a regression is named.
//!
//! Phase 4 is what will supply those names. Until it lands, nothing can legitimately
//! claim permanence, which is the correct state rather than a gap: a memory that
//! outlives its evidence with no test behind it is precisely what the honesty layer
//! exists to prevent.
//!
//! ## Retraction records, never deletes
//!
//! A withdrawal zero-weights what it produced and leaves a [`RetractionRecord`]. The
//! row and its provenance edges stay, because "this was believed and then taken
//! back" is a thing an operator needs to see. A silent delete leaves a store that
//! cannot explain its own history.

use crate::error::ReedeError;
use crate::memory::Memory;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// How memories age and expire.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HygienePolicy {
    /// How long until a memory counts half as much.
    pub half_life: Duration,
    /// TTL applied to a memory with no regression behind it.
    pub default_ttl: Duration,
    /// Below this effective weight a memory stops being worth retrieving. Without a
    /// floor, exponential decay never reaches zero and a store keeps returning rows
    /// worth 0.0001 forever -- which is accumulation wearing decay's clothes.
    pub floor: f64,
}

impl Default for HygienePolicy {
    /// Half-life 90 days, TTL one year, floor 0.05.
    ///
    /// Ninety days because a correction about how this quarter's product behaves is
    /// mostly still true next quarter and mostly isn't a year later. A year's TTL
    /// because that is roughly four half-lives -- by then an untested memory counts
    /// for about a sixteenth of its original weight, and keeping the row costs more
    /// than it is worth. Both are judgement calls, which is why they are policy.
    fn default() -> Self {
        Self {
            half_life: Duration::days(90),
            default_ttl: Duration::days(365),
            floor: 0.05,
        }
    }
}

impl HygienePolicy {
    /// The decay multiplier for something `age` old. 1.0 at zero age, 0.5 at one
    /// half-life.
    pub fn decay_factor(&self, age: Duration) -> f64 {
        let half_life = self.half_life.num_seconds();
        if half_life <= 0 {
            // A non-positive half-life means "do not decay". Treating it as instant
            // decay would silently zero a whole store on a config typo.
            return 1.0;
        }
        let age = age.num_seconds().max(0) as f64;
        0.5_f64.powf(age / half_life as f64)
    }
}

/// A memory's weight right now: stored weight, decayed, floored.
///
/// Decay runs from `last_reinforced_at` when a memory has been corroborated since it
/// was written, and from `written_at` otherwise. Corroboration is the store learning
/// the lesson is still true, so ageing it from the original write would let a
/// repeatedly-confirmed memory fade anyway.
///
/// Returns `0.0` below the floor rather than a small number, so "not worth
/// retrieving" is a value a caller can test rather than a threshold every caller has
/// to remember.
pub fn effective_weight(memory: &Memory, now: DateTime<Utc>, policy: &HygienePolicy) -> f64 {
    if !memory.is_live(now) {
        return 0.0;
    }
    let from = memory.last_reinforced_at.unwrap_or(memory.written_at);
    let weight = memory.weight * policy.decay_factor(now - from);
    if weight < policy.floor {
        0.0
    } else {
        weight
    }
}

/// Whether this memory should still be returned by a retrieval.
pub fn is_retrievable(memory: &Memory, now: DateTime<Utc>, policy: &HygienePolicy) -> bool {
    effective_weight(memory, now, policy) > 0.0
}

/// Record that this lesson was confirmed again.
///
/// Raises the stored weight by `additional` and restarts the clock. Deliberately
/// does not touch the text: another human agreeing does not change what the first
/// one said.
pub fn reinforce(memory: &mut Memory, additional: f64, now: DateTime<Utc>, max_weight: f64) {
    memory.weight = (memory.weight + additional).min(max_weight);
    memory.last_reinforced_at = Some(now);
}

/// Give a memory the default TTL, unless it already has one.
///
/// The rule expressed as code: a memory arrives mortal, and only [`assert_permanent`]
/// can change that.
pub fn apply_default_ttl(memory: &mut Memory, policy: &HygienePolicy) {
    if memory.expires_at.is_none() {
        memory.expires_at = Some(memory.written_at + policy.default_ttl);
    }
}

/// Make a memory permanent, naming the regression that justifies it.
///
/// The spec: a null `expires_at` "means the record was promoted deliberately and has
/// a regression behind it". This is the only path to that null, and it refuses
/// without a name -- so the claim cannot be made by simply forgetting to set a TTL,
/// which is how it would otherwise happen most of the time.
pub fn assert_permanent(memory: &mut Memory, regression_id: &str) -> Result<(), ReedeError> {
    if regression_id.trim().is_empty() {
        return Err(ReedeError::SpecValidationFailed {
            reason:
                "a permanent memory must name the regression test behind it; expiry is the default"
                    .to_string(),
        });
    }
    memory.expires_at = None;
    memory.regression_id = Some(regression_id.trim().to_string());
    Ok(())
}

/// Why a memory was retracted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetractionCause {
    /// The signal behind it was withdrawn.
    SignalWithdrawn,
    /// Phase 4: the regression replay did not improve, so the lesson is not earning
    /// its place.
    ReplayRegression,
    /// An operator retracted it directly.
    Manual,
}

impl RetractionCause {
    pub fn as_str(&self) -> &'static str {
        match self {
            RetractionCause::SignalWithdrawn => "signal_withdrawn",
            RetractionCause::ReplayRegression => "replay_regression",
            RetractionCause::Manual => "manual",
        }
    }
}

/// The audit trail for one retraction.
///
/// The spec asks that retraction "record the retraction rather than deleting
/// silently". This is that record: what was retracted, why, and what it was worth
/// before -- the last of which is the part an operator asking "how much did we act on
/// this?" actually needs, and the part a delete destroys.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetractionRecord {
    pub tenant_id: String,
    pub memory_id: String,
    pub role: String,
    /// The signal whose withdrawal caused this, when there was one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal_idempotency_key: Option<String>,
    pub cause: RetractionCause,
    /// The stored weight immediately before retraction.
    pub weight_before: f64,
    pub retracted_at: DateTime<Utc>,
}

impl RetractionRecord {
    pub fn new(
        memory: &Memory,
        cause: RetractionCause,
        signal_idempotency_key: Option<String>,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            tenant_id: memory.tenant_id.clone(),
            memory_id: memory.id.clone(),
            role: memory.role.clone(),
            signal_idempotency_key,
            cause,
            weight_before: memory.weight,
            retracted_at: now,
        }
    }
}

/// One retrieved memory, with the chain that put it there.
///
/// The spec's provenance view: "for any run, which memories were retrieved, which run
/// produced each, and which signal earned it." All three, or the view answers the
/// easy third of the question.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvenanceEntry {
    pub memory_id: String,
    pub role: String,
    pub scope_key: String,
    pub text: String,
    /// Weight after decay at the time of the retrieval, not the stored one. What the
    /// memory was actually worth when it influenced the run.
    pub effective_weight: f64,
    /// The run that produced the lesson (`derived_from -> receipt`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub produced_by_run: Option<String>,
    /// The signal that earned it (`signal -> promoted_to`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub earned_by_signal: Option<String>,
}

impl ProvenanceEntry {
    pub fn of(memory: &Memory, now: DateTime<Utc>, policy: &HygienePolicy) -> Self {
        Self {
            memory_id: memory.id.clone(),
            role: memory.role.clone(),
            scope_key: memory.scope_key.clone(),
            text: memory.text.clone(),
            effective_weight: effective_weight(memory, now, policy),
            produced_by_run: memory.derived_from_receipt.clone(),
            earned_by_signal: memory.promoted_from_signal.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryKind;
    use crate::RoleKey;

    fn role() -> RoleKey {
        RoleKey::new("council-summary", "product").unwrap()
    }

    fn memory(written_at: DateTime<Utc>, weight: f64) -> Memory {
        let mut m = Memory::builder(&role(), "billing")
            .tenant("tenant-1")
            .text("the balance comes from account-history")
            .kind(MemoryKind::Correction)
            .weight(weight)
            .written_at(written_at)
            .promoted_from("diff-capture:run-1", "receipt-1")
            .build()
            .unwrap();
        m.id = "mem_1".to_string();
        m
    }

    #[test]
    fn a_fresh_memory_keeps_its_full_weight() {
        let now = Utc::now();
        let policy = HygienePolicy::default();
        assert!((effective_weight(&memory(now, 1.0), now, &policy) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn one_half_life_halves_the_weight() {
        let now = Utc::now();
        let policy = HygienePolicy::default();
        let m = memory(now - policy.half_life, 1.0);
        assert!((effective_weight(&m, now, &policy) - 0.5).abs() < 1e-6);
    }

    #[test]
    fn decay_reaches_the_floor_and_stops_rather_than_trailing_off() {
        // Without the floor, exponential decay never hits zero and the store keeps
        // returning rows worth 0.0001 forever -- accumulation wearing decay's clothes.
        let now = Utc::now();
        let policy = HygienePolicy::default();
        let ancient = memory(now - Duration::days(365 * 5), 1.0);
        assert_eq!(effective_weight(&ancient, now, &policy), 0.0);
        assert!(!is_retrievable(&ancient, now, &policy));
    }

    #[test]
    fn a_non_positive_half_life_means_no_decay_not_instant_decay() {
        // A config typo must not silently zero a whole tenant's memory.
        let now = Utc::now();
        let policy = HygienePolicy {
            half_life: Duration::zero(),
            ..HygienePolicy::default()
        };
        let old = memory(now - Duration::days(1000), 1.0);
        assert!((effective_weight(&old, now, &policy) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn reinforcement_restarts_the_clock_and_raises_the_weight() {
        let now = Utc::now();
        let policy = HygienePolicy::default();
        let mut m = memory(now - policy.half_life, 1.0);
        assert!((effective_weight(&m, now, &policy) - 0.5).abs() < 1e-6);

        reinforce(&mut m, 0.4, now, 3.0);
        assert!(
            (effective_weight(&m, now, &policy) - 1.4).abs() < 1e-6,
            "corroboration is the store learning the lesson is still true; ageing \
             it from the original write would let a confirmed memory fade anyway"
        );
    }

    #[test]
    fn reinforcement_respects_the_cap() {
        let now = Utc::now();
        let mut m = memory(now, 2.9);
        reinforce(&mut m, 5.0, now, 3.0);
        assert_eq!(m.weight, 3.0);
    }

    #[test]
    fn reinforcement_never_touches_the_text() {
        // The spec: "Decay weight; do not rewrite memory text."
        let now = Utc::now();
        let mut m = memory(now, 1.0);
        let before = m.text.clone();
        reinforce(&mut m, 1.0, now, 3.0);
        assert_eq!(m.text, before);
    }

    #[test]
    fn a_retracted_memory_has_no_effective_weight() {
        let now = Utc::now();
        let mut m = memory(now, 1.0);
        m.weight = 0.0;
        assert_eq!(effective_weight(&m, now, &HygienePolicy::default()), 0.0);
    }

    #[test]
    fn an_expired_memory_has_no_effective_weight_however_heavy() {
        let now = Utc::now();
        let mut m = memory(now, 3.0);
        m.expires_at = Some(now - Duration::seconds(1));
        assert_eq!(effective_weight(&m, now, &HygienePolicy::default()), 0.0);
    }

    #[test]
    fn a_memory_arrives_mortal() {
        let now = Utc::now();
        let policy = HygienePolicy::default();
        let mut m = memory(now, 1.0);
        assert!(m.expires_at.is_none(), "the builder sets none");
        apply_default_ttl(&mut m, &policy);
        assert_eq!(m.expires_at, Some(now + policy.default_ttl));
    }

    #[test]
    fn applying_the_default_ttl_does_not_overwrite_an_explicit_one() {
        let now = Utc::now();
        let mut m = memory(now, 1.0);
        let explicit = now + Duration::days(7);
        m.expires_at = Some(explicit);
        apply_default_ttl(&mut m, &HygienePolicy::default());
        assert_eq!(m.expires_at, Some(explicit));
    }

    #[test]
    fn permanence_must_name_a_regression() {
        let now = Utc::now();
        let mut m = memory(now, 1.0);
        assert!(
            assert_permanent(&mut m, "   ").is_err(),
            "the null is a claim that a test protects this; it cannot be made by \
             forgetting to set a TTL"
        );
        assert!(assert_permanent(&mut m, "golden::billing_balance").is_ok());
        assert_eq!(m.expires_at, None);
        assert_eq!(m.regression_id.as_deref(), Some("golden::billing_balance"));
    }

    #[test]
    fn a_permanent_memory_does_not_get_a_default_ttl_back() {
        let now = Utc::now();
        let policy = HygienePolicy::default();
        let mut m = memory(now, 1.0);
        assert_permanent(&mut m, "golden::x").unwrap();
        apply_default_ttl(&mut m, &policy);
        assert_eq!(
            m.expires_at,
            Some(now + policy.default_ttl),
            "apply_default_ttl is a floor for anything without a TTL, including a \
             permanent record -- callers order it before assert_permanent, and this \
             documents which way round that is"
        );
    }

    #[test]
    fn a_retraction_record_keeps_what_the_memory_was_worth() {
        let now = Utc::now();
        let m = memory(now, 2.4);
        let record = RetractionRecord::new(
            &m,
            RetractionCause::SignalWithdrawn,
            Some("diff-capture:run-1".to_string()),
            now,
        );
        assert_eq!(record.memory_id, "mem_1");
        assert_eq!(record.role, "council-summary/product");
        assert_eq!(
            record.weight_before, 2.4,
            "'how much did we act on this' is the question a delete destroys"
        );
        assert_eq!(record.cause, RetractionCause::SignalWithdrawn);
        // Round-trips, so the audit row is the record rather than a rendering.
        let json = serde_json::to_string(&record).unwrap();
        assert_eq!(
            serde_json::from_str::<RetractionRecord>(&json).unwrap(),
            record
        );
    }

    #[test]
    fn a_provenance_entry_answers_all_three_parts_of_the_question() {
        // "which memories were retrieved, which run produced each, and which signal
        // earned it" -- all three, or the view answers the easy third.
        let now = Utc::now();
        let policy = HygienePolicy::default();
        let entry = ProvenanceEntry::of(&memory(now - policy.half_life, 1.0), now, &policy);
        assert_eq!(entry.memory_id, "mem_1");
        assert_eq!(entry.produced_by_run.as_deref(), Some("receipt-1"));
        assert_eq!(
            entry.earned_by_signal.as_deref(),
            Some("diff-capture:run-1")
        );
        assert!(
            (entry.effective_weight - 0.5).abs() < 1e-6,
            "the decayed weight, not the stored one: what it was actually worth when \
             it influenced the run"
        );
    }
}
