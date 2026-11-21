//! Whether a signal becomes a memory, and how much it counts.
//!
//! Two gates, in order:
//!
//! 1. **Attribution** (Phase 1). `Signal::is_promotable` -- a run, a role, and a
//!    source that claims attribution. Nothing here can override it.
//! 2. **Corroboration.** High-trust signals stand alone. Low-trust ones need N
//!    agreeing within a window, both per-tenant.
//!
//! The spec's acceptance criterion is the shortest statement of the point: *"A
//! single anonymous thumbs-down provably does not promote."* One stranger's thumb is
//! not a lesson. Three within a week might be.
//!
//! ## What makes a signal high-trust
//!
//! Someone with the context did specific work that only makes sense as a judgement
//! of *this* output:
//!
//! - a human edited a drafted output (`diff-capture`) -- they read it and changed it;
//! - a human rejected it at a HITL gate, or reversed a shipped decision;
//! - a human wrote prose in reply to this run's inquiry (`inquiry`).
//!
//! What makes a signal low-trust is the absence of that: an anonymous thumb costs one
//! click and carries no account of what was wrong, and a rejection the system merely
//! *inferred* was never asserted by anybody.
//!
//! ## Inferred attribution forces corroboration, whatever the trust tier
//!
//! This is the rule that is easy to miss. A human edit is high-trust evidence *that
//! something was wrong*; it is not evidence about **which role** was wrong unless
//! something recorded that. When U1.2's attribution pass supplied the role, the
//! model's verdict is the weakest link in the chain, and promoting on it alone would
//! write one role's lesson into another role's scope on the strength of a guess --
//! the exact failure the whole loop is built to avoid, and the one nothing
//! downstream can detect.
//!
//! So `AttributionSource::Inferred` demotes to needing corroboration. It is the
//! reason `Explicit` and `Inferred` are distinct values rather than one "attributed"
//! flag; if they were the same, this rule could not be written.
//!
//! ## inquiry text is never paraphrased
//!
//! The spec: *"Store the inquiry text as the correction body; do not paraphrase or
//! summarise it."* It is the "why it was wrong" prose everything else has to
//! reconstruct, and a summary of it is a lossy copy of the most valuable thing in the
//! system. [`PromotionDecision::body`] returns the signal's text unchanged.
//!
//! ## Every decision is logged with its inputs
//!
//! [`PromotionDecision`] carries the tier, the corroboration count, the threshold it
//! was measured against and the resulting weight -- not a verdict alone. A promotion
//! nobody can reconstruct is a memory nobody can defend when it turns out to be
//! wrong.

use crate::signal::{AttributionSource, Signal, SignalKind};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// How much a signal's own evidence is worth before corroboration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustTier {
    /// Someone with the context did specific work judging this output. Promotes
    /// alone.
    High,
    /// A cheap or inferred signal. Needs N agreeing within the window.
    Low,
}

impl TrustTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustTier::High => "high",
            TrustTier::Low => "low",
        }
    }

    /// The signal-type weight, the first factor in the stored weight.
    ///
    /// A corroborated low-trust signal is worth less than a high-trust one even at
    /// equal counts: three anonymous thumbs agree that *something* is off, while one
    /// human edit says what. Making them equal at N=2 would let volume outrank
    /// specificity, which is how a memory store fills up with vague lessons.
    pub fn base_weight(&self) -> f64 {
        match self {
            TrustTier::High => 1.0,
            TrustTier::Low => 0.4,
        }
    }
}

impl std::fmt::Display for TrustTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Producers whose signals are high-trust. See the module note on what qualifies.
///
/// A producer absent from this list is low-trust, which is the fail-safe direction:
/// the cost of being wrong is a signal that waits for corroboration, not a memory
/// written on one click.
const HIGH_TRUST_PRODUCERS: &[&str] = &[
    "diff-capture",
    "frogen",
    "inquiry",
    "hitl-rejection",
    "reversal",
];

/// Per-tenant corroboration thresholds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PromotionPolicy {
    /// How many agreeing low-trust signals are needed.
    pub corroboration_n: usize,
    /// How far back agreement counts.
    pub window: Duration,
    /// Cap on the stored weight, so a viral thumbs-down cannot outrank everything a
    /// role has ever learned. Without it, weight = base x count is unbounded and one
    /// heavily-corroborated lesson silently becomes the only one retrieval returns.
    pub max_weight: f64,
}

impl Default for PromotionPolicy {
    /// Three within seven days.
    ///
    /// Three because two is a coincidence often enough to matter and four is rare
    /// enough that most real agreement never reaches it. Seven days because feedback
    /// on the same failure arrives across a working week, and a shorter window
    /// discards agreement that is genuinely about one problem. Both are per-tenant
    /// precisely because these are judgement calls, not findings.
    fn default() -> Self {
        Self {
            corroboration_n: 3,
            window: Duration::days(7),
            max_weight: 3.0,
        }
    }
}

impl PromotionPolicy {
    pub fn new(corroboration_n: usize, window: Duration) -> Self {
        Self {
            corroboration_n,
            window,
            ..Self::default()
        }
    }

    pub fn with_max_weight(mut self, max_weight: f64) -> Self {
        self.max_weight = max_weight;
        self
    }
}

/// Why a signal did not promote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionRefusal {
    /// Gate 1: no run, no role, or no attribution.
    Unattributed,
    /// Gate 2: not enough agreement yet. Carries both numbers so the log says how
    /// close it came, not merely that it failed.
    NeedsCorroboration { have: usize, need: usize },
}

impl PromotionRefusal {
    pub fn reason(&self) -> String {
        match self {
            PromotionRefusal::Unattributed => {
                "the signal has no run and role, so there is no memory scope to write to"
                    .to_string()
            }
            PromotionRefusal::NeedsCorroboration { have, need } => format!(
                "low-trust signal corroborated {have} time(s) within the window, needs {need}"
            ),
        }
    }
}

/// The full record of one promotion decision, refusals included.
///
/// Serializable and logged whole. The spec asks that "every promotion decision is
/// logged with the inputs that produced it"; a boolean plus a message would satisfy
/// the letter of that and none of the use, which is reconstructing months later why
/// a particular memory exists.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PromotionDecision {
    pub signal_idempotency_key: String,
    pub tenant_id: String,
    /// The role the memory would be written to. `None` when the signal is
    /// unattributed, which is itself the reason it was refused.
    pub role: Option<String>,
    pub tier: TrustTier,
    pub attribution_source: AttributionSource,
    /// True when a high-trust signal was held to the low-trust rule because its role
    /// was inferred. Recorded explicitly: without it the log shows a `diff-capture`
    /// signal refused for corroboration and reads like a bug.
    pub demoted_for_inferred_role: bool,
    /// Agreeing signals found in the window, this one included.
    pub corroboration: usize,
    /// What `corroboration` had to reach. Zero for a high-trust signal.
    pub required: usize,
    /// `base_weight x corroboration`, capped. Zero when refused.
    pub weight: f64,
    pub refusal: Option<PromotionRefusal>,
    pub decided_at: DateTime<Utc>,
}

impl PromotionDecision {
    pub fn promoted(&self) -> bool {
        self.refusal.is_none()
    }

    /// One line for the log.
    pub fn summary(&self) -> String {
        match &self.refusal {
            None => format!(
                "promote {} to {} (tier {}, {} corroborating, weight {:.2})",
                self.signal_idempotency_key,
                self.role.as_deref().unwrap_or("?"),
                self.tier,
                self.corroboration,
                self.weight
            ),
            Some(refusal) => format!(
                "hold {} (tier {}, {})",
                self.signal_idempotency_key,
                self.tier,
                refusal.reason()
            ),
        }
    }
}

/// Which tier a signal falls in, before the inferred-role demotion.
pub fn trust_tier(signal: &Signal) -> TrustTier {
    if HIGH_TRUST_PRODUCERS.contains(&signal.source.as_str()) {
        TrustTier::High
    } else {
        TrustTier::Low
    }
}

/// The correction body to store, verbatim.
///
/// Returns the signal's own text with nothing done to it. Exists as a named function
/// rather than an inline field read so the spec's "do not paraphrase or summarise"
/// has somewhere to live where a future caller will see it.
///
/// It read `raw.text`, which **no producer in the tree writes**. The canonical
/// payloads are fixed by the producers themselves:
///
/// - inquiry `Response` -- `{"question": ..., "answer": ...}` (`signal.rs`)
/// - diff-capture `Correction` -- `{"before": ..., "after": ...}` (`correction.rs`)
///
/// So every real signal fell through to the generic "<source> recorded a <kind>"
/// sentence and the verbatim human answer -- the whole reason the promotion contract
/// says to store the body -- was discarded. The field is chosen by kind rather than
/// by trying them all, so a payload that happens to carry both cannot pick the wrong
/// one; `text` stays as a last resort for a producer that does use it.
pub fn correction_body(signal: &Signal) -> Option<&str> {
    let canonical = match signal.kind {
        SignalKind::Response => "answer",
        SignalKind::Correction => "after",
        _ => "text",
    };
    let read = |field: &str| {
        signal
            .raw
            .get(field)
            .and_then(|v| v.as_str())
            .filter(|t| !t.trim().is_empty())
    };
    read(canonical).or_else(|| read("text"))
}

/// Count `signal` and every other signal that agrees with it inside the window.
///
/// "Agrees" is deliberately narrow: same tenant, same role, same kind, same sign of
/// `value`, inside the window, and not the same signal twice. Same sign matters --
/// a thumbs-up and a thumbs-down on one role are not two votes for a lesson, they are
/// a disagreement, and counting them together would promote on the strength of
/// people contradicting each other.
///
/// The window applies to the signal itself too. It used to be added unconditionally
/// -- `1 + others…` -- while the cutoff filtered only `others`, so a rating held for
/// a fortnight promoted the moment two fresh ones agreed with it, on a threshold of
/// three: two signals inside the window, counted as three. A queue that holds rows
/// until they corroborate makes stale targets the normal case, not the exotic one.
pub fn corroboration_count(
    signal: &Signal,
    others: &[Signal],
    policy: &PromotionPolicy,
    now: DateTime<Utc>,
) -> usize {
    let cutoff = now - policy.window;
    let target = usize::from(signal.observed_at >= cutoff);
    let agrees = |other: &Signal| {
        other.idempotency_key != signal.idempotency_key
            && other.tenant_id == signal.tenant_id
            && other.role == signal.role
            && other.kind == signal.kind
            && other.observed_at >= cutoff
            && other.value.signum() == signal.value.signum()
            // A withdrawn signal is not agreement. Stores exclude these from reads
            // already; checking here means a caller passing an unfiltered set cannot
            // accidentally count a retracted vote.
            && other.kind != SignalKind::Withdrawal
    };
    target + others.iter().filter(|o| agrees(o)).count()
}

/// Decide whether `signal` promotes, given the other signals that might corroborate it.
pub fn decide(
    signal: &Signal,
    others: &[Signal],
    policy: &PromotionPolicy,
    now: DateTime<Utc>,
) -> PromotionDecision {
    decide_with_corroboration_count(
        signal,
        corroboration_count(signal, others, policy, now),
        policy,
        now,
    )
}

/// Apply the canonical policy to an independently measured corroboration count.
///
/// Storage adapters can aggregate evidence without transferring entire signal payloads.
/// The caller must apply the same tenant, role, kind, sign, observation-window and
/// distinct-key rules as [`corroboration_count`], excluding withdrawn evidence. The
/// count includes the target only when it falls inside the window. This function
/// retains attribution, inferred-role, threshold and weighting rules in one place.
pub fn decide_with_corroboration_count(
    signal: &Signal,
    corroboration: usize,
    policy: &PromotionPolicy,
    now: DateTime<Utc>,
) -> PromotionDecision {
    let tier = trust_tier(signal);
    let base = PromotionDecision {
        signal_idempotency_key: signal.idempotency_key.clone(),
        tenant_id: signal.tenant_id.clone(),
        role: signal.role.clone(),
        tier,
        attribution_source: signal.attribution_source,
        demoted_for_inferred_role: false,
        corroboration: 0,
        required: 0,
        weight: 0.0,
        refusal: None,
        decided_at: now,
    };

    // Gate 1. Nothing below can override it.
    if !signal.is_promotable() {
        return PromotionDecision {
            refusal: Some(PromotionRefusal::Unattributed),
            ..base
        };
    }

    // A high-trust signal whose role was worked out by a model is only as reliable as
    // that verdict. See the module note.
    let inferred = signal.attribution_source == AttributionSource::Inferred;
    let demoted = tier == TrustTier::High && inferred;
    let effective = if inferred { TrustTier::Low } else { tier };

    let required = match effective {
        TrustTier::High => 0,
        TrustTier::Low => policy.corroboration_n,
    };

    if corroboration < required {
        return PromotionDecision {
            demoted_for_inferred_role: demoted,
            corroboration,
            required,
            refusal: Some(PromotionRefusal::NeedsCorroboration {
                have: corroboration,
                need: required,
            }),
            ..base
        };
    }

    // Weight uses the signal's *own* tier, not the demoted one: an inferred role
    // changes how much agreement is needed before the lesson is trusted, not how
    // valuable the underlying evidence was once it is.
    //
    // `max(1)` covers the one case where the count can be zero and the signal still
    // promotes: a high-trust signal observed before the corroboration window opened.
    // It needs no agreement, so the window is not a gate on it -- but it is still
    // one piece of evidence, and a weight of zero would write a memory nothing can
    // ever retrieve.
    let evidence = corroboration.max(1);
    let weight = (tier.base_weight() * evidence as f64).min(policy.max_weight);
    PromotionDecision {
        demoted_for_inferred_role: demoted,
        corroboration,
        required,
        weight,
        ..base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signal(source: &str, key: &str, value: f64) -> Signal {
        let mut s = Signal::builder("sub_1")
            .tenant("tenant-1")
            // The capability must agree with the role key's capability half, or
            // `Signal::role_key` refuses the pair (they are two names for one thing).
            .capability("council-summary")
            .kind(SignalKind::Correction)
            .source(source)
            .idempotency(key)
            .run("run-1")
            .value(value)
            .build();
        s.role = Some("council-summary/product".to_string());
        s.attribution_source = AttributionSource::Explicit;
        s
    }

    fn thumbs(key: &str, value: f64, observed_at: DateTime<Utc>) -> Signal {
        let mut s = Signal::builder("sub_1")
            .tenant("tenant-1")
            // The capability must agree with the role key's capability half, or
            // `Signal::role_key` refuses the pair (they are two names for one thing).
            .capability("council-summary")
            .kind(SignalKind::Rating)
            .source("rating")
            .idempotency(key)
            .run("run-1")
            .value(value)
            .observed_at(observed_at)
            .build();
        s.role = Some("council-summary/product".to_string());
        s.attribution_source = AttributionSource::Explicit;
        s
    }

    #[test]
    fn count_adapter_matches_slice_policy() {
        let now = Utc::now();
        let policy = PromotionPolicy::default();
        let others = vec![thumbs("r2", -1.0, now), thumbs("r3", -1.0, now)];
        for source in ["diff-capture", "rating"] {
            for attribution in [
                AttributionSource::Explicit,
                AttributionSource::Inferred,
                AttributionSource::None,
            ] {
                let mut target = signal(source, "target", -1.0);
                target.attribution_source = attribution;
                assert_eq!(
                    decide(&target, &others, &policy, now),
                    decide_with_corroboration_count(
                        &target,
                        corroboration_count(&target, &others, &policy, now),
                        &policy,
                        now
                    )
                );
            }
        }
    }

    // The spec's acceptance criterion, verbatim.
    #[test]
    fn a_single_anonymous_thumbs_down_does_not_promote() {
        let policy = PromotionPolicy::default();
        let decision = decide(&thumbs("r1", -1.0, Utc::now()), &[], &policy, Utc::now());
        assert!(!decision.promoted());
        assert_eq!(
            decision.refusal,
            Some(PromotionRefusal::NeedsCorroboration { have: 1, need: 3 })
        );
        assert_eq!(decision.weight, 0.0);
    }

    #[test]
    fn a_human_edit_promotes_on_its_own() {
        let decision = decide(
            &signal("diff-capture", "d1", -0.4),
            &[],
            &PromotionPolicy::default(),
            Utc::now(),
        );
        assert!(decision.promoted());
        assert_eq!(decision.tier, TrustTier::High);
        assert_eq!(decision.required, 0);
        assert_eq!(decision.weight, 1.0);
    }

    #[test]
    fn every_high_trust_producer_promotes_alone() {
        for source in HIGH_TRUST_PRODUCERS {
            let decision = decide(
                &signal(source, "k", -1.0),
                &[],
                &PromotionPolicy::default(),
                Utc::now(),
            );
            assert!(decision.promoted(), "{source} should promote alone");
        }
    }

    #[test]
    fn an_unknown_producer_is_low_trust_not_high() {
        // The fail-safe direction: a producer nobody classified waits for agreement
        // rather than writing a memory on one click.
        assert_eq!(
            trust_tier(&signal("brand-new-thing", "k", -1.0)),
            TrustTier::Low
        );
    }

    #[test]
    fn enough_agreeing_thumbs_within_the_window_do_promote() {
        let now = Utc::now();
        let policy = PromotionPolicy::default();
        let others = vec![thumbs("r2", -1.0, now), thumbs("r3", -1.0, now)];
        let decision = decide(&thumbs("r1", -1.0, now), &others, &policy, now);
        assert!(decision.promoted());
        assert_eq!(decision.corroboration, 3);
        assert!((decision.weight - 1.2).abs() < 1e-9, "0.4 x 3");
    }

    #[test]
    fn agreement_outside_the_window_does_not_count() {
        let now = Utc::now();
        let policy = PromotionPolicy::default();
        let stale = now - Duration::days(8);
        let others = vec![thumbs("r2", -1.0, stale), thumbs("r3", -1.0, stale)];
        assert!(!decide(&thumbs("r1", -1.0, now), &others, &policy, now).promoted());
    }

    #[test]
    fn disagreement_is_not_corroboration() {
        // Two thumbs-up and one thumbs-down is not three votes for a lesson.
        let now = Utc::now();
        let others = vec![thumbs("r2", 1.0, now), thumbs("r3", 1.0, now)];
        let decision = decide(
            &thumbs("r1", -1.0, now),
            &others,
            &PromotionPolicy::default(),
            now,
        );
        assert_eq!(decision.corroboration, 1);
        assert!(!decision.promoted());
    }

    #[test]
    fn another_roles_agreement_does_not_count() {
        let now = Utc::now();
        let mut other = thumbs("r2", -1.0, now);
        other.role = Some("council-summary/account-history".to_string());
        let decision = decide(
            &thumbs("r1", -1.0, now),
            &[other],
            &PromotionPolicy::default(),
            now,
        );
        assert_eq!(
            decision.corroboration, 1,
            "corroboration is per role, or one role's complaints promote another's lesson"
        );
    }

    #[test]
    fn another_tenants_agreement_does_not_count() {
        let now = Utc::now();
        let mut other = thumbs("r2", -1.0, now);
        other.tenant_id = "tenant-2".to_string();
        assert_eq!(
            decide(
                &thumbs("r1", -1.0, now),
                &[other],
                &PromotionPolicy::default(),
                now
            )
            .corroboration,
            1
        );
    }

    #[test]
    fn the_same_signal_is_not_its_own_corroboration() {
        let now = Utc::now();
        let s = thumbs("r1", -1.0, now);
        assert_eq!(
            corroboration_count(
                &s,
                std::slice::from_ref(&s),
                &PromotionPolicy::default(),
                now
            ),
            1,
            "a store returning the signal itself must not double-count it"
        );
    }

    // Gate 1 outranks everything.
    #[test]
    fn an_unattributed_signal_never_promotes_however_corroborated() {
        let now = Utc::now();
        let mut s = signal("diff-capture", "d1", -1.0);
        s.role = None;
        s.attribution_source = AttributionSource::None;
        let others: Vec<Signal> = (0..20)
            .map(|i| signal("diff-capture", &format!("d{i}"), -1.0))
            .collect();
        let decision = decide(&s, &others, &PromotionPolicy::default(), now);
        assert_eq!(decision.refusal, Some(PromotionRefusal::Unattributed));
        assert_eq!(decision.weight, 0.0);
    }

    // The rule that is easy to miss.
    #[test]
    fn a_high_trust_signal_with_an_inferred_role_needs_corroboration() {
        let now = Utc::now();
        let mut s = signal("diff-capture", "d1", -0.4);
        s.attribution_source = AttributionSource::Inferred;
        let decision = decide(&s, &[], &PromotionPolicy::default(), now);
        assert!(
            !decision.promoted(),
            "a model's guess about which role is the weakest link in the chain"
        );
        assert!(
            decision.demoted_for_inferred_role,
            "the log must say why, or this reads as a bug"
        );
        assert_eq!(
            decision.tier,
            TrustTier::High,
            "the tier records what the evidence is, the demotion records what was done about it"
        );
    }

    #[test]
    fn an_inferred_role_promotes_once_corroborated_at_full_weight() {
        let now = Utc::now();
        let make = |key: &str| {
            let mut s = signal("diff-capture", key, -0.4);
            s.attribution_source = AttributionSource::Inferred;
            s
        };
        let others = vec![make("d2"), make("d3")];
        let decision = decide(&make("d1"), &others, &PromotionPolicy::default(), now);
        assert!(decision.promoted());
        assert!(
            (decision.weight - 3.0).abs() < 1e-9,
            "high-trust evidence keeps its weight once the role is corroborated: 1.0 x 3"
        );
    }

    #[test]
    fn the_weight_is_capped() {
        let now = Utc::now();
        let others: Vec<Signal> = (2..30)
            .map(|i| thumbs(&format!("r{i}"), -1.0, now))
            .collect();
        let decision = decide(
            &thumbs("r1", -1.0, now),
            &others,
            &PromotionPolicy::default(),
            now,
        );
        assert_eq!(
            decision.weight,
            PromotionPolicy::default().max_weight,
            "a viral thumbs-down must not outrank everything the role has learned"
        );
    }

    #[test]
    fn thresholds_are_per_tenant() {
        let now = Utc::now();
        let strict = PromotionPolicy::new(5, Duration::days(1));
        let lax = PromotionPolicy::new(1, Duration::days(30));
        let s = thumbs("r1", -1.0, now);
        assert!(!decide(&s, &[], &strict, now).promoted());
        assert!(decide(&s, &[], &lax, now).promoted());
    }

    #[test]
    fn the_decision_carries_its_inputs_not_just_a_verdict() {
        // The spec: "Every promotion decision is logged with the inputs that produced
        // it." Reconstructable months later is the requirement, not a boolean.
        let now = Utc::now();
        let decision = decide(
            &thumbs("r1", -1.0, now),
            &[thumbs("r2", -1.0, now)],
            &PromotionPolicy::default(),
            now,
        );
        assert_eq!(decision.signal_idempotency_key, "r1");
        assert_eq!(decision.tenant_id, "tenant-1");
        assert_eq!(decision.role.as_deref(), Some("council-summary/product"));
        assert_eq!(decision.tier, TrustTier::Low);
        assert_eq!(decision.attribution_source, AttributionSource::Explicit);
        assert_eq!(decision.corroboration, 2);
        assert_eq!(decision.required, 3);
        assert_eq!(decision.decided_at, now);
        // ...and it round-trips, so the log entry is the decision rather than a
        // rendering of it.
        let json = serde_json::to_string(&decision).unwrap();
        assert_eq!(
            serde_json::from_str::<PromotionDecision>(&json).unwrap(),
            decision
        );
    }

    #[test]
    fn a_refusal_summary_says_how_close_it_came() {
        let now = Utc::now();
        let summary = decide(
            &thumbs("r1", -1.0, now),
            &[thumbs("r2", -1.0, now)],
            &PromotionPolicy::default(),
            now,
        )
        .summary();
        assert!(summary.contains('2') && summary.contains('3'), "{summary}");
    }

    #[test]
    fn frogen_text_is_stored_verbatim() {
        // The spec: "Store the inquiry text as the correction body; do not paraphrase
        // or summarise it."
        let prose = "The 412 EUR figure is from the old plan. We moved to annual \
                     billing in March, so the balance should be 0.";
        let mut s = signal("frogen", "f1", -1.0);
        s.raw = serde_json::json!({ "text": prose });
        assert_eq!(correction_body(&s), Some(prose));
    }

    /// The payloads producers actually write, not the one the extractor guessed at.
    ///
    /// `raw.text` is written by nothing in the tree. inquiry emits
    /// `{"question", "answer"}` and diff-capture emits `{"before", "after"}`, so
    /// every real signal fell through to the generic "<source> recorded a <kind>"
    /// sentence -- discarding the verbatim body the promotion contract exists to
    /// preserve, while looking like it worked.
    #[test]
    fn the_canonical_producer_payloads_yield_a_body() {
        let answer = "It kept failing; my file was probably too big.";
        let mut response = signal("frogen", "f1", 0.0);
        response.kind = SignalKind::Response;
        response.raw = serde_json::json!({ "question": "why?", "answer": answer });
        assert_eq!(correction_body(&response), Some(answer));

        let after = "Your balance is 0 EUR since the annual billing move.";
        let mut correction = signal("diff-capture", "d1", -1.0);
        correction.raw = serde_json::json!({
            "before": "Your balance is 412 EUR.",
            "after": after,
            "kind": "modified",
        });
        assert_eq!(
            correction_body(&correction),
            Some(after),
            "the corrected text is the lesson; the rejected one is not"
        );
    }

    #[test]
    fn a_signal_with_no_text_has_no_body() {
        assert_eq!(correction_body(&signal("diff-capture", "d1", -1.0)), None);
        let mut blank = signal("frogen", "f1", -1.0);
        blank.raw = serde_json::json!({ "text": "   " });
        assert_eq!(correction_body(&blank), None, "whitespace is not a lesson");
    }

    /// The window counts the target too.
    ///
    /// It was added unconditionally while the cutoff filtered only the others, so a
    /// rating held past the window promoted the moment two fresh ones agreed with it
    /// -- two signals inside the window, counted as three. A queue that holds rows
    /// until they corroborate makes this the normal case.
    #[test]
    fn a_target_outside_the_window_is_not_its_own_first_corroboration() {
        let now = Utc::now();
        let policy = PromotionPolicy::default();
        let stale = {
            let mut s = thumbs("t-old", -1.0, now - policy.window - Duration::hours(1));
            s.source = "rating".to_string();
            s
        };
        let fresh: Vec<Signal> = ["t-a", "t-b"]
            .iter()
            .map(|k| thumbs(k, -1.0, now - Duration::hours(1)))
            .collect();

        assert_eq!(
            corroboration_count(&stale, &fresh, &policy, now),
            2,
            "two signals are inside the window, so the count is two"
        );
        let decision = decide(&stale, &fresh, &policy, now);
        assert!(!decision.promoted(), "{:?}", decision.refusal);

        // ...and the same signal observed inside the window does promote on three.
        let in_window = thumbs("t-new", -1.0, now - Duration::hours(1));
        assert_eq!(corroboration_count(&in_window, &fresh, &policy, now), 3);
        assert!(decide(&in_window, &fresh, &policy, now).promoted());
    }

    #[test]
    fn a_stale_high_trust_signal_still_promotes_alone_and_at_weight() {
        // The window is a gate on corroboration, and a human edit needs none. A
        // count of zero must not become a weight of zero -- that writes a memory
        // nothing can ever retrieve.
        let policy = PromotionPolicy::default();
        let now = Utc::now();
        let mut old_edit = signal("diff-capture", "d-old", -1.0);
        old_edit.observed_at = now - policy.window - Duration::days(30);
        let decision = decide(&old_edit, &[], &policy, now);
        assert!(decision.promoted(), "{:?}", decision.refusal);
        assert_eq!(decision.weight, TrustTier::High.base_weight());
    }
}
