//! The honesty layer.
//!
//! The spec's instruction about this phase is unusually direct -- *"This phase is
//! what keeps the loop from drifting silently. Do not defer it."* -- and the reason
//! is that every other phase makes the loop more capable while this is the only one
//! that makes it **falsifiable**.
//!
//! Without it the loop has a failure mode that is invisible by construction: memories
//! accumulate, answers get worse, and the store's own metrics look healthy the whole
//! time. Promotion counts go up. Retrieval returns rows. A memory that actively
//! misleads a role is indistinguishable from one that helps, because nothing ever
//! asks whether the answer improved.
//!
//! ## The loop the spec describes
//!
//! 1. A signal promotes -> the originating run also enters the golden dataset.
//! 2. The memory is written.
//! 3. The dataset replays.
//! 4. If replay does not improve, the memory is weighted down or left to expire.
//!
//! Step 3 is the whole point, and step 1 is what makes it possible: the correction
//! that produced the memory is *also* the test case that can check it. A human said
//! "this output was wrong, here is the right one" -- that is a regression test
//! somebody already wrote, and throwing it away to keep only the memory is how a
//! reflection loop ends up unfalsifiable.
//!
//! ## `--no-memory` is the measurement, not a debug flag
//!
//! The spec: *"Add a `--no-memory` ablation alongside the existing retrieval
//! ablation, as a first-class replay option in the run manifest. This is the one
//! thing worth copying outright from the source repo, which has `--no-rag` for
//! exactly this reason."*
//!
//! First-class in the manifest matters because an ablation you have to hand-configure
//! is an ablation nobody runs. [`ReplayManifest`] carries the mode, serializes, and
//! round-trips -- so "replay this exact comparison" is a stored artifact rather than
//! a remembered command line.
//!
//! ## A memory earns permanence; it is never granted it
//!
//! Wave 5 made `expires_at: None` a claim that a regression protects the record, and
//! `assert_permanent` refuses without a name. This module is what produces those
//! names: [`assess`] compares memory-on against memory-off and only returns
//! [`MemoryVerdict::Earned`] -- carrying the regression id -- when the memory actually
//! helped.
//!
//! Everything else decays. Not as a penalty: a memory nobody can show a passing test
//! for is exactly the kind that should fade, and the default TTL already does that
//! without anyone deciding to.

use crate::error::ReedeError;
use crate::golden::{EvalReport, GoldenCase};
use crate::memory::Memory;
use crate::signal::Signal;
use serde::{Deserialize, Serialize};

/// Which retrieval paths a replay is allowed to use.
///
/// Two independent switches rather than four names, because they ablate different
/// things and the interesting run is often one of them: `NoMemory` asks whether the
/// reflection loop earns its place, `NoRetrieval` asks whether grounding does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayMode {
    /// `--no-memory`: per-role memory is withheld.
    #[serde(default)]
    pub no_memory: bool,
    /// The pre-existing retrieval ablation: grounded retrieval is withheld.
    #[serde(default)]
    pub no_retrieval: bool,
}

impl ReplayMode {
    /// Everything on. The baseline a comparison is measured against.
    pub fn full() -> Self {
        Self {
            no_memory: false,
            no_retrieval: false,
        }
    }

    /// `--no-memory`, grounding left on. The comparison that decides whether a
    /// memory earned its place: it isolates the reflection loop rather than turning
    /// off everything the agent knows.
    pub fn no_memory() -> Self {
        Self {
            no_memory: true,
            no_retrieval: false,
        }
    }

    pub fn no_retrieval() -> Self {
        Self {
            no_memory: false,
            no_retrieval: true,
        }
    }

    /// Neither. The floor: what the model alone can do.
    pub fn bare() -> Self {
        Self {
            no_memory: true,
            no_retrieval: true,
        }
    }

    /// The CLI form, for a manifest a human will read.
    pub fn flags(&self) -> Vec<&'static str> {
        let mut flags = Vec::new();
        if self.no_memory {
            flags.push("--no-memory");
        }
        if self.no_retrieval {
            flags.push("--no-retrieval");
        }
        flags
    }
}

impl Default for ReplayMode {
    fn default() -> Self {
        Self::full()
    }
}

/// Everything needed to run one replay again, exactly.
///
/// The spec's "replayable from the run manifest": this is the manifest. It names the
/// **golden version**, not just the capability, because a golden set is append-only
/// and versioned -- replaying against "the latest" would compare two runs judged on
/// different tests and call the difference a result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayManifest {
    pub tenant_id: String,
    pub agent_id: String,
    pub capability: String,
    /// The exact golden-set version to score against.
    pub golden_version: u32,
    #[serde(default)]
    pub mode: ReplayMode,
}

impl ReplayManifest {
    pub fn new(
        tenant_id: impl Into<String>,
        agent_id: impl Into<String>,
        capability: impl Into<String>,
        golden_version: u32,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            agent_id: agent_id.into(),
            capability: capability.into(),
            golden_version,
            mode: ReplayMode::full(),
        }
    }

    pub fn with_mode(mut self, mode: ReplayMode) -> Self {
        self.mode = mode;
        self
    }

    /// The same manifest with memory withheld -- the other half of the comparison.
    pub fn ablated(&self) -> Self {
        Self {
            mode: ReplayMode::no_memory(),
            ..self.clone()
        }
    }

    /// A stable id for the regression behind a memory.
    ///
    /// Names the capability and the golden version, so the id says *what* protects
    /// the memory and *which* version of the tests did. An opaque uuid would satisfy
    /// "has a regression behind it" while telling a reader nothing.
    pub fn regression_id(&self) -> String {
        format!(
            "golden::{}::{}::v{}",
            self.agent_id, self.capability, self.golden_version
        )
    }
}

/// Whether a memory has earned its place.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryVerdict {
    /// Memory-on beat memory-off. Carries the regression id that justifies making
    /// the memory permanent.
    Earned {
        regression_id: String,
        /// Pass rate with memory minus pass rate without. Positive by construction.
        improvement: f64,
    },
    /// It did not help. The memory stays, decaying on its default TTL.
    NotEarned { reason: String, improvement: f64 },
}

impl MemoryVerdict {
    pub fn earned(&self) -> bool {
        matches!(self, MemoryVerdict::Earned { .. })
    }

    pub fn improvement(&self) -> f64 {
        match self {
            MemoryVerdict::Earned { improvement, .. }
            | MemoryVerdict::NotEarned { improvement, .. } => *improvement,
        }
    }

    pub fn regression_id(&self) -> Option<&str> {
        match self {
            MemoryVerdict::Earned { regression_id, .. } => Some(regression_id),
            MemoryVerdict::NotEarned { .. } => None,
        }
    }
}

/// How much better memory-on has to be before it counts.
///
/// Not zero. A golden set of twenty cases moves in steps of 0.05, so any real
/// improvement clears a small margin easily -- while a margin of zero would let
/// measurement noise and judge nondeterminism grant permanence, which is the one
/// thing this layer exists to prevent. Nor is "it did no harm" enough: a memory that
/// changes nothing is context a role pays for on every run.
pub const MIN_IMPROVEMENT: f64 = 0.01;

/// Compare a replay with memory against the same replay without it.
///
/// The spec's step 4. `with_memory` and `without_memory` must be reports for the same
/// golden version -- scoring against different versions and subtracting produces a
/// number that looks like a result and is not one, so it is refused rather than
/// computed.
///
/// The version alone is not enough to say two reports are comparable, and checking
/// only it was a real hole: every capability's golden set starts at version 1, so a
/// pair of unrelated reports agreeing on a small integer is the *common* case, not a
/// freak one. Subtracting those pass rates would grant permanence to one agent's
/// memory on the strength of another agent's replay. `EvalReport` already carries
/// `agent_id` and `capability`, so both are checked against each other and against
/// the manifest.
pub fn assess(
    manifest: &ReplayManifest,
    with_memory: &EvalReport,
    without_memory: &EvalReport,
) -> Result<MemoryVerdict, ReedeError> {
    let mismatch = |what: &str, a: &str, b: &str| ReedeError::SpecValidationFailed {
        reason: format!(
            "honesty: comparing a report for {what} {a:?} against one for {b:?} is not \
             a comparison"
        ),
    };
    if with_memory.agent_id != without_memory.agent_id {
        return Err(mismatch(
            "agent",
            &with_memory.agent_id,
            &without_memory.agent_id,
        ));
    }
    if with_memory.capability != without_memory.capability {
        return Err(mismatch(
            "capability",
            &with_memory.capability,
            &without_memory.capability,
        ));
    }
    if with_memory.agent_id != manifest.agent_id {
        return Err(mismatch("agent", &with_memory.agent_id, &manifest.agent_id));
    }
    if with_memory.capability != manifest.capability {
        return Err(mismatch(
            "capability",
            &with_memory.capability,
            &manifest.capability,
        ));
    }
    if with_memory.golden_version != without_memory.golden_version {
        return Err(ReedeError::SpecValidationFailed {
            reason: format!(
                "honesty: comparing golden version {} against {} is not a comparison",
                with_memory.golden_version, without_memory.golden_version
            ),
        });
    }
    if with_memory.golden_version != manifest.golden_version {
        return Err(ReedeError::SpecValidationFailed {
            reason: format!(
                "honesty: reports are for golden version {} but the manifest names {}",
                with_memory.golden_version, manifest.golden_version
            ),
        });
    }
    if with_memory.total == 0 {
        // An empty golden set gives a pass rate of 1.0 for anything at all. Treating
        // that as "memory did not help" would be true but useless; treating it as
        // help would be a lie.
        return Ok(MemoryVerdict::NotEarned {
            reason: "the golden set is empty, so there is nothing to have improved".to_string(),
            improvement: 0.0,
        });
    }

    let improvement = with_memory.pass_rate - without_memory.pass_rate;
    if improvement < MIN_IMPROVEMENT {
        return Ok(MemoryVerdict::NotEarned {
            reason: format!(
                "memory-on scored {:.3} against memory-off {:.3}; \
                 an improvement of {improvement:+.3} is below the {MIN_IMPROVEMENT} margin",
                with_memory.pass_rate, without_memory.pass_rate
            ),
            improvement,
        });
    }
    Ok(MemoryVerdict::Earned {
        regression_id: manifest.regression_id(),
        improvement,
    })
}

/// Apply a verdict to the memory it is about.
///
/// `Earned` makes the memory permanent and records which regression protects it,
/// which is what satisfies "every retained memory is reachable from a regression
/// result". `NotEarned` does **nothing at all** -- and that is the point: the memory
/// already carries a default TTL from Wave 5, so it decays without anyone deciding
/// to. An explicit "weight it down" step here would be a second mechanism doing the
/// same job, and the one that needs remembering is the one that gets forgotten.
pub fn apply_verdict(memory: &mut Memory, verdict: &MemoryVerdict) -> Result<(), ReedeError> {
    if let MemoryVerdict::Earned { regression_id, .. } = verdict {
        crate::hygiene::assert_permanent(memory, regression_id)?;
    }
    Ok(())
}

/// Turn the correction behind a promoted memory into a golden case.
///
/// The spec's step 1. A human saying "this was wrong, here is the right answer" *is*
/// a regression test, and the loop's honesty depends on keeping it: without the case,
/// step 3 has nothing to replay and the memory can never be checked.
///
/// Returns `None` without both sides and available, bounded captured input. That
/// is a real limit rather than an oversight -- diff capture records an edit distance
/// and the corrected text, but a thumbs rating has no "right answer" in it, so there
/// is no case to make and inventing one would put a fabricated expectation in the
/// regression set.
///
/// ## The field names are the producer's, not this module's
///
/// It read `rejected_output` / `corrected_output`, which nothing writes.
/// `reede::correction::correction_signals` -- the producer of the high-trust human
/// corrections this feature exists to capture -- emits `before` and `after`. So this
/// returned `None` for every real correction, `PromotionConsumer` filed no golden
/// case, and step 3 had nothing to replay: the honesty layer was silently checking
/// an empty set. The old names are still accepted, since a caller may already be
/// constructing signals to them, but the canonical pair is first.
pub fn golden_case_from_signal(signal: &Signal) -> Option<GoldenCase> {
    let read = |field: &str| signal.raw.get(field).and_then(|v| v.as_str());
    let rejected = read("before").or_else(|| read("rejected_output"))?;
    let corrected = read("after").or_else(|| read("corrected_output"))?;
    let (input, retention) = crate::replay_input::retained_input(signal, chrono::Utc::now())?;
    if rejected.trim().is_empty() || corrected.trim().is_empty() {
        return None;
    }
    let mut case = GoldenCase::promote(
        &signal.tenant_id,
        &signal.agent_id,
        &signal.capability,
        signal
            .dimension
            .clone()
            .unwrap_or_else(|| "accuracy".to_string()),
        input,
        rejected,
        corrected,
    );
    case.id = crate::replay_input::signal_case_id(signal);
    case.created_at = signal.observed_at;
    case.source_signal = Some(signal.idempotency_key.clone());
    case.input_retention = Some(retention);
    Some(case)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::golden::{EvalHarness, GoldenSet, GoldenStore, InMemoryGoldenStore};
    use crate::hygiene::{apply_default_ttl, HygienePolicy};
    use crate::memory::MemoryKind;
    use crate::signal::{AttributionSource, SignalKind};
    use crate::RoleKey;

    fn manifest() -> ReplayManifest {
        ReplayManifest::new("tenant-1", "kira-agent", "council-summary", 3)
    }

    fn report(version: u32, total: usize, passed: usize) -> EvalReport {
        EvalReport {
            agent_id: "kira-agent".to_string(),
            capability: "council-summary".to_string(),
            golden_version: version,
            total,
            passed,
            failed: total - passed,
            pass_rate: if total == 0 {
                1.0
            } else {
                passed as f64 / total as f64
            },
        }
    }

    fn memory() -> Memory {
        let mut m = Memory::builder(
            &RoleKey::new("council-summary", "product").unwrap(),
            "billing",
        )
        .tenant("tenant-1")
        .text("the balance comes from account-history")
        .kind(MemoryKind::Correction)
        .promoted_from("diff-capture:run-1", "receipt-1")
        .build()
        .unwrap();
        apply_default_ttl(&mut m, &HygienePolicy::default());
        m
    }

    // The spec's third acceptance criterion: both ablations replayable from the
    // manifest.
    #[test]
    fn both_ablations_are_first_class_in_the_manifest() {
        for mode in [
            ReplayMode::full(),
            ReplayMode::no_memory(),
            ReplayMode::no_retrieval(),
            ReplayMode::bare(),
        ] {
            let m = manifest().with_mode(mode);
            let json = serde_json::to_string(&m).unwrap();
            assert_eq!(
                serde_json::from_str::<ReplayManifest>(&json).unwrap(),
                m,
                "an ablation you have to hand-configure is one nobody runs"
            );
        }
        assert_eq!(ReplayMode::no_memory().flags(), ["--no-memory"]);
        assert_eq!(ReplayMode::no_retrieval().flags(), ["--no-retrieval"]);
        assert_eq!(
            ReplayMode::bare().flags(),
            ["--no-memory", "--no-retrieval"]
        );
        assert!(ReplayMode::full().flags().is_empty());
    }

    #[test]
    fn the_ablated_manifest_keeps_everything_but_the_mode() {
        let full = manifest();
        let ablated = full.ablated();
        assert_eq!(ablated.golden_version, full.golden_version);
        assert_eq!(ablated.capability, full.capability);
        assert!(ablated.mode.no_memory);
        assert!(
            !ablated.mode.no_retrieval,
            "isolating memory means leaving grounding on, not turning everything off"
        );
    }

    #[test]
    fn a_manifest_with_no_mode_decodes_as_full() {
        // Migration: a stored manifest from before the ablation existed.
        let json = r#"{"tenant_id":"t","agent_id":"a","capability":"c","golden_version":1}"#;
        let m: ReplayManifest = serde_json::from_str(json).unwrap();
        assert_eq!(m.mode, ReplayMode::full());
    }

    #[test]
    fn a_memory_that_helps_earns_permanence() {
        let verdict = assess(&manifest(), &report(3, 20, 18), &report(3, 20, 14)).unwrap();
        assert!(verdict.earned());
        assert!((verdict.improvement() - 0.2).abs() < 1e-9);
        assert_eq!(
            verdict.regression_id(),
            Some("golden::kira-agent::council-summary::v3"),
            "the id must say what protects the memory and which tests did"
        );
    }

    #[test]
    fn a_memory_that_changes_nothing_does_not_earn_permanence() {
        // "It did no harm" is not enough: a memory that changes nothing is context a
        // role pays for on every run.
        let verdict = assess(&manifest(), &report(3, 20, 16), &report(3, 20, 16)).unwrap();
        assert!(!verdict.earned());
        assert_eq!(verdict.improvement(), 0.0);
    }

    #[test]
    fn a_memory_that_makes_things_worse_does_not_earn_permanence() {
        let verdict = assess(&manifest(), &report(3, 20, 12), &report(3, 20, 16)).unwrap();
        assert!(!verdict.earned());
        assert!(verdict.improvement() < 0.0);
    }

    #[test]
    fn an_improvement_below_the_margin_is_not_an_improvement() {
        // Half a case out of two hundred. A zero margin would let judge
        // nondeterminism grant permanence.
        let verdict = assess(&manifest(), &report(3, 200, 161), &report(3, 200, 160)).unwrap();
        assert!(
            !verdict.earned(),
            "{}",
            match &verdict {
                MemoryVerdict::NotEarned { reason, .. } => reason.clone(),
                _ => unreachable!(),
            }
        );
    }

    /// A shared version number is not a shared subject.
    ///
    /// Every capability's golden set starts at version 1, so two unrelated reports
    /// agreeing on the number is the common case. Subtracting their pass rates would
    /// grant permanence to one agent's memory on the strength of another's replay.
    #[test]
    fn reports_about_different_subjects_are_refused() {
        let mine = report(3, 10, 10);
        let mut other_agent = report(3, 10, 0);
        other_agent.agent_id = "some-other-agent".to_string();
        assert!(assess(&manifest(), &mine, &other_agent).is_err());
        assert!(assess(&manifest(), &other_agent, &mine).is_err());

        let mut other_capability = report(3, 10, 0);
        other_capability.capability = "some-other-capability".to_string();
        assert!(assess(&manifest(), &mine, &other_capability).is_err());

        // ...and a matched pair that the manifest is not about is refused too.
        let mut both_elsewhere_a = report(3, 10, 10);
        both_elsewhere_a.agent_id = "elsewhere".to_string();
        let mut both_elsewhere_b = report(3, 10, 0);
        both_elsewhere_b.agent_id = "elsewhere".to_string();
        assert!(assess(&manifest(), &both_elsewhere_a, &both_elsewhere_b).is_err());
    }

    #[test]
    fn comparing_two_different_golden_versions_is_refused() {
        // Subtracting pass rates judged on different tests produces a number that
        // looks like a result and is not one.
        assert!(assess(&manifest(), &report(3, 20, 18), &report(2, 20, 14)).is_err());
    }

    #[test]
    fn reports_for_a_version_the_manifest_does_not_name_are_refused() {
        assert!(assess(&manifest(), &report(9, 20, 18), &report(9, 20, 14)).is_err());
    }

    #[test]
    fn an_empty_golden_set_earns_nothing() {
        // Everything scores 1.0 against no cases, so the difference is zero and the
        // reason has to say why rather than reading as "memory did not help".
        let verdict = assess(&manifest(), &report(3, 0, 0), &report(3, 0, 0)).unwrap();
        match verdict {
            MemoryVerdict::NotEarned { reason, .. } => {
                assert!(reason.contains("empty"), "{reason}")
            }
            other => panic!("expected NotEarned, got {other:?}"),
        }
    }

    // The spec's first acceptance criterion: every retained memory is reachable from
    // a regression result.
    #[test]
    fn an_earned_verdict_makes_the_memory_permanent_and_names_its_test() {
        let mut m = memory();
        assert!(m.expires_at.is_some(), "it arrives mortal");
        let verdict = assess(&manifest(), &report(3, 20, 18), &report(3, 20, 14)).unwrap();
        apply_verdict(&mut m, &verdict).unwrap();
        assert_eq!(m.expires_at, None);
        assert_eq!(
            m.regression_id.as_deref(),
            Some("golden::kira-agent::council-summary::v3")
        );
    }

    // The spec's second: a memory with no passing test behind it decays by default.
    #[test]
    fn a_memory_that_did_not_earn_its_place_is_left_to_decay() {
        let mut m = memory();
        let ttl = m.expires_at;
        let verdict = assess(&manifest(), &report(3, 20, 16), &report(3, 20, 16)).unwrap();
        apply_verdict(&mut m, &verdict).unwrap();
        assert_eq!(
            m.expires_at, ttl,
            "nothing is done to it; the TTL it already carries is the mechanism, and \
             a second one that needs remembering is the one that gets forgotten"
        );
        assert_eq!(m.regression_id, None);
    }

    fn correction_signal(raw: serde_json::Value) -> Signal {
        let mut s = Signal::builder("sub_1")
            .tenant("tenant-1")
            .agent("kira-agent")
            .capability("council-summary")
            .kind(SignalKind::Correction)
            .source("diff-capture")
            .idempotency("d1")
            .run("run-1")
            .dimension("accuracy")
            .value(-0.4)
            .build();
        s.role = Some("council-summary/product".to_string());
        s.attribution_source = AttributionSource::Explicit;
        s.raw = raw;
        if let Some(input) = s.raw.as_object_mut().and_then(|raw| raw.remove("input")) {
            crate::replay_input::capture_replay_input(
                &mut s,
                input.as_str().unwrap(),
                chrono::Utc::now(),
                &HygienePolicy::default(),
            )
            .unwrap();
        }
        s
    }

    #[test]
    fn a_correction_becomes_a_golden_case() {
        let case = golden_case_from_signal(&correction_signal(serde_json::json!({
            "input": "what is my balance?",
            "rejected_output": "Your balance is 412 EUR.",
            "corrected_output": "Your balance is 0 EUR; you moved to annual billing."
        })))
        .unwrap();
        assert_eq!(case.tenant_id, "tenant-1");
        assert_eq!(case.capability, "council-summary");
        assert_eq!(case.dimension, "accuracy");
        assert_eq!(case.input, "what is my balance?");
        assert!(case.corrected_output.contains("annual billing"));
    }

    /// The inputless payload `correction_signals` actually emits.
    ///
    /// This is the case that mattered and the one that was missing: the extractor
    /// read `rejected_output`/`corrected_output`, the producer writes `before`/
    /// `after`, so every real human correction produced no golden case at all and
    /// the honesty layer replayed an empty set while looking like it worked.
    #[test]
    fn an_inputless_before_after_payload_is_not_replay_evidence() {
        let changes = crate::correction::sectioned_diff(
            "## Hook\nYour balance is 412 EUR.\n",
            "## Hook\nYour balance is 0 EUR; you moved to annual billing.\n",
        );
        let signals = crate::correction::correction_signals_with_context(
            crate::correction::CorrectionSignalContext {
                tenant_id: "tenant-1",
                subject_id: "sub_1",
                agent_id: "kira-agent",
                capability: "council-summary",
                source_version: "1.0",
                run_id: "run-1",
                role: "council-summary/product",
            },
            &changes,
        );
        let signal = signals.first().expect("the diff produced a correction");

        assert!(
            golden_case_from_signal(signal).is_none(),
            "before/after alone can teach a memory, but cannot replay a missing input"
        );
    }

    #[test]
    fn a_signal_with_no_right_answer_makes_no_case() {
        // A thumbs rating has no corrected output in it. Inventing one would put a
        // fabricated expectation in the regression set.
        assert!(
            golden_case_from_signal(&correction_signal(serde_json::json!({
                "normalized_edit_distance": 0.4
            })))
            .is_none()
        );
        assert!(
            golden_case_from_signal(&correction_signal(serde_json::json!({
                "rejected_output": "x",
                "corrected_output": "   "
            })))
            .is_none()
        );
    }

    /// The loop, end to end, against the real harness rather than hand-built reports:
    /// a correction becomes a golden case, a candidate that repeats the mistake fails
    /// it, one that applies the lesson passes, and the memory earns permanence.
    #[tokio::test]
    async fn the_whole_honesty_loop_runs_against_the_real_harness() {
        let signal = correction_signal(serde_json::json!({
            "input": "what is my balance?",
            "rejected_output": "your balance is 412 eur from the legacy plan",
            "corrected_output": "your balance is 0 eur since the annual billing move"
        }));
        let case = golden_case_from_signal(&signal).unwrap();

        let store = InMemoryGoldenStore::new();
        let version = store
            .add_case(
                "tenant-1",
                "kira-agent",
                "council-summary",
                "interim-1",
                &case,
            )
            .await
            .unwrap();
        let set: GoldenSet = store
            .get_version("tenant-1", "kira-agent", "council-summary", version)
            .await
            .unwrap()
            .unwrap();

        let harness = EvalHarness::new();
        // With the memory, the agent produces the corrected answer.
        let with_memory = harness
            .evaluate("your balance is 0 eur since the annual billing move", &set)
            .await
            .unwrap();
        // Without it, it repeats the mistake the human corrected.
        let without_memory = harness
            .evaluate("your balance is 412 eur from the legacy plan", &set)
            .await
            .unwrap();
        assert_eq!(with_memory.passed, 1);
        assert_eq!(without_memory.failed, 1);

        let manifest = ReplayManifest::new("tenant-1", "kira-agent", "council-summary", version);
        let verdict = assess(&manifest, &with_memory, &without_memory).unwrap();
        assert!(verdict.earned());

        let mut m = memory();
        apply_verdict(&mut m, &verdict).unwrap();
        assert_eq!(m.expires_at, None);
        assert_eq!(
            m.regression_id.as_deref(),
            Some("golden::kira-agent::council-summary::v1")
        );
    }
}
