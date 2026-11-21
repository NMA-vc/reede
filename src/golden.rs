//! Golden set and regression eval harness.
//!
//! Turns recurring corrections into test cases, so an agent has to
//! earn its promotion instead of drifting continuously.
//!
//! A `GoldenCase` records the acceptance counter-example: the input, the
//! rejected output, the human-corrected output, and the rubric dimension it
//! failed on. Cases live in a per-capability, versioned `GoldenSet` that is
//! stored with the agent (not with the vertical), and a promotion adds a new
//! immutable evidence version. Q6 permits captured input payload expiry in every
//! version while retaining its identity, digest, deadline and signal lineage.
//!
//! The `EvalHarness` scores a *candidate* agent output for a future version
//! against the latest golden set before deploy. The judge is deterministic -
//! a candidate must be closer to the corrected output than to the rejected one
//! on each case - so regressions are caught without an LLM. (An LLM judge can
//! be layered on the same trait later; see `EvalJudge`.) A verdict below the
//! per-capability pass threshold blocks the promote step, so agent changes and
//! code changes go through comparable review.

use crate::error::ReedeError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

/// A regression test case promoted from a human correction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GoldenCase {
    /// Immutable case id (random for manual cases, signal-derived for producer cases).
    pub id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub capability: String,
    /// The rubric dimension the output failed on.
    pub dimension: String,
    /// The prompt/input the agent was given.
    pub input: String,
    /// The agent output that was rejected.
    pub rejected_output: String,
    /// The human-corrected output that shipped.
    pub corrected_output: String,
    pub created_at: DateTime<Utc>,
    /// Producer cases retain the tenant-scoped signal natural key after redaction.
    /// Static/manual cases have neither field and keep their existing semantics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_signal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_retention: Option<crate::replay_input::InputRetention>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_redacted_at: Option<DateTime<Utc>>,
}

impl GoldenCase {
    /// Promote a correction into a golden case.
    pub fn promote(
        tenant_id: impl Into<String>,
        agent_id: impl Into<String>,
        capability: impl Into<String>,
        dimension: impl Into<String>,
        input: impl Into<String>,
        rejected_output: impl Into<String>,
        corrected_output: impl Into<String>,
    ) -> Self {
        Self {
            id: format!("gld_{}", Uuid::new_v4()),
            tenant_id: tenant_id.into(),
            agent_id: agent_id.into(),
            capability: capability.into(),
            dimension: dimension.into(),
            input: input.into(),
            rejected_output: rejected_output.into(),
            corrected_output: corrected_output.into(),
            created_at: Utc::now(),
            source_signal: None,
            input_retention: None,
            input_redacted_at: None,
        }
    }

    pub fn replay_available(&self, now: DateTime<Utc>) -> bool {
        match (&self.source_signal, &self.input_retention) {
            (None, None) => self.input_redacted_at.is_none(),
            (Some(source), Some(retention)) => {
                !source.is_empty()
                    && self.input_redacted_at.is_none()
                    && retention.available(&self.input, now)
            }
            _ => false,
        }
    }

    /// Q6's exception changes only the payload, preserving version/case identity.
    pub fn redact_expired_input(&mut self, now: DateTime<Utc>) -> bool {
        if self.input_redacted_at.is_none()
            && self
                .input_retention
                .as_ref()
                .is_some_and(|r| r.expires_at <= now)
        {
            self.input.clear();
            self.input_redacted_at = Some(now);
            return true;
        }
        false
    }
}

/// A versioned golden set for one agent capability.
///
/// Immutable: adding a case produces a *new* version, so a regression can be
/// scored against the exact set the agent was last validated on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GoldenSet {
    pub agent_id: String,
    pub capability: String,
    /// Monotonic version; 1 is the first case added.
    pub version: u32,
    /// The rubric version these cases were judged under.
    pub rubric_version: String,
    #[serde(default)]
    pub cases: Vec<GoldenCase>,
}

impl GoldenSet {
    pub fn redact_expired_inputs(&mut self, now: DateTime<Utc>) -> usize {
        self.cases
            .iter_mut()
            .map(|case| usize::from(case.redact_expired_input(now)))
            .sum()
    }

    /// Earliest remaining captured payload, including every case in this version.
    pub fn input_expires_at(&self) -> Option<DateTime<Utc>> {
        self.cases
            .iter()
            .filter(|case| case.input_redacted_at.is_none())
            .filter_map(|case| case.input_retention.as_ref().map(|r| r.expires_at))
            .min()
    }
}

/// Resilient golden-case store. `add_case` appends to the *latest* set or
/// starts a new one, and returns the new version (append-only versioning).
#[async_trait]
pub trait GoldenStore: Send + Sync {
    /// Add a case to the capability's set, returning the new immutable version.
    async fn add_case(
        &self,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
        rubric_version: &str,
        case: &GoldenCase,
    ) -> Result<u32, ReedeError>;

    async fn latest_version(
        &self,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
    ) -> Result<Option<u32>, ReedeError>;

    async fn get_version(
        &self,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
        version: u32,
    ) -> Result<Option<GoldenSet>, ReedeError>;

    async fn latest(
        &self,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
    ) -> Result<Option<GoldenSet>, ReedeError>;
}

/// Key for a capability's golden-set family: (tenant, agent, capability).
type GoldenKey = (String, String, String);

/// In-memory golden-store.
pub struct InMemoryGoldenStore {
    /// (tenant, agent, capability) -> (version -> GoldenSet)
    sets: Mutex<HashMap<GoldenKey, HashMap<u32, GoldenSet>>>,
}

impl InMemoryGoldenStore {
    pub fn new() -> Self {
        Self {
            sets: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryGoldenStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl GoldenStore for InMemoryGoldenStore {
    async fn add_case(
        &self,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
        rubric_version: &str,
        case: &GoldenCase,
    ) -> Result<u32, ReedeError> {
        if !case.replay_available(Utc::now()) {
            return Err(ReedeError::SpecValidationFailed {
                reason: "cannot file unavailable producer input".into(),
            });
        }
        let mut sets = self.sets.lock().unwrap();
        let key = (
            tenant_id.to_string(),
            agent_id.to_string(),
            capability.to_string(),
        );
        let versions = sets.entry(key).or_default();

        // Derive the next version from the highest existing one, and build on THAT
        // version's cases.
        //
        // `versions.values().next()` used to supply the base, which is an arbitrary
        // entry of a HashMap rather than the newest set. Every add branched off
        // whichever version the iterator happened to yield, so cases were silently
        // dropped: six adds produced a latest set holding three. The golden set is
        // what the honesty layer replays against, so that made the regression check
        // pass on a fraction of its own tests -- and nothing anywhere went red.
        let latest = versions.keys().max().copied();
        if let Some(version) = latest.filter(|_| case.source_signal.is_some()) {
            if versions[&version]
                .cases
                .iter()
                .any(|existing| existing.id == case.id)
            {
                return Ok(version);
            }
        }
        let next = latest.unwrap_or(0) + 1;
        let mut cases = latest
            .and_then(|v| versions.get(&v))
            .map(|s| s.cases.clone())
            .unwrap_or_default();
        for case in &mut cases {
            case.redact_expired_input(Utc::now());
        }
        if !cases.iter().any(|c| c.id == case.id) {
            cases.push(case.clone());
        }
        versions.insert(
            next,
            GoldenSet {
                agent_id: agent_id.to_string(),
                capability: capability.to_string(),
                version: next,
                rubric_version: rubric_version.to_string(),
                cases,
            },
        );
        Ok(next)
    }

    async fn latest_version(
        &self,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
    ) -> Result<Option<u32>, ReedeError> {
        let sets = self.sets.lock().unwrap();
        let key = (
            tenant_id.to_string(),
            agent_id.to_string(),
            capability.to_string(),
        );
        Ok(sets.get(&key).and_then(|m| m.keys().max().copied()))
    }

    async fn get_version(
        &self,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
        version: u32,
    ) -> Result<Option<GoldenSet>, ReedeError> {
        let sets = self.sets.lock().unwrap();
        let key = (
            tenant_id.to_string(),
            agent_id.to_string(),
            capability.to_string(),
        );
        Ok(sets
            .get(&key)
            .and_then(|m| m.get(&version).cloned())
            .map(|mut set| {
                set.redact_expired_inputs(Utc::now());
                set
            }))
    }

    async fn latest(
        &self,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
    ) -> Result<Option<GoldenSet>, ReedeError> {
        let v = self.latest_version(tenant_id, agent_id, capability).await?;
        match v {
            Some(version) => {
                self.get_version(tenant_id, agent_id, capability, version)
                    .await
            }
            None => Ok(None),
        }
    }
}

/// How well a candidate performed on one golden case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaseVerdict {
    /// Candidate is closer to the corrected output than to the rejected one.
    Pass,
    /// Candidate regressed toward (or still reproduces) the rejected output.
    Fail,
}

/// Score a candidate output on one golden case using a deterministic judge.
///
/// Pass iff the candidate is *strictly* closer to the corrected output than to the
/// rejected one. Anything else fails.
///
/// The strictness is the point, and it used to be missing: with `to_rejected >
/// to_corrected` deciding failure, a tie fell through to `Pass`. Text sharing no
/// tokens with either output scores 0.0 against both, so an empty or entirely
/// unrelated candidate passed **every** case, and a zero-failure report is enough
/// for `evaluate_promotion` to allow a promotion. Word-order-only corrections tie
/// too, because `similarity` compares token *sets*.
///
/// Equality is not evidence that the correction was adopted, so it is not a pass.
pub fn judge_case(candidate_output: &str, case: &GoldenCase) -> CaseVerdict {
    let to_corrected = similarity(candidate_output, &case.corrected_output);
    let to_rejected = similarity(candidate_output, &case.rejected_output);
    if to_corrected > to_rejected {
        CaseVerdict::Pass
    } else {
        CaseVerdict::Fail
    }
}

/// Token-overlap similarity in [0, 1] over normalized word sets.
pub fn similarity(a: &str, b: &str) -> f64 {
    let set_a: std::collections::HashSet<String> = normalize(a)
        .split_whitespace()
        .map(str::to_string)
        .collect();
    let set_b: std::collections::HashSet<String> = normalize(b)
        .split_whitespace()
        .map(str::to_string)
        .collect();
    if set_a.is_empty() && set_b.is_empty() {
        return 1.0;
    }
    if set_a.is_empty() || set_b.is_empty() {
        return 0.0;
    }
    let intersection = set_a.intersection(&set_b).count();
    let union = set_a.union(&set_b).count();
    if union == 0 {
        return 1.0;
    }
    intersection as f64 / union as f64
}

fn normalize(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// The aggregate result of scoring a candidate against a golden set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvalReport {
    pub agent_id: String,
    pub capability: String,
    pub golden_version: u32,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    /// passed / total, in [0, 1].
    pub pass_rate: f64,
}

/// A pluggable judge (deterministic default; an LLM judge can implement this).
#[async_trait]
pub trait EvalJudge: Send + Sync {
    async fn judge(&self, candidate_output: &str, case: &GoldenCase) -> CaseVerdict;
}

/// Deterministic judge using `judge_case`.
pub struct DeterministicJudge;

#[async_trait]
impl EvalJudge for DeterministicJudge {
    async fn judge(&self, candidate_output: &str, case: &GoldenCase) -> CaseVerdict {
        judge_case(candidate_output, case)
    }
}

/// The regression eval harness. Scores a candidate against a golden set and
/// derives a promotion verdict.
pub struct EvalHarness {
    judge: Box<dyn EvalJudge>,
}

impl EvalHarness {
    pub fn new() -> Self {
        Self {
            judge: Box::new(DeterministicJudge),
        }
    }

    pub fn with_judge(judge: Box<dyn EvalJudge>) -> Self {
        Self { judge }
    }

    /// Score one candidate output against every case for **one** input.
    ///
    /// The count of cases is not the question; the count of distinct *inputs* is.
    /// Each case records the input that produced it, so one output can only be the
    /// answer to one prompt — scoring it against cases for other prompts compares a
    /// response with expectations it never saw, and the resulting pass rate reads
    /// like a measurement while meaning nothing. That set is refused; use
    /// [`EvalHarness::evaluate_with`], which runs each case's own input.
    ///
    /// Several cases *sharing* one input is a different thing and is scored
    /// normally. A store groups cases by capability, not by prompt, so one prompt
    /// legitimately carries a case per rubric dimension — `hook` and `tone` on the
    /// same draft — and the candidate really is the answer to both. Refusing on
    /// `cases.len() > 1` made that ordinary set unscoreable, which is what an
    /// earlier revision of this guard did.
    pub async fn evaluate(
        &self,
        candidate_output: &str,
        set: &GoldenSet,
    ) -> Result<EvalReport, ReedeError> {
        require_replay_inputs(set)?;
        let distinct_inputs: std::collections::BTreeSet<&str> =
            set.cases.iter().map(|c| c.input.as_str()).collect();
        if distinct_inputs.len() > 1 {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!(
                    "one candidate output cannot be scored against {} different \
                     inputs; use evaluate_with to run each case's input",
                    distinct_inputs.len()
                ),
            });
        }
        let mut passed = 0usize;
        let mut failed = 0usize;
        for case in &set.cases {
            require_replay_input(case)?;
            match self.judge.judge(candidate_output, case).await {
                CaseVerdict::Pass => passed += 1,
                CaseVerdict::Fail => failed += 1,
            }
        }
        let total = set.cases.len();
        let pass_rate = if total == 0 {
            1.0
        } else {
            passed as f64 / total as f64
        };
        require_replay_inputs(set)?;
        Ok(EvalReport {
            agent_id: set.agent_id.clone(),
            capability: set.capability.clone(),
            golden_version: set.version,
            total,
            passed,
            failed,
            pass_rate,
        })
    }

    /// Replay the whole set: run each case's own input, judge each answer.
    ///
    /// This is what a regression replay actually is, and what the honesty layer
    /// needs — a candidate per stored prompt, not one candidate reused. A runner
    /// error fails the whole evaluation rather than counting as a failed case: a
    /// provider outage is not evidence that the agent regressed, and silently
    /// scoring it as a failure would let infrastructure trouble read as a quality
    /// drop and block promotions for the wrong reason.
    pub async fn evaluate_with(
        &self,
        runner: &dyn CandidateRunner,
        set: &GoldenSet,
    ) -> Result<EvalReport, ReedeError> {
        require_replay_inputs(set)?;
        let mut passed = 0usize;
        let mut failed = 0usize;
        for case in &set.cases {
            require_replay_input(case)?;
            let output = runner.run(&case.input).await?;
            require_replay_input(case)?;
            match self.judge.judge(&output, case).await {
                CaseVerdict::Pass => passed += 1,
                CaseVerdict::Fail => failed += 1,
            }
        }
        let total = set.cases.len();
        let pass_rate = if total == 0 {
            1.0
        } else {
            passed as f64 / total as f64
        };
        require_replay_inputs(set)?;
        Ok(EvalReport {
            agent_id: set.agent_id.clone(),
            capability: set.capability.clone(),
            golden_version: set.version,
            total,
            passed,
            failed,
            pass_rate,
        })
    }
}

fn require_replay_inputs(set: &GoldenSet) -> Result<(), ReedeError> {
    for case in &set.cases {
        require_replay_input(case)?;
    }
    Ok(())
}

fn require_replay_input(case: &GoldenCase) -> Result<(), ReedeError> {
    if !case.replay_available(Utc::now()) {
        return Err(ReedeError::SpecValidationFailed {
            reason: "golden replay requires available, unexpired producer input".into(),
        });
    }
    Ok(())
}

/// Produces the candidate answer for one golden case's input.
///
/// A trait rather than a closure because the real implementation runs an agent,
/// which is async and lives host-side.
#[async_trait]
pub trait CandidateRunner: Send + Sync {
    async fn run(&self, input: &str) -> Result<String, ReedeError>;
}

impl Default for EvalHarness {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether a promotion should be allowed. Failures block promotion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromoteVerdict {
    Allow,
    /// No cases were scored, a case failed, or pass_rate is below the threshold.
    Block,
}

/// The promote gate: empty evidence, a candidate earning below `min_pass_rate`,
/// or any failed regression is blocked. Any failure blocks even if the rate is okay,
/// matching "regression blocks the promote step".
pub fn evaluate_promotion(report: &EvalReport, min_pass_rate: f64) -> PromoteVerdict {
    if report.total == 0 || report.failed > 0 || report.pass_rate < min_pass_rate {
        PromoteVerdict::Block
    } else {
        PromoteVerdict::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    #[tokio::test]
    async fn expiry_during_runner_or_judge_refuses_later_cases_and_final_pass() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct AwaitExpiry {
            deadline: DateTime<Utc>,
            delay_runner: bool,
            runs: AtomicUsize,
            judgements: AtomicUsize,
        }

        impl AwaitExpiry {
            async fn expire(&self) {
                while Utc::now() < self.deadline {
                    let remaining = (self.deadline - Utc::now()).to_std().unwrap_or_default();
                    tokio::time::sleep(remaining).await;
                }
            }
        }

        #[async_trait]
        impl CandidateRunner for Arc<AwaitExpiry> {
            async fn run(&self, _input: &str) -> Result<String, ReedeError> {
                self.runs.fetch_add(1, Ordering::SeqCst);
                if self.delay_runner {
                    self.expire().await;
                }
                Ok("right".into())
            }
        }

        #[async_trait]
        impl EvalJudge for Arc<AwaitExpiry> {
            async fn judge(&self, _output: &str, _case: &GoldenCase) -> CaseVerdict {
                self.judgements.fetch_add(1, Ordering::SeqCst);
                if !self.delay_runner {
                    self.expire().await;
                }
                CaseVerdict::Pass
            }
        }

        // One case exercises the final-report guard; two also exercise the next
        // boundary after an await. Both harness entry points must fail closed.
        for stage in ["evaluate-judge", "replay-runner", "replay-judge"] {
            for count in [1, 2] {
                let deadline = Utc::now() + chrono::Duration::seconds(1);
                let boundary = Arc::new(AwaitExpiry {
                    deadline,
                    delay_runner: stage == "replay-runner",
                    runs: AtomicUsize::new(0),
                    judgements: AtomicUsize::new(0),
                });
                let mut set = GoldenSet {
                    agent_id: "agent-1".into(),
                    capability: "copy".into(),
                    version: 1,
                    rubric_version: "r1".into(),
                    cases: (0..count)
                        .map(|index| {
                            let mut case = case("tenant-1", "accuracy", "in", "wrong", "right");
                            case.source_signal = Some(format!("correction-{index}"));
                            case.input_retention = Some(crate::replay_input::InputRetention {
                                sha256: hex::encode(sha2::Sha256::digest(b"in")),
                                expires_at: deadline,
                            });
                            case
                        })
                        .collect(),
                };
                let harness = EvalHarness::with_judge(Box::new(boundary.clone()));
                let result = if stage == "evaluate-judge" {
                    harness.evaluate("right", &set).await
                } else {
                    harness.evaluate_with(&boundary, &set).await
                };
                assert!(result.is_err(), "{stage}, {count} cases");
                assert_eq!(
                    boundary.runs.load(Ordering::SeqCst),
                    usize::from(stage != "evaluate-judge")
                );
                assert_eq!(
                    boundary.judgements.load(Ordering::SeqCst),
                    usize::from(stage != "replay-runner")
                );

                // Static/manual cases have no captured-input deadline and retain
                // their existing semantics even after the await crosses that time.
                for case in &mut set.cases {
                    case.source_signal = None;
                    case.input_retention = None;
                }
                let report = if stage == "evaluate-judge" {
                    harness.evaluate("right", &set).await
                } else {
                    harness.evaluate_with(&boundary, &set).await
                }
                .unwrap();
                assert_eq!(report.passed, count);
            }
        }
    }

    #[tokio::test]
    async fn expired_producer_inputs_refuse_replay_but_static_cases_keep_their_contract() {
        let mut producer = case("tenant-1", "accuracy", "original", "wrong", "right");
        producer.source_signal = Some("diff-capture:run".into());
        producer.input_retention = Some(crate::replay_input::InputRetention {
            sha256: hex::encode(sha2::Sha256::digest(b"original")),
            expires_at: Utc::now() - chrono::Duration::seconds(1),
        });
        let set = GoldenSet {
            agent_id: "agent-1".into(),
            capability: "copy".into(),
            version: 1,
            rubric_version: "r1".into(),
            cases: vec![producer.clone()],
        };
        assert!(EvalHarness::new().evaluate("right", &set).await.is_err());
        struct MustNotRun;
        #[async_trait]
        impl CandidateRunner for MustNotRun {
            async fn run(&self, _input: &str) -> Result<String, ReedeError> {
                panic!("expired input must never reach the runner")
            }
        }
        assert!(EvalHarness::new()
            .evaluate_with(&MustNotRun, &set)
            .await
            .is_err());
        let store = InMemoryGoldenStore::new();
        assert!(store
            .add_case("tenant-1", "agent-1", "copy", "r1", &producer)
            .await
            .is_err());
        let manual = case("tenant-1", "accuracy", "", "wrong", "right");
        assert_eq!(
            store
                .add_case("tenant-1", "agent-1", "copy", "r1", &manual)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .add_case("tenant-1", "agent-1", "copy", "r1", &manual)
                .await
                .unwrap(),
            2
        );
        let json = serde_json::to_value(&manual).unwrap();
        assert!(json.get("input_retention").is_none());
        assert!(json.get("source_signal").is_none());
    }

    /// Six adds, six cases in the latest set.
    ///
    /// The module's other version tests only ever added two cases, which is exactly
    /// the range where a HashMap with one or two entries yields the right one by
    /// luck. Three or more is where the old base-case selection lost rows.
    #[tokio::test]
    async fn every_added_case_survives_into_the_latest_version() {
        let store = InMemoryGoldenStore::new();
        for i in 0..6 {
            let case =
                GoldenCase::promote("t", "a", "c", "accuracy", format!("in{i}"), "bad", "good");
            let version = store.add_case("t", "a", "c", "r1", &case).await.unwrap();
            let set = store
                .get_version("t", "a", "c", version)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                set.cases.len(),
                i + 1,
                "version {version} should hold {} cases",
                i + 1
            );
        }
        let latest = store.latest("t", "a", "c").await.unwrap().unwrap();
        assert_eq!(latest.version, 6);
        assert_eq!(
            latest.cases.len(),
            6,
            "a golden set that loses cases makes the honesty layer check a fraction \
             of its own tests, silently"
        );
    }

    fn case(
        tenant: &str,
        dimension: &str,
        input: &str,
        rejected: &str,
        corrected: &str,
    ) -> GoldenCase {
        GoldenCase::promote(
            tenant, "agent-1", "copy", dimension, input, rejected, corrected,
        )
    }

    #[tokio::test]
    async fn test_golden_store_versions_append_immutably() {
        let store = InMemoryGoldenStore::new();
        let c1 = case("tenant-1", "hook", "in", "bad hook", "sharp hook");

        let v1 = store
            .add_case("tenant-1", "agent-1", "copy", "r1", &c1)
            .await
            .unwrap();
        assert_eq!(v1, 1);

        let c2 = case("tenant-1", "structure", "in2", "messy", "clear");
        let v2 = store
            .add_case("tenant-1", "agent-1", "copy", "r1", &c2)
            .await
            .unwrap();
        assert_eq!(v2, 2, "adding a case bumps the version");

        let set_v1 = store
            .get_version("tenant-1", "agent-1", "copy", 1)
            .await
            .unwrap()
            .unwrap();
        let set_v2 = store
            .get_version("tenant-1", "agent-1", "copy", 2)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(set_v1.cases.len(), 1, "v1 only had the first case");
        assert_eq!(set_v2.cases.len(), 2, "v2 carries both (append-only)");
        assert_eq!(
            store
                .latest_version("tenant-1", "agent-1", "copy")
                .await
                .unwrap(),
            Some(2)
        );
    }

    #[tokio::test]
    async fn test_harness_fails_regression_and_blocks_promotion() {
        let store = InMemoryGoldenStore::new();
        let c = case(
            "tenant-1",
            "hook",
            "in",
            "a boring flat opening",
            "an irresistible sharp hook",
        );
        store
            .add_case("tenant-1", "agent-1", "copy", "r1", &c)
            .await
            .unwrap();
        let set = store
            .latest("tenant-1", "agent-1", "copy")
            .await
            .unwrap()
            .unwrap();

        // Candidate regresses to the rejected output: must fail and block.
        let harness = EvalHarness::new();
        let report = harness
            .evaluate("a boring flat opening", &set)
            .await
            .unwrap();
        assert_eq!(report.failed, 1);
        assert_eq!(promotion(&report, 1.0), PromoteVerdict::Block);
    }

    #[tokio::test]
    async fn test_harness_passes_adopted_correction_and_allows() {
        let store = InMemoryGoldenStore::new();
        let c = case(
            "tenant-1",
            "hook",
            "in",
            "a boring flat opening",
            "an irresistible sharp hook",
        );
        store
            .add_case("tenant-1", "agent-1", "copy", "r1", &c)
            .await
            .unwrap();
        let set = store
            .latest("tenant-1", "agent-1", "copy")
            .await
            .unwrap()
            .unwrap();

        // Candidate incorporated the corrected hook.
        let harness = EvalHarness::new();
        let report = harness
            .evaluate("an irresistible sharp hook and then some", &set)
            .await
            .unwrap();
        assert_eq!(report.failed, 0);
        assert_eq!(promotion(&report, 1.0), PromoteVerdict::Allow);
    }

    /// A runner that answers each stored input with a scripted output.
    struct ScriptedRunner(std::collections::HashMap<String, String>);

    #[async_trait]
    impl CandidateRunner for ScriptedRunner {
        async fn run(&self, input: &str) -> Result<String, ReedeError> {
            self.0
                .get(input)
                .cloned()
                .ok_or_else(|| ReedeError::SpecValidationFailed {
                    reason: format!("no scripted answer for input {input:?}"),
                })
        }
    }

    #[tokio::test]
    async fn test_per_capability_threshold_blocks_borderline() {
        let store = InMemoryGoldenStore::new();
        let good = case("tenant-1", "hook", "in", "bad", "good hook");
        store
            .add_case("tenant-1", "agent-1", "copy", "r1", &good)
            .await
            .unwrap();
        let bad = case("tenant-1", "tone", "in2", "rude", "friendly");
        store
            .add_case("tenant-1", "agent-1", "copy", "r1", &bad)
            .await
            .unwrap();
        let set = store
            .latest("tenant-1", "agent-1", "copy")
            .await
            .unwrap()
            .unwrap();

        // Each case is replayed against its OWN input: the agent adopts the hook fix
        // for "in" and regresses to the rejected tone for "in2" -> rates 0.5. Any
        // failure blocks, and a demanding per-capability threshold also blocks.
        let runner = ScriptedRunner(
            [
                ("in".to_string(), "good hook".to_string()),
                ("in2".to_string(), "rude".to_string()),
            ]
            .into_iter()
            .collect(),
        );
        let harness = EvalHarness::new();
        let report = harness.evaluate_with(&runner, &set).await.unwrap();
        assert_eq!(report.passed, 1);
        assert_eq!(report.failed, 1);
        assert!((report.pass_rate - 0.5).abs() < 1e-6);
        assert_eq!(promotion(&report, 0.75), PromoteVerdict::Block);
        assert_eq!(
            promotion(&report, 0.5),
            PromoteVerdict::Block,
            "any failure blocks"
        );
    }

    /// `evaluate` must refuse a set it cannot honestly score.
    ///
    /// One candidate string is the answer to exactly one of the stored inputs;
    /// scoring it against the others compares a response with expectations for
    /// prompts it never saw. That produced a number that read like a measurement
    /// and meant nothing, so it is now an error rather than a pass rate.
    #[tokio::test]
    async fn evaluate_refuses_a_set_spanning_two_inputs() {
        let store = InMemoryGoldenStore::new();
        store
            .add_case(
                "tenant-1",
                "agent-1",
                "copy",
                "r1",
                &case("tenant-1", "hook", "in", "bad", "good hook"),
            )
            .await
            .unwrap();
        store
            .add_case(
                "tenant-1",
                "agent-1",
                "copy",
                "r1",
                &case("tenant-1", "tone", "in2", "rude", "friendly"),
            )
            .await
            .unwrap();
        let set = store
            .latest("tenant-1", "agent-1", "copy")
            .await
            .unwrap()
            .unwrap();

        let err = EvalHarness::new()
            .evaluate("good hook", &set)
            .await
            .expect_err("two cases with different inputs cannot share one output");
        assert!(
            err.to_string().contains("evaluate_with"),
            "the error should name the method that replays each input: {err}"
        );

        // A single-case set is still scorable through `evaluate`.
        let v1 = store
            .get_version("tenant-1", "agent-1", "copy", 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            EvalHarness::new()
                .evaluate("good hook", &v1)
                .await
                .unwrap()
                .passed,
            1
        );
    }

    /// Several cases for the SAME input are scored, not refused.
    ///
    /// A store groups cases by capability rather than by prompt, so one prompt
    /// legitimately carries a case per rubric dimension — `hook` and `tone` on one
    /// draft — and the candidate really is the answer to both. The first version of
    /// this guard tested `cases.len() > 1` and refused that ordinary set, which
    /// turned a review finding into an unscoreable capability.
    #[tokio::test]
    async fn several_dimensions_on_one_input_are_scored_together() {
        let store = InMemoryGoldenStore::new();
        for (dimension, rejected, corrected) in [
            ("hook", "a flat opening", "an irresistible sharp hook"),
            ("tone", "rude and clipped", "warm and direct"),
        ] {
            store
                .add_case(
                    "tenant-1",
                    "agent-1",
                    "copy",
                    "r1",
                    // Same input, different rubric dimension: one draft judged twice.
                    &case(
                        "tenant-1",
                        dimension,
                        "write the intro",
                        rejected,
                        corrected,
                    ),
                )
                .await
                .unwrap();
        }
        let set = store
            .latest("tenant-1", "agent-1", "copy")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(set.cases.len(), 2);

        // Adopts the hook, keeps the rejected tone: one of two, and scoreable.
        let report = EvalHarness::new()
            .evaluate("an irresistible sharp hook, rude and clipped", &set)
            .await
            .expect("cases sharing one input are exactly what one output answers");
        assert_eq!(report.total, 2);
        assert_eq!(report.passed, 1);
        assert_eq!(report.failed, 1);
        assert_eq!(promotion(&report, 1.0), PromoteVerdict::Block);
    }

    /// A tie is a failure, and text that resembles neither output ties at 0.0.
    ///
    /// While a tie counted as a pass, an empty or entirely unrelated candidate
    /// passed *every* case, and a report with zero failures is all
    /// `evaluate_promotion` needs to allow a promotion.
    #[tokio::test]
    async fn unrelated_and_empty_candidates_fail_every_case() {
        let c = case(
            "tenant-1",
            "hook",
            "in",
            "a boring flat opening",
            "an irresistible sharp hook",
        );
        for candidate in ["", "   ", "quokka xylophone zeppelin"] {
            assert_eq!(
                judge_case(candidate, &c),
                CaseVerdict::Fail,
                "candidate {candidate:?} matches neither output, so it is not evidence \
                 the correction was adopted"
            );
        }

        // And it does not slip through the harness into an Allow.
        let set = GoldenSet {
            agent_id: "agent-1".into(),
            capability: "copy".into(),
            version: 1,
            rubric_version: "r1".into(),
            cases: vec![c],
        };
        let report = EvalHarness::new().evaluate("", &set).await.unwrap();
        assert_eq!(report.failed, 1);
        assert_eq!(promotion(&report, 1.0), PromoteVerdict::Block);
    }

    /// A word-order-only correction also ties, because `similarity` compares
    /// token *sets* — and must therefore fail rather than pass for free.
    #[test]
    fn a_reordering_only_correction_ties_and_fails() {
        let c = case("t", "order", "in", "hook the sharp", "the sharp hook");
        assert_eq!(
            similarity("the sharp hook", &c.rejected_output),
            similarity("the sharp hook", &c.corrected_output),
            "same token set both ways"
        );
        assert_eq!(judge_case("the sharp hook", &c), CaseVerdict::Fail);
    }

    #[tokio::test]
    async fn empty_golden_set_reports_no_cases_and_blocks_promotion() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct MustNotRun(AtomicUsize);

        #[async_trait]
        impl CandidateRunner for MustNotRun {
            async fn run(&self, _input: &str) -> Result<String, ReedeError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                panic!("empty golden set must not run a candidate")
            }
        }
        let set = GoldenSet {
            agent_id: "agent-1".into(),
            capability: "copy".into(),
            version: 1,
            rubric_version: "r1".into(),
            cases: vec![],
        };
        let harness = EvalHarness::new();
        let runner = MustNotRun(AtomicUsize::new(0));
        let reports = [
            harness.evaluate("anything", &set).await.unwrap(),
            harness.evaluate_with(&runner, &set).await.unwrap(),
        ];
        assert_eq!(runner.0.load(Ordering::SeqCst), 0);
        for report in reports {
            assert_eq!(report.total, 0);
            assert_eq!(report.passed, 0);
            assert_eq!(report.failed, 0);
            assert_eq!(report.pass_rate, 1.0);
            for threshold in [0.0, 1.0] {
                assert_eq!(promotion(&report, threshold), PromoteVerdict::Block);
            }
        }
    }

    #[test]
    fn test_similarity_and_carried_helpers() {
        assert!((similarity("a b c", "a b c") - 1.0).abs() < 1e-6);
        assert!((similarity("a b c", "x y z") - 0.0).abs() < 1e-6);
        assert!((similarity("", "") - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_judge_regression_and_adoption_direct() {
        let c = case(
            "t",
            "hook",
            "in",
            "the old weak hook line",
            "the new strong hook line",
        );
        assert_eq!(judge_case("the old weak hook line", &c), CaseVerdict::Fail);
        assert_eq!(
            judge_case("the new strong hook line", &c),
            CaseVerdict::Pass
        );
    }

    fn promotion(report: &EvalReport, threshold: f64) -> PromoteVerdict {
        evaluate_promotion(report, threshold)
    }
}
