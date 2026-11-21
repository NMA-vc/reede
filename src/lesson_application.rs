//! Evaluated, signed-review lesson mutations. No production Host caller is enabled here.
//!
//! The evaluation token is deliberately not deserializable: a caller-supplied EvalReport
//! is not evidence that a candidate ran. The runtime must verify the canonical review
//! with its configured trusted key before constructing this token.

use crate::consumer::{AppliedLesson, LessonDelta, LessonReviewResolution, LessonStatus};
use crate::gateway::{Gateway, TaskContext};
use crate::golden::{
    evaluate_promotion, CandidateRunner, EvalHarness, EvalReport, GoldenSet, PromoteVerdict,
};
use crate::govern::TOOL_APPLY_LESSON_DELTA;
use crate::receipt::{
    emit_execution_receipt, ExecutionReceipt, ReceiptSigner, ReceiptStore, REEDE_V1_FORMAT,
};
use crate::ReedeError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::Mutex;

pub fn application_error(reason: impl Into<String>) -> ReedeError {
    ReedeError::SpecValidationFailed {
        reason: reason.into(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LessonScope {
    pub tenant_id: String,
    pub agent_id: String,
    pub capability: String,
}

impl LessonScope {
    pub fn of(delta: &LessonDelta) -> Self {
        Self {
            tenant_id: delta.tenant_id.clone(),
            agent_id: delta.agent_id.clone(),
            capability: delta.capability.clone(),
        }
    }

    pub fn validate(&self) -> Result<(), ReedeError> {
        if [&self.tenant_id, &self.agent_id, &self.capability]
            .iter()
            .any(|v| v.trim().is_empty())
        {
            return Err(application_error("blank lesson application scope"));
        }
        Ok(())
    }
}

/// Active instructions and immutable ledger high-water mark, read consistently.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LessonSnapshot {
    pub scope: LessonScope,
    pub last_version: u32,
    pub active: Vec<AppliedLesson>,
}

impl LessonSnapshot {
    pub fn validate(&self) -> Result<(), ReedeError> {
        self.scope.validate()?;
        let mut previous = 0;
        for lesson in &self.active {
            if lesson.version <= previous
                || lesson.version > self.last_version
                || lesson.capability != self.scope.capability
                || lesson.delta_id.trim().is_empty()
                || lesson.instruction.trim().is_empty()
            {
                return Err(application_error("invalid active lesson snapshot"));
            }
            previous = lesson.version;
        }
        Ok(())
    }
}

/// The runner's actual immutable configuration, checked before the first case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LessonCandidateBinding {
    pub scope: LessonScope,
    pub delta_id: String,
    pub review_digest: String,
    pub agent_spec_id: String,
    pub baseline_digest: String,
}
impl LessonCandidateBinding {
    pub fn for_review(
        resolution: &LessonReviewResolution,
        agent_spec_id: &str,
        baseline: &LessonSnapshot,
    ) -> Result<Self, ReedeError> {
        let approved = resolution.resolved_delta()?;
        baseline.validate()?;
        if approved.status != LessonStatus::Approved
            || LessonScope::of(&approved) != baseline.scope
            || agent_spec_id.trim().is_empty()
        {
            return Err(application_error(
                "invalid reviewed candidate configuration",
            ));
        }
        Ok(Self {
            scope: baseline.scope.clone(),
            delta_id: approved.id,
            review_digest: json_digest(resolution)?,
            agent_spec_id: agent_spec_id.into(),
            baseline_digest: json_digest(baseline)?,
        })
    }
}

/// A Host implementation must report the configuration it actually executes, not
/// attach this metadata to an unrelated CandidateRunner after evaluation.
pub trait ReviewedLessonCandidateRunner: CandidateRunner {
    fn lesson_binding(&self) -> &LessonCandidateBinding;
}

/// Permanent evidence contains identities/digests, never another retained golden payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LessonEvaluationEvidence {
    pub candidate: LessonCandidateBinding,
    pub agent_spec_id: String,
    pub golden_digest: String,
    pub case_ids: Vec<String>,
    pub input_expires_at: Option<DateTime<Utc>>,
    pub evaluated_at: DateTime<Utc>,
    pub report: EvalReport,
    pub baseline: LessonSnapshot,
}

impl LessonEvaluationEvidence {
    pub fn validate(&self) -> Result<(), ReedeError> {
        self.baseline.validate()?;
        let r = &self.report;
        let scope = &self.baseline.scope;
        if self.candidate.scope != *scope
            || self.candidate.agent_spec_id != self.agent_spec_id
            || self.candidate.baseline_digest != json_digest(&self.baseline)?
            || self.candidate.delta_id.trim().is_empty()
            || self.candidate.review_digest.len() != 64
            || !self
                .candidate
                .review_digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
            || self.agent_spec_id.trim().is_empty()
            || self.golden_digest.len() != 64
            || !self.golden_digest.bytes().all(|b| b.is_ascii_hexdigit())
            || r.agent_id != scope.agent_id
            || r.capability != scope.capability
            || r.golden_version == 0
            || r.total == 0
            || r.total != self.case_ids.len()
            || self.case_ids.iter().any(|id| id.trim().is_empty())
            || self.case_ids.iter().collect::<BTreeSet<_>>().len() != self.case_ids.len()
            || r.passed != r.total
            || r.failed != 0
            || !r.pass_rate.is_finite()
            || r.pass_rate != 1.0
            || self
                .input_expires_at
                .is_some_and(|at| at <= self.evaluated_at)
            || evaluate_promotion(r, 1.0) != PromoteVerdict::Allow
        {
            return Err(application_error(
                "incomplete or inconsistent lesson evaluation",
            ));
        }
        Ok(())
    }
}

/// Transient full snapshot is retained only for the commit CAS, not copied into the ledger.
#[derive(Debug, Clone)]
pub struct EvaluatedLesson {
    resolution: LessonReviewResolution,
    golden: GoldenSet,
    evidence: LessonEvaluationEvidence,
}

impl EvaluatedLesson {
    /// Only use after the runtime verified the configured trusted signing key and canonical pair.
    pub async fn evaluate(
        resolution: LessonReviewResolution,
        agent_spec_id: String,
        baseline: LessonSnapshot,
        golden: GoldenSet,
        runner: &dyn ReviewedLessonCandidateRunner,
        harness: &EvalHarness,
    ) -> Result<Self, ReedeError> {
        let approved = resolution.resolved_delta()?;
        if approved.status != LessonStatus::Approved || LessonScope::of(&approved) != baseline.scope
        {
            return Err(application_error(
                "evaluation requires the exact approved lesson scope",
            ));
        }
        baseline.validate()?;
        if agent_spec_id.trim().is_empty() || resolution.decided_at > Utc::now() {
            return Err(application_error(
                "invalid manifest or future lesson decision",
            ));
        }
        require_full_set(&golden, &baseline.scope, Utc::now())?;
        let expected = LessonCandidateBinding::for_review(&resolution, &agent_spec_id, &baseline)?;
        if runner.lesson_binding() != &expected {
            return Err(application_error(
                "runner configuration differs from reviewed candidate",
            ));
        }
        let report = harness.evaluate_with(runner, &golden).await?;
        let evidence = LessonEvaluationEvidence {
            candidate: expected,
            agent_spec_id,
            golden_digest: json_digest(&golden)?,
            case_ids: golden.cases.iter().map(|c| c.id.clone()).collect(),
            input_expires_at: golden.input_expires_at(),
            evaluated_at: Utc::now(),
            report,
            baseline,
        };
        evidence.validate()?;
        let candidate = Self {
            resolution,
            golden,
            evidence,
        };
        candidate.validate(Utc::now())?;
        Ok(candidate)
    }

    pub fn resolution(&self) -> &LessonReviewResolution {
        &self.resolution
    }
    pub fn golden(&self) -> &GoldenSet {
        &self.golden
    }
    pub fn evidence(&self) -> &LessonEvaluationEvidence {
        &self.evidence
    }
    pub fn scope(&self) -> &LessonScope {
        &self.evidence.baseline.scope
    }
    pub fn version(&self) -> Result<u32, ReedeError> {
        self.evidence
            .baseline
            .last_version
            .checked_add(1)
            .ok_or_else(|| application_error("lesson version exhausted"))
    }
    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), ReedeError> {
        self.evidence.validate()?;
        let approved = self.resolution.resolved_delta()?;
        if approved.status != LessonStatus::Approved
            || LessonScope::of(&approved) != *self.scope()
            || self.evidence.candidate
                != LessonCandidateBinding::for_review(
                    &self.resolution,
                    &self.evidence.agent_spec_id,
                    &self.evidence.baseline,
                )?
            || self.evidence.golden_digest != json_digest(&self.golden)?
            || self.evidence.case_ids
                != self
                    .golden
                    .cases
                    .iter()
                    .map(|c| c.id.clone())
                    .collect::<Vec<_>>()
            || self.evidence.report.golden_version != self.golden.version
            || self.evidence.input_expires_at != self.golden.input_expires_at()
        {
            return Err(application_error("lesson evaluation binding changed"));
        }
        require_full_set(&self.golden, self.scope(), now)?;
        self.version()?;
        Ok(())
    }
    pub fn summary(&self) -> Result<String, ReedeError> {
        apply_summary(&self.resolution, &self.evidence, self.version()?)
    }
}

fn require_full_set(
    set: &GoldenSet,
    scope: &LessonScope,
    now: DateTime<Utc>,
) -> Result<(), ReedeError> {
    if set.version == 0
        || set.cases.is_empty()
        || set
            .cases
            .iter()
            .map(|c| &c.id)
            .collect::<BTreeSet<_>>()
            .len()
            != set.cases.len()
        || set.agent_id != scope.agent_id
        || set.capability != scope.capability
        || set.cases.iter().any(|c| {
            c.tenant_id != scope.tenant_id
                || c.agent_id != scope.agent_id
                || c.capability != scope.capability
                || c.id.trim().is_empty()
                || !c.replay_available(now)
        })
    {
        return Err(application_error("full scoped golden set is unavailable"));
    }
    Ok(())
}

pub fn json_digest(value: &impl Serialize) -> Result<String, ReedeError> {
    let mut canonical =
        serde_json::to_value(value).map_err(|e| application_error(e.to_string()))?;
    // This is a new application digest contract, independent of legacy receipt bytes.
    // Preserve arrays/scalars and exact reviewed strings while normalizing object order.
    canonical.sort_all_objects();
    let bytes = serde_json::to_vec(&canonical).map_err(|e| application_error(e.to_string()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn apply_summary(
    resolution: &LessonReviewResolution,
    evidence: &LessonEvaluationEvidence,
    version: u32,
) -> Result<String, ReedeError> {
    serde_json::to_string(&serde_json::json!({
        "action": crate::govern::LEGACY_APPLY_SUMMARY_ACTION, "review_digest": json_digest(resolution)?,
        "evaluation_digest": json_digest(evidence)?, "scope": evidence.baseline.scope,
        "delta_id": resolution.enrollment.original.id, "version": version,
    }))
    .map_err(|e| application_error(e.to_string()))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LessonApplication {
    pub resolution: LessonReviewResolution,
    pub evaluation: LessonEvaluationEvidence,
    pub lesson: AppliedLesson,
    pub receipt: ExecutionReceipt,
}

impl LessonApplication {
    pub fn validate(&self) -> Result<(), ReedeError> {
        let d = self.resolution.resolved_delta()?;
        self.evaluation.validate()?;
        let l = &self.lesson;
        if self.evaluation.candidate
            != LessonCandidateBinding::for_review(
                &self.resolution,
                &self.evaluation.agent_spec_id,
                &self.evaluation.baseline,
            )?
            || d.status != LessonStatus::Approved
            || LessonScope::of(&d) != self.evaluation.baseline.scope
            || l.delta_id != d.id
            || l.capability != d.capability
            || l.dimension != d.dimension
            || l.instruction != d.proposed_instruction
            || l.version
                != self
                    .evaluation
                    .baseline
                    .last_version
                    .checked_add(1)
                    .ok_or_else(|| application_error("lesson version exhausted"))?
            || l.applied_at != self.receipt.timestamp
            || self.receipt.tenant_id != d.tenant_id
            || self.evaluation.evaluated_at < self.resolution.decided_at
            || self.evaluation.evaluated_at > self.receipt.timestamp
            || self
                .evaluation
                .input_expires_at
                .is_some_and(|at| at <= self.receipt.timestamp)
        {
            return Err(application_error("stored application binding changed"));
        }
        validate_operation_receipt(
            &self.receipt,
            &apply_summary(&self.resolution, &self.evaluation, l.version)?,
        )
    }

    pub fn delta(&self, rolled_back: bool) -> Result<LessonDelta, ReedeError> {
        let mut d = self.resolution.resolved_delta()?;
        d.status = if rolled_back {
            LessonStatus::RolledBack
        } else {
            LessonStatus::Applied
        };
        d.version = Some(self.lesson.version);
        Ok(d)
    }

    pub fn matches(&self, candidate: &EvaluatedLesson) -> bool {
        self.resolution == *candidate.resolution() && self.evaluation == *candidate.evidence()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedLessonRollback {
    pub scope: LessonScope,
    pub delta_id: String,
    pub version: u32,
    pub application_receipt_hash: String,
    pub actor: String,
}

impl ScopedLessonRollback {
    pub fn validate(&self) -> Result<(), ReedeError> {
        self.scope.validate()?;
        if self.delta_id.trim().is_empty()
            || self.version == 0
            || self.actor.trim().is_empty()
            || self.application_receipt_hash.len() != 64
        {
            return Err(application_error("invalid scoped lesson rollback"));
        }
        Ok(())
    }
    pub fn summary(&self) -> Result<String, ReedeError> {
        self.validate()?;
        serde_json::to_string(
            &serde_json::json!({"action":crate::govern::LEGACY_ROLLBACK_SUMMARY_ACTION, "rollback":self}),
        )
        .map_err(|e| application_error(e.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LessonRollback {
    pub request: ScopedLessonRollback,
    pub receipt: ExecutionReceipt,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredLessonApplication {
    pub application: LessonApplication,
    pub rollback: Option<LessonRollback>,
}

impl StoredLessonApplication {
    pub fn validate(&self) -> Result<(), ReedeError> {
        self.application.validate()?;
        if let Some(r) = &self.rollback {
            r.request.validate()?;
            if r.request.scope != self.application.evaluation.baseline.scope
                || r.request.delta_id != self.application.lesson.delta_id
                || r.request.version != self.application.lesson.version
                || r.request.application_receipt_hash != self.application.receipt.content_hash
                || r.receipt.tenant_id != r.request.scope.tenant_id
            {
                return Err(application_error("rollback application binding changed"));
            }
            validate_operation_receipt(&r.receipt, &r.request.summary()?)?;
        }
        Ok(())
    }
}

pub fn validate_operation_receipt(
    receipt: &ExecutionReceipt,
    summary: &str,
) -> Result<(), ReedeError> {
    // reede-v2 is what the writer emits; reede-v1 operation receipts written before it still
    // verify. Each recomputes by its own format's rule.
    let signed_format = matches!(
        receipt.format.as_deref(),
        Some(REEDE_V1_FORMAT | crate::receipt::REEDE_V2_FORMAT)
    );
    if !signed_format
        || receipt.payload_summary != summary
        || crate::receipt::recompute_content_hash(receipt).as_deref()
            != Some(receipt.content_hash.as_str())
        || receipt.signature.is_empty()
        || receipt.sequence_no == 0
        || receipt.credits_spent != 0
        || receipt.tokens_used != 0
        || receipt.reservation_credits != 0
        || receipt.subject_id.is_some()
    {
        return Err(application_error("invalid lesson operation receipt"));
    }
    Ok(())
}

/// Implementations must commit mutation and receipt together, and recover the full winner.
#[async_trait]
pub trait LessonApplicationStore: ReceiptStore {
    async fn application(
        &self,
        scope: &LessonScope,
        delta_id: &str,
    ) -> Result<Option<StoredLessonApplication>, ReedeError>;
    async fn active_snapshot(&self, scope: &LessonScope) -> Result<LessonSnapshot, ReedeError>;
    async fn commit_application(
        &self,
        candidate: &EvaluatedLesson,
        receipt: &ExecutionReceipt,
    ) -> Result<StoredLessonApplication, ReedeError>;
    async fn commit_rollback(
        &self,
        request: &ScopedLessonRollback,
        receipt: &ExecutionReceipt,
    ) -> Result<StoredLessonApplication, ReedeError>;
}

#[derive(Clone, Copy)]
enum Mutation<'a> {
    Apply(&'a EvaluatedLesson),
    Rollback(&'a ScopedLessonRollback),
}
struct MutationReceiptStore<'a> {
    store: &'a dyn LessonApplicationStore,
    mutation: Mutation<'a>,
    winner: Mutex<Option<StoredLessonApplication>>,
}

#[async_trait]
impl ReceiptStore for MutationReceiptStore<'_> {
    async fn append(&self, receipt: ExecutionReceipt) -> Result<(), ReedeError> {
        let winner = match self.mutation {
            Mutation::Apply(candidate) => {
                self.store.commit_application(candidate, &receipt).await?
            }
            Mutation::Rollback(request) => self.store.commit_rollback(request, &receipt).await?,
        };
        winner.validate()?;
        let committed = match self.mutation {
            Mutation::Apply(_) => &winner.application.receipt,
            Mutation::Rollback(_) => {
                &winner
                    .rollback
                    .as_ref()
                    .ok_or_else(|| application_error("rollback winner absent"))?
                    .receipt
            }
        };
        let same_receipt = committed == &receipt;
        *self.winner.lock().unwrap() = Some(winner);
        if same_receipt {
            Ok(())
        } else {
            Err(application_error(
                "lesson operation has a different committed receipt winner",
            ))
        }
    }
    async fn chain(&self, tenant: &str) -> Result<Vec<ExecutionReceipt>, ReedeError> {
        self.store.chain(tenant).await
    }
    async fn latest_hash(&self, tenant: &str) -> Result<Option<String>, ReedeError> {
        self.store.latest_hash(tenant).await
    }
    async fn latest_sequence(&self, tenant: &str) -> Result<u64, ReedeError> {
        self.store.latest_sequence(tenant).await
    }
}

/// No caller may skip the gateway, even when recovering an already committed operation.
pub async fn apply_evaluated_lesson(
    gateway: &dyn Gateway,
    ctx: &TaskContext,
    store: &dyn LessonApplicationStore,
    signer: &dyn ReceiptSigner,
    candidate: &EvaluatedLesson,
) -> Result<StoredLessonApplication, ReedeError> {
    let scope = candidate.scope();
    gateway.call_tool(ctx, TOOL_APPLY_LESSON_DELTA, serde_json::json!({"tenant_id":scope.tenant_id,"delta_id":candidate.resolution.enrollment.original.id})).await?;
    if ctx.tenant_id != scope.tenant_id
        || ctx.policy.agent_id != scope.agent_id
        || ctx.agent_spec_id != candidate.evidence.agent_spec_id
    {
        return Err(application_error(
            "application task context does not match evaluated scope",
        ));
    }
    if let Some(winner) = store
        .application(scope, &candidate.resolution.enrollment.original.id)
        .await?
    {
        winner.validate()?;
        if !winner.application.matches(candidate) {
            return Err(application_error("application retry changed evaluation"));
        }
        return Ok(winner);
    }
    candidate.validate(Utc::now())?;
    let adapter = MutationReceiptStore {
        store,
        mutation: Mutation::Apply(candidate),
        winner: Mutex::new(None),
    };
    let result = emit_execution_receipt(
        signer,
        &adapter,
        ctx.task_id,
        &ctx.tenant_id,
        candidate.summary()?,
        0,
        0,
        0,
        None,
    )
    .await;
    if let Some(winner) = adapter.winner.into_inner().unwrap() {
        return Ok(winner);
    }
    result?;
    Err(application_error(
        "application returned no committed winner",
    ))
}

pub async fn rollback_lesson(
    gateway: &dyn Gateway,
    ctx: &TaskContext,
    store: &dyn LessonApplicationStore,
    signer: &dyn ReceiptSigner,
    request: &ScopedLessonRollback,
) -> Result<StoredLessonApplication, ReedeError> {
    gateway.call_tool(ctx, TOOL_APPLY_LESSON_DELTA, serde_json::json!({"tenant_id":request.scope.tenant_id,"delta_id":request.delta_id,"action":"rollback","version":request.version})).await?;
    if ctx.tenant_id != request.scope.tenant_id {
        return Err(application_error("rollback task tenant changed"));
    }
    request.validate()?;
    let winner = store
        .application(&request.scope, &request.delta_id)
        .await?
        .ok_or_else(|| application_error("rollback application missing"))?;
    winner.validate()?;
    if winner.application.lesson.version != request.version
        || winner.application.receipt.content_hash != request.application_receipt_hash
    {
        return Err(application_error("rollback target changed"));
    }
    if let Some(rollback) = &winner.rollback {
        if rollback.request != *request {
            return Err(application_error("rollback retry changed"));
        }
        return Ok(winner);
    }
    let adapter = MutationReceiptStore {
        store,
        mutation: Mutation::Rollback(request),
        winner: Mutex::new(None),
    };
    let result = emit_execution_receipt(
        signer,
        &adapter,
        ctx.task_id,
        &ctx.tenant_id,
        request.summary()?,
        0,
        0,
        0,
        None,
    )
    .await;
    if let Some(winner) = adapter.winner.into_inner().unwrap() {
        return Ok(winner);
    }
    result?;
    Err(application_error("rollback returned no committed winner"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consumer::LessonReviewEnrollment;
    use crate::golden::GoldenCase;
    use crate::replay_input::InputRetention;
    use serde_json::json;

    fn fixture() -> (LessonReviewResolution, LessonSnapshot, GoldenSet) {
        let d = LessonDelta::propose(
            "tenant-a",
            "agent-a",
            "summarize",
            "acceptance",
            "original",
            1,
        );
        let scope = LessonScope::of(&d);
        let key = format!("lesson:{}", d.id);
        let proposal = json!({"tenant_id":d.tenant_id,"delta_id":d.id,"agent_id":d.agent_id,"capability":d.capability,"dimension":d.dimension,"proposed_instruction":d.proposed_instruction,"evidence_signal_ids":[]});
        let enrollment = LessonReviewEnrollment {
            original: d.clone(),
            approval_key: key.clone(),
            canonical_record_id: format!(
                "lesson-v1:{}:{}:{}:{}",
                d.tenant_id.len(),
                d.tenant_id,
                key.len(),
                key
            ),
            proposal_context: proposal.clone(),
        };
        let mut context = proposal;
        context.as_object_mut().unwrap().insert(
            "review".into(),
            json!({"decision":"approve","reviewed_instruction":"human text"}),
        );
        let at = Utc::now();
        let resolution = LessonReviewResolution {
            enrollment: enrollment.clone(),
            reviewed_instruction: Some("human text".into()),
            actor: "alice".into(),
            decided_at: at,
            signed_record: json!({"thread_id":key,"gate_type":"lesson_delta","status":"approved","decision":"approve","decider":"alice","decided_at":at,"created_at":d.created_at,"reason":enrollment.reason(),"receipt":{},"context":context}),
        };
        let cases = ["input-a", "input-b"]
            .into_iter()
            .map(|input| {
                GoldenCase::promote(
                    "tenant-a",
                    "agent-a",
                    "summarize",
                    "acceptance",
                    input,
                    "wrong",
                    format!("correct {input}"),
                )
            })
            .collect();
        (
            resolution,
            LessonSnapshot {
                scope,
                last_version: 0,
                active: Vec::new(),
            },
            GoldenSet {
                agent_id: "agent-a".into(),
                capability: "summarize".into(),
                version: 1,
                rubric_version: "v1".into(),
                cases,
            },
        )
    }
    struct RecordingRunner {
        calls: Mutex<Vec<String>>,
        binding: LessonCandidateBinding,
    }
    impl RecordingRunner {
        fn new(review: &LessonReviewResolution, baseline: &LessonSnapshot) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                binding: LessonCandidateBinding::for_review(review, "manifest", baseline).unwrap(),
            }
        }
    }
    impl ReviewedLessonCandidateRunner for RecordingRunner {
        fn lesson_binding(&self) -> &LessonCandidateBinding {
            &self.binding
        }
    }
    #[async_trait]
    impl CandidateRunner for RecordingRunner {
        async fn run(&self, input: &str) -> Result<String, ReedeError> {
            self.calls.lock().unwrap().push(input.into());
            Ok(format!("correct {input}"))
        }
    }
    struct PanicRunner;
    impl ReviewedLessonCandidateRunner for PanicRunner {
        fn lesson_binding(&self) -> &LessonCandidateBinding {
            panic!("invalid set must refuse before runner configuration")
        }
    }
    #[async_trait]
    impl CandidateRunner for PanicRunner {
        async fn run(&self, _: &str) -> Result<String, ReedeError> {
            panic!("invalid evidence must refuse before candidate execution")
        }
    }
    #[test]
    fn application_digest_normalizes_nested_objects_but_preserves_array_and_text_order() {
        let mut first = serde_json::Map::new();
        first.insert("z".into(), serde_json::json!({"b":2,"a":1}));
        first.insert(
            "a".into(),
            serde_json::json!([{"y":4,"x":3}," exact text "]),
        );
        let mut reordered = serde_json::Map::new();
        reordered.insert(
            "a".into(),
            serde_json::json!([{"x":3,"y":4}," exact text "]),
        );
        reordered.insert("z".into(), serde_json::json!({"a":1,"b":2}));
        let first = serde_json::Value::Object(first);
        let reordered = serde_json::Value::Object(reordered);
        assert_eq!(
            json_digest(&first).unwrap(),
            json_digest(&reordered).unwrap()
        );
        let mut changed = reordered.clone();
        changed["a"].as_array_mut().unwrap().reverse();
        assert_ne!(json_digest(&first).unwrap(), json_digest(&changed).unwrap());
        let mut changed = reordered;
        changed["a"][1] = serde_json::json!("exact text");
        assert_ne!(json_digest(&first).unwrap(), json_digest(&changed).unwrap());
    }

    #[tokio::test]
    async fn token_replays_every_input_and_keeps_payload_out_of_permanent_evidence() {
        let (review, baseline, set) = fixture();
        let runner = RecordingRunner::new(&review, &baseline);
        let token = EvaluatedLesson::evaluate(
            review,
            "manifest".into(),
            baseline,
            set,
            &runner,
            &EvalHarness::new(),
        )
        .await
        .unwrap();
        assert_eq!(*runner.calls.lock().unwrap(), vec!["input-a", "input-b"]);
        assert_eq!(token.evidence.report.total, 2);
        assert_eq!(token.evidence.report.passed, 2);
        assert_eq!(token.version().unwrap(), 1);
        let stored = serde_json::to_string(token.evidence()).unwrap();
        assert!(!stored.contains("input-a"));
        assert!(!stored.contains("input-b"));
        assert!(!stored.contains("correct input"));
        for changed in 0..6 {
            let mut e = token.evidence.clone();
            match changed {
                0 => e.report.total = 0,
                1 => e.report.passed = 1,
                2 => e.report.pass_rate = f64::NAN,
                3 => e.report.pass_rate = f64::INFINITY,
                4 => e.report.agent_id = "other".into(),
                _ => e.case_ids[1] = e.case_ids[0].clone(),
            }
            assert!(e.validate().is_err());
        }
    }
    /// Receipts stored before the rename carry the legacy action strings inside their signed
    /// `payload_summary`, and validation recomputes and compares byte for byte. The produced
    /// summary must therefore stay identical to what the pre-rename code wrote.
    #[tokio::test]
    async fn summaries_stay_byte_identical_to_the_pre_rename_form() {
        let (review, baseline, set) = fixture();
        let runner = RecordingRunner::new(&review, &baseline);
        let token = EvaluatedLesson::evaluate(
            review,
            "manifest".into(),
            baseline,
            set,
            &runner,
            &EvalHarness::new(),
        )
        .await
        .unwrap();
        let old_way = serde_json::to_string(&serde_json::json!({
            "action": "weeger/apply_lesson_delta",
            "review_digest": json_digest(&token.resolution).unwrap(),
            "evaluation_digest": json_digest(&token.evidence).unwrap(),
            "scope": token.evidence.baseline.scope,
            "delta_id": token.resolution.enrollment.original.id,
            "version": token.version().unwrap(),
        }))
        .unwrap();
        assert_eq!(token.summary().unwrap(), old_way);
        assert_eq!(
            crate::govern::LEGACY_ROLLBACK_SUMMARY_ACTION,
            "weeger/rollback_lesson_delta"
        );
        assert_eq!(
            crate::govern::LEGACY_APPLY_SUMMARY_PREFIX,
            "weeger:apply_lesson_delta"
        );
    }

    #[tokio::test]
    async fn wrong_runner_scope_delta_review_spec_or_baseline_never_runs_candidate() {
        for changed in 0..5 {
            let (review, baseline, set) = fixture();
            let mut runner = RecordingRunner::new(&review, &baseline);
            match changed {
                0 => runner.binding.scope.tenant_id = "other-tenant".into(),
                1 => runner.binding.delta_id = "other-delta".into(),
                2 => runner.binding.review_digest = "0".repeat(64),
                3 => runner.binding.agent_spec_id = "other-manifest".into(),
                _ => runner.binding.baseline_digest = "0".repeat(64),
            }
            assert!(EvaluatedLesson::evaluate(
                review,
                "manifest".into(),
                baseline,
                set,
                &runner,
                &EvalHarness::new()
            )
            .await
            .is_err());
            assert!(runner.calls.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn empty_duplicate_wrong_scope_or_expired_full_set_never_calls_candidate() {
        for changed in 0..5 {
            let (review, baseline, mut set) = fixture();
            match changed {
                0 => set.cases.clear(),
                1 => set.cases[1].id = set.cases[0].id.clone(),
                2 => set.cases[0].tenant_id = "other".into(),
                3 => {
                    set.cases[0].source_signal = Some("original-source".into());
                    set.cases[0].input_retention = Some(InputRetention {
                        sha256: hex::encode(Sha256::digest(set.cases[0].input.as_bytes())),
                        expires_at: Utc::now() - chrono::Duration::seconds(1),
                    });
                }
                _ => set.version = 0,
            }
            assert!(EvaluatedLesson::evaluate(
                review,
                "manifest".into(),
                baseline,
                set,
                &PanicRunner,
                &EvalHarness::new()
            )
            .await
            .is_err());
        }
    }
    #[tokio::test]
    async fn pass_token_expires_and_modified_snapshot_cannot_be_rebound() {
        let (review, baseline, mut set) = fixture();
        for case in &mut set.cases {
            case.source_signal = Some("original-source".into());
            case.input_retention = Some(InputRetention {
                sha256: hex::encode(Sha256::digest(case.input.as_bytes())),
                expires_at: Utc::now() + chrono::Duration::seconds(1),
            });
        }
        let runner = RecordingRunner::new(&review, &baseline);
        let token = EvaluatedLesson::evaluate(
            review,
            "manifest".into(),
            baseline,
            set,
            &runner,
            &EvalHarness::new(),
        )
        .await
        .unwrap();
        assert!(token
            .validate(token.evidence.input_expires_at.unwrap())
            .is_err());
        let mut changed = token.clone();
        changed.golden.cases[0].input = "substituted input".into();
        assert!(changed.validate(Utc::now()).is_err());
        let mut changed = token.clone();
        changed.resolution.reviewed_instruction = Some("unreviewed text".into());
        assert!(changed.validate(Utc::now()).is_err());
        let mut changed = token;
        changed.evidence.baseline.last_version = u32::MAX;
        assert!(changed.version().is_err());
    }
}
