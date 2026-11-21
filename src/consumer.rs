//! Consumers - human-gated lesson deltas.
//!
//! What actually changes agent behaviour. Deliberately conservative: nothing
//! rewrites a prompt on its own.
//!
//! * There is no few-shot store. An earlier cleanup deleted it: memories
//!   (`crate::memory`) are the few-shot store, and nothing wrote or read the
//!   separate example table.
//! * A lesson delta is a *proposed* addition to a capability's instructions,
//!   generated from repeated dimension failures and queued for human approval.
//!   It is never auto-applied; `approve` is the explicit human gate. Applied
//!   deltas are versioned so a bad delta can be rolled back and re-scored
//!   against the golden set.
//!
//! Everything here is owned by Reede (standalone): the host application surface that
//! renders proposals for human decision lands elsewhere, but the contract and
//! the conservative gating live here.

use crate::error::ReedeError;
use crate::reducer::{Judgement, ReductionScope};
use crate::signal::Signal;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

/// Lifecycle of a lesson delta. Nothing reaches `Applied` without a human
/// `approve`; nothing reaches `RolledBack` except an explicit rollback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LessonStatus {
    Proposed,
    Approved,
    Applied,
    Rejected,
    RolledBack,
}

impl LessonStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            LessonStatus::Applied | LessonStatus::Rejected | LessonStatus::RolledBack
        )
    }
}

/// A proposed (later applied) instruction delta for a capability.
///
/// `proposed_instruction` is the human reviewable text. `trigger_count` is how
/// many repeated dimension failures produced it. `version` is assigned only on
/// apply, enabling versioned rollback. `approved_by` is the human/actor
/// identity that approved the delta -- it is the record that a human, not a
/// process, made the decision, and is set only by `approve_delta`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LessonDelta {
    pub id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub capability: String,
    pub dimension: String,
    pub proposed_instruction: String,
    pub trigger_count: u32,
    /// Original source signals captured when the worker proposed this delta.
    /// Historical and manually authored proposals may have no recorded sources.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_signal_ids: Vec<String>,
    pub status: LessonStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<DateTime<Utc>>,
    /// Actor identity recorded when this delta moved Proposed -> Approved.
    /// `None` until approved; a delta can never reach `Applied` without this
    /// being set, since `apply_delta` requires `Approved` status first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
}

impl LessonDelta {
    /// Prepare a new proposed delta. Status is always `Proposed`; applying to
    /// the agent's instructions requires an explicit `approve_delta` followed
    /// by `apply_delta` elsewhere.
    pub fn propose(
        tenant_id: impl Into<String>,
        agent_id: impl Into<String>,
        capability: impl Into<String>,
        dimension: impl Into<String>,
        proposed_instruction: impl Into<String>,
        trigger_count: u32,
    ) -> Self {
        Self {
            id: format!("dlt_{}", Uuid::new_v4()),
            tenant_id: tenant_id.into(),
            agent_id: agent_id.into(),
            capability: capability.into(),
            dimension: dimension.into(),
            proposed_instruction: proposed_instruction.into(),
            trigger_count,
            evidence_signal_ids: Vec::new(),
            status: LessonStatus::Proposed,
            version: None,
            created_at: Utc::now(),
            decided_at: None,
            approved_by: None,
        }
    }
}

/// An applied lesson delta, resolved into a concrete versioned instruction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppliedLesson {
    pub version: u32,
    pub delta_id: String,
    pub capability: String,
    pub dimension: String,
    pub instruction: String,
    pub applied_at: DateTime<Utc>,
}

/// Portable binding between an immutable proposal and its canonical signed review.
/// The runtime verifies signatures; Reede retains the exact record without importing it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LessonReviewEnrollment {
    pub original: LessonDelta,
    pub approval_key: String,
    pub canonical_record_id: String,
    pub proposal_context: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LessonReviewResolution {
    pub enrollment: LessonReviewEnrollment,
    pub reviewed_instruction: Option<String>,
    pub actor: String,
    pub decided_at: DateTime<Utc>,
    pub signed_record: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundLessonReview {
    pub enrollment: LessonReviewEnrollment,
    pub resolution: Option<LessonReviewResolution>,
}

fn review_error(reason: &str) -> ReedeError {
    ReedeError::SpecValidationFailed {
        reason: reason.into(),
    }
}

impl LessonReviewEnrollment {
    pub fn validate(&self) -> Result<(), ReedeError> {
        let d = &self.original;
        let key = format!("lesson:{}", d.id);
        let record_id = format!(
            "lesson-v1:{}:{}:{}:{}",
            d.tenant_id.len(),
            d.tenant_id,
            key.len(),
            key
        );
        if d.status != LessonStatus::Proposed
            || d.version.is_some()
            || d.decided_at.is_some()
            || d.approved_by.is_some()
            || d.evidence_signal_ids.iter().any(|id| id.trim().is_empty())
            || self.approval_key != key
            || self.canonical_record_id != record_id
            || [
                &d.id,
                &d.tenant_id,
                &d.agent_id,
                &d.capability,
                &d.dimension,
                &d.proposed_instruction,
            ]
            .iter()
            .any(|v| v.trim().is_empty())
        {
            return Err(review_error("invalid lesson review enrollment"));
        }
        let c = &self.proposal_context;
        for (field, expected) in [
            ("tenant_id", &d.tenant_id),
            ("delta_id", &d.id),
            ("agent_id", &d.agent_id),
            ("capability", &d.capability),
            ("dimension", &d.dimension),
            ("proposed_instruction", &d.proposed_instruction),
        ] {
            if c.get(field).and_then(serde_json::Value::as_str) != Some(expected.as_str()) {
                return Err(review_error("lesson review proposal scope changed"));
            }
        }
        let evidence = serde_json::to_value(&d.evidence_signal_ids)
            .map_err(|_| review_error("invalid original lesson evidence"))?;
        if c.get("evidence_signal_ids") != Some(&evidence) {
            return Err(review_error("lesson review original evidence changed"));
        }
        if c.get("review").is_some() {
            return Err(review_error("enrollment already carries a decision"));
        }
        Ok(())
    }

    pub fn reason(&self) -> String {
        format!("Review lesson {}", self.original.id)
    }
}

impl LessonReviewResolution {
    /// Structural defense at the portable boundary, in addition to runtime signature verification.
    pub fn resolved_delta(&self) -> Result<LessonDelta, ReedeError> {
        self.enrollment.validate()?;
        let r = &self.signed_record;
        let approved = self.reviewed_instruction.is_some();
        let decision = if approved { "approve" } else { "reject" };
        let mut proposal = r
            .get("context")
            .cloned()
            .ok_or_else(|| review_error("signed context missing"))?;
        let review = proposal
            .as_object_mut()
            .and_then(|c| c.remove("review"))
            .ok_or_else(|| review_error("signed review missing"))?;
        if self.actor.trim().is_empty()
            || self
                .reviewed_instruction
                .as_ref()
                .is_some_and(|v| v.trim().is_empty())
            || proposal != self.enrollment.proposal_context
            || r.get("thread_id").and_then(serde_json::Value::as_str)
                != Some(self.enrollment.approval_key.as_str())
            || r.get("gate_type").and_then(serde_json::Value::as_str) != Some("lesson_delta")
            || r.get("status").and_then(serde_json::Value::as_str)
                != Some(if approved { "approved" } else { "rejected" })
            || r.get("decision").and_then(serde_json::Value::as_str) != Some(decision)
            || r.get("decider").and_then(serde_json::Value::as_str) != Some(self.actor.as_str())
            || r.get("decided_at")
                != Some(
                    &serde_json::to_value(self.decided_at)
                        .map_err(|_| review_error("invalid decision time"))?,
                )
            || r.get("created_at")
                != Some(
                    &serde_json::to_value(self.enrollment.original.created_at)
                        .map_err(|_| review_error("invalid proposal time"))?,
                )
            || r.get("reason").and_then(serde_json::Value::as_str)
                != Some(self.enrollment.reason().as_str())
            || !r.get("receipt").is_some_and(serde_json::Value::is_object)
            || review.get("decision").and_then(serde_json::Value::as_str) != Some(decision)
            || review
                .get("reviewed_instruction")
                .and_then(serde_json::Value::as_str)
                != self.reviewed_instruction.as_deref()
        {
            return Err(review_error(
                "signed lesson winner does not match enrollment",
            ));
        }
        let mut delta = self.enrollment.original.clone();
        delta.status = if approved {
            LessonStatus::Approved
        } else {
            LessonStatus::Rejected
        };
        if let Some(instruction) = &self.reviewed_instruction {
            delta.proposed_instruction = instruction.clone();
            delta.approved_by = Some(self.actor.clone());
        }
        delta.decided_at = Some(self.decided_at);
        Ok(delta)
    }
}

/// The conservative consumer store: lesson deltas and their applied versions.
#[async_trait]
pub trait ConsumerStore: Send + Sync {
    /// Opt-in signed review protocol. Custom stores must implement all three operations.
    async fn enroll_review(
        &self,
        _enrollment: &LessonReviewEnrollment,
    ) -> Result<BoundLessonReview, ReedeError> {
        Err(review_error("signed lesson review enrollment unsupported"))
    }
    async fn load_review(
        &self,
        _tenant_id: &str,
        _delta_id: &str,
    ) -> Result<Option<BoundLessonReview>, ReedeError> {
        Err(review_error("signed lesson review lookup unsupported"))
    }
    async fn resolve_review(
        &self,
        _resolution: &LessonReviewResolution,
    ) -> Result<BoundLessonReview, ReedeError> {
        Err(review_error("signed lesson review resolution unsupported"))
    }

    // Lessons ----------------------------------------------------------------
    /// Insert an original proposal. An identical unenrolled retry is a no-op;
    /// changed content or an enrolled proposal requires the signed review path.
    async fn propose_delta(&self, delta: &LessonDelta) -> Result<(), ReedeError>;

    /// Deltas awaiting human decision (`Proposed`/`Approved`), oldest first.
    async fn pending_deltas(
        &self,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
    ) -> Result<Vec<LessonDelta>, ReedeError>;

    /// Applied deltas by capability, oldest version first.
    async fn applied_deltas(
        &self,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
    ) -> Result<Vec<AppliedLesson>, ReedeError>;

    /// The human approval gate, step one: `Proposed -> Approved`. Records
    /// `approved_by` as the deciding actor. Does not apply anything -- an
    /// approved delta still requires a separate `apply_delta` call.
    async fn approve_delta(
        &self,
        tenant_id: &str,
        delta_id: &str,
        approved_by: &str,
    ) -> Result<(), ReedeError>;

    /// The human approval gate, step two: `Approved -> Applied`. Assigns the
    /// next monotonic version and records it as an `AppliedLesson`. Rejects
    /// any delta not currently `Approved` -- there is no direct
    /// `Proposed -> Applied` path.
    async fn apply_delta(&self, tenant_id: &str, delta_id: &str) -> Result<u32, ReedeError>;

    async fn reject_delta(&self, tenant_id: &str, delta_id: &str) -> Result<(), ReedeError>;

    /// Versioned rollback: voids an applied version so a bad delta can be
    /// re-scored against the golden set.
    async fn rollback_applied(&self, agent_id: &str, version: u32) -> Result<(), ReedeError>;
}

/// In-memory consumer store.
pub struct InMemoryConsumerStore {
    // Outer lock serializes enrollment/resolution with every legacy mutation.
    reviews: Mutex<HashMap<(String, String), BoundLessonReview>>,
    deltas: Mutex<Vec<LessonDelta>>,
    applied: Mutex<Vec<AppliedEntry>>,
}

#[derive(Debug, Clone, PartialEq)]
struct AppliedEntry {
    tenant_id: String,
    agent_id: String,
    lesson: AppliedLesson,
}

impl InMemoryConsumerStore {
    pub fn new() -> Self {
        Self {
            reviews: Mutex::new(HashMap::new()),
            deltas: Mutex::new(Vec::new()),
            applied: Mutex::new(Vec::new()),
        }
    }
}

impl Default for InMemoryConsumerStore {
    fn default() -> Self {
        Self::new()
    }
}

// Small index helpers to keep trait impl lean.
fn delta_matches(d: &LessonDelta, t: &str, a: &str, c: &str) -> bool {
    d.tenant_id == t && d.agent_id == a && d.capability == c
}

#[async_trait]
impl ConsumerStore for InMemoryConsumerStore {
    async fn enroll_review(
        &self,
        enrollment: &LessonReviewEnrollment,
    ) -> Result<BoundLessonReview, ReedeError> {
        enrollment.validate()?;
        let key = (
            enrollment.original.tenant_id.clone(),
            enrollment.original.id.clone(),
        );
        let mut reviews = self.reviews.lock().unwrap();
        if let Some(existing) = reviews.get(&key) {
            if existing.enrollment != *enrollment {
                return Err(review_error("lesson enrollment changed"));
            }
            let expected = match &existing.resolution {
                Some(resolution) => resolution.resolved_delta()?,
                None => existing.enrollment.original.clone(),
            };
            let deltas = self.deltas.lock().unwrap();
            let mut matching = deltas
                .iter()
                .filter(|d| d.tenant_id == key.0 && d.id == key.1);
            if matching.next() != Some(&expected) || matching.next().is_some() {
                return Err(review_error("enrolled lesson changed"));
            }
            return Ok(existing.clone());
        }
        let deltas = self.deltas.lock().unwrap();
        let mut matching = deltas
            .iter()
            .filter(|d| d.tenant_id == key.0 && d.id == key.1);
        if matching.next() != Some(&enrollment.original) || matching.next().is_some() {
            return Err(review_error(
                "enrollment requires one exact original proposal",
            ));
        }
        let review = BoundLessonReview {
            enrollment: enrollment.clone(),
            resolution: None,
        };
        reviews.insert(key, review.clone());
        Ok(review)
    }

    async fn load_review(
        &self,
        tenant_id: &str,
        delta_id: &str,
    ) -> Result<Option<BoundLessonReview>, ReedeError> {
        let reviews = self.reviews.lock().unwrap();
        let Some(review) = reviews.get(&(tenant_id.into(), delta_id.into())) else {
            return Ok(None);
        };
        review.enrollment.validate()?;
        let expected = match &review.resolution {
            Some(resolution) => {
                if resolution.enrollment != review.enrollment {
                    return Err(review_error("lesson resolution proposal changed"));
                }
                resolution.resolved_delta()?
            }
            None => review.enrollment.original.clone(),
        };
        let deltas = self.deltas.lock().unwrap();
        let mut matching = deltas
            .iter()
            .filter(|d| d.tenant_id == tenant_id && d.id == delta_id);
        if matching.next() != Some(&expected) || matching.next().is_some() {
            return Err(review_error("enrolled lesson changed"));
        }
        Ok(Some(review.clone()))
    }

    async fn resolve_review(
        &self,
        resolution: &LessonReviewResolution,
    ) -> Result<BoundLessonReview, ReedeError> {
        let delta = resolution.resolved_delta()?;
        let mut reviews = self.reviews.lock().unwrap();
        let review = reviews
            .get_mut(&(delta.tenant_id.clone(), delta.id.clone()))
            .ok_or_else(|| review_error("lesson review not enrolled"))?;
        if review.enrollment != resolution.enrollment {
            return Err(review_error("lesson enrollment changed"));
        }
        let mut deltas = self.deltas.lock().unwrap();
        if deltas
            .iter()
            .filter(|d| d.tenant_id == delta.tenant_id && d.id == delta.id)
            .count()
            != 1
        {
            return Err(review_error("ambiguous enrolled lesson"));
        }
        let current = deltas
            .iter_mut()
            .find(|d| d.tenant_id == delta.tenant_id && d.id == delta.id)
            .ok_or_else(|| review_error("enrolled lesson missing"))?;
        if let Some(winner) = &review.resolution {
            if winner != resolution || current != &delta {
                return Err(review_error("lesson winner changed"));
            }
        } else {
            if current != &review.enrollment.original {
                return Err(review_error("enrolled proposal changed"));
            }
            *current = delta;
            review.resolution = Some(resolution.clone());
        }
        Ok(review.clone())
    }

    async fn propose_delta(&self, delta: &LessonDelta) -> Result<(), ReedeError> {
        let reviews = self.reviews.lock().unwrap();
        if reviews.contains_key(&(delta.tenant_id.clone(), delta.id.clone())) {
            return Err(review_error("enrolled lesson requires signed review"));
        }
        let mut deltas = self.deltas.lock().unwrap();
        if let Some(existing) = deltas
            .iter()
            .find(|d| d.tenant_id == delta.tenant_id && d.id == delta.id)
        {
            if existing != delta {
                return Err(ReedeError::SpecValidationFailed {
                    reason: "proposal already exists with different content".into(),
                });
            }
            return Ok(());
        }
        deltas.push(delta.clone());
        Ok(())
    }

    async fn pending_deltas(
        &self,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
    ) -> Result<Vec<LessonDelta>, ReedeError> {
        let guards = self.deltas.lock().unwrap();
        let mut out: Vec<LessonDelta> = guards
            .iter()
            .filter(|d| {
                !d.status.is_terminal() && delta_matches(d, tenant_id, agent_id, capability)
            })
            .cloned()
            .collect();
        out.sort_by_key(|d| d.created_at);
        Ok(out)
    }

    async fn applied_deltas(
        &self,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
    ) -> Result<Vec<AppliedLesson>, ReedeError> {
        let gu = self.applied.lock().unwrap();
        let mut out: Vec<AppliedLesson> = gu
            .iter()
            .filter(|a| {
                a.tenant_id == tenant_id
                    && a.agent_id == agent_id
                    && a.lesson.capability == capability
            })
            .map(|a| a.lesson.clone())
            .collect();
        out.sort_by_key(|a| a.version);
        Ok(out)
    }

    async fn approve_delta(
        &self,
        tenant_id: &str,
        delta_id: &str,
        approved_by: &str,
    ) -> Result<(), ReedeError> {
        let reviews = self.reviews.lock().unwrap();
        if reviews.contains_key(&(tenant_id.into(), delta_id.into())) {
            return Err(review_error("enrolled lesson requires signed review"));
        }
        let mut deltas = self.deltas.lock().unwrap();
        let Some(delta) = deltas
            .iter_mut()
            .find(|d| d.id == delta_id && d.tenant_id == tenant_id)
        else {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!("lesson delta '{delta_id}' not found"),
            });
        };
        if delta.status != LessonStatus::Proposed {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!(
                    "lesson delta '{delta_id}' must be Proposed to approve, is {:?}",
                    delta.status
                ),
            });
        }
        delta.status = LessonStatus::Approved;
        delta.approved_by = Some(approved_by.to_string());
        delta.decided_at = Some(Utc::now());
        Ok(())
    }

    async fn apply_delta(&self, tenant_id: &str, delta_id: &str) -> Result<u32, ReedeError> {
        let reviews = self.reviews.lock().unwrap();
        if reviews.contains_key(&(tenant_id.into(), delta_id.into())) {
            return Err(review_error("enrolled lesson requires signed review"));
        }
        // Find and flip the delta. Requires Approved -- there is no direct
        // Proposed -> Applied path, so a delta can never be applied without
        // having recorded a human approver first.
        let mut applied = self.applied.lock().unwrap();
        let version = {
            let mut deltas = self.deltas.lock().unwrap();
            let Some(delta) = deltas
                .iter_mut()
                .find(|d| d.id == delta_id && d.tenant_id == tenant_id)
            else {
                return Err(ReedeError::SpecValidationFailed {
                    reason: format!("lesson delta '{delta_id}' not found"),
                });
            };
            if delta.status != LessonStatus::Approved {
                return Err(ReedeError::SpecValidationFailed {
                    reason: format!(
                        "lesson delta '{delta_id}' must be Approved to apply, is {:?}",
                        delta.status
                    ),
                });
            }
            // Monotonic version per tenant, agent and capability, including rolled-back entries.
            let next = applied
                .iter()
                .filter(|a| {
                    a.tenant_id == delta.tenant_id
                        && a.agent_id == delta.agent_id
                        && a.lesson.capability == delta.capability
                })
                .map(|a| a.lesson.version)
                .max()
                .unwrap_or(0)
                + 1;
            let now = Utc::now();
            delta.status = LessonStatus::Applied;
            delta.version = Some(next);
            applied.push(AppliedEntry {
                tenant_id: delta.tenant_id.clone(),
                agent_id: delta.agent_id.clone(),
                lesson: AppliedLesson {
                    version: next,
                    delta_id: delta.id.clone(),
                    capability: delta.capability.clone(),
                    dimension: delta.dimension.clone(),
                    instruction: delta.proposed_instruction.clone(),
                    applied_at: now,
                },
            });
            next
        };
        Ok(version)
    }

    async fn reject_delta(&self, tenant_id: &str, delta_id: &str) -> Result<(), ReedeError> {
        let reviews = self.reviews.lock().unwrap();
        if reviews.contains_key(&(tenant_id.into(), delta_id.into())) {
            return Err(review_error("enrolled lesson requires signed review"));
        }
        let mut deltas = self.deltas.lock().unwrap();
        let Some(delta) = deltas
            .iter_mut()
            .find(|d| d.id == delta_id && d.tenant_id == tenant_id)
        else {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!("lesson delta '{delta_id}' not found"),
            });
        };
        delta.status = LessonStatus::Rejected;
        delta.decided_at = Some(Utc::now());
        Ok(())
    }

    async fn rollback_applied(&self, agent_id: &str, version: u32) -> Result<(), ReedeError> {
        let reviews = self.reviews.lock().unwrap();
        // This legacy API has no tenant or capability: only one exact owner is safe.
        // Hold the ownership lock through the delta update, in apply_delta's lock order.
        let applied = self.applied.lock().unwrap();
        let mut matches = applied
            .iter()
            .filter(|a| a.agent_id == agent_id && a.lesson.version == version);
        let Some(target) = matches.next() else {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!(
                    "no applied lesson version {version} for agent '{agent_id}' to roll back"
                ),
            });
        };
        if matches.next().is_some() {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!("applied lesson version {version} for agent '{agent_id}' is ambiguous without tenant and capability"),
            });
        }
        if reviews.contains_key(&(target.tenant_id.clone(), target.lesson.delta_id.clone())) {
            return Err(review_error("enrolled lesson cannot use legacy rollback"));
        }
        let mut deltas = self.deltas.lock().unwrap();
        let Some(delta) = deltas.iter_mut().find(|d| {
            d.tenant_id == target.tenant_id
                && d.agent_id == target.agent_id
                && d.id == target.lesson.delta_id
                && d.capability == target.lesson.capability
                && d.version == Some(version)
        }) else {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!("owning delta for applied lesson version {version} not found"),
            });
        };
        delta.status = LessonStatus::RolledBack;
        delta.decided_at = Some(Utc::now());
        Ok(())
    }
}

/// Evidence of a dimension failure (a negative judgement or a failing signal).
#[derive(Debug, Clone, PartialEq)]
pub struct FailureEvidence {
    pub dimension: String,
    /// A representative failing passage/note, folded into the proposed lesson.
    pub failing_text: String,
    /// When the failure was observed.
    pub observed_at: DateTime<Utc>,
}

/// Longest passage of a signal's text carried into a `FailureEvidence`, in characters.
const EVIDENCE_TEXT_MAX_CHARS: usize = 280;

/// Build the proposer's input from the reducer's output: one `FailureEvidence` per
/// weak instance judgement, with the text taken from the signals that produced it.
///
/// This is the missing hop between the reducer and [`LessonProposer`]: the reducer
/// writes judgements, the proposer reads `FailureEvidence`, and until now nothing
/// built the second from the first.
///
/// * Only **instance** judgements with a negative value count. A cohort judgement
///   is computed over the same batch the instance judgements came from, so counting
///   both would report one failed output twice.
/// * `signals` is the pool to look the judgement's `source_signal_ids` up in; an id
///   not in the pool is skipped, never invented.
/// * The text is, in order: what a human changed (`raw.before` -> `raw.after`, which
///   is what an edit signal carries), else the judgement's own note (a decision or a
///   scout outcome has no text, only the rule that fired), else the dimension name.
///   It is deterministic: no model is involved.
/// * The text comes from content a third party may have written. It lands in a
///   proposed instruction a human reads and rewrites at the gate, and is cut to
///   [`EVIDENCE_TEXT_MAX_CHARS`] characters.
pub fn failure_evidence(judgements: &[Judgement], signals: &[Signal]) -> Vec<FailureEvidence> {
    judgements
        .iter()
        .filter(|j| j.scope == ReductionScope::Instance && j.is_negative())
        .map(|j| {
            let sources: Vec<&Signal> = j
                .source_signal_ids
                .iter()
                .filter_map(|id| signals.iter().find(|s| &s.id == id))
                .collect();
            let text = sources
                .iter()
                .find_map(|s| edit_text(s))
                .or_else(|| j.note.clone())
                .unwrap_or_else(|| j.dimension.clone());
            let observed_at = sources
                .iter()
                .map(|s| s.observed_at)
                .min()
                .unwrap_or(j.created_at);
            FailureEvidence {
                dimension: j.dimension.clone(),
                failing_text: truncate_chars(&text, EVIDENCE_TEXT_MAX_CHARS),
                observed_at,
            }
        })
        .collect()
}

/// `before -> after` for a signal that carries both, or whichever of the two it has.
fn edit_text(signal: &Signal) -> Option<String> {
    let field = |key: &str| {
        signal
            .raw
            .get(key)
            .and_then(|v| v.as_str())
            .filter(|v| !v.trim().is_empty())
    };
    match (field("before"), field("after")) {
        (Some(before), Some(after)) => Some(format!("changed \"{before}\" to \"{after}\"")),
        (Some(only), None) | (None, Some(only)) => Some(only.to_string()),
        (None, None) => None,
    }
}

fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let cut: String = text.chars().take(max).collect();
    format!("{cut}...")
}

/// Turns repeated dimension failures into one reviewable proposed lesson delta.
///
/// Conservative: no delta is applied here, only proposed. `threshold` repeated
/// failures on a dimension must accumulate before a single delta is proposed,
/// and a proposal is made at most once per dimension while one is still pending
/// or already applied.
pub struct LessonProposer {
    threshold: u32,
}

impl LessonProposer {
    pub fn new(threshold: u32) -> Self {
        Self { threshold }
    }

    /// Consider a batch of failures and return zero or more proposed deltas
    /// (one per dimension that crossed the threshold and has no open/applied
    /// proposal already).
    pub fn consider(
        &self,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
        failures: &[FailureEvidence],
        existing: &[LessonDelta],
    ) -> Vec<LessonDelta> {
        // Group failures by dimension.
        let mut by_dim: HashMap<&str, Vec<&FailureEvidence>> = HashMap::new();
        for f in failures {
            by_dim.entry(f.dimension.as_str()).or_default().push(f);
        }

        let mut proposed = Vec::new();
        for (dim, evs) in by_dim {
            if (evs.len() as u32) < self.threshold {
                continue;
            }
            // Do not re-propose a dimension that already has an open (Proposed/Approved)
            // or applied delta. Only a rejected or rolled-back delta frees the
            // dimension for a new proposal.
            let already_handled = existing.iter().any(|d| {
                d.capability == capability
                    && d.dimension == dim
                    && matches!(
                        d.status,
                        LessonStatus::Proposed | LessonStatus::Approved | LessonStatus::Applied
                    )
            });
            if already_handled {
                continue;
            }

            // Synthesize one reviewable instruction from the failing passages.
            let mut texts: Vec<&str> = evs.iter().map(|e| e.failing_text.as_str()).collect();
            texts.dedup();
            let detail = if texts.is_empty() {
                String::new()
            } else {
                format!(" Evidence: {}", texts.first().copied().unwrap_or_default())
            };
            let count = evs.len();
            let instruction = format!(
                "Improve {dim} in this capability. {count} recent outputs failed this dimension.{detail}"
            );
            proposed.push(LessonDelta::propose(
                tenant_id,
                agent_id,
                capability,
                dim,
                instruction,
                evs.len() as u32,
            ));
        }
        proposed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_proposals_decode_without_fabricated_evidence() {
        let delta = LessonDelta::propose("tenant", "agent", "copy", "hook", "Improve.", 1);
        let legacy = serde_json::to_value(&delta).unwrap();
        assert!(legacy.get("evidence_signal_ids").is_none());
        let decoded: LessonDelta = serde_json::from_value(legacy).unwrap();
        assert!(decoded.evidence_signal_ids.is_empty());
        let mut captured = decoded;
        captured.evidence_signal_ids = vec!["sig_original".into()];
        assert_eq!(
            serde_json::from_str::<LessonDelta>(&serde_json::to_string(&captured).unwrap())
                .unwrap(),
            captured
        );
    }

    #[tokio::test]
    async fn proposal_retries_preserve_original_evidence_and_decisions() {
        let store = InMemoryConsumerStore::new();
        let mut original = LessonDelta::propose("tenant", "agent", "copy", "hook", "Improve.", 1);
        original.evidence_signal_ids = vec!["sig_original".into()];
        store.propose_delta(&original).await.unwrap();
        store.propose_delta(&original).await.unwrap();
        let mut changed = original.clone();
        changed.evidence_signal_ids = vec!["sig_newer".into()];
        assert!(store.propose_delta(&changed).await.is_err());
        assert_eq!(
            store
                .pending_deltas("tenant", "agent", "copy")
                .await
                .unwrap(),
            vec![original.clone()]
        );
        store
            .approve_delta("tenant", &original.id, "human")
            .await
            .unwrap();
        assert!(store.propose_delta(&original).await.is_err());
        let stored = store
            .pending_deltas("tenant", "agent", "copy")
            .await
            .unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].evidence_signal_ids, original.evidence_signal_ids);
        assert_eq!(stored[0].approved_by.as_deref(), Some("human"));
    }

    fn evidence(dim: &str, text: &str) -> FailureEvidence {
        FailureEvidence {
            dimension: dim.to_string(),
            failing_text: text.to_string(),
            observed_at: Utc::now(),
        }
    }

    fn enrollment(original: &LessonDelta) -> LessonReviewEnrollment {
        let key = format!("lesson:{}", original.id);
        LessonReviewEnrollment {
            original: original.clone(),
            approval_key: key.clone(),
            canonical_record_id: format!(
                "lesson-v1:{}:{}:{}:{}",
                original.tenant_id.len(),
                original.tenant_id,
                key.len(),
                key
            ),
            proposal_context: serde_json::json!({"lesson_review": 1, "tenant_id": original.tenant_id, "delta_id": original.id,
                "agent_id": original.agent_id, "capability": original.capability, "dimension": original.dimension,
                "proposed_instruction": original.proposed_instruction, "evidence_signal_ids": original.evidence_signal_ids, "golden_case_ids": ["case"]}),
        }
    }

    #[tokio::test]
    async fn enrolled_memory_refuses_stale_original_and_legacy_ledger_rollback() {
        let store = InMemoryConsumerStore::new();
        let d = LessonDelta::propose(
            "tenant",
            "agent",
            "capability",
            "dimension",
            "Original instruction",
            3,
        );
        store.propose_delta(&d).await.unwrap();
        let e = enrollment(&d);
        let first = store.enroll_review(&e).await.unwrap();
        assert_eq!(store.enroll_review(&e).await.unwrap(), first);
        let mut changed = e.clone();
        changed.original.trigger_count += 1;
        assert!(store.enroll_review(&changed).await.is_err());
        // A corrupt legacy ledger link must not grant rollback authority over an enrolled row.
        store.applied.lock().unwrap().push(AppliedEntry {
            tenant_id: d.tenant_id.clone(),
            agent_id: d.agent_id.clone(),
            lesson: AppliedLesson {
                version: 1,
                delta_id: d.id.clone(),
                capability: d.capability.clone(),
                dimension: d.dimension.clone(),
                instruction: "corrupt legacy ledger".into(),
                applied_at: Utc::now(),
            },
        });
        let before_deltas = store.deltas.lock().unwrap().clone();
        let before_applied = store.applied.lock().unwrap().clone();
        assert!(store
            .rollback_applied(&d.agent_id, 1)
            .await
            .unwrap_err()
            .to_string()
            .contains("enrolled"));
        assert_eq!(*store.deltas.lock().unwrap(), before_deltas);
        assert_eq!(*store.applied.lock().unwrap(), before_applied);
        assert_eq!(
            store.load_review("tenant", &d.id).await.unwrap(),
            Some(first)
        );
        store.deltas.lock().unwrap()[0].trigger_count += 1;
        assert!(store.load_review("tenant", &d.id).await.is_err());
    }

    struct LegacyConsumer;
    #[async_trait]
    impl ConsumerStore for LegacyConsumer {
        async fn propose_delta(&self, _: &LessonDelta) -> Result<(), ReedeError> {
            panic!("unused legacy call")
        }
        async fn pending_deltas(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<Vec<LessonDelta>, ReedeError> {
            panic!("unused legacy call")
        }
        async fn applied_deltas(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<Vec<AppliedLesson>, ReedeError> {
            panic!("unused legacy call")
        }
        async fn approve_delta(&self, _: &str, _: &str, _: &str) -> Result<(), ReedeError> {
            panic!("unused legacy call")
        }
        async fn apply_delta(&self, _: &str, _: &str) -> Result<u32, ReedeError> {
            panic!("unused legacy call")
        }
        async fn reject_delta(&self, _: &str, _: &str) -> Result<(), ReedeError> {
            panic!("unused legacy call")
        }
        async fn rollback_applied(&self, _: &str, _: u32) -> Result<(), ReedeError> {
            panic!("unused legacy call")
        }
    }
    #[tokio::test]
    async fn custom_consumer_signed_review_defaults_fail_closed() {
        let store = LegacyConsumer;
        let d = LessonDelta::propose(
            "tenant",
            "agent",
            "capability",
            "dimension",
            "Instruction",
            3,
        );
        let e = enrollment(&d);
        assert!(store
            .enroll_review(&e)
            .await
            .unwrap_err()
            .to_string()
            .contains("unsupported"));
        assert!(store
            .load_review("tenant", &d.id)
            .await
            .unwrap_err()
            .to_string()
            .contains("unsupported"));
        let resolution = LessonReviewResolution {
            enrollment: e,
            reviewed_instruction: None,
            actor: "actor".into(),
            decided_at: Utc::now(),
            signed_record: serde_json::Value::Null,
        };
        assert!(store
            .resolve_review(&resolution)
            .await
            .unwrap_err()
            .to_string()
            .contains("unsupported"));
    }

    #[tokio::test]
    async fn test_three_failures_produce_one_proposed_delta_not_prompt_mutation() {
        let store = InMemoryConsumerStore::new();
        let proposer = LessonProposer::new(3);

        // Three failures on 'hook', none existing.
        let failures = vec![
            evidence("hook", "weak opening"),
            evidence("hook", "weak opening"),
            evidence("hook", "weak opening"),
        ];
        let proposed = proposer.consider("tenant-1", "agent-1", "copy", &failures, &[]);
        assert_eq!(proposed.len(), 1, "three failures -> exactly one proposal");
        assert_eq!(proposed[0].dimension, "hook");
        assert_eq!(proposed[0].status, LessonStatus::Proposed);
        assert_eq!(proposed[0].trigger_count, 3);
        assert!(proposed[0].proposed_instruction.contains("hook"));

        // Persist it as proposed only - nothing auto-applied.
        store.propose_delta(&proposed[0]).await.unwrap();
        let pending = store
            .pending_deltas("tenant-1", "agent-1", "copy")
            .await
            .unwrap();
        assert_eq!(pending.len(), 1);
        let applied = store
            .applied_deltas("tenant-1", "agent-1", "copy")
            .await
            .unwrap();
        assert!(applied.is_empty(), "no silent application");
    }

    #[tokio::test]
    async fn test_below_threshold_produces_no_proposal() {
        let proposer = LessonProposer::new(3);
        let proposed = proposer.consider(
            "tenant-1",
            "agent-1",
            "copy",
            &[evidence("tone", "a bit off")], // only one failure
            &[],
        );
        assert!(proposed.is_empty());
    }

    #[tokio::test]
    async fn test_already_handled_dimension_is_not_reproposed() {
        let store = InMemoryConsumerStore::new();
        let proposer = LessonProposer::new(3);
        let failures = vec![
            evidence("hook", "weak"),
            evidence("hook", "weak"),
            evidence("hook", "weak"),
        ];
        // Propose and hold pending.
        let proposed = proposer.consider("tenant-1", "agent-1", "copy", &failures, &[]);
        store.propose_delta(&proposed[0]).await.unwrap();

        let existing = store
            .pending_deltas("tenant-1", "agent-1", "copy")
            .await
            .unwrap();
        let again = proposer.consider("tenant-1", "agent-1", "copy", &failures, &existing);
        assert!(
            again.is_empty(),
            "a pending proposal suppresses a new one on the same dimension"
        );
    }

    #[tokio::test]
    async fn test_approve_then_apply_assigns_versioned_applied_lesson() {
        let store = InMemoryConsumerStore::new();
        let delta = LessonDelta::propose("tenant-1", "agent-1", "copy", "hook", "Improve hook.", 3);
        store.propose_delta(&delta).await.unwrap();

        store
            .approve_delta("tenant-1", &delta.id, "owner@example.com")
            .await
            .unwrap();
        {
            let deltas = store.deltas.lock().unwrap();
            let d = deltas.iter().find(|x| x.id == delta.id).unwrap();
            assert_eq!(d.status, LessonStatus::Approved);
            assert_eq!(d.approved_by.as_deref(), Some("owner@example.com"));
        }

        let v = store.apply_delta("tenant-1", &delta.id).await.unwrap();
        assert_eq!(v, 1, "first applied delta is v1");

        let applied = store
            .applied_deltas("tenant-1", "agent-1", "copy")
            .await
            .unwrap();
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].version, 1);
        assert_eq!(applied[0].dimension, "hook");

        // Second approve+apply on another dimension -> v2.
        let d2 = LessonDelta::propose("tenant-1", "agent-1", "copy", "tone", "Improve tone.", 2);
        store.propose_delta(&d2).await.unwrap();
        store
            .approve_delta("tenant-1", &d2.id, "owner@example.com")
            .await
            .unwrap();
        let v2 = store.apply_delta("tenant-1", &d2.id).await.unwrap();
        assert_eq!(v2, 2);
    }

    #[tokio::test]
    async fn test_apply_without_approval_is_rejected() {
        let store = InMemoryConsumerStore::new();
        let delta = LessonDelta::propose("tenant-1", "agent-1", "copy", "hook", "Improve hook.", 3);
        store.propose_delta(&delta).await.unwrap();

        // Proposed -> Applied directly, skipping Approved, must be rejected.
        let err = store.apply_delta("tenant-1", &delta.id).await.unwrap_err();
        assert!(matches!(err, ReedeError::SpecValidationFailed { .. }));

        let deltas = store.deltas.lock().unwrap();
        let d = deltas.iter().find(|x| x.id == delta.id).unwrap();
        assert_eq!(
            d.status,
            LessonStatus::Proposed,
            "rejected apply must not change status"
        );
        assert!(d.approved_by.is_none());
    }

    #[tokio::test]
    async fn test_double_approve_is_rejected() {
        let store = InMemoryConsumerStore::new();
        let delta = LessonDelta::propose("tenant-1", "agent-1", "copy", "hook", "Improve hook.", 3);
        store.propose_delta(&delta).await.unwrap();
        store
            .approve_delta("tenant-1", &delta.id, "owner@example.com")
            .await
            .unwrap();

        let err = store
            .approve_delta("tenant-1", &delta.id, "other@example.com")
            .await
            .unwrap_err();
        assert!(matches!(err, ReedeError::SpecValidationFailed { .. }));
    }

    #[tokio::test]
    async fn test_rollback_voids_applied_version() {
        let store = InMemoryConsumerStore::new();
        let delta = LessonDelta::propose("tenant-1", "agent-1", "copy", "hook", "Improve hook.", 3);
        store.propose_delta(&delta).await.unwrap();
        store
            .approve_delta("tenant-1", &delta.id, "owner@example.com")
            .await
            .unwrap();
        store.apply_delta("tenant-1", &delta.id).await.unwrap();

        store.rollback_applied("agent-1", 1).await.unwrap();

        // The applied ledger retains the record (audit) but the owning delta is
        // rolled back and its status reflects it.
        let deltas = store.deltas.lock().unwrap();
        let d = deltas.iter().find(|x| x.id == delta.id).unwrap();
        assert_eq!(d.status, LessonStatus::RolledBack);
    }

    async fn apply_lesson(
        store: &InMemoryConsumerStore,
        tenant: &str,
        agent: &str,
        capability: &str,
        id: &str,
    ) -> u32 {
        let mut delta = LessonDelta::propose(
            tenant,
            agent,
            capability,
            "accuracy",
            format!("{tenant}/{agent}/{capability}/{id}"),
            3,
        );
        delta.id = id.to_string();
        store.propose_delta(&delta).await.unwrap();
        store.approve_delta(tenant, id, "operator").await.unwrap();
        store.apply_delta(tenant, id).await.unwrap()
    }

    async fn refused_rollback(store: &InMemoryConsumerStore, agent: &str, version: u32) -> String {
        let before_applied = store.applied.lock().unwrap().clone();
        let before_deltas = store.deltas.lock().unwrap().clone();
        let error = store.rollback_applied(agent, version).await.unwrap_err();
        assert_eq!(*store.applied.lock().unwrap(), before_applied);
        assert_eq!(*store.deltas.lock().unwrap(), before_deltas);
        let ReedeError::SpecValidationFailed { reason } = error else {
            panic!("unexpected rollback error: {error:?}");
        };
        reason
    }

    #[tokio::test]
    async fn applied_lessons_and_versions_are_scoped_to_tenant_agent_and_capability() {
        let store = InMemoryConsumerStore::new();
        let scopes = [
            ("tenant-a", "agent", "copy", "shared-id"),
            ("tenant-b", "agent", "copy", "shared-id"),
            ("tenant-a", "other-agent", "copy", "other-agent-id"),
            ("tenant-a", "agent", "review", "review-id"),
        ];
        for (tenant, agent, capability, id) in scopes {
            assert_eq!(apply_lesson(&store, tenant, agent, capability, id).await, 1);
        }
        for (tenant, agent, capability, id) in scopes {
            let rows = store
                .applied_deltas(tenant, agent, capability)
                .await
                .unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].delta_id, id);
            assert_eq!(rows[0].version, 1);
            assert_eq!(
                rows[0].instruction,
                format!("{tenant}/{agent}/{capability}/{id}")
            );
        }
        for (tenant, agent, capability) in [
            ("missing-tenant", "agent", "copy"),
            ("tenant-a", "missing-agent", "copy"),
            ("tenant-a", "agent", "missing-capability"),
        ] {
            assert!(store
                .applied_deltas(tenant, agent, capability)
                .await
                .unwrap()
                .is_empty());
        }
        assert_eq!(
            apply_lesson(&store, "tenant-a", "agent", "copy", "second").await,
            2
        );
        let rows = store
            .applied_deltas("tenant-a", "agent", "copy")
            .await
            .unwrap();
        assert_eq!(
            rows.iter().map(|r| r.version).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(
            store
                .applied_deltas("tenant-b", "agent", "copy")
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn rollback_refuses_foreign_agents_and_unknown_versions_without_mutation() {
        let store = InMemoryConsumerStore::new();
        apply_lesson(&store, "tenant-a", "owner", "copy", "owned").await;
        apply_lesson(&store, "tenant-b", "other-agent", "copy", "other").await;
        assert!(refused_rollback(&store, "foreign-agent", 1)
            .await
            .contains("no applied lesson"));
        assert!(refused_rollback(&store, "owner", 99)
            .await
            .contains("no applied lesson"));
    }

    #[tokio::test]
    async fn rollback_refuses_ambiguous_tenants_or_capabilities_without_mutation() {
        for scopes in [
            [("tenant-a", "copy"), ("tenant-b", "copy")],
            [("tenant-a", "copy"), ("tenant-a", "review")],
        ] {
            let store = InMemoryConsumerStore::new();
            for (index, (tenant, capability)) in scopes.into_iter().enumerate() {
                assert_eq!(
                    apply_lesson(
                        &store,
                        tenant,
                        "agent",
                        capability,
                        &format!("delta-{index}")
                    )
                    .await,
                    1
                );
            }
            assert!(refused_rollback(&store, "agent", 1)
                .await
                .contains("ambiguous"));
        }
    }

    #[tokio::test]
    async fn rollback_changes_only_the_unique_owner_and_keeps_the_applied_ledger() {
        let store = InMemoryConsumerStore::new();
        for (tenant, agent, capability, id, version) in [
            ("tenant-a", "owner", "copy", "first", 1),
            ("tenant-a", "owner", "copy", "shared-id", 2),
            ("tenant-b", "other-agent", "copy", "shared-id", 1),
            ("tenant-a", "owner", "review", "review-id", 1),
        ] {
            assert_eq!(
                apply_lesson(&store, tenant, agent, capability, id).await,
                version
            );
        }
        let before_applied = store.applied.lock().unwrap().clone();
        store.rollback_applied("owner", 2).await.unwrap();
        assert_eq!(
            *store.applied.lock().unwrap(),
            before_applied,
            "immutable audit ledger"
        );
        {
            let deltas = store.deltas.lock().unwrap();
            for delta in deltas.iter() {
                let expected = if delta.tenant_id == "tenant-a" && delta.id == "shared-id" {
                    LessonStatus::RolledBack
                } else {
                    LessonStatus::Applied
                };
                assert_eq!(delta.status, expected);
            }
        }
        assert_eq!(
            apply_lesson(&store, "tenant-a", "owner", "copy", "after-rollback").await,
            3
        );
    }

    #[tokio::test]
    async fn rollback_refuses_a_replaced_owning_delta_without_mutation() {
        let store = InMemoryConsumerStore::new();
        apply_lesson(&store, "tenant-a", "agent", "copy", "shared-id").await;
        let mut replacement =
            LessonDelta::propose("tenant-a", "agent", "copy", "accuracy", "new proposal", 1);
        replacement.id = "shared-id".to_string();
        store.deltas.lock().unwrap()[0] = replacement;
        assert!(refused_rollback(&store, "agent", 1)
            .await
            .contains("owning delta"));
    }

    // -- the proposer's feed -------------------------------------

    use crate::signal::{LatencyClass, SignalKind};

    fn edit_signal(id: &str, before: &str, after: &str) -> Signal {
        let mut s = Signal::builder("sub_1")
            .tenant("tenant-1")
            .agent("agent-1")
            .capability("copy")
            .source("diff-capture")
            .kind(SignalKind::Correction)
            .value(-0.5)
            .raw(serde_json::json!({ "before": before, "after": after }))
            .latency(LatencyClass::Immediate)
            .idempotency(id)
            .run("run-1")
            .build();
        s.id = id.to_string();
        s
    }

    fn judgement(dim: &str, value: f64, scope: ReductionScope, sources: &[&str]) -> Judgement {
        Judgement {
            id: format!("jdg_{dim}_{value}"),
            tenant_id: "tenant-1".to_string(),
            agent_id: "agent-1".to_string(),
            capability: "copy".to_string(),
            dimension: dim.to_string(),
            value,
            confidence: 0.6,
            rubric_version: "interim-1".to_string(),
            scope,
            subject_id: (scope == ReductionScope::Instance).then(|| "sub_1".to_string()),
            source_signal_ids: sources.iter().map(|s| s.to_string()).collect(),
            note: Some("hitl-decision fell threshold 0 (value -1)".to_string()),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn a_weak_instance_judgement_becomes_evidence_from_the_edit_that_caused_it() {
        let signals = vec![edit_signal("sig_1", "Good morning", "Hello")];
        let evidence = failure_evidence(
            &[judgement(
                "accuracy",
                -1.0,
                ReductionScope::Instance,
                &["sig_1"],
            )],
            &signals,
        );

        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].dimension, "accuracy");
        assert_eq!(
            evidence[0].failing_text,
            "changed \"Good morning\" to \"Hello\""
        );
        assert_eq!(evidence[0].observed_at, signals[0].observed_at);
    }

    #[test]
    fn a_decision_has_no_text_so_the_judgements_note_is_the_evidence() {
        let mut decision = edit_signal("sig_2", "", "");
        decision.raw = serde_json::json!({ "decision": "reject" });
        let evidence = failure_evidence(
            &[judgement(
                "acceptance",
                -1.0,
                ReductionScope::Instance,
                &["sig_2"],
            )],
            &[decision],
        );

        assert_eq!(
            evidence[0].failing_text,
            "hitl-decision fell threshold 0 (value -1)"
        );
    }

    #[test]
    fn cohort_and_non_negative_judgements_are_not_evidence() {
        let signals = vec![edit_signal("sig_1", "a", "b")];
        let evidence = failure_evidence(
            &[
                judgement("accuracy", -1.0, ReductionScope::Cohort, &["sig_1"]),
                judgement("accuracy", 0.0, ReductionScope::Instance, &["sig_1"]),
                judgement("accuracy", 1.0, ReductionScope::Instance, &["sig_1"]),
            ],
            &signals,
        );

        assert!(
            evidence.is_empty(),
            "one failed output must not be counted twice"
        );
    }

    #[test]
    fn a_source_id_missing_from_the_pool_falls_back_rather_than_inventing_text() {
        let mut j = judgement("accuracy", -1.0, ReductionScope::Instance, &["sig_gone"]);
        j.note = None;
        let evidence = failure_evidence(&[j.clone()], &[]);

        assert_eq!(evidence[0].failing_text, "accuracy");
        assert_eq!(evidence[0].observed_at, j.created_at);
    }

    #[test]
    fn long_text_is_cut_on_a_character_boundary() {
        let long = "\u{e4}".repeat(EVIDENCE_TEXT_MAX_CHARS + 50);
        let signals = vec![edit_signal("sig_1", &long, "")];
        let evidence = failure_evidence(
            &[judgement(
                "accuracy",
                -1.0,
                ReductionScope::Instance,
                &["sig_1"],
            )],
            &signals,
        );

        assert!(evidence[0].failing_text.ends_with("..."));
        assert!(evidence[0].failing_text.chars().count() <= EVIDENCE_TEXT_MAX_CHARS + 3);
    }

    #[test]
    fn evidence_feeds_the_proposer_and_one_edit_opens_one_lesson_at_threshold_one() {
        let signals = vec![edit_signal("sig_1", "Good morning", "Hello")];
        let evidence = failure_evidence(
            &[judgement(
                "accuracy",
                -1.0,
                ReductionScope::Instance,
                &["sig_1"],
            )],
            &signals,
        );

        let proposed =
            LessonProposer::new(1).consider("tenant-1", "agent-1", "copy", &evidence, &[]);

        assert_eq!(proposed.len(), 1);
        assert_eq!(proposed[0].dimension, "accuracy");
        assert_eq!(proposed[0].trigger_count, 1);
        assert_eq!(proposed[0].status, LessonStatus::Proposed);
        assert!(proposed[0].proposed_instruction.contains("Good morning"));
        // And a second pass over the same evidence does not open a second lesson.
        let again =
            LessonProposer::new(1).consider("tenant-1", "agent-1", "copy", &evidence, &proposed);
        assert!(again.is_empty());
    }
}
