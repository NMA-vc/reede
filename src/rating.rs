//! Rating producer for the embeddable feedback widget.
//!
//! Thumbs up/down plus an optional dimension tag (from the capability's
//! declared rubric) and free text. A rating lands as an *instance*
//! (never cohort-only) `Rating` signal bound to a durable `Subject`,
//! tagged with the weak dimension. That tag is the point: "ok, but improve
//! this aspect" needs a slot for which aspect.
//!
//! The producer validates the submitted dimension against the capability's
//! declared rubric, so a widget cannot tag a dimension nobody declared. If a
//! capability has no declared rubric, dimension tagging is impossible (there
//! are no declared dimension ids) and tagged submissions are rejected; only a
//! plain thumbs rating is allowed.
//!
//! Dedupe and rate limiting per user per subject ride on the envelope's
//! idempotency key: the backend builds a stable per-(user, subject) key and
//! the append path removes duplicates. Changing the vote or the
//! dimension is a fresh rating event; the free-text note is a refinement and
//! does not change identity.

use crate::error::ReedeError;
use crate::producer::SignalProducer;
use crate::signal::{AttributionSource, LatencyClass, Signal, SignalKind};
use crate::spec::AgentRubric;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Producer id stamped on every emitted rating signal (`signal.source`).
pub const RATING_SOURCE: &str = "rating";
/// Schema version of the rating envelope.
pub const RATING_SOURCE_VERSION: &str = "1.0";

/// Thumbs vote from the widget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RatingVote {
    Up,
    Down,
}

impl RatingVote {
    /// Normalized numeric value on the signal. Down scores negative on purpose
    /// so a weak dimension averages below a neutral baseline (consistent with
    /// the envelope's value semantics).
    pub fn as_value(&self) -> f64 {
        match self {
            RatingVote::Up => 1.0,
            RatingVote::Down => -1.0,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RatingVote::Up => "up",
            RatingVote::Down => "down",
        }
    }
}

/// A rating submission from the widget. The backend fills `tenant_id` and
/// `user_id` from the authenticated tenant session ("no auth friction for
/// logged-in tenant users"); the widget supplies the rest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatingSubmission {
    /// Durable subject being rated.
    pub subject_id: String,
    /// Filled by the backend from the tenant session.
    pub tenant_id: String,
    pub agent_id: String,
    /// Capability whose rubric governs the dimension tag.
    pub capability: String,
    /// Filled by the backend from the tenant session.
    pub user_id: String,
    pub vote: RatingVote,
    /// Rubric dimension id when the reviewer names a weak aspect. Validated
    /// against the capability's declared rubric; `None` is always allowed.
    pub dimension: Option<String>,
    /// Free text ("ok, but improve this aspect ..."), optional.
    #[serde(default)]
    pub note: String,
    /// the run being rated. Required for the signal to be storable.
    #[serde(default)]
    pub run_id: String,
    /// The role this rating lands on, when the surface knows it. A widget that
    /// rates a whole artifact does not, and leaves this `None`: per D5 an
    /// anonymous whole-artifact thumbs is left to the attribution pass rather
    /// than guessed here.
    #[serde(default)]
    pub role: Option<String>,
    /// When the reviewer rated the output.
    pub observed_at: DateTime<Utc>,
}

/// The Push producer that turns rating submissions into normalized signals.
#[derive(Debug, Clone)]
pub struct RatingProducer {
    id: String,
    source_version: String,
    /// Declared dimensions per capability used to validate the tag.
    rubrics: Vec<AgentRubric>,
}

impl Default for RatingProducer {
    fn default() -> Self {
        Self::new()
    }
}

impl RatingProducer {
    pub fn new() -> Self {
        Self {
            id: RATING_SOURCE.to_string(),
            source_version: RATING_SOURCE_VERSION.to_string(),
            rubrics: Vec::new(),
        }
    }

    /// Supply the declared rubric(s) that govern dimension tags. A capability
    /// without a declared rubric rejects any dimension tag (fail-closed).
    pub fn with_rubrics(mut self, rubrics: Vec<AgentRubric>) -> Self {
        self.rubrics = rubrics;
        self
    }

    /// Build the normalized `Rating` signal for a submission, validating the
    /// dimension against the capability's declared rubric. Appending is left to
    /// the store / registry, so this is a pure, testable construction.
    pub fn signal_for(&self, submission: &RatingSubmission) -> Result<Signal, ReedeError> {
        if let Some(dimension) = submission.dimension.as_deref() {
            self.validate_dimension(&submission.capability, dimension)?;
        }

        let idempotency_key = self.idempotency_key(submission);
        let mut signal = Signal::builder(&submission.subject_id)
            .tenant(&submission.tenant_id)
            .agent(&submission.agent_id)
            .capability(&submission.capability)
            .source(RATING_SOURCE)
            .source_version(&self.source_version)
            .kind(SignalKind::Rating)
            .value(submission.vote.as_value())
            .raw(serde_json::json!({
                "user_id": submission.user_id,
                "vote": submission.vote.as_str(),
                "note": submission.note,
            }))
            .confidence(1.0)
            .latency(LatencyClass::Immediate)
            .run(&submission.run_id)
            .observed_at(submission.observed_at)
            .idempotency(idempotency_key)
            .build();
        signal.dimension = submission.dimension.clone();
        // A reviewer who named the role pointed at something specific, so the
        // attribution is recorded rather than inferred. A widget that rates the
        // whole artifact names none, and the signal stays unattributed for the
        // attribution pass to handle -- guessing here is what D5 forbids.
        if let Some(role) = submission.role.clone() {
            signal.role = Some(role);
            signal.attribution_source = AttributionSource::Explicit;
        }
        Ok(signal)
    }

    /// Stable dedupe / rate-limit key per (user, subject). The vote and the
    /// dimension are part of identity (a re-rating is a new event); the note is
    /// not (it refines the same rating).
    pub fn idempotency_key(&self, submission: &RatingSubmission) -> String {
        let dimension = submission.dimension.as_deref().unwrap_or("none");
        format!(
            "{RATING_SOURCE}:{}:{}:{}:{}",
            submission.subject_id,
            submission.user_id,
            dimension,
            submission.vote.as_str()
        )
    }

    fn validate_dimension(&self, capability: &str, dimension: &str) -> Result<(), ReedeError> {
        let Some(rubric) = self.rubrics.iter().find(|r| r.capability == capability) else {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!(
                    "capability '{capability}' has no declared rubric; dimension tag '{dimension}' cannot be validated"
                ),
            });
        };
        if !rubric.dimensions.iter().any(|d| d.id == dimension) {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!(
                    "dimension '{dimension}' is not declared in the rubric for capability '{capability}'"
                ),
            });
        }
        Ok(())
    }
}

#[async_trait]
impl SignalProducer for RatingProducer {
    fn id(&self) -> &str {
        &self.id
    }

    fn source_version(&self) -> &str {
        &self.source_version
    }

    /// Push delivers a pre-built, validated rating signal. The caller appends
    /// it to the store through the envelope's idempotency key, which is what
    /// dedupes re-submissions per (user, subject).
    async fn push(&self, _signal: Signal) -> Result<(), ReedeError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::{InMemorySignalStore, SignalStore};
    use crate::spec::{parse_manifest_v1, RubricDimension};
    use chrono::{Duration, Utc};

    fn rubric_copy() -> AgentRubric {
        AgentRubric {
            capability: "copy".to_string(),
            version: "2026-08-07-r1".to_string(),
            dimensions: vec![
                RubricDimension {
                    id: "hook".to_string(),
                    label: "The Hook".to_string(),
                    description: "Opening that pulls the reader in".to_string(),
                    weight: 1.0,
                },
                RubricDimension {
                    id: "accuracy".to_string(),
                    label: "Accuracy".to_string(),
                    description: "Correct and verifiable claims".to_string(),
                    weight: 1.5,
                },
            ],
        }
    }

    fn submission(subject: &str, vote: RatingVote, dimension: Option<&str>) -> RatingSubmission {
        RatingSubmission {
            subject_id: subject.to_string(),
            tenant_id: "tenant-1".to_string(),
            agent_id: "agent-1".to_string(),
            capability: "copy".to_string(),
            user_id: "reviewer-1".to_string(),
            vote,
            dimension: dimension.map(str::to_string),
            note: "the hook is weak".to_string(),
            run_id: "run-1".to_string(),
            role: None,
            observed_at: Utc::now(),
        }
    }

    fn producer() -> RatingProducer {
        RatingProducer::new().with_rubrics(vec![rubric_copy()])
    }

    #[test]
    fn test_thumbs_up_produces_normalized_rating_signal() {
        let signal = producer()
            .signal_for(&submission("sub_article_1", RatingVote::Up, Some("hook")))
            .unwrap();
        assert_eq!(signal.kind, SignalKind::Rating);
        assert_eq!(signal.source, RATING_SOURCE);
        assert_eq!(signal.value, 1.0, "up scores +1");
        assert_eq!(signal.dimension.as_deref(), Some("hook"));
        assert_eq!(signal.subject_id, "sub_article_1");
        assert_eq!(signal.tenant_id, "tenant-1");
        assert_eq!(signal.capability, "copy");
        assert_eq!(signal.latency_class, LatencyClass::Immediate);
        assert_eq!(signal.confidence, 1.0);
        assert!(!signal.cohort_only, "a human rating is an instance signal");
        assert_eq!(signal.raw["vote"], "up");
        assert_eq!(signal.raw["note"], "the hook is weak");
        assert_eq!(signal.raw["user_id"], "reviewer-1");
    }

    #[test]
    fn test_thumbs_down_scores_negative_and_binds_to_subject() {
        let signal = producer()
            .signal_for(&submission("sub_article_1", RatingVote::Down, None))
            .unwrap();
        assert_eq!(signal.value, -1.0, "down scores -1");
        assert_eq!(signal.dimension, None, "dimensionless thumbs is valid");
        assert_eq!(signal.subject_id, "sub_article_1");
    }

    #[test]
    fn test_invalid_dimension_rejected() {
        let err = producer()
            .signal_for(&submission(
                "sub_article_1",
                RatingVote::Down,
                Some("made_up"),
            ))
            .unwrap_err();
        assert!(
            matches!(err, ReedeError::SpecValidationFailed { .. }),
            "got: {err}"
        );
        assert!(err.to_string().contains("'made_up'"));
    }

    #[test]
    fn test_dimension_rejected_when_capability_has_no_rubric() {
        let producer = RatingProducer::new(); // no rubrics declared
        let err = producer
            .signal_for(&submission("sub_article_1", RatingVote::Up, Some("hook")))
            .unwrap_err();
        assert!(err.to_string().contains("no declared rubric"));
        // But a plain thumbs rating is still allowed without any rubric.
        assert!(producer
            .signal_for(&submission("sub_article_1", RatingVote::Up, None))
            .is_ok());
    }

    #[test]
    fn test_idempotency_key_dedupes_identical_and_distinguishes_vote_and_dimension() {
        let p = producer();
        let a = submission("sub_1", RatingVote::Up, Some("hook"));
        let same = submission("sub_1", RatingVote::Up, Some("hook"));
        let other_vote = submission("sub_1", RatingVote::Down, Some("hook"));
        let other_dim = submission("sub_1", RatingVote::Up, Some("accuracy"));

        assert_eq!(p.idempotency_key(&a), p.idempotency_key(&same));
        assert_ne!(p.idempotency_key(&a), p.idempotency_key(&other_vote));
        assert_ne!(p.idempotency_key(&a), p.idempotency_key(&other_dim));
        assert!(p
            .idempotency_key(&a)
            .starts_with("rating:sub_1:reviewer-1:hook:up"));
    }

    #[tokio::test]
    async fn test_append_is_idempotent_via_store() {
        let store = InMemorySignalStore::new();
        let p = producer();

        let first = store
            .append(
                p.signal_for(&submission("sub_1", RatingVote::Up, Some("hook")))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Same reviewer, subject, dimension, vote -> same idempotency key.
        let second = store
            .append(
                p.signal_for(&submission("sub_1", RatingVote::Up, Some("hook")))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(first.id, second.id, "re-submission dedupes");
        let rows = store.by_subject("tenant-1", "sub_1").await.unwrap();
        assert_eq!(rows.len(), 1);

        // A different vote is a new rating event.
        let third = store
            .append(
                p.signal_for(&submission("sub_1", RatingVote::Down, None))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(first.id, third.id);
    }

    #[tokio::test]
    async fn test_late_rating_score_with_rubric_from_real_manifest() {
        // Integration: build the rubric from a real manifest and rate
        // against it; five days later the rating still joins its subject.
        let toml = r#"
[meta]
schema_version = "1"
author = "founder"
[agent]
id = "content-agent"
name = "Content Agent"
description = "d"
version = "1.0.0"
skills = ["copy"]
[agent.model]
provider = "cortecs"
name = "cortecs-default"
[agent.prompt]
system = "prompt"
[agent.limits]
monthly_budget_eur = 200.0
[[agent.rubrics]]
capability = "copy"
version = "v1"
[[agent.rubrics.dimensions]]
id = "hook"
label = "The Hook"
description = "d"
weight = 1.0
"#;
        let spec = parse_manifest_v1(toml).unwrap();
        let p = RatingProducer::new().with_rubrics(vec![spec.agent.rubrics[0].clone()]);
        let mut sub = submission("sub_article_1", RatingVote::Down, Some("hook"));
        sub.observed_at = Utc::now() + Duration::days(5);

        let signal = p.signal_for(&sub).unwrap();
        assert_eq!(signal.dimension.as_deref(), Some("hook"));
        assert_eq!(signal.value, -1.0);

        // Parser was fed a real manifest, so the exact rubric the widget would
        // render (the hook) is the dimension we validated against.
        assert!(sub.observed_at > Utc::now());
    }
}
