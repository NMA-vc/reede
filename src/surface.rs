//! Reede surface - the read model behind the feedback timeline.
//!
//! Everything here is read-only aggregation over the Reede stores. Its purpose:
//! one page can answer "why does this agent behave the way it does now" from
//! receipts and signals alone. It surfaces, per subject, the run receipt linkage
//! and the signal timeline in arrival order with latency class; per capability,
//! a dimension scorecard with applied lesson deltas and cohort baselines; and it
//! lets you drill from a judgement down to the exact signals behind it and from
//! a signal up to its producer, and see the open lesson deltas awaiting approval.
//!
//! Reede stays standalone (one-way dependency): this facade depends only on
//! Reede stores and never on a host application crate. The frontend page renders it.

use crate::consumer::{AppliedLesson, ConsumerStore, LessonDelta};
use crate::error::ReedeError;
use crate::reducer::{Judgement, JudgementStore};
use crate::signal::{Signal, SignalKind, SignalStore};
use crate::subject::{Subject, SubjectStore};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Identifies the producer that emitted a signal (drill-up from a signal).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProducerInfo {
    /// The producer id stamped on the signal (`signal.source`).
    pub producer_id: String,
    /// Schema version stamped as `signal.source_version`.
    pub source_version: String,
    /// Human-readable label.
    pub label: String,
}

/// One entry on a subject timeline: the signal plus the fields the page shows
/// next to it (latency class, kind, producing source).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimelineSignal {
    pub signal: Signal,
    pub kind: SignalKind,
    pub latency_class: crate::signal::LatencyClass,
    pub source: String,
    pub observed_at: DateTime<Utc>,
}

/// The read model for one subject: receipt linkage + signal timeline + judgements.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubjectView {
    /// The durable subject (carries `producing_task_id` / `producing_receipt_hash`
    /// for the "run receipt next to the timeline" story). `None` if the subject
    /// was never registered.
    pub subject: Option<Subject>,
    /// Signals in arrival order (ascending `observed_at`), each with latency
    /// class visible.
    pub signals: Vec<TimelineSignal>,
    /// Instance judgements against this subject, ascending `created_at`.
    pub judgements: Vec<Judgement>,
}

/// One dimension of a capability scorecard.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DimensionScore {
    pub dimension: String,
    pub judgement_count: usize,
    pub mean_value: f64,
    /// 0..1 fraction of judgements that were negative (weak).
    pub negative_ratio: f64,
}

/// Per-capability read model: dimension scorecard over time + applied lessons.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityView {
    pub agent_id: String,
    pub capability: String,
    pub dimensions: Vec<DimensionScore>,
    /// Which lesson deltas were applied and when (ascending version).
    pub applied_lessons: Vec<AppliedLesson>,
}

/// A cohort baseline for one dimension within a window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DimensionBaseline {
    pub dimension: String,
    pub sample_count: usize,
    pub mean_value: f64,
    pub negative_ratio: f64,
}

/// Drill-down from a judgement to the exact signals behind it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JudgementDrilldown {
    pub judgement: Judgement,
    /// The `Signal` rows referenced by `judgement.source_signal_ids`.
    pub source_signals: Vec<Signal>,
}

/// The read-only Reede surface. Generic over the four stores so any impl
/// (in-memory today, the SurrealDB binding later) backs it unchanged.
/// How many rows a surface read returns when the caller does not say.
///
/// Bounded by construction rather than by whoever remembers to pass a limit: a
/// timeline grows with a subject's life and the cohort archive grows on the
/// reduction tick's clock, so an unbounded default would be a page that works in
/// week one and times out in month six.
pub const DEFAULT_PAGE_SIZE: usize = 100;

pub struct ReedeSurface<S, J, C, Sub>
where
    S: SignalStore,
    J: JudgementStore,
    C: ConsumerStore,
    Sub: SubjectStore,
{
    signals: S,
    judgements: J,
    consumers: C,
    subjects: Sub,
    page_size: usize,
}

impl<S, J, C, Sub> ReedeSurface<S, J, C, Sub>
where
    S: SignalStore,
    J: JudgementStore,
    C: ConsumerStore,
    Sub: SubjectStore,
{
    pub fn new(signals: S, judgements: J, consumers: C, subjects: Sub) -> Self {
        Self {
            signals,
            judgements,
            consumers,
            subjects,
            page_size: DEFAULT_PAGE_SIZE,
        }
    }

    /// Cap every read this surface performs. Zero is treated as the default rather
    /// than as "return nothing", so a mis-parsed query string cannot silently empty
    /// a page.
    pub fn with_page_size(mut self, page_size: usize) -> Self {
        self.page_size = if page_size == 0 {
            DEFAULT_PAGE_SIZE
        } else {
            page_size
        };
        self
    }

    pub fn page_size(&self) -> usize {
        self.page_size
    }

    /// Per-subject: receipt linkage + signal timeline (arrival order, latency
    /// class) + instance judgements.
    pub async fn subject_timeline(
        &self,
        tenant_id: &str,
        subject_id: &str,
    ) -> Result<SubjectView, ReedeError> {
        let subject = self.subjects.get(tenant_id, subject_id).await?;
        let signals = self
            .signals
            .by_subject_page(tenant_id, subject_id, self.page_size)
            .await?;
        let mut timeline: Vec<TimelineSignal> = signals
            .into_iter()
            .map(|signal| TimelineSignal {
                latency_class: signal.latency_class,
                source: signal.source.clone(),
                observed_at: signal.observed_at,
                kind: signal.kind,
                signal,
            })
            .collect();
        // Arrival order, defensive re-sort on observed_at.
        timeline.sort_by_key(|t| t.observed_at);
        let judgements = self.judgements.by_subject(tenant_id, subject_id).await?;
        Ok(SubjectView {
            subject,
            signals: timeline,
            judgements,
        })
    }

    /// Per-capability dimension scorecard over time (from cohort judgements)
    /// plus which lesson deltas were applied and when.
    pub async fn capability_scorecard(
        &self,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
    ) -> Result<CapabilityView, ReedeError> {
        let judgements = self
            .judgements
            .cohort_latest(tenant_id, agent_id, capability, self.page_size)
            .await?;
        let mut groups: HashMap<String, Vec<f64>> = HashMap::new();
        for j in &judgements {
            groups.entry(j.dimension.clone()).or_default().push(j.value);
        }
        let mut dimensions: Vec<DimensionScore> = groups
            .into_iter()
            .map(|(dimension, values)| {
                let count = values.len();
                let mean = values.iter().sum::<f64>() / count as f64;
                let neg = values.iter().filter(|v| **v < 0.0).count();
                DimensionScore {
                    dimension,
                    judgement_count: count,
                    mean_value: mean,
                    negative_ratio: neg as f64 / count as f64,
                }
            })
            .collect();
        dimensions.sort_by(|a, b| a.dimension.cmp(&b.dimension));

        let applied_lessons = self
            .consumers
            .applied_deltas(tenant_id, agent_id, capability)
            .await?;
        Ok(CapabilityView {
            agent_id: agent_id.to_string(),
            capability: capability.to_string(),
            dimensions,
            applied_lessons,
        })
    }

    /// Cohort baseline per dimension within a window, from raw cohort signals
    /// (which carry their own `dimension` and `value`).
    pub async fn cohort_baseline(
        &self,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
        after: DateTime<Utc>,
        before: DateTime<Utc>,
    ) -> Result<Vec<DimensionBaseline>, ReedeError> {
        let signals = self
            .signals
            .cohort(tenant_id, agent_id, capability, after, before)
            .await?;
        let mut groups: HashMap<String, Vec<f64>> = HashMap::new();
        for s in &signals {
            let dimension = s
                .dimension
                .clone()
                .unwrap_or_else(|| "unscoped".to_string());
            groups.entry(dimension).or_default().push(s.value);
        }
        let mut out: Vec<DimensionBaseline> = groups
            .into_iter()
            .map(|(dimension, values)| {
                let count = values.len();
                let mean = values.iter().sum::<f64>() / count as f64;
                let neg = values.iter().filter(|v| **v < 0.0).count();
                DimensionBaseline {
                    dimension,
                    sample_count: count,
                    mean_value: mean,
                    negative_ratio: neg as f64 / count as f64,
                }
            })
            .collect();
        out.sort_by(|a, b| a.dimension.cmp(&b.dimension));
        Ok(out)
    }

    /// Drill from a judgement down to the exact signals it was derived from.
    pub async fn judgement_drilldown(
        &self,
        tenant_id: &str,
        judgement: &Judgement,
    ) -> Result<JudgementDrilldown, ReedeError> {
        let mut source_signals = Vec::new();
        for id in &judgement.source_signal_ids {
            if let Some(signal) = self.signals.get(tenant_id, id).await? {
                source_signals.push(signal);
            }
        }
        Ok(JudgementDrilldown {
            judgement: judgement.clone(),
            source_signals,
        })
    }

    /// Drill from a signal up to the producer that emitted it. Based on the
    /// producer id already stamped on the signal; known Reede producers get a
    /// precise mode + label, anything else falls back to 'unknown'.
    pub fn signal_producer(&self, signal: &Signal) -> ProducerInfo {
        ProducerInfo {
            producer_id: signal.source.clone(),
            source_version: signal.source_version.clone(),
            label: producer_label(&signal.source),
        }
    }

    /// Open lesson deltas awaiting human approval for a capability.
    pub async fn pending_lesson_deltas(
        &self,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
    ) -> Result<Vec<LessonDelta>, ReedeError> {
        self.consumers
            .pending_deltas(tenant_id, agent_id, capability)
            .await
    }
}

/// Map a producer id to its human label, for the signal->producer drill.
fn producer_label(source: &str) -> String {
    match source {
        "rating" => "Human rating".to_string(),
        "diff-capture" => "Diff correction".to_string(),
        crate::reducer::HITL_DECISION_SOURCE => "Review decision".to_string(),
        crate::reducer::SCOUT_OUTCOME_SOURCE => "Scout outcome".to_string(),
        "nakiek" => "Automated review".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consumer::{InMemoryConsumerStore, LessonDelta};
    use crate::reducer::{InMemoryJudgementStore, Judgement, ReductionScope};
    use crate::signal::{InMemorySignalStore, LatencyClass};
    use crate::subject::{ArtifactKind, InMemorySubjectStore};
    use chrono::Duration;

    fn test_signal(
        subject: &str,
        source: &str,
        kind: SignalKind,
        value: f64,
        observed_at: DateTime<Utc>,
    ) -> Signal {
        Signal::builder(subject)
            .tenant("tenant-1")
            .agent("agent-1")
            .capability("copy")
            .source(source)
            .kind(kind)
            .dimension("hook")
            .value(value)
            .latency(LatencyClass::Immediate)
            .observed_at(observed_at)
            .idempotency(format!("{source}:{subject}:eq-1"))
            .run("run-1")
            .build()
    }

    #[tokio::test]
    async fn test_subject_timeline_returns_signals_in_arrival_order_with_latency() {
        let signals = InMemorySignalStore::new();
        let now = Utc::now();
        // Two signals out of order on purpose.
        let mut late = test_signal("sub_1", "rating", SignalKind::Rating, 1.0, now);
        late.idempotency_key = "rating:sub_1:e2".to_string();
        late.source = "analytics-poller".to_string();
        late.kind = SignalKind::Metric;
        late.latency_class = LatencyClass::Delayed;
        let early = test_signal(
            "sub_1",
            "rating",
            SignalKind::Rating,
            1.0,
            now - Duration::days(2),
        );
        let early_at = early.observed_at;
        let late_at = late.observed_at;
        signals.append(early).await.unwrap();
        signals.append(late).await.unwrap();

        let judgements = InMemoryJudgementStore::new();
        let consumers = InMemoryConsumerStore::new();
        let subjects = InMemorySubjectStore::new();

        let surf = ReedeSurface::new(signals, judgements, consumers, subjects);
        let view = surf.subject_timeline("tenant-1", "sub_1").await.unwrap();
        assert_eq!(view.signals.len(), 2);
        // Arrival order = ascending observed_at.
        assert_eq!(view.signals[0].observed_at, early_at);
        assert_eq!(view.signals[1].observed_at, late_at);
        assert_eq!(
            view.signals[1].latency_class,
            LatencyClass::Delayed,
            "latency class visible on the timeline"
        );
        assert_eq!(view.signals[0].latency_class, LatencyClass::Immediate);
        assert_eq!(view.signals[1].source, "analytics-poller");
    }

    #[tokio::test]
    async fn test_subject_timeline_surfaces_receipt_linkage() {
        let signals = InMemorySignalStore::new();
        let judgements = InMemoryJudgementStore::new();
        let consumers = InMemoryConsumerStore::new();
        let subjects = InMemorySubjectStore::new();
        let mut s = Subject::mint("tenant-1", ArtifactKind::Article);
        s.id = "sub_article_1".to_string();
        s.bind_to_run(uuid::Uuid::new_v4(), "receipt-hash-abc");
        subjects.save(&s).await.unwrap();

        let surf = ReedeSurface::new(signals, judgements, consumers, subjects);
        let view = surf
            .subject_timeline("tenant-1", "sub_article_1")
            .await
            .unwrap();
        assert_eq!(
            view.subject
                .as_ref()
                .unwrap()
                .producing_receipt_hash
                .as_deref(),
            Some("receipt-hash-abc")
        );
    }

    #[tokio::test]
    async fn test_capability_scorecard_computes_dimension_aggregates_and_applied_lessons() {
        let signals = InMemorySignalStore::new();
        let judgements = InMemoryJudgementStore::new();
        let consumers = InMemoryConsumerStore::new();
        let subjects = InMemorySubjectStore::new();

        // Two cohort judgements on 'hook', one negative.
        let mut j1 = Judgement {
            id: "jdg_1".to_string(),
            tenant_id: "tenant-1".to_string(),
            agent_id: "agent-1".to_string(),
            capability: "copy".to_string(),
            dimension: "hook".to_string(),
            value: 0.5,
            confidence: 0.6,
            rubric_version: "v1".to_string(),
            scope: ReductionScope::Cohort,
            subject_id: None,
            source_signal_ids: vec![],
            note: None,
            created_at: Utc::now(),
        };
        judgements.save(&j1).await.unwrap();
        j1.id = "jdg_2".to_string();
        j1.value = -0.5;
        judgements.save(&j1).await.unwrap();

        let lesson = LessonDelta::propose(
            "tenant-1",
            "agent-1",
            "copy",
            "hook",
            "Make the hook stronger",
            2,
        );
        consumers.propose_delta(&lesson).await.unwrap();
        consumers
            .approve_delta("tenant-1", &lesson.id, "owner@example.com")
            .await
            .unwrap();
        consumers.apply_delta("tenant-1", &lesson.id).await.unwrap();

        let surf = ReedeSurface::new(signals, judgements, consumers, subjects);
        let view = surf
            .capability_scorecard("tenant-1", "agent-1", "copy")
            .await
            .unwrap();
        assert_eq!(view.dimensions.len(), 1);
        let hook = &view.dimensions[0];
        assert_eq!(hook.dimension, "hook");
        assert_eq!(hook.judgement_count, 2);
        assert!((hook.mean_value - 0.0).abs() < 1e-9);
        assert!((hook.negative_ratio - 0.5).abs() < 1e-9);
        assert_eq!(view.applied_lessons.len(), 1);
    }

    #[tokio::test]
    async fn test_cohort_baseline_groups_dimensions_in_window() {
        let signals = InMemorySignalStore::new();
        let judgements = InMemoryJudgementStore::new();
        let consumers = InMemoryConsumerStore::new();
        let subjects = InMemorySubjectStore::new();

        let now = Utc::now();
        let in_window = test_signal("sub_1", "analytics-poller", SignalKind::Metric, -0.3, now);
        let mut other_dim = in_window.clone();
        other_dim.dimension = Some("accuracy".to_string());
        other_dim.idempotency_key = "analytics-poller:sub_1:eq-acc".to_string();
        let stale = {
            let mut s = test_signal(
                "sub_2",
                "analytics-poller",
                SignalKind::Metric,
                2.0,
                now - Duration::days(90),
            );
            s.idempotency_key = "analytics-poller:sub_2:stale".to_string();
            s
        };
        signals.append(in_window).await.unwrap();
        signals.append(other_dim).await.unwrap();
        signals.append(stale).await.unwrap();

        let surf = ReedeSurface::new(signals, judgements, consumers, subjects);
        let base = surf
            .cohort_baseline(
                "tenant-1",
                "agent-1",
                "copy",
                now - Duration::days(7),
                now + Duration::days(7),
            )
            .await
            .unwrap();
        assert_eq!(base.len(), 2, "stale 90-day row outside window excluded");
        assert!(base.iter().any(|b| b.dimension == "hook"));
        assert!(base.iter().any(|b| b.dimension == "accuracy"));
        assert!(base.iter().all(|b| b.dimension != "unscoped"));
    }

    #[tokio::test]
    async fn test_judgement_drilldown_resolves_source_signals() {
        let signals = InMemorySignalStore::new();
        let judgements = InMemoryJudgementStore::new();
        let consumers = InMemoryConsumerStore::new();
        let subjects = InMemorySubjectStore::new();

        let sig = test_signal(
            "sub_1",
            "diff-capture",
            SignalKind::Correction,
            -1.0,
            Utc::now(),
        );
        let stored = signals.append(sig).await.unwrap();

        let judgement = Judgement {
            id: "jdg_1".to_string(),
            tenant_id: "tenant-1".to_string(),
            agent_id: "agent-1".to_string(),
            capability: "copy".to_string(),
            dimension: "structure".to_string(),
            value: -1.0,
            confidence: 0.6,
            rubric_version: "v1".to_string(),
            scope: ReductionScope::Instance,
            subject_id: Some("sub_1".to_string()),
            source_signal_ids: vec![stored.id.clone()],
            note: None,
            created_at: Utc::now(),
        };

        let surf = ReedeSurface::new(signals, judgements, consumers, subjects);
        let dd = surf
            .judgement_drilldown("tenant-1", &judgement)
            .await
            .unwrap();
        assert_eq!(dd.source_signals.len(), 1);
        assert_eq!(dd.source_signals[0].id, stored.id);
        assert_eq!(dd.source_signals[0].kind, SignalKind::Correction);
    }

    #[test]
    fn test_signal_producer_maps_known_and_falls_back() {
        let ratings = test_signal("sub_1", "rating", SignalKind::Rating, 1.0, Utc::now());
        let unknown = test_signal(
            "sub_1",
            "mystery-poller",
            SignalKind::Metric,
            1.0,
            Utc::now(),
        );
        let pi_rating = ReedeSurface::new(
            InMemorySignalStore::new(),
            InMemoryJudgementStore::new(),
            InMemoryConsumerStore::new(),
            InMemorySubjectStore::new(),
        )
        .signal_producer(&ratings);
        assert_eq!(pi_rating.producer_id, "rating");
        assert_eq!(pi_rating.label, "Human rating");

        let pi_unknown = ReedeSurface::new(
            InMemorySignalStore::new(),
            InMemoryJudgementStore::new(),
            InMemoryConsumerStore::new(),
            InMemorySubjectStore::new(),
        )
        .signal_producer(&unknown);
        assert_eq!(pi_unknown.producer_id, "mystery-poller");
        assert_eq!(pi_unknown.label, "mystery-poller");
    }

    #[tokio::test]
    async fn test_pending_lesson_deltas_surfaces_open_deltas() {
        let signals = InMemorySignalStore::new();
        let judgements = InMemoryJudgementStore::new();
        let consumers = InMemoryConsumerStore::new();
        let subjects = InMemorySubjectStore::new();

        consumers
            .propose_delta(&LessonDelta::propose(
                "tenant-1",
                "agent-1",
                "copy",
                "hook",
                "Write a stronger opening hook.",
                3,
            ))
            .await
            .unwrap();

        let surf = ReedeSurface::new(signals, judgements, consumers, subjects);
        let pending = surf
            .pending_lesson_deltas("tenant-1", "agent-1", "copy")
            .await
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert!(pending[0].proposed_instruction.contains("hook"));
    }
}
