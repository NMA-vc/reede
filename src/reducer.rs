//! Reducer plugin trait and signal-to-dimension mapping.
//!
//! Where the human sentence and the analytics number finally meet. A reducer
//! consumes normalized `Signal`s for a subject or a cohort and emits a
//! `Judgement` against a capability's declared rubric.
//!
//! Two judgement scopes, kept strictly apart:
//!   * `Instance` - about one subject (one article, one email). Produced from
//!     instance-level human supervision (rating, correction/diff).
//!   * `Cohort`   - about an agent + capability over a window. Produced from
//!     aggregated, confounded analytics.
//!
//! Hard separation is enforced in code, not convention: a `cohort_only` signal
//! (analytics) can never contribute to an `Instance` judgement. See
//! `MappingReducer::reduce`.
//!
//! The signal -> dimension mapping is declarative config we write, not
//! something the system infers: a `MappingRule` names a source and a metric and
//! maps it to a rubric dimension with a threshold and a direction ("scroll depth
//! below baseline -> hook, negative"). Free text and diffs are classified into a
//! dimension by a `Classifier` (LLM-assisted on the host side via the one-way
//! rule; deterministic `KeywordClassifier` shipped here as the reference).
//!
//! Judgements are stored separately (not as `Signal`s), versioned, and each
//! carries the exact source signals (their ids) that produced it, so a judgement
//! is always traceable and never re-labels old raw rows.

use crate::error::ReedeError;
use crate::signal::{Signal, SignalKind, SignalStore};
use crate::spec::RubricDimension;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// Whether a judgement is about a single subject or an agent+capability cohort.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReductionScope {
    Instance,
    Cohort,
}

impl ReductionScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReductionScope::Instance => "instance",
            ReductionScope::Cohort => "cohort",
        }
    }
}

impl std::fmt::Display for ReductionScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A versioned, traceable judgement against one rubric dimension.
///
/// `Judgement` is intentionally *not* a `Signal`: raw signal rows are immutable
/// and this lets a reducer attach dimensions + qualitative notes without
/// mutating them. Every judgement records which rubric version it was judged
/// under, and the exact source signal ids it was derived from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Judgement {
    /// Row id: `jdg_<sha256>` of the judgement's scope and evidence (see `judgement_id`),
    /// so re-reducing the same signals overwrites rather than duplicates.
    pub id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub capability: String,
    /// Rubric dimension this judgement scores (e.g. "hook").
    pub dimension: String,
    /// Normalized score in [-1, 1]; negative = weak on the dimension.
    pub value: f64,
    /// Attribution confidence (0..1).
    pub confidence: f64,
    /// The rubric version this judgement was made under.
    pub rubric_version: String,
    pub scope: ReductionScope,
    /// `Some(subject_id)` for instance judgements, `None` for cohort.
    pub subject_id: Option<String>,
    /// The exact signals (by `Signal.id`) this judgement was derived from.
    #[serde(default)]
    pub source_signal_ids: Vec<String>,
    /// Optional free-text rationale, kept alongside (never replacing the raw).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl Judgement {
    pub fn is_negative(&self) -> bool {
        self.value < 0.0
    }
}

/// A declarative signal -> dimension mapping, written by us.
///
/// `source` is the producer id; `metric` selects *which* numeric to compare:
///   * `None`      -> use `signal.value`
///   * `Some(key)` -> read `signal.raw[key]` as a number
///
/// `fails_when_below` is the direction: if true, a value below `threshold` is
/// weak (negative); if false, a value above `threshold` is weak.
/// `cohort_only` marks rules that only ever consume cohort (analytics) signals.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MappingRule {
    pub source: String,
    pub metric: Option<String>,
    pub dimension: String,
    pub threshold: f64,
    pub fails_when_below: bool,
    pub cohort_only: bool,
}

/// A deterministic classifier that maps free text / diff passages to a rubric
/// dimension. Reference implementation shipped here; the host side provides a
/// cortecs-backed LLM classifier implementing the same trait (one-way rule).
#[async_trait]
pub trait Classifier: Send + Sync {
    /// Return the rubric dimension id best matching `text`, or `None` if
    /// nothing is clear (the reducer is fail-open on classification).
    async fn classify(
        &self,
        text: &str,
        dimensions: &[RubricDimension],
    ) -> Result<Option<String>, ReedeError>;
}

/// Keyword-based classifier used to keep free-text reduction dependency-free
/// and testable. It lowercases the text and returns the first dimension whose
/// keyword list appears. Deterministic, fail-open (None when no keyword hits).
pub struct KeywordClassifier {
    /// dimension_id -> list of trigger keywords/phrases.
    keywords: HashMap<String, Vec<String>>,
}

impl KeywordClassifier {
    pub fn new() -> Self {
        Self {
            keywords: HashMap::new(),
        }
    }

    pub fn add_dimension(
        mut self,
        dimension_id: impl Into<String>,
        keywords: Vec<impl Into<String>>,
    ) -> Self {
        self.keywords.insert(
            dimension_id.into(),
            keywords.into_iter().map(Into::into).collect(),
        );
        self
    }
}

impl Default for KeywordClassifier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Classifier for KeywordClassifier {
    async fn classify(
        &self,
        text: &str,
        dimensions: &[RubricDimension],
    ) -> Result<Option<String>, ReedeError> {
        let hay = text.to_lowercase();
        for dim in dimensions {
            if let Some(kws) = self.keywords.get(&dim.id) {
                if kws.iter().any(|k| hay.contains(&k.to_lowercase())) {
                    return Ok(Some(dim.id.clone()));
                }
            }
        }
        Ok(None)
    }
}

/// Converts a raw signal into a judgement for a rule, or nothing when the rule
/// does not fire. Enforces the cohort/instance boundary at the signal level.
struct FiredRule {
    dimension: String,
    value: f64,
    source_signal_id: String,
    note: Option<String>,
}

/// Reads the numeric to compare for a rule (`signal.value` or a raw key).
fn rule_metric_value(signal: &Signal, metric: &Option<String>) -> Option<f64> {
    match metric {
        Some(key) => signal.raw.get(key).and_then(|v| v.as_f64()),
        None => Some(signal.value),
    }
}

/// Applies a mapping to a signal and returns a fired judgement contribution if
/// the rule's threshold/direction condition holds.
fn apply_rule(signal: &Signal, rule: &MappingRule) -> Option<FiredRule> {
    // Cohort boundary: a cohort_only signal may never fire an instance rule.
    if signal.cohort_only && !rule.cohort_only {
        return None;
    }
    let value = rule_metric_value(signal, &rule.metric)?;
    let fired = if rule.fails_when_below {
        value < rule.threshold
    } else {
        value > rule.threshold
    };
    if !fired {
        return None;
    }
    // Negative score for a weak dimension; positive for a pass.
    let polarity = if rule.fails_when_below {
        if value < rule.threshold {
            -1.0
        } else {
            1.0
        }
    } else if value > rule.threshold {
        -1.0
    } else {
        1.0
    };
    Some(FiredRule {
        dimension: rule.dimension.clone(),
        value: polarity,
        source_signal_id: signal.id.clone(),
        note: Some(format!(
            "{}{} {} threshold {} (value {value})",
            rule.source,
            rule.metric.as_deref().unwrap_or(""),
            if polarity < 0.0 { "fell" } else { "exceeded" },
            rule.threshold
        )),
    })
}

/// The reducer: maps a batch of signals to rubric judgements.
///
/// * Instance scope ignores cohort_only signals entirely (hard separation);
///   cohort scope is where cohort_only signals are expected to contribute.
/// * `classifier` is optional and fail-open: when absent, free text/diff signal
///   raw payloads that carry no explicit dimension are not dimension-tagged.
pub struct MappingReducer {
    rules: Vec<MappingRule>,
    classifier: Option<std::sync::Arc<dyn Classifier>>,
}

/// The input to a single reduction. Bundled as one struct so the reducer's
/// signature stays small (clippy) and so the caller assembles a self-describing
/// request.
#[derive(Debug, Clone)]
pub struct ReductionRequest {
    pub tenant_id: String,
    pub agent_id: String,
    pub capability: String,
    /// The rubric version this reduction is judged under (recorded on each
    /// judgement so a later rubric edit never re-labels an old judgement).
    pub rubric_version: String,
    /// The declared rubric dimensions for this capability (single source of
    /// truth from the manifest), handed to the classifier.
    pub dimensions: Vec<RubricDimension>,
    /// `Some(subject_id)` selects Instance scope; `None` selects Cohort.
    pub subject_id: Option<String>,
    pub signals: Vec<Signal>,
}

impl ReductionRequest {
    pub fn scope(&self) -> ReductionScope {
        if self.subject_id.is_some() {
            ReductionScope::Instance
        } else {
            ReductionScope::Cohort
        }
    }
}

impl MappingReducer {
    pub fn new(rules: Vec<MappingRule>) -> Self {
        Self {
            rules,
            classifier: None,
        }
    }

    pub fn with_classifier(self, classifier: std::sync::Arc<dyn Classifier>) -> Self {
        Self {
            classifier: Some(classifier),
            ..self
        }
    }

    /// Reduce a batch of signals into rubric judgements.
    ///
    /// Instance scope ignores `cohort_only` signals entirely (hard separation);
    /// cohort scope is where cohort_only signals are expected to contribute.
    pub async fn reduce(&self, req: &ReductionRequest) -> Result<Vec<Judgement>, ReedeError> {
        let scope = req.scope();

        let mut fired: Vec<FiredRule> = Vec::new();
        let mut classified_dimensions: HashMap<String, String> = HashMap::new(); // signal.id -> dimension

        for signal in &req.signals {
            // A withdrawal cancels evidence; it is not evidence. Skipped before any
            // rule sees it, because rules match on `source` and a withdrawal carries
            // its producer's source — a rating rule would otherwise fire on the act
            // of taking a rating back.
            if signal.kind == SignalKind::Withdrawal {
                continue;
            }
            // Hard separation: cohort_only signals can never drive an instance
            // judgement, regardless of any rule's flag.
            if scope == ReductionScope::Instance && signal.cohort_only {
                continue;
            }
            for rule in self.rules.iter().filter(|r| r.source == signal.source) {
                if let Some(f) = apply_rule(signal, rule) {
                    fired.push(f);
                }
            }
            // Fail-open free-text/diff classification into a dimension.
            if let Some(classifier) = &self.classifier {
                if let Some(text) = signal_text(signal) {
                    if let Some(dim) = classifier.classify(&text, &req.dimensions).await? {
                        classified_dimensions.insert(signal.id.clone(), dim);
                    }
                }
            }
        }

        // Build one judgement per (dimension) for deterministic output ordering.
        let mut seen: HashSet<String> = HashSet::new();
        let mut judgements: Vec<Judgement> = Vec::new();

        for fr in &fired {
            if seen.insert(fr.dimension.clone()) {
                let note = fr.note.clone();
                judgements.push(Judgement {
                    id: String::new(),
                    tenant_id: req.tenant_id.clone(),
                    agent_id: req.agent_id.clone(),
                    capability: req.capability.clone(),
                    dimension: fr.dimension.clone(),
                    value: fr.value,
                    confidence: 0.6,
                    rubric_version: req.rubric_version.clone(),
                    scope,
                    subject_id: req.subject_id.clone(),
                    source_signal_ids: vec![fr.source_signal_id.clone()],
                    note,
                    created_at: Utc::now(),
                });
            } else {
                // Merge source-signal provenance into the existing judgement.
                if let Some(j) = judgements.iter_mut().find(|j| j.dimension == fr.dimension) {
                    j.source_signal_ids.push(fr.source_signal_id.clone());
                }
            }
        }

        // Emit a judgement for each classified free-text dimension (if any).
        // A dimension the classifier reaches that a rule already fired on
        // does not get a second judgement, but the classifier's contributing
        // signal id must still be attributed on the existing one rather than
        // dropped.
        for (signal_id, dim) in classified_dimensions {
            if seen.insert(dim.clone()) {
                judgements.push(Judgement {
                    id: String::new(),
                    tenant_id: req.tenant_id.clone(),
                    agent_id: req.agent_id.clone(),
                    capability: req.capability.clone(),
                    dimension: dim.clone(),
                    value: -1.0,
                    confidence: 0.4,
                    rubric_version: req.rubric_version.clone(),
                    scope,
                    subject_id: req.subject_id.clone(),
                    source_signal_ids: vec![signal_id.clone()],
                    note: Some("classified from free text".to_string()),
                    created_at: Utc::now(),
                });
            } else if let Some(j) = judgements.iter_mut().find(|j| j.dimension == dim) {
                if !j.source_signal_ids.contains(&signal_id) {
                    j.source_signal_ids.push(signal_id.clone());
                }
            }
        }

        // Ids last, once provenance is merged: the id is a function of the evidence.
        for judgement in &mut judgements {
            judgement.id = judgement_id(judgement);
        }
        Ok(judgements)
    }
}

/// Deterministic judgement id: sha256 over tenant, agent, capability, scope, subject,
/// dimension, rubric version and the sorted source signal ids.
///
/// Re-reducing the same signals (a replayed cursor, a second reducer on the same
/// table) yields the same id, so the store's overwrite-by-id dedupes instead of
/// writing the judgement twice (audit 2026-10-26, finding 12).
fn judgement_id(j: &Judgement) -> String {
    let mut sources: Vec<&str> = j.source_signal_ids.iter().map(String::as_str).collect();
    sources.sort_unstable();
    sources.dedup();
    let mut fields = vec![
        j.tenant_id.as_str(),
        j.agent_id.as_str(),
        j.capability.as_str(),
        j.scope.as_str(),
        j.subject_id.as_deref().unwrap_or(""),
        j.dimension.as_str(),
        j.rubric_version.as_str(),
    ];
    fields.extend(sources);
    let digest = Sha256::digest(crate::receipt::encode_fields_injective(&fields));
    format!("jdg_{}", hex::encode(digest))
}

/// Best-effort text extraction from a signal for classification.
fn signal_text(signal: &Signal) -> Option<String> {
    // Diff/correction signals carry before/after in raw; rating carries text.
    if let Some(after) = signal.raw.get("after").and_then(|v| v.as_str()) {
        return Some(after.to_string());
    }
    if let Some(before) = signal.raw.get("before").and_then(|v| v.as_str()) {
        return Some(before.to_string());
    }
    signal
        .raw
        .get("text")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// Producer id the reduction tick books its watermark under.
///
/// Shares the [`WatermarkStore`](crate::producer::WatermarkStore) with poll producers
/// deliberately: "how far has this consumer got" is the same question whether the
/// consumer is pulling signals in or reducing them onward, and one table answering it
/// for both is one fewer thing to reconcile.
pub const REDUCER_WATERMARK_ID: &str = "reducer";

/// What one capability's reduction needs that the stores cannot supply: its rubric.
///
/// Dimensions and the rubric version come from the agent's declared spec,
/// which reede does not read on the caller's behalf — the owning process knows where
/// its specs live.
#[derive(Debug, Clone)]
pub struct ReductionBinding {
    pub tenant_id: String,
    pub agent_id: String,
    pub capability: String,
    pub rubric_version: String,
    pub dimensions: Vec<RubricDimension>,
}

/// What a tick did, so a caller can log or assert on it rather than guess.
#[derive(Debug, Clone, PartialEq)]
pub struct ReductionOutcome {
    pub signals_read: usize,
    pub judgements_written: usize,
    /// The new watermark, when the tick advanced it. `None` means nothing arrived.
    pub watermark: Option<DateTime<Utc>>,
}

/// Reduce everything that has arrived for one capability since the last tick.
///
/// This is the driver the feedback subsystem was missing. Producers wrote, the surface could read, and
/// nothing in between turned signals into judgements — so every scorecard answered zero
/// however much landed.
///
/// ## Why it pages by arrival, not by observation
///
/// The watermark tracks `ingested_at` and the read is
/// [`SignalStore::ingested_since`]. Tracking `observed_at` instead would look correct
/// and quietly break the one property this layer exists for: a verdict observed five
/// days ago and ingested today sorts *before* the watermark, so the late signal —
/// exactly the kind the feedback subsystem promises to accept — would never be reduced.
///
/// ## Delivery
///
/// At-least-once. Judgements are saved before the watermark advances, so a crash
/// between the two re-reduces that batch on the next tick and can duplicate a
/// judgement. That is the safe direction to fail: a duplicated judgement is visible
/// and correctable, a dropped one is neither. Exactly-once needs a deterministic
/// judgement identity, which is a separate change to [`Judgement`].
///
/// Both scopes are produced from the same batch: one instance judgement per subject
/// that received signals, and one cohort judgement over the whole batch. The reducer
/// itself enforces the boundary — a `cohort_only` signal can never drive an instance
/// judgement.
pub async fn run_reduction_tick<S, J, W>(
    signals: &S,
    judgements: &J,
    watermarks: &W,
    reducer: &MappingReducer,
    binding: &ReductionBinding,
    now: DateTime<Utc>,
) -> Result<ReductionOutcome, ReedeError>
where
    S: SignalStore,
    J: JudgementStore,
    W: crate::producer::WatermarkStore,
{
    let since = watermarks
        .get(
            REDUCER_WATERMARK_ID,
            &binding.tenant_id,
            &binding.agent_id,
            &binding.capability,
        )
        .await?
        // First run for this capability: everything ever ingested is new.
        .unwrap_or(DateTime::<Utc>::MIN_UTC);

    let batch = signals
        .ingested_since(
            &binding.tenant_id,
            &binding.agent_id,
            &binding.capability,
            since,
        )
        .await?;

    if batch.is_empty() {
        return Ok(ReductionOutcome {
            signals_read: 0,
            judgements_written: 0,
            watermark: None,
        });
    }

    let mut written = 0usize;

    // One instance judgement set per subject that received signals in this batch.
    let mut by_subject: HashMap<String, Vec<Signal>> = HashMap::new();
    for signal in &batch {
        by_subject
            .entry(signal.subject_id.clone())
            .or_default()
            .push(signal.clone());
    }
    // Deterministic order so a tick's output does not depend on hash iteration.
    let mut subject_ids: Vec<&String> = by_subject.keys().collect();
    subject_ids.sort();

    for subject_id in subject_ids {
        // The subject's FULL current evidence, not just what arrived in this batch.
        // Two reasons, and the second is why withdrawal works at all: a judgement
        // about an artifact should weigh everything known about it, and a withdrawal
        // arriving alone in a batch would otherwise re-judge the subject on no
        // evidence. `by_subject` already excludes withdrawn signals, so re-reading
        // is what makes the newer judgement reflect the cancellation.
        let evidence = signals
            .by_subject(&binding.tenant_id, subject_id)
            .await
            .unwrap_or_else(|_| by_subject[subject_id].clone())
            .into_iter()
            // A subject may be reused by several agents or capabilities; the
            // binding still defines which evidence this judgement can weigh.
            .filter(|signal| {
                signal.tenant_id == binding.tenant_id
                    && signal.agent_id == binding.agent_id
                    && signal.capability == binding.capability
            })
            .collect();
        let req = ReductionRequest {
            tenant_id: binding.tenant_id.clone(),
            agent_id: binding.agent_id.clone(),
            capability: binding.capability.clone(),
            rubric_version: binding.rubric_version.clone(),
            dimensions: binding.dimensions.clone(),
            subject_id: Some(subject_id.clone()),
            signals: evidence,
        };
        for judgement in reducer.reduce(&req).await? {
            judgements.save(&judgement).await?;
            written += 1;
        }
    }

    // ...and one cohort pass over the whole batch.
    let cohort_req = ReductionRequest {
        tenant_id: binding.tenant_id.clone(),
        agent_id: binding.agent_id.clone(),
        capability: binding.capability.clone(),
        rubric_version: binding.rubric_version.clone(),
        dimensions: binding.dimensions.clone(),
        subject_id: None,
        signals: batch.clone(),
    };
    for judgement in reducer.reduce(&cohort_req).await? {
        judgements.save(&judgement).await?;
        written += 1;
    }

    // Advance to the newest ARRIVAL in the batch rather than to `now`: a signal that
    // lands while this tick is running must not be skipped by a watermark that jumped
    // past it. `now` is taken as an argument only so a caller can pin time in a test.
    let _ = now;
    let high_water = batch.iter().map(|s| s.ingested_at).max().unwrap_or(since);
    watermarks
        .put(
            REDUCER_WATERMARK_ID,
            &binding.tenant_id,
            &binding.agent_id,
            &binding.capability,
            high_water,
        )
        .await?;

    Ok(ReductionOutcome {
        signals_read: batch.len(),
        judgements_written: written,
        watermark: Some(high_water),
    })
}

/// The mapping rule for the diff-capture producer.
///
/// the host runtime emits a `Correction` whose value is the
/// negated normalized edit distance, so the rule fires exactly when a human actually
/// changed something: an untouched draft scores 0.0 and stays silent, any real edit is
/// below zero and scores the dimension weak.
pub fn diff_capture_rule(dimension: &str) -> MappingRule {
    MappingRule {
        source: "diff-capture".to_string(),
        metric: None,
        dimension: dimension.to_string(),
        threshold: 0.0,
        fails_when_below: true,
        cohort_only: false,
    }
}

/// The mapping rule for the thumbs-rating producer.
///
/// Symmetric with [`diff_capture_rule`], and deliberately so: a thumbs-down is
/// `-1.0` and scores the dimension weak, a thumbs-up is `+1.0` and fires nothing.
/// Silence on approval is the same convention diff capture uses — a judgement
/// records that something was found wanting, and "nobody objected" is not a finding.
/// Without this rule a rating reaches the store and stops there, which is exactly
/// the shape of gap the feedback layer keeps producing: recorded, never concluded.
pub fn rating_rule(dimension: &str) -> MappingRule {
    MappingRule {
        source: crate::rating::RATING_SOURCE.to_string(),
        metric: None,
        dimension: dimension.to_string(),
        threshold: 0.0,
        fails_when_below: true,
        cohort_only: false,
    }
}

/// Producer id on a human's decision at a review gate (`+1.0` approve, `-1.0` reject).
///
/// The agent host stamps it (the host runtime's outcome writer, which re-exports
/// this constant, so the producer and the rule cannot name different strings). Reede
/// owns the name because the reducer matches on it: a rule that spelled it differently
/// would leave every decision unjudged without any error.
pub const HITL_DECISION_SOURCE: &str = "hitl-decision";

/// Producer id on a human's action on an agent-surfaced candidate (`+1.0` it led
/// somewhere, `-1.0` it was dismissed). Stamped by the host runtime's
/// the host runtime's outcome writer, which re-exports this constant. See [`HITL_DECISION_SOURCE`].
pub const SCOUT_OUTCOME_SOURCE: &str = "scout-outcome";

/// The interim `accuracy` dimension: how much a human had to change before shipping.
/// Scored by edits ([`diff_capture_rule`]) and ratings ([`rating_rule`]).
pub const INTERIM_ACCURACY_DIMENSION: &str = "accuracy";

/// The interim `acceptance` dimension: whether a human accepted what the agent put in
/// front of them. Scored by review decisions ([`decision_rule`]) and scout outcomes
/// ([`scout_outcome_rule`]).
pub const INTERIM_ACCEPTANCE_DIMENSION: &str = "acceptance";

/// The rubric version a judgement made under [`interim_rules`] and
/// [`interim_dimensions`] records. `interim-1` was `accuracy` alone;
/// `interim-2` adds `acceptance`, so a judgement says which of the two it was made under.
/// Never collides with a declared rubric's version.
pub const INTERIM_RUBRIC_VERSION: &str = "interim-2";

/// The mapping rule for a human decision at a review gate (`hitl-decision`).
///
/// Same convention as [`diff_capture_rule`] and [`rating_rule`]: a rejection is `-1.0`
/// and scores the dimension weak, an approval is `+1.0` and fires nothing, because
/// "nobody objected" is not a finding. Before this rule the reducer dropped every
/// decision the host emitted (a signal no rule names is never judged).
pub fn decision_rule(dimension: &str) -> MappingRule {
    MappingRule {
        source: HITL_DECISION_SOURCE.to_string(),
        metric: None,
        dimension: dimension.to_string(),
        threshold: 0.0,
        fails_when_below: true,
        cohort_only: false,
    }
}

/// The mapping rule for a scout outcome (`scout-outcome`): a dismissed candidate
/// (`-1.0`) scores the dimension weak, an acted-on one (`+1.0`) fires nothing. See
/// [`decision_rule`].
pub fn scout_outcome_rule(dimension: &str) -> MappingRule {
    MappingRule {
        source: SCOUT_OUTCOME_SOURCE.to_string(),
        metric: None,
        dimension: dimension.to_string(),
        threshold: 0.0,
        fails_when_below: true,
        cohort_only: false,
    }
}

/// The interim rubric's dimensions: `accuracy` and `acceptance`.
/// Used until an agent declares its own `agent.rubrics`, which none does today.
pub fn interim_dimensions() -> Vec<RubricDimension> {
    vec![
        RubricDimension {
            id: INTERIM_ACCURACY_DIMENSION.to_string(),
            label: "Accuracy".to_string(),
            description: "How much a human had to change before shipping the output".to_string(),
            weight: 1.0,
        },
        RubricDimension {
            id: INTERIM_ACCEPTANCE_DIMENSION.to_string(),
            label: "Acceptance".to_string(),
            description: "Whether a human accepted what the agent put in front of them".to_string(),
            weight: 1.0,
        },
    ]
}

/// One rule per live human-feedback producer, each under its interim dimension:
/// edits and ratings judge `accuracy`; decisions and scout outcomes judge `acceptance`.
pub fn interim_rules() -> Vec<MappingRule> {
    vec![
        diff_capture_rule(INTERIM_ACCURACY_DIMENSION),
        rating_rule(INTERIM_ACCURACY_DIMENSION),
        decision_rule(INTERIM_ACCEPTANCE_DIMENSION),
        scout_outcome_rule(INTERIM_ACCEPTANCE_DIMENSION),
    ]
}

/// Append-only judgement store (queried/versioned in the Reede surface).
#[async_trait]
pub trait JudgementStore: Send + Sync {
    async fn save(&self, judgement: &Judgement) -> Result<(), ReedeError>;

    /// One judgement by its own id, tenant-scoped.
    ///
    /// Exists so a drilldown can be served from a URL. Without it the only way to
    /// reach a judgement is to list a subject or a cohort and search, which turns a
    /// single-row read into a scan and makes the drilldown's cost a lie.
    async fn get(
        &self,
        tenant_id: &str,
        judgement_id: &str,
    ) -> Result<Option<Judgement>, ReedeError>;

    /// The most recent cohort judgements for a capability, newest first, capped.
    ///
    /// [`JudgementStore::cohort`] returns every cohort judgement ever written, and
    /// that set grows on a machine's clock rather than a human's: the reduction tick
    /// writes one per capability per tick that finds signals. A scorecard wants the
    /// current picture, not the archive, so anything user-facing reads through this.
    async fn cohort_latest(
        &self,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
        limit: usize,
    ) -> Result<Vec<Judgement>, ReedeError>;
    async fn by_subject(
        &self,
        tenant_id: &str,
        subject_id: &str,
    ) -> Result<Vec<Judgement>, ReedeError>;
    async fn cohort(
        &self,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
    ) -> Result<Vec<Judgement>, ReedeError>;
}

/// In-memory judgement store.
pub struct InMemoryJudgementStore {
    rows: Mutex<Vec<Judgement>>,
}

impl InMemoryJudgementStore {
    pub fn new() -> Self {
        Self {
            rows: Mutex::new(Vec::new()),
        }
    }
}

impl Default for InMemoryJudgementStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl JudgementStore for InMemoryJudgementStore {
    async fn save(&self, judgement: &Judgement) -> Result<(), ReedeError> {
        // Overwrite by id, like the Surreal store: a re-reduction must not duplicate.
        let mut rows = self.rows.lock().unwrap();
        rows.retain(|j| !(j.id == judgement.id && j.tenant_id == judgement.tenant_id));
        rows.push(judgement.clone());
        Ok(())
    }

    async fn get(
        &self,
        tenant_id: &str,
        judgement_id: &str,
    ) -> Result<Option<Judgement>, ReedeError> {
        let rows = self.rows.lock().unwrap();
        Ok(rows
            .iter()
            .find(|j| j.id == judgement_id && j.tenant_id == tenant_id)
            .cloned())
    }

    async fn cohort_latest(
        &self,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
        limit: usize,
    ) -> Result<Vec<Judgement>, ReedeError> {
        let rows = self.rows.lock().unwrap();
        let mut out: Vec<Judgement> = rows
            .iter()
            .filter(|j| {
                j.tenant_id == tenant_id
                    && j.agent_id == agent_id
                    && j.capability == capability
                    && j.scope == ReductionScope::Cohort
            })
            .cloned()
            .collect();
        out.sort_by_key(|j| std::cmp::Reverse(j.created_at));
        out.truncate(limit);
        Ok(out)
    }

    async fn by_subject(
        &self,
        tenant_id: &str,
        subject_id: &str,
    ) -> Result<Vec<Judgement>, ReedeError> {
        let rows = self.rows.lock().unwrap();
        let mut out: Vec<Judgement> = rows
            .iter()
            .filter(|j| j.tenant_id == tenant_id && j.subject_id.as_deref() == Some(subject_id))
            .cloned()
            .collect();
        out.sort_by_key(|j| j.created_at);
        Ok(out)
    }

    async fn cohort(
        &self,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
    ) -> Result<Vec<Judgement>, ReedeError> {
        let rows = self.rows.lock().unwrap();
        let mut out: Vec<Judgement> = rows
            .iter()
            .filter(|j| {
                j.tenant_id == tenant_id
                    && j.agent_id == agent_id
                    && j.capability == capability
                    && j.scope == ReductionScope::Cohort
            })
            .cloned()
            .collect();
        out.sort_by_key(|j| j.created_at);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::{
        AttributionSource, InMemorySignalStore, LatencyClass, SignalKind, SignalStore,
    };

    fn metric_signal(
        tenant: &str,
        subject: &str,
        idem: &str,
        value: f64,
        cohort_only: bool,
    ) -> Signal {
        Signal::builder(subject)
            .tenant(tenant)
            .agent("agent-1")
            .capability("copy")
            .source("analytics-poller")
            .kind(SignalKind::Metric)
            .value(value)
            .raw(serde_json::json!({ "scroll_depth": value }))
            .cohort_only(cohort_only)
            .latency(LatencyClass::Delayed)
            .idempotency(idem)
            .run("run-1")
            .build()
    }

    fn diff_signal(subject: &str, after: &str) -> Signal {
        Signal::builder(subject)
            .tenant("tenant-1")
            .agent("agent-1")
            .capability("copy")
            .source("diff-capture")
            .kind(SignalKind::Correction)
            .value(-1.0)
            .raw(serde_json::json!({ "after": after }))
            .latency(LatencyClass::Immediate)
            .idempotency(format!("diff:{subject}:section"))
            .run("run-1")
            .build()
    }

    fn copy_dimensions() -> Vec<RubricDimension> {
        vec![
            RubricDimension {
                id: "hook".into(),
                label: "Hook".into(),
                description: "opening that pulls the reader in".into(),
                weight: 1.0,
            },
            RubricDimension {
                id: "structure".into(),
                label: "Structure".into(),
                description: "reading flow".into(),
                weight: 1.0,
            },
            RubricDimension {
                id: "tone".into(),
                label: "Tone".into(),
                description: "brand voice".into(),
                weight: 1.0,
            },
        ]
    }

    fn reduce_req(subject: Option<&str>, signals: Vec<Signal>) -> ReductionRequest {
        ReductionRequest {
            tenant_id: "tenant-1".into(),
            agent_id: "agent-1".into(),
            capability: "copy".into(),
            rubric_version: "r1".into(),
            dimensions: copy_dimensions(),
            subject_id: subject.map(str::to_string),
            signals,
        }
    }

    #[tokio::test]
    async fn test_mapping_reducer_instance_uses_mapping_rule() {
        let store = InMemorySignalStore::new();
        // A diff correction on the hook: rewritten passage mentions 'hook opening'.
        let diff = diff_signal("sub_article_1", "The hook, now a sharper opening line.");
        let stored = store.append(diff).await.unwrap();

        let mut classifier_kw = KeywordClassifier::new();
        classifier_kw = classifier_kw
            .add_dimension("hook", vec!["hook", "opening"])
            .add_dimension("structure", vec!["structure", "flow"]);

        let reducer =
            MappingReducer::new(vec![]).with_classifier(std::sync::Arc::new(classifier_kw));
        let judgements = reducer
            .reduce(&reduce_req(Some("sub_article_1"), vec![stored]))
            .await
            .unwrap();

        assert!(
            judgements.iter().any(|j| j.dimension == "hook"),
            "diff classified to hook"
        );
        assert!(judgements
            .iter()
            .all(|j| j.scope == ReductionScope::Instance));
        assert!(judgements
            .iter()
            .all(|j| j.subject_id.as_deref() == Some("sub_article_1")));
        assert!(judgements.iter().all(|j| j.rubric_version == "r1"));
    }

    #[tokio::test]
    async fn test_mapping_rule_analytics_below_threshold_dimension() {
        // "scroll depth below baseline -> hook, negative": a cohort rule.
        let rule = MappingRule {
            source: "analytics-poller".to_string(),
            metric: Some("scroll_depth".to_string()),
            dimension: "hook".to_string(),
            threshold: 0.5,
            fails_when_below: true,
            cohort_only: true,
        };
        let reducer = MappingReducer::new(vec![rule]);

        let signal = metric_signal("tenant-1", "sub_1", "a:1", 0.2, true); // below threshold -> weak hook
        let store = InMemorySignalStore::new();
        let stored = store.append(signal).await.unwrap();

        let judgements = reducer
            .reduce(&reduce_req(None, vec![stored]))
            .await
            .unwrap();
        assert_eq!(judgements.len(), 1);
        assert_eq!(judgements[0].dimension, "hook");
        assert!(
            judgements[0].is_negative(),
            "below threshold is a negative hook judgement"
        );
        assert_eq!(judgements[0].scope, ReductionScope::Cohort);
        assert!(judgements[0].note.as_deref().unwrap().contains("fell"));
    }

    /// Finding 12 (audit 2026-10-26): reducing the same signals twice must overwrite,
    /// not duplicate, and the id must still separate a different rubric.
    #[tokio::test]
    async fn reducing_the_same_batch_twice_leaves_one_judgement_row() {
        let rule = MappingRule {
            source: "analytics-poller".to_string(),
            metric: Some("scroll_depth".to_string()),
            dimension: "hook".to_string(),
            threshold: 0.5,
            fails_when_below: true,
            cohort_only: true,
        };
        let reducer = MappingReducer::new(vec![rule]);
        let store = InMemorySignalStore::new();
        let a = store
            .append(metric_signal("tenant-1", "sub_1", "a:1", 0.2, true))
            .await
            .unwrap();
        let b = store
            .append(metric_signal("tenant-1", "sub_1", "a:2", 0.1, true))
            .await
            .unwrap();
        let judgements = InMemoryJudgementStore::new();

        let first = reducer
            .reduce(&reduce_req(None, vec![a.clone(), b.clone()]))
            .await
            .unwrap();
        // Same signals in the other order: the id sorts its sources.
        let second = reducer
            .reduce(&reduce_req(None, vec![b.clone(), a.clone()]))
            .await
            .unwrap();
        for j in first.iter().chain(&second) {
            judgements.save(j).await.unwrap();
        }
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].id, second[0].id);
        assert_eq!(
            judgements
                .cohort("tenant-1", "agent-1", "copy")
                .await
                .unwrap()
                .len(),
            1
        );

        let mut other_rubric = reduce_req(None, vec![a, b]);
        other_rubric.rubric_version = "r2".into();
        let third = reducer.reduce(&other_rubric).await.unwrap();
        assert_ne!(third[0].id, first[0].id);
    }

    #[tokio::test]
    async fn test_cohort_only_signal_cannot_produce_instance_judgement() {
        // Identity: an analytics (cohort_only) signal must NOT yield an instance
        // judgement even if a rule would fire on it.
        let rule = MappingRule {
            source: "analytics-poller".to_string(),
            metric: Some("scroll_depth".to_string()),
            dimension: "hook".to_string(),
            threshold: 0.5,
            fails_when_below: true,
            cohort_only: true,
        };
        let reducer = MappingReducer::new(vec![rule]);
        let signal = metric_signal("tenant-1", "sub_1", "a:1", 0.2, true);
        let store = InMemorySignalStore::new();
        let stored = store.append(signal).await.unwrap();

        let judgements = reducer
            .reduce(&reduce_req(Some("sub_1"), vec![stored]))
            .await
            .unwrap();
        assert!(
            judgements.is_empty(),
            "cohort_only signal must not yield an instance judgement"
        );
    }

    #[tokio::test]
    async fn test_instance_and_cohort_are_distinct_judgements() {
        // Acceptance: an article with a human correction AND a weak analytics
        // cohort shows two distinct dimension judgements, not a blurred score.
        let diff = diff_signal("sub_1", "The structure needs reflowing badly.");
        let analytics = metric_signal("tenant-1", "sub_1", "a:1", 0.2, true);

        let mut classifier_kw = KeywordClassifier::new();
        classifier_kw = classifier_kw.add_dimension("structure", vec!["structure", "reflow"]);

        // Instance reducer over the correction only (cohort signal excluded by
        // the boundary), so the diff -> structure is the singular instance read.
        let reducer =
            MappingReducer::new(vec![]).with_classifier(std::sync::Arc::new(classifier_kw));
        let instance = reducer
            .reduce(&reduce_req(Some("sub_1"), vec![diff]))
            .await
            .unwrap();
        assert!(instance.iter().any(|j| j.scope == ReductionScope::Instance));

        // Cohort reducer over analytics -> hook, negative.
        let cohort_rule = MappingRule {
            source: "analytics-poller".to_string(),
            metric: Some("scroll_depth".to_string()),
            dimension: "hook".to_string(),
            threshold: 0.5,
            fails_when_below: true,
            cohort_only: true,
        };
        let cohort_reducer = MappingReducer::new(vec![cohort_rule]);
        let cohort = cohort_reducer
            .reduce(&reduce_req(None, vec![analytics]))
            .await
            .unwrap();
        assert!(cohort
            .iter()
            .any(|j| j.dimension == "hook" && j.scope == ReductionScope::Cohort));

        // Distinct semantic readouts: instance dimension != cohort dimension here.
        assert!(
            instance.iter().any(|j| j.dimension == "structure"),
            "human correction read as structure"
        );
        assert!(
            !instance.iter().any(|j| j.dimension == "hook"),
            "analytics hook signal does not contaminate the instance judgement"
        );
    }

    #[tokio::test]
    async fn test_judgement_traceable_to_source_signals() {
        let reducer = MappingReducer::new(vec![MappingRule {
            source: "analytics-poller".to_string(),
            metric: Some("scroll_depth".to_string()),
            dimension: "hook".to_string(),
            threshold: 0.5,
            fails_when_below: true,
            cohort_only: true,
        }]);
        let signal = metric_signal("tenant-1", "sub_1", "a:1", 0.1, true);
        let store = InMemorySignalStore::new();
        let stored = store.append(signal).await.unwrap();

        let judgements = reducer
            .reduce(&reduce_req(None, vec![stored.clone()]))
            .await
            .unwrap();
        assert_eq!(
            judgements[0].source_signal_ids,
            vec![stored.id.clone()],
            "judgement traces back to the exact source signal id"
        );
    }

    #[tokio::test]
    async fn test_judgement_store_scopes_instance_and_cohort() {
        let store = InMemoryJudgementStore::new();
        let r = MappingReducer::new(vec![MappingRule {
            source: "analytics-poller".to_string(),
            metric: Some("scroll_depth".to_string()),
            dimension: "hook".to_string(),
            threshold: 0.5,
            fails_when_below: true,
            cohort_only: true,
        }]);

        let analytic = metric_signal("tenant-1", "sub_1", "a:1", 0.2, true);
        let sig_store = InMemorySignalStore::new();
        let stored_a = sig_store.append(analytic).await.unwrap();

        let cohort = r.reduce(&reduce_req(None, vec![stored_a])).await.unwrap();
        for j in &cohort {
            store.save(j).await.unwrap();
        }
        let cohort_back = store.cohort("tenant-1", "agent-1", "copy").await.unwrap();
        assert_eq!(cohort_back.len(), 1);
        assert!(cohort_back[0].scope == ReductionScope::Cohort);
        assert!(store
            .by_subject("tenant-1", "sub_1")
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn test_rule_uses_signal_value_when_no_metric_key() {
        let reducer = MappingReducer::new(vec![MappingRule {
            source: "rating".to_string(),
            metric: None,
            dimension: "tone".to_string(),
            threshold: 0.0,
            fails_when_below: true,
            cohort_only: false,
        }]);
        // A rating with value 0.0 => fails_when_below threshold 0.0 is not <0, so no fire.
        let sig = Signal::builder("sub_1")
            .tenant("tenant-1")
            .agent("agent-1")
            .capability("copy")
            .source("rating")
            .kind(SignalKind::Rating)
            .value(-0.5)
            .raw(serde_json::json!({}))
            .latency(LatencyClass::Immediate)
            .idempotency("rating:1")
            .run("run-1")
            .build();
        let judgements = reducer
            .reduce(&reduce_req(Some("sub_1"), vec![sig]))
            .await
            .unwrap();
        assert!(judgements
            .iter()
            .any(|j| j.dimension == "tone" && j.is_negative()));
    }

    #[tokio::test]
    async fn test_classifier_dimension_merges_signal_id_when_rule_already_fired() {
        let store = InMemorySignalStore::new();
        // A diff correction fires the "hook" rule directly (source = diff-capture).
        let diff = diff_signal("sub_article_1", "irrelevant replacement text");
        let rule_signal = store.append(diff).await.unwrap();

        // A second, unrelated-source signal (not matched by any rule) whose free
        // text the classifier maps to the SAME "hook" dimension.
        let rating = Signal::builder("sub_article_1")
            .tenant("tenant-1")
            .agent("agent-1")
            .capability("copy")
            .source("rating-widget")
            .kind(SignalKind::Rating)
            .value(-1.0)
            .raw(serde_json::json!({ "text": "the hook falls flat" }))
            .latency(LatencyClass::Immediate)
            .idempotency("rating:sub_article_1:1")
            .run("run-1")
            .build();
        let classified_signal = store.append(rating).await.unwrap();

        let rule = MappingRule {
            source: "diff-capture".to_string(),
            metric: None,
            dimension: "hook".to_string(),
            threshold: -0.5,
            fails_when_below: true,
            cohort_only: false,
        };
        let classifier = KeywordClassifier::new().add_dimension("hook", vec!["hook"]);
        let reducer =
            MappingReducer::new(vec![rule]).with_classifier(std::sync::Arc::new(classifier));

        let judgements = reducer
            .reduce(&reduce_req(
                Some("sub_article_1"),
                vec![rule_signal.clone(), classified_signal.clone()],
            ))
            .await
            .unwrap();

        let hook_judgements: Vec<_> = judgements
            .iter()
            .filter(|j| j.dimension == "hook")
            .collect();
        assert_eq!(
            hook_judgements.len(),
            1,
            "rule and classifier agreeing on one dimension must not double-emit"
        );
        assert!(hook_judgements[0]
            .source_signal_ids
            .contains(&rule_signal.id));
        assert!(
            hook_judgements[0]
                .source_signal_ids
                .contains(&classified_signal.id),
            "classifier's contributing signal id must not be dropped when a rule already produced the dimension"
        );
    }

    // ─── the reduction tick ───────────────────────────────────────

    use crate::producer::InMemoryWatermarkStore;

    fn accuracy_rubric() -> Vec<RubricDimension> {
        vec![RubricDimension {
            id: "accuracy".to_string(),
            label: "Accuracy".to_string(),
            description: "Did the agent get the facts right".to_string(),
            weight: 1.0,
        }]
    }

    fn binding() -> ReductionBinding {
        ReductionBinding {
            tenant_id: "tenant-a".to_string(),
            agent_id: "kira-agent".to_string(),
            capability: "council-summary".to_string(),
            rubric_version: "v1".to_string(),
            dimensions: accuracy_rubric(),
        }
    }

    /// A diff-capture correction, exactly as the runtime emits one.
    fn correction(subject: &str, key: &str, edit_distance: f64, observed: DateTime<Utc>) -> Signal {
        Signal {
            id: String::new(),
            subject_id: subject.to_string(),
            tenant_id: "tenant-a".to_string(),
            agent_id: "kira-agent".to_string(),
            capability: "council-summary".to_string(),
            source: "diff-capture".to_string(),
            source_version: "1".to_string(),
            kind: SignalKind::Correction,
            dimension: Some("accuracy".to_string()),
            value: -edit_distance,
            raw: serde_json::json!({ "normalized_edit_distance": edit_distance }),
            confidence: 1.0,
            latency_class: LatencyClass::Immediate,
            observed_at: observed,
            ingested_at: observed,
            idempotency_key: key.to_string(),
            cohort_only: false,
            // A diff-capture correction is the canonical *explicit* attribution
            // (D5): the section the human edited is the attribution, so the
            // runtime does not have to infer anything.
            run_id: "run-1".to_string(),
            role: Some("council-summary/summarize".to_string()),
            attribution_source: AttributionSource::Explicit,
            derived_from: vec![],
        }
    }

    async fn tick(
        signals: &InMemorySignalStore,
        judgements: &InMemoryJudgementStore,
        watermarks: &InMemoryWatermarkStore,
    ) -> ReductionOutcome {
        let reducer = MappingReducer::new(vec![diff_capture_rule("accuracy")]);
        run_reduction_tick(
            signals,
            judgements,
            watermarks,
            &reducer,
            &binding(),
            Utc::now(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn shared_subject_evidence_stays_with_its_agent_and_capability() {
        let signals = InMemorySignalStore::new();
        let judgements = InMemoryJudgementStore::new();
        let watermarks = InMemoryWatermarkStore::new();
        let own = signals
            .append(correction("shared", "own", 0.25, Utc::now()))
            .await
            .unwrap();
        for (key, tenant, agent, capability) in [
            ("other-capability", "tenant-a", "kira-agent", "other"),
            ("other-agent", "tenant-a", "other-agent", "council-summary"),
            ("other-tenant", "tenant-b", "kira-agent", "council-summary"),
        ] {
            let mut foreign = correction("shared", key, 1.0, Utc::now());
            foreign.tenant_id = tenant.to_string();
            foreign.agent_id = agent.to_string();
            foreign.capability = capability.to_string();
            foreign.role = Some(format!("{capability}/summarize"));
            signals.append(foreign).await.unwrap();
        }
        let outcome = tick(&signals, &judgements, &watermarks).await;
        assert_eq!(outcome.signals_read, 1);
        let instance = judgements.by_subject("tenant-a", "shared").await.unwrap();
        assert_eq!(instance.len(), 1);
        assert_eq!(instance[0].source_signal_ids, vec![own.id]);
        assert_eq!(instance[0].value, -1.0);
        assert!(instance[0].note.as_deref().unwrap().contains("value -0.25"));
    }

    #[tokio::test]
    async fn a_human_edit_becomes_a_judgement() {
        let (signals, judgements, watermarks) = (
            InMemorySignalStore::new(),
            InMemoryJudgementStore::new(),
            InMemoryWatermarkStore::new(),
        );
        signals
            .append(correction("sub_1", "diff-capture:run-1", 0.25, Utc::now()))
            .await
            .unwrap();

        let outcome = tick(&signals, &judgements, &watermarks).await;
        assert_eq!(outcome.signals_read, 1);
        assert!(
            outcome.judgements_written >= 1,
            "the empty middle must not stay empty"
        );

        let instance = judgements.by_subject("tenant-a", "sub_1").await.unwrap();
        assert_eq!(instance.len(), 1);
        assert_eq!(instance[0].dimension, "accuracy");
        assert!(
            instance[0].is_negative(),
            "an edit scores the dimension weak"
        );
        assert_eq!(instance[0].rubric_version, "v1");
        assert_eq!(instance[0].source_signal_ids.len(), 1, "provenance is kept");
    }

    #[tokio::test]
    async fn an_untouched_draft_produces_no_judgement() {
        // Distance 0.0 means the human shipped the draft as written. That is not
        // evidence of weakness and must not be scored as any.
        let (signals, judgements, watermarks) = (
            InMemorySignalStore::new(),
            InMemoryJudgementStore::new(),
            InMemoryWatermarkStore::new(),
        );
        signals
            .append(correction("sub_1", "diff-capture:run-1", 0.0, Utc::now()))
            .await
            .unwrap();

        let outcome = tick(&signals, &judgements, &watermarks).await;
        assert_eq!(outcome.signals_read, 1);
        assert_eq!(outcome.judgements_written, 0);
    }

    #[tokio::test]
    async fn a_second_tick_does_not_re_reduce_the_same_signals() {
        let (signals, judgements, watermarks) = (
            InMemorySignalStore::new(),
            InMemoryJudgementStore::new(),
            InMemoryWatermarkStore::new(),
        );
        signals
            .append(correction("sub_1", "diff-capture:run-1", 0.4, Utc::now()))
            .await
            .unwrap();

        let first = tick(&signals, &judgements, &watermarks).await;
        assert!(first.judgements_written > 0);
        let before = judgements
            .by_subject("tenant-a", "sub_1")
            .await
            .unwrap()
            .len();

        let second = tick(&signals, &judgements, &watermarks).await;
        assert_eq!(second.signals_read, 0, "the watermark held");
        assert_eq!(second.watermark, None);
        assert_eq!(
            judgements
                .by_subject("tenant-a", "sub_1")
                .await
                .unwrap()
                .len(),
            before
        );
    }

    #[tokio::test]
    async fn a_late_signal_is_still_reduced() {
        // The property the whole layer exists for, and the one a naive watermark on
        // observed_at would silently break: this signal happened five days ago and
        // arrives now, AFTER a tick has already run and moved the watermark.
        let (signals, judgements, watermarks) = (
            InMemorySignalStore::new(),
            InMemoryJudgementStore::new(),
            InMemoryWatermarkStore::new(),
        );
        signals
            .append(correction("sub_1", "diff-capture:run-1", 0.3, Utc::now()))
            .await
            .unwrap();
        tick(&signals, &judgements, &watermarks).await;

        // Observed five days ago; ingested (by append) right now.
        signals
            .append(correction(
                "sub_late",
                "diff-capture:run-late",
                0.6,
                Utc::now() - chrono::Duration::days(5),
            ))
            .await
            .unwrap();

        let outcome = tick(&signals, &judgements, &watermarks).await;
        assert_eq!(
            outcome.signals_read, 1,
            "the late arrival must be picked up"
        );
        let late = judgements.by_subject("tenant-a", "sub_late").await.unwrap();
        assert_eq!(
            late.len(),
            1,
            "a five-day-late signal still earns its judgement"
        );
    }

    #[tokio::test]
    async fn each_subject_is_judged_separately_and_the_cohort_once() {
        let (signals, judgements, watermarks) = (
            InMemorySignalStore::new(),
            InMemoryJudgementStore::new(),
            InMemoryWatermarkStore::new(),
        );
        for (subject, key) in [("sub_1", "k1"), ("sub_2", "k2")] {
            signals
                .append(correction(subject, key, 0.5, Utc::now()))
                .await
                .unwrap();
        }

        tick(&signals, &judgements, &watermarks).await;

        assert_eq!(
            judgements
                .by_subject("tenant-a", "sub_1")
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            judgements
                .by_subject("tenant-a", "sub_2")
                .await
                .unwrap()
                .len(),
            1
        );
        let cohort = judgements
            .cohort("tenant-a", "kira-agent", "council-summary")
            .await
            .unwrap();
        assert_eq!(
            cohort.len(),
            1,
            "one cohort judgement over the batch, not one per subject"
        );
    }

    #[tokio::test]
    async fn a_withdrawal_is_never_scored_as_evidence() {
        // A withdrawal carries its producer's `source`, so without the explicit skip a
        // rating rule would fire on the act of taking a rating back.
        let (signals, judgements, watermarks) = (
            InMemorySignalStore::new(),
            InMemoryJudgementStore::new(),
            InMemoryWatermarkStore::new(),
        );
        let mut wd = correction("sub_1", "wd:1", 0.0, Utc::now());
        wd.kind = SignalKind::Withdrawal;
        wd.value = 0.0;
        wd.dimension = None;
        wd.derived_from = vec!["diff-capture:run-1".to_string()];
        signals.append(wd).await.unwrap();

        let outcome = tick(&signals, &judgements, &watermarks).await;
        assert_eq!(outcome.signals_read, 1, "the withdrawal itself is read");
        assert_eq!(outcome.judgements_written, 0, "but it scores nothing");
    }

    #[tokio::test]
    async fn withdrawing_the_evidence_changes_the_next_verdict() {
        // The propagation decision, end to end: the original judgement stands as a
        // historical fact, and a re-reduction after the withdrawal produces a newer
        // judgement that no longer rests on the retracted signal.
        let (signals, judgements, watermarks) = (
            InMemorySignalStore::new(),
            InMemoryJudgementStore::new(),
            InMemoryWatermarkStore::new(),
        );
        signals
            .append(correction("sub_1", "diff-capture:run-1", 0.5, Utc::now()))
            .await
            .unwrap();

        let first = tick(&signals, &judgements, &watermarks).await;
        assert!(first.judgements_written > 0, "a weak score was recorded");
        let before = judgements.by_subject("tenant-a", "sub_1").await.unwrap();
        assert_eq!(before.len(), 1);
        assert!(before[0].is_negative());

        // The human takes it back.
        let mut wd = correction("sub_1", "wd:1", 0.0, Utc::now());
        wd.kind = SignalKind::Withdrawal;
        wd.value = 0.0;
        wd.dimension = None;
        wd.derived_from = vec!["diff-capture:run-1".to_string()];
        signals.append(wd).await.unwrap();

        let second = tick(&signals, &judgements, &watermarks).await;
        assert_eq!(second.signals_read, 1, "the withdrawal arrived");
        assert_eq!(
            second.judgements_written, 0,
            "re-reducing a subject whose only evidence was withdrawn yields no new score"
        );

        // The original judgement is still there - it was true when it was made.
        let after = judgements.by_subject("tenant-a", "sub_1").await.unwrap();
        assert_eq!(after.len(), 1, "history is not rewritten");

        // And the withdrawn signal is invisible to anything reading the evidence.
        assert!(
            !signals
                .by_subject("tenant-a", "sub_1")
                .await
                .unwrap()
                .iter()
                .any(|s| s.idempotency_key == "diff-capture:run-1"),
            "the retracted signal no longer counts as evidence"
        );
    }

    // -- the rules for the signals the host emits ------------

    /// A human decision or scout outcome, exactly as the host runtime's outcome writer emits one.
    fn outcome(source: &str, subject: &str, key: &str, value: f64) -> Signal {
        Signal::builder(subject)
            .tenant("tenant-a")
            .agent("kira-agent")
            .capability("council-summary")
            .source(source)
            .kind(SignalKind::Outcome)
            .dimension("engagement")
            .value(value)
            .raw(serde_json::json!({ "decision": if value > 0.0 { "approve" } else { "reject" } }))
            .latency(LatencyClass::Immediate)
            .idempotency(key)
            .run("run-1")
            .build()
    }

    fn interim_binding() -> ReductionBinding {
        ReductionBinding {
            rubric_version: INTERIM_RUBRIC_VERSION.to_string(),
            dimensions: interim_dimensions(),
            ..binding()
        }
    }

    async fn tick_with(rules: Vec<MappingRule>, signals: &InMemorySignalStore) -> Vec<Judgement> {
        let judgements = InMemoryJudgementStore::new();
        let reducer = MappingReducer::new(rules);
        run_reduction_tick(
            signals,
            &judgements,
            &InMemoryWatermarkStore::new(),
            &reducer,
            &interim_binding(),
            Utc::now(),
        )
        .await
        .unwrap();
        judgements.by_subject("tenant-a", "sub_1").await.unwrap()
    }

    #[tokio::test]
    async fn a_rejected_review_becomes_a_weak_acceptance_judgement() {
        let signals = InMemorySignalStore::new();
        let stored = signals
            .append(outcome(
                HITL_DECISION_SOURCE,
                "sub_1",
                "hitl-decision:run-1:gate",
                -1.0,
            ))
            .await
            .unwrap();

        let found = tick_with(interim_rules(), &signals).await;

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].dimension, INTERIM_ACCEPTANCE_DIMENSION);
        assert!(found[0].is_negative());
        assert_eq!(found[0].scope, ReductionScope::Instance);
        assert_eq!(found[0].rubric_version, INTERIM_RUBRIC_VERSION);
        assert_eq!(found[0].source_signal_ids, vec![stored.id]);
    }

    #[tokio::test]
    async fn an_approved_review_fires_nothing() {
        let signals = InMemorySignalStore::new();
        signals
            .append(outcome(
                HITL_DECISION_SOURCE,
                "sub_1",
                "hitl-decision:run-1:gate",
                1.0,
            ))
            .await
            .unwrap();

        assert!(tick_with(interim_rules(), &signals).await.is_empty());
    }

    #[tokio::test]
    async fn a_dismissed_scout_candidate_becomes_a_weak_acceptance_judgement() {
        let signals = InMemorySignalStore::new();
        let stored = signals
            .append(outcome(
                SCOUT_OUTCOME_SOURCE,
                "sub_1",
                "scout-outcome:run-1:entry-9",
                -1.0,
            ))
            .await
            .unwrap();

        let found = tick_with(interim_rules(), &signals).await;

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].dimension, INTERIM_ACCEPTANCE_DIMENSION);
        assert!(found[0].is_negative());
        assert_eq!(found[0].source_signal_ids, vec![stored.id]);
    }

    #[tokio::test]
    async fn an_acted_on_scout_candidate_fires_nothing() {
        let signals = InMemorySignalStore::new();
        signals
            .append(outcome(
                SCOUT_OUTCOME_SOURCE,
                "sub_1",
                "scout-outcome:run-1:entry-9",
                1.0,
            ))
            .await
            .unwrap();

        assert!(tick_with(interim_rules(), &signals).await.is_empty());
    }

    #[tokio::test]
    async fn an_edit_and_a_rejection_on_one_run_are_judged_on_their_own_dimensions() {
        let signals = InMemorySignalStore::new();
        signals
            .append(correction("sub_1", "diff-capture:run-1", 0.4, Utc::now()))
            .await
            .unwrap();
        signals
            .append(outcome(
                HITL_DECISION_SOURCE,
                "sub_1",
                "hitl-decision:run-1:gate",
                -1.0,
            ))
            .await
            .unwrap();

        let found = tick_with(interim_rules(), &signals).await;

        let mut dims: Vec<&str> = found.iter().map(|j| j.dimension.as_str()).collect();
        dims.sort_unstable();
        assert_eq!(
            dims,
            vec![INTERIM_ACCEPTANCE_DIMENSION, INTERIM_ACCURACY_DIMENSION]
        );
        assert!(found.iter().all(Judgement::is_negative));
    }

    /// The existing rules keep their behaviour: the two rules the live reducer runs
    /// today produce the same judgement from the same signals whether or not the new
    /// rules sit beside them, and a decision signal is still ignored without the new rule.
    #[tokio::test]
    async fn the_existing_rules_judge_an_edit_and_a_rating_as_before() {
        let signals = InMemorySignalStore::new();
        signals
            .append(correction("sub_1", "diff-capture:run-1", 0.25, Utc::now()))
            .await
            .unwrap();
        let mut rating = outcome("rating", "sub_1", "rating:run-1", -1.0);
        rating.kind = SignalKind::Rating;
        signals.append(rating).await.unwrap();
        signals
            .append(outcome(
                HITL_DECISION_SOURCE,
                "sub_1",
                "hitl-decision:run-1:gate",
                -1.0,
            ))
            .await
            .unwrap();

        let live_today = vec![
            diff_capture_rule(INTERIM_ACCURACY_DIMENSION),
            rating_rule(INTERIM_ACCURACY_DIMENSION),
        ];
        let before = tick_with(live_today, &signals).await;
        let after = tick_with(interim_rules(), &signals).await;

        // Without the new rules the decision is dropped: one accuracy judgement,
        // citing the edit and the rating.
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].dimension, INTERIM_ACCURACY_DIMENSION);
        assert_eq!(before[0].source_signal_ids.len(), 2);

        // With them, the accuracy judgement is unchanged and one acceptance one is added.
        let accuracy: Vec<&Judgement> = after
            .iter()
            .filter(|j| j.dimension == INTERIM_ACCURACY_DIMENSION)
            .collect();
        assert_eq!(accuracy.len(), 1);
        assert_eq!(accuracy[0].value, before[0].value);
        assert_eq!(accuracy[0].confidence, before[0].confidence);
        assert_eq!(accuracy[0].source_signal_ids, before[0].source_signal_ids);
        assert_eq!(after.len(), 2);
    }

    #[test]
    fn the_interim_rules_name_every_live_feedback_source() {
        let rules = interim_rules();
        let sources: Vec<&str> = rules.iter().map(|r| r.source.as_str()).collect();
        for live in [
            "diff-capture",
            crate::rating::RATING_SOURCE,
            HITL_DECISION_SOURCE,
            SCOUT_OUTCOME_SOURCE,
        ] {
            assert!(sources.contains(&live), "no interim rule for source {live}");
        }
        // The names the emitters stamp are literals in other crates; pin them here so a
        // rename on either side fails a test instead of silently un-judging a source.
        assert_eq!(HITL_DECISION_SOURCE, "hitl-decision");
        assert_eq!(SCOUT_OUTCOME_SOURCE, "scout-outcome");
    }

    #[test]
    fn every_interim_rule_scores_a_declared_interim_dimension() {
        let declared: Vec<String> = interim_dimensions().into_iter().map(|d| d.id).collect();
        for rule in interim_rules() {
            assert!(
                declared.contains(&rule.dimension),
                "rule for {} scores undeclared dimension {}",
                rule.source,
                rule.dimension
            );
        }
    }
}
