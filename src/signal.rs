//! Signal envelope and append-only store.
//!
//! One normalized envelope for every kind of agent feedback, stored append-only
//! so a run is never "closed". Late writes are always accepted: a thumbs-down
//! arrives in 10 seconds, an analytics verdict in 5 days, a closed deal in 3
//! months - same envelope, different latency class. Anything that references a
//! durable `Subject` can land here at any time.
//!
//! Envelope fields follow the signal contract:
//!   subject_id, tenant, agent_id, capability
//!   source, source_version
//!   kind: rating | correction | metric | outcome | verdict | response
//!   dimension (optional; set by a producer or attached by a derived judgement)
//!   value (normalized numeric) + raw payload
//!
//! `SignalKind::Response` is the open-question payload -- an
//! answer to a business inquiry, not a judgement on agent output. The envelope
//! stretches to carry it (subject/tenant/source/confidence/latency/timestamps/
//! idempotency/derived_from are all generic), with two explicit conventions
//! rather than silently repurposing fields for something the doc comments
//! don't say they mean:
//!   * `raw` carries the actual payload: `{"question": ..., "answer": ...}` at
//!     minimum. This is the natural fit -- `raw` already exists precisely for
//!     "unstructured payload the normalized fields don't capture".
//!   * `value` and `dimension` carry no meaning for `Response` and MUST be left
//!     at their defaults (`0.0` / `None`). A response is not scored against a
//!     rubric dimension in `[-1, 1]`; forcing a placeholder number into a
//!     required field to make the type check is exactly the "bending the
//!     rubric model to fit" the design says not to do, so this is enforced in
//!     `SignalStore::append` (fail closed), not left as an unchecked
//!     convention a future producer could quietly violate.
//!
//! What does NOT stretch: `Judgement` (reducer.rs) requires a rubric
//! `dimension: String` and a `value` in `[-1, 1]` -- that is a quality score
//! against a declared capability rubric, not "what did this claim turn out to
//! be". A inquiry claim (many free-text responses reduced to one statement with
//! evidence) needs a sibling reducer output type, not `Judgement` reused.
//! Deliberately not built here: the design gates synthesis on the durable store (the
//! eval-harness/persistent-store rework) landing first.
//!   confidence, latency_class (immediate | delayed | terminal)
//!   observed_at and ingested_at kept separate
//!   idempotency_key per producer so pollers can re-run safely
//!
//! Store rules enforced here:
//!   * append-only evidence: identity, attribution and scores are immutable. Q6
//!     permits only captured `raw.input` payload expiry; its digest/deadline stay.
//!   * "corrections are new rows, not updates" - a corrected signal is appended
//!     as a fresh row, never written over the original.
//!   * late writes always accepted; nothing ever closes a subject.
//!   * idempotency: a poller re-pushing the same natural event yields the
//!     already-stored row and does not duplicate it.
//!   * indices modelled for `subject_id` and `(agent_id, capability,
//!     observed_at)` (the cohort query shape).
//!
//! A reducer that wants to attach a `dimension` to an existing signal
//! does NOT mutate the base row. It appends a new derived judgement row (kind
//! `Outcome`) that carries the dimension and the source signal's
//! `idempotency_key` as provenance. Base rows stay immutable; judgements stay
//! traceable to the exact signals that produced them.

use crate::error::ReedeError;
use crate::role::RoleKey;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use uuid::Uuid;

/// Human-readable prefix for a signal row id.
pub const SIGNAL_ID_PREFIX: &str = "sig";

/// The six signal kinds. Normalized across every producer so a rating, an
/// analytics metric, a HITL outcome, an email reply, and an inquiry answer
/// share one envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SignalKind {
    /// Explicit human thumbs/judgement ("ok, but improve X").
    Rating,
    /// A structured change the human made to an output before shipping (diff).
    Correction,
    /// A measured number (impressions, scroll depth, click rate, ...).
    Metric,
    /// A closed outcome (deal won, task result, HITL gate result).
    Outcome,
    /// An automated review verdict (e.g. nakiek).
    Verdict,
    /// a free-text answer to an open business inquiry, not
    /// a judgement on agent output. `value`/`dimension` carry no meaning for
    /// this kind -- see the module doc comment.
    Response,
    /// cancels an earlier signal. `derived_from` names exactly one
    /// idempotency key -- the signal being withdrawn.
    ///
    /// A withdrawal is a *later fact about an earlier one*, never an edit to it:
    /// the original row stays exactly as appended, and the audit trail keeps who
    /// withdrew and when. Reads exclude the cancelled signal; the withdrawal
    /// itself is returned, because a consumer needs to see that it happened.
    ///
    /// This is "I take that back", not "erase my data". Erasure is a retention
    /// concern and needs its own path.
    Withdrawal,
}

impl SignalKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SignalKind::Rating => "rating",
            SignalKind::Withdrawal => "withdrawal",
            SignalKind::Correction => "correction",
            SignalKind::Metric => "metric",
            SignalKind::Outcome => "outcome",
            SignalKind::Verdict => "verdict",
            SignalKind::Response => "response",
        }
    }
}

impl std::fmt::Display for SignalKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How long after the producing run a signal is expected to arrive.
///
/// * `Immediate`  - human thumbs, HITL gate, diff correction (seconds).
/// * `Delayed`    - analytics poll within days (day 1 / 3 / 7).
/// * `Terminal`   - closed deals, final outcomes (weeks to months).
///
/// Coarse by design: it is used to keep ingest expectations honest, not to be
/// a precise timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LatencyClass {
    Immediate,
    Delayed,
    Terminal,
}

impl LatencyClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            LatencyClass::Immediate => "immediate",
            LatencyClass::Delayed => "delayed",
            LatencyClass::Terminal => "terminal",
        }
    }
}

impl std::fmt::Display for LatencyClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// how this signal came to be attributed to a run and a role.
///
/// The distinction is load-bearing, not bookkeeping. `Explicit` means the
/// surface already knew what the human touched - they edited *this* section,
/// the gate blocked *this* node - so the attribution is a recorded fact.
/// `Inferred` means the attribution pass guessed it from a coarse complaint,
/// which costs a Cortecs call and can be wrong. `None` means nobody could say,
/// and such a signal is stored but can never promote: a memory attributed to
/// the wrong role teaches one role another's lesson, and nothing downstream
/// can detect that. See docs/reflection/decisions/D5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttributionSource {
    /// A human pointed at a specific part; the surface recorded which.
    Explicit,
    /// The attribution pass supplied it with confidence.
    Inferred,
    /// Not attributable. Storable, never promotable.
    None,
}

impl AttributionSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            AttributionSource::Explicit => "explicit",
            AttributionSource::Inferred => "inferred",
            AttributionSource::None => "none",
        }
    }

    /// Whether an attribution of this provenance can carry a promotion.
    /// `None` cannot, by construction rather than by consumer discipline.
    pub fn is_attributed(&self) -> bool {
        !matches!(self, AttributionSource::None)
    }
}

/// Unattributed is the safe default: a producer that says nothing about
/// attribution gets a signal that cannot promote, rather than one that
/// silently claims a role it never established.
impl Default for AttributionSource {
    fn default() -> Self {
        AttributionSource::None
    }
}

impl std::fmt::Display for AttributionSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One immutable feedback event about a durable subject.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Signal {
    /// Immutable row id (`sig_<uuid>`), minted on append.
    pub id: String,
    /// Durable subject this signal is about. A signal always has a
    /// subject; without one there is nothing to join it back to.
    pub subject_id: String,
    /// the run this signal is attributable to. Mandatory - a signal
    /// that cannot name its run is refused at write time, because nothing
    /// downstream can join it back to what produced the output.
    ///
    /// `serde(default)` only so rows appended before this field existed still
    /// deserialize; they load with an empty run_id, are visibly unattributed,
    /// and cannot be re-appended.
    #[serde(default)]
    pub run_id: String,
    /// The role within that run this signal lands on (D2: manifest capability
    /// plus the DAG node's step_type). `None` exactly when
    /// `attribution_source` is `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// How the role above was arrived at. Defaults to `None`, so a producer
    /// that says nothing gets a signal that cannot promote.
    #[serde(default)]
    pub attribution_source: AttributionSource,
    pub tenant_id: String,
    pub agent_id: String,
    pub capability: String,
    /// Which producer emitted this (e.g. `rating`, `diff-capture`,
    /// `analytics-poller`, `nakiek`), plus the producer's schema version.
    pub source: String,
    pub source_version: String,
    pub kind: SignalKind,
    /// Rubric dimension this signal speaks to, when the producer already knows
    /// it. May be filled by a *derived* judgement row rather than by mutating
    /// this row - base rows never change after append.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dimension: Option<String>,
    /// Normalized numeric value. Negative scores a weak dimension on purpose
    /// (e.g. a correction on the hook is `-1`, an analytics shortfall is a
    /// negative delta vs baseline). Meaning is producer- and kind-specific.
    pub value: f64,
    /// Raw, potentially-unstructured payload (free text, diff, metric object).
    /// Kept alongside the normalized value so nothing is lost.
    pub raw: serde_json::Value,
    /// Attribution / trustworthiness (0..1). Analytics are near-useless below a
    /// baseline volume, so their confidence starts low.
    pub confidence: f64,
    /// Expected arrival latency class of this kind of signal.
    pub latency_class: LatencyClass,
    /// When the event happened in the world.
    pub observed_at: DateTime<Utc>,
    /// When the store ingested it. Kept separate from `observed_at`: a signal
    /// observed five days ago may be ingested today.
    pub ingested_at: DateTime<Utc>,
    /// Producer-scoped dedupe. A poller re-pushing the same natural event must
    /// reuse the same key so re-runs are safe.
    pub idempotency_key: String,
    /// Set to true for cohort-only signals (e.g. analytics). A true value means
    /// this signal must never reach an instance-level consumer.
    #[serde(default)]
    pub cohort_only: bool,
    /// Provenance: the idempotency key(s) of the base signal(s) a derived
    /// judgement was computed from. Empty for base signals.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub derived_from: Vec<String>,
}

impl Signal {
    /// Start building a signal. `id` is minted on `build()`; the store re-mints
    /// it on append so id + idempotency key stay distinct.
    pub fn builder(subject_id: impl Into<String>) -> SignalBuilder {
        SignalBuilder {
            subject_id: subject_id.into(),
            tenant_id: String::default(),
            agent_id: String::default(),
            capability: String::default(),
            source: String::default(),
            source_version: "1".to_string(),
            kind: SignalKind::Metric,
            dimension: None,
            value: 0.0,
            raw: serde_json::Value::Null,
            confidence: 1.0,
            latency_class: LatencyClass::Immediate,
            observed_at: Utc::now(),
            idempotency_key: String::default(),
            cohort_only: false,
            run_id: String::default(),
            role: None,
            attribution_source: AttributionSource::None,
        }
    }

    /// Whether this signal may carry a promotion into memory.
    ///
    /// Phase 1's acceptance criterion in one place: an unattributed signal is
    /// storable but provably cannot promote. Kept on the signal rather than in
    /// each consumer so a consumer that forgets the rule cannot exist.
    ///
    /// Deliberately narrow: this answers "is the attribution good enough", not
    /// "should this kind of signal reach memory at all". The population-level
    /// vs instance-level fork (`cohort_only`, analytics) is a separate gate.
    ///
    /// "Good enough" includes the role being a *usable* one. Testing
    /// `role.is_some()` accepted `Some("")` and any bare step name such as
    /// `"summarize"`, so a producer taking a `&str` role -- which
    /// [`crate::correction::correction_signals`] does -- could stamp a scope the
    /// registry never issued and promote into it. A memory on such a shelf is
    /// unreachable by every normal read, because reads build their key from a
    /// [`RoleKey`], and nothing goes red.
    pub fn is_promotable(&self) -> bool {
        !self.run_id.trim().is_empty()
            && matches!(self.role_key(), Ok(Some(_)))
            && self.attribution_source.is_attributed()
    }

    /// The signal's role parsed as a canonical key scoped to its own capability.
    ///
    /// `Ok(None)` means the signal names no role at all, which is a normal
    /// state. `Err` means it names one that cannot be used, and says why.
    ///
    /// Two things are checked beyond "it parses":
    ///
    /// - The stored string must already *be* the canonical form.
    ///   [`RoleKey::parse`] lowercases and trims internally, so
    ///   `"Council-Summary/Product"` parses happily while the row keeps the
    ///   original spelling -- and a query built from the parsed key then looks
    ///   on a different shelf from the one the row is on.
    /// - The key's capability half must match the signal's own `capability`.
    ///   They are two names for one thing (D2: the key is the agent's declared
    ///   capability plus the step type), so a disagreement means one of them is
    ///   wrong and there is no way to tell which.
    pub fn role_key(&self) -> Result<Option<RoleKey>, ReedeError> {
        let Some(role) = self.role.as_deref() else {
            return Ok(None);
        };
        let key = RoleKey::parse(role)?;
        if key.as_key() != role {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!(
                    "role {role:?} is not canonical; store it as {:?} or it lands on a \
                     shelf no reader looks at",
                    key.as_key()
                ),
            });
        }
        if key.capability() != self.capability {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!(
                    "role {role:?} is scoped to capability {:?} but the signal's \
                     capability is {:?}; they are two names for one thing",
                    key.capability(),
                    self.capability
                ),
            });
        }
        Ok(Some(key))
    }
}

/// Incremental constructor for `Signal`. Splitting construction out of the
/// struct keeps the required fields explicit and the optional ones defaulted,
/// instead of a 14-argument positional constructor.
#[derive(Debug, Clone)]
pub struct SignalBuilder {
    subject_id: String,
    run_id: String,
    role: Option<String>,
    attribution_source: AttributionSource,
    tenant_id: String,
    agent_id: String,
    capability: String,
    source: String,
    source_version: String,
    kind: SignalKind,
    dimension: Option<String>,
    value: f64,
    raw: serde_json::Value,
    confidence: f64,
    latency_class: LatencyClass,
    observed_at: DateTime<Utc>,
    idempotency_key: String,
    cohort_only: bool,
}

impl SignalBuilder {
    pub fn tenant(mut self, v: impl Into<String>) -> Self {
        self.tenant_id = v.into();
        self
    }
    pub fn agent(mut self, v: impl Into<String>) -> Self {
        self.agent_id = v.into();
        self
    }
    pub fn capability(mut self, v: impl Into<String>) -> Self {
        self.capability = v.into();
        self
    }
    pub fn source(mut self, v: impl Into<String>) -> Self {
        self.source = v.into();
        self
    }
    pub fn source_version(mut self, v: impl Into<String>) -> Self {
        self.source_version = v.into();
        self
    }
    pub fn kind(mut self, v: SignalKind) -> Self {
        self.kind = v;
        self
    }
    pub fn dimension(mut self, v: impl Into<String>) -> Self {
        self.dimension = Some(v.into());
        self
    }
    pub fn value(mut self, v: f64) -> Self {
        self.value = v;
        self
    }
    pub fn raw(mut self, v: serde_json::Value) -> Self {
        self.raw = v;
        self
    }
    pub fn confidence(mut self, v: f64) -> Self {
        self.confidence = v;
        self
    }
    pub fn latency(mut self, v: LatencyClass) -> Self {
        self.latency_class = v;
        self
    }
    pub fn observed_at(mut self, v: DateTime<Utc>) -> Self {
        self.observed_at = v;
        self
    }
    pub fn idempotency(mut self, v: impl Into<String>) -> Self {
        self.idempotency_key = v.into();
        self
    }
    pub fn cohort_only(mut self, v: bool) -> Self {
        self.cohort_only = v;
        self
    }
    /// the run this signal is attributable to. Required.
    pub fn run(mut self, v: impl Into<String>) -> Self {
        self.run_id = v.into();
        self
    }
    /// Attribute this signal to a role, saying how it was arrived at.
    ///
    /// Role and provenance are set together on purpose: they are one fact, and
    /// splitting the setters would let a caller claim a role with no provenance
    /// (or the reverse), which `prepare_for_append` would then have to reject.
    pub fn attributed_to(mut self, role: impl Into<String>, how: AttributionSource) -> Self {
        self.role = Some(role.into());
        self.attribution_source = how;
        self
    }

    pub fn build(self) -> Signal {
        Signal {
            id: format!("{SIGNAL_ID_PREFIX}_{}", Uuid::new_v4()),
            subject_id: self.subject_id,
            tenant_id: self.tenant_id,
            agent_id: self.agent_id,
            capability: self.capability,
            source: self.source,
            source_version: self.source_version,
            kind: self.kind,
            dimension: self.dimension,
            value: self.value,
            raw: self.raw,
            confidence: self.confidence,
            latency_class: self.latency_class,
            observed_at: self.observed_at,
            ingested_at: Utc::now(),
            idempotency_key: self.idempotency_key,
            cohort_only: self.cohort_only,
            run_id: self.run_id,
            role: self.role,
            attribution_source: self.attribution_source,
            derived_from: Vec::new(),
        }
    }
}

/// The idempotency keys cancelled by a withdrawal, for one tenant.
///
/// Store-enforced rather than left to each consumer: a reader that forgets the rule
/// counts feedback its author has taken back, and that is the kind of mistake nobody
/// notices until a scorecard is wrong.
fn withdrawn_keys(signals: &HashMap<String, Signal>, tenant_id: &str) -> HashSet<String> {
    signals
        .values()
        .filter(|s| s.tenant_id == tenant_id && s.kind == SignalKind::Withdrawal)
        .flat_map(|s| s.derived_from.iter().cloned())
        .collect()
}

/// True when this signal has been withdrawn. A withdrawal itself is never hidden.
fn is_withdrawn(signal: &Signal, withdrawn: &HashSet<String>) -> bool {
    signal.kind != SignalKind::Withdrawal && withdrawn.contains(&signal.idempotency_key)
}

/// The append-only signal store.
#[async_trait]
pub trait SignalStore: Send + Sync {
    /// Append a signal. Late writes are always accepted. If a signal with the
    /// same `tenant_id` + `idempotency_key` already exists, the existing row is
    /// returned and nothing is duplicated (idempotent re-run safety).
    async fn append(&self, signal: Signal) -> Result<Signal, ReedeError>;

    /// Fetch one signal by its `sig_<uuid>` id, tenant-scoped.
    async fn get(&self, tenant_id: &str, signal_id: &str) -> Result<Option<Signal>, ReedeError>;

    /// All signals for one subject (the "late write, five day gap"
    /// acceptance path: two sources land on the same subject and query cleanly).
    /// Order: by `observed_at` ascending.
    async fn by_subject(
        &self,
        tenant_id: &str,
        subject_id: &str,
    ) -> Result<Vec<Signal>, ReedeError>;

    /// The most recent signals for one subject, newest first, capped.
    ///
    /// [`SignalStore::by_subject`] returns a subject's whole history in arrival
    /// order, which is right for a reducer and wrong for a page: a long-lived
    /// artifact accumulates signals indefinitely. Anything rendering a timeline
    /// reads through this and says so when it truncates.
    async fn by_subject_page(
        &self,
        tenant_id: &str,
        subject_id: &str,
        limit: usize,
    ) -> Result<Vec<Signal>, ReedeError>;

    /// Signals *ingested* strictly after `after`, oldest arrival first.
    ///
    /// Distinct from [`SignalStore::cohort`] on purpose, and the distinction is the
    /// whole reason this method exists. `cohort` filters on `observed_at` — when the
    /// event happened in the world. A consumer that tracks its progress by
    /// `observed_at` silently drops exactly the signals this layer was built for: a
    /// verdict observed five days ago but ingested today sorts *before* the
    /// consumer's watermark and is never seen again.
    ///
    /// Anything that reduces, exports or forwards signals must page through them by
    /// arrival, which is what this returns. `observed_at` remains the right axis for
    /// asking "what happened in this window"; `ingested_at` is the right axis for
    /// "what have I not yet processed".
    async fn ingested_since(
        &self,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
        after: DateTime<Utc>,
    ) -> Result<Vec<Signal>, ReedeError>;

    /// All signals for one agent capability within a window (the cohort query
    /// shape). `cohort_only` rows are included here for aggregation; they carry
    /// their own flag so they cannot be mis-read as instance judgement sources.
    /// Order: by `observed_at` ascending.
    async fn cohort(
        &self,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
        after: DateTime<Utc>,
        before: DateTime<Utc>,
    ) -> Result<Vec<Signal>, ReedeError>;
}

/// In-memory implementation, matching the `InMemory*` store style used across
/// Reede. The production SurrealDB binding lands here when the substrate moves
/// to the DB (kept independent so the envelope semantics are provable now).
pub struct InMemorySignalStore {
    /// signal_id -> signal
    signals: Mutex<HashMap<String, Signal>>,
    /// (tenant, idempotency_key) -> signal_id  (dedup register)
    by_idempotency: Mutex<HashMap<(String, String), String>>,
}

impl InMemorySignalStore {
    pub fn new() -> Self {
        Self {
            signals: Mutex::new(HashMap::new()),
            by_idempotency: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemorySignalStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate and stamp a signal on its way into a store.
///
/// The append contract, in one place: reject an empty idempotency key (it is
/// the natural-event identity), enforce the rule that a `Response`
/// carries no rubric score, mint a fresh immutable id, and clamp confidence
/// into 0..1. Every [`SignalStore`] implementation must apply it — it lives
/// here rather than inside one store so a durable implementation cannot drift
/// from the in-memory one it is supposed to replace.
///
/// Callers set `ingested_at` themselves at the moment of write; dedupe on
/// `(tenant_id, idempotency_key)` is the store's own job, since only the store
/// knows whether the row already exists.
pub fn prepare_for_append(signal: &mut Signal) -> Result<(), ReedeError> {
    if signal.idempotency_key.trim().is_empty() {
        return Err(ReedeError::SpecValidationFailed {
            reason: "signal idempotency_key must not be empty".to_string(),
        });
    }

    // an instance-level signal that cannot name its run is not usable
    // by anything downstream, so it is refused here rather than stored as a row
    // nobody can join. This is the one place both stores share, so neither can
    // drift from the rule.
    //
    // `cohort_only` signals are deliberately exempt, and this is a reading of
    // the spec rather than a loophole. Section 1 puts population-level signals
    // (analytics, aggregate thumbs) in the dataset and *never* in per-role
    // memory, and an analytics poller aggregating five days of impressions has
    // no single run to name. Demanding one would mean fabricating it, which is
    // worse than admitting there is none: a synthetic run id would join to
    // nothing while looking like provenance. The guarantee that matters is
    // unaffected - `is_promotable` is false without a run_id either way, so a
    // cohort signal still cannot reach memory.
    if signal.run_id.trim().is_empty() && !signal.cohort_only {
        return Err(ReedeError::SpecValidationFailed {
            reason: "signal run_id must not be empty".to_string(),
        });
    }

    // Role and provenance are one fact and must agree. A role with no
    // provenance is a claim nobody made; provenance with no role is a claim
    // about nothing. Either would make `is_promotable` lie.
    match (&signal.role, signal.attribution_source) {
        (Some(_), AttributionSource::None) => {
            return Err(ReedeError::SpecValidationFailed {
                reason:
                    "a signal naming a role must say how it was attributed (explicit or inferred)"
                        .to_string(),
            });
        }
        (None, src) if src.is_attributed() => {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!(
                    "attribution_source is {src} but no role is named; an attributed signal must say to what"
                ),
            });
        }
        _ => {}
    }

    // ...and a role that is named must be one that exists. Rejecting here rather
    // than only in `is_promotable` keeps a malformed scope out of the store
    // entirely: left in, it is a row that looks attributed, reads as a bug in the
    // retrieval side, and can only be found by noticing an absence.
    signal.role_key()?;

    // a Response signal is not a rubric judgement -- value and
    // dimension carry no meaning for it and must stay at their defaults,
    // enforced here rather than left as an unchecked convention.
    if signal.kind == SignalKind::Response {
        if signal.value != 0.0 {
            return Err(ReedeError::SpecValidationFailed {
                reason: "Response signals must not set value (no rubric score applies; use raw)"
                    .to_string(),
            });
        }
        if signal.dimension.is_some() {
            return Err(ReedeError::SpecValidationFailed {
                reason: "Response signals must not set dimension (not a rubric judgement)"
                    .to_string(),
            });
        }
    }

    // A withdrawal must say what it withdraws, and carries no rubric score of its
    // own: it cancels evidence, it is not evidence.
    if signal.kind == SignalKind::Withdrawal {
        if signal.derived_from.len() != 1 {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!(
                    "a Withdrawal must name exactly one withdrawn signal in derived_from (got {})",
                    signal.derived_from.len()
                ),
            });
        }
        if signal.value != 0.0 || signal.dimension.is_some() {
            return Err(ReedeError::SpecValidationFailed {
                reason: "Withdrawal signals must not set value or dimension (they cancel a score, they are not one)"
                    .to_string(),
            });
        }
    }

    // Mint a fresh immutable id (never reuse across appends).
    signal.id = format!("{SIGNAL_ID_PREFIX}_{}", Uuid::new_v4());
    signal.confidence = guarantee_confidence(signal.confidence);
    crate::replay_input::redact_signal_input(signal, Utc::now());
    Ok(())
}

fn readable_signal(mut signal: Signal) -> Signal {
    crate::replay_input::redact_signal_input(&mut signal, Utc::now());
    signal
}

fn guarantee_confidence(c: f64) -> f64 {
    c.clamp(0.0, 1.0)
}

#[async_trait]
impl SignalStore for InMemorySignalStore {
    async fn append(&self, signal: Signal) -> Result<Signal, ReedeError> {
        // Appended rows are always effective (`observed_at` is already UTC now
        // in callers); set ingested_at to the moment of write.
        let mut signal = signal;
        signal.ingested_at = Utc::now();

        // Dedup register first: re-running a poller with the same natural key
        // must be safe and idempotent.
        let mut dedup = self.by_idempotency.lock().unwrap();
        let key_bucket = (signal.tenant_id.clone(), signal.idempotency_key.clone());
        if let Some(existing_id) = dedup.get(&key_bucket) {
            let signals = self.signals.lock().unwrap();
            return Ok(readable_signal(signals[existing_id].clone()));
        }

        prepare_for_append(&mut signal)?;

        let id = signal.id.clone();
        let mut signals = self.signals.lock().unwrap();
        signals.insert(id.clone(), signal.clone());
        dedup.insert(key_bucket, id);

        Ok(signal)
    }

    async fn get(&self, tenant_id: &str, signal_id: &str) -> Result<Option<Signal>, ReedeError> {
        let signals = self.signals.lock().unwrap();
        Ok(signals
            .get(signal_id)
            .filter(|s| s.tenant_id == tenant_id)
            .cloned()
            .map(readable_signal))
    }

    async fn by_subject(
        &self,
        tenant_id: &str,
        subject_id: &str,
    ) -> Result<Vec<Signal>, ReedeError> {
        let signals = self.signals.lock().unwrap();
        let withdrawn = withdrawn_keys(&signals, tenant_id);
        let mut rows: Vec<Signal> = signals
            .values()
            .filter(|s| {
                s.tenant_id == tenant_id
                    && s.subject_id == subject_id
                    && !is_withdrawn(s, &withdrawn)
            })
            .cloned()
            .map(readable_signal)
            .collect();
        rows.sort_by_key(|s| s.observed_at);
        Ok(rows)
    }

    async fn by_subject_page(
        &self,
        tenant_id: &str,
        subject_id: &str,
        limit: usize,
    ) -> Result<Vec<Signal>, ReedeError> {
        let signals = self.signals.lock().unwrap();
        let withdrawn = withdrawn_keys(&signals, tenant_id);
        let mut rows: Vec<Signal> = signals
            .values()
            .filter(|s| {
                s.tenant_id == tenant_id
                    && s.subject_id == subject_id
                    && !is_withdrawn(s, &withdrawn)
            })
            .cloned()
            .map(readable_signal)
            .collect();
        rows.sort_by_key(|s| std::cmp::Reverse(s.observed_at));
        rows.truncate(limit);
        Ok(rows)
    }

    async fn ingested_since(
        &self,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
        after: DateTime<Utc>,
    ) -> Result<Vec<Signal>, ReedeError> {
        let signals = self.signals.lock().unwrap();
        let withdrawn = withdrawn_keys(&signals, tenant_id);
        let mut rows: Vec<Signal> = signals
            .values()
            .filter(|s| {
                s.tenant_id == tenant_id
                    && s.agent_id == agent_id
                    && s.capability == capability
                    && s.ingested_at > after
                    && !is_withdrawn(s, &withdrawn)
            })
            .cloned()
            .map(readable_signal)
            .collect();
        rows.sort_by_key(|s| s.ingested_at);
        Ok(rows)
    }

    async fn cohort(
        &self,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
        after: DateTime<Utc>,
        before: DateTime<Utc>,
    ) -> Result<Vec<Signal>, ReedeError> {
        let signals = self.signals.lock().unwrap();
        let withdrawn = withdrawn_keys(&signals, tenant_id);
        let mut rows: Vec<Signal> = signals
            .values()
            .filter(|s| {
                s.tenant_id == tenant_id
                    && s.agent_id == agent_id
                    && s.capability == capability
                    && s.observed_at >= after
                    && s.observed_at <= before
                    && !is_withdrawn(s, &withdrawn)
            })
            .cloned()
            .map(readable_signal)
            .collect();
        rows.sort_by_key(|s| s.observed_at);
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    /// Builds a signal with a *unique* natural idempotency key unless the caller
    /// passes the same `key` twice (used to exercise idempotent dedupe).
    fn signal_with_key(subject: &str, source: &str, kind: SignalKind, key: &str) -> Signal {
        Signal::builder(subject)
            .tenant("tenant-1")
            .agent("agent-1")
            .capability("copy")
            .source(source)
            .source_version("1.0")
            .kind(kind)
            .value(1.0)
            .raw(serde_json::json!({ "note": "raw" }))
            .confidence(1.0)
            .latency(LatencyClass::Immediate)
            .idempotency(key)
            .run("run-1")
            .build()
    }

    fn base_signal(subject: &str, source: &str, kind: SignalKind) -> Signal {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        signal_with_key(
            subject,
            source,
            kind,
            &format!("{source}:natural-event-{n}"),
        )
    }

    #[tokio::test]
    async fn test_late_write_two_sources_five_day_gap_land_on_same_subject() {
        let store = InMemorySignalStore::new();

        // Immediate human rating, t=0.
        let mut rating = base_signal("sub_article_1", "rating", SignalKind::Rating);
        rating.observed_at = Utc::now();
        rating.ingested_at = Utc::now();
        store.append(rating).await.unwrap();

        // Delayed analytics verdict, five days later, same subject.
        let mut analytics = base_signal("sub_article_1", "analytics-poller", SignalKind::Metric);
        analytics.observed_at = Utc::now() + Duration::days(5);
        analytics.ingested_at = Utc::now() + Duration::days(5);
        analytics.latency_class = LatencyClass::Delayed;
        analytics.cohort_only = true;
        store.append(analytics).await.unwrap();

        let rows = store.by_subject("tenant-1", "sub_article_1").await.unwrap();
        assert_eq!(rows.len(), 2, "both signals on the same subject");
        // Ascending by observed_at: the late signal is ordered after the rating.
        assert_eq!(rows[0].source, "rating");
        assert_eq!(rows[1].source, "analytics-poller");
        assert!(
            rows[1].observed_at - rows[0].observed_at >= Duration::days(4),
            "five-day gap preserved"
        );
    }

    #[tokio::test]
    async fn test_corrections_are_new_rows_never_updates() {
        let store = InMemorySignalStore::new();
        let first = store
            .append(base_signal("sub_1", "diff", SignalKind::Correction))
            .await
            .unwrap();
        let second = store
            .append(base_signal("sub_1", "diff", SignalKind::Correction))
            .await
            .unwrap();
        // Distinct natural keys -> two distinct immutable rows.
        assert_ne!(first.id, second.id);
        let rows = store.by_subject("tenant-1", "sub_1").await.unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[tokio::test]
    async fn test_idempotency_re_run_poller_is_safe() {
        let store = InMemorySignalStore::new();
        let first = store
            .append(signal_with_key(
                "sub_1",
                "analytics-poller",
                SignalKind::Metric,
                "poller:run-1",
            ))
            .await
            .unwrap();
        // Poller re-runs with the same natural key: no duplicate row, returns existing.
        let second = store
            .append(signal_with_key(
                "sub_1",
                "analytics-poller",
                SignalKind::Metric,
                "poller:run-1",
            ))
            .await
            .unwrap();
        assert_eq!(first.id, second.id, "idempotent re-run dedupes");
        let rows = store.by_subject("tenant-1", "sub_1").await.unwrap();
        assert_eq!(rows.len(), 1);
    }

    // ---------------------------------------------------------------- run attribution
    // Phase 1 acceptance: a signal is usable only if it resolves to a run plus a
    // role, and an unattributed one is storable but provably cannot promote.

    #[tokio::test]
    async fn test_empty_run_id_rejected() {
        let store = InMemorySignalStore::new();
        let mut s = base_signal("sub_1", "rating", SignalKind::Rating);
        s.run_id = "   ".to_string();
        let err = store.append(s).await.unwrap_err();
        assert!(
            matches!(err, ReedeError::SpecValidationFailed { .. }),
            "a signal with no run_id must be refused at write time"
        );
    }

    #[tokio::test]
    async fn test_every_kind_carries_run_attribution_through_the_store() {
        // The spec asks for the shape to be tested per variant, because each
        // kind reaches the store by a different producer path.
        let store = InMemorySignalStore::new();
        for (i, kind) in [
            SignalKind::Rating,
            SignalKind::Correction,
            SignalKind::Metric,
            SignalKind::Outcome,
            SignalKind::Verdict,
        ]
        .into_iter()
        .enumerate()
        {
            let mut s = signal_with_key("sub_kinds", "producer", kind, &format!("k-{i}"));
            s.run_id = format!("run-{i}");
            s.role = Some("copy/summarize".to_string());
            s.attribution_source = AttributionSource::Explicit;
            let stored = store.append(s).await.expect("kind appends");
            assert_eq!(stored.run_id, format!("run-{i}"), "{kind} keeps its run");
            assert_eq!(
                stored.role.as_deref(),
                Some("copy/summarize"),
                "{kind} keeps its role"
            );
            assert!(
                stored.is_promotable(),
                "{kind} attributed explicitly is promotable"
            );
        }
    }

    #[tokio::test]
    async fn test_unattributed_signal_stores_but_cannot_promote() {
        let store = InMemorySignalStore::new();
        // Default provenance is None, so this is what a producer that says
        // nothing about attribution actually produces.
        let s = base_signal("sub_1", "rating", SignalKind::Rating);
        assert_eq!(s.attribution_source, AttributionSource::None);
        let stored = store
            .append(s)
            .await
            .expect("unattributed signals are storable");
        assert!(
            !stored.is_promotable(),
            "an unattributed signal must never be promotable"
        );
        // And it really is retrievable -- storable, not silently dropped.
        let rows = store.by_subject("tenant-1", "sub_1").await.unwrap();
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].is_promotable());
    }

    #[tokio::test]
    async fn test_role_without_provenance_is_refused() {
        let store = InMemorySignalStore::new();
        let mut s = base_signal("sub_1", "rating", SignalKind::Rating);
        s.role = Some("copy/summarize".to_string());
        // attribution_source deliberately left at None: a role nobody claimed.
        let err = store.append(s).await.unwrap_err();
        assert!(matches!(err, ReedeError::SpecValidationFailed { .. }));
    }

    #[tokio::test]
    async fn test_provenance_without_role_is_refused() {
        let store = InMemorySignalStore::new();
        let mut s = base_signal("sub_1", "rating", SignalKind::Rating);
        s.attribution_source = AttributionSource::Inferred;
        // role deliberately left None: a claim about nothing.
        let err = store.append(s).await.unwrap_err();
        assert!(matches!(err, ReedeError::SpecValidationFailed { .. }));
    }

    #[test]
    fn test_inferred_is_promotable_but_unattributed_is_not() {
        // Inference is weaker evidence than explicit capture, but it is still an
        // attribution; only `None` blocks promotion.
        let mut s = Signal::builder("sub_1")
            .tenant("tenant-1")
            .capability("copy")
            .idempotency("k")
            .run("run-1")
            .attributed_to("copy/summarize", AttributionSource::Inferred)
            .build();
        assert!(s.is_promotable());
        s.attribution_source = AttributionSource::None;
        s.role = None;
        assert!(!s.is_promotable());
    }

    /// A role that is not a usable key must not be promotable, and must not be
    /// storable either.
    ///
    /// `Option::is_some` was the whole test, so `Some("")`, a bare step name, a
    /// non-canonical spelling and a role scoped to somebody else's capability all
    /// counted as attribution. Each of those promotes onto a shelf that reads
    /// build their key for, and never find.
    #[tokio::test]
    async fn a_role_that_is_not_a_usable_key_neither_promotes_nor_stores() {
        let cases: [(&str, &str); 5] = [
            ("", "an empty role is not a role"),
            ("summarize", "a bare step name has no capability half"),
            ("copy/", "an empty step type is not a step type"),
            (
                "Copy/Summarize",
                "not canonical: reads and writes would disagree",
            ),
            (
                "other/summarize",
                "scoped to a capability this signal is not about",
            ),
        ];
        for (role, why) in cases {
            let mut s = base_signal("sub_1", "diff-capture", SignalKind::Correction);
            s.capability = "copy".to_string();
            s.run_id = "run-1".to_string();
            s.role = Some(role.to_string());
            s.attribution_source = AttributionSource::Explicit;

            assert!(!s.is_promotable(), "{role:?} must not promote -- {why}");

            let store = InMemorySignalStore::new();
            let Err(err) = store.append(s).await else {
                panic!("{role:?} must not be storable either -- {why}");
            };
            assert!(matches!(err, ReedeError::SpecValidationFailed { .. }));
        }
    }

    #[test]
    fn a_canonical_role_scoped_to_the_signals_own_capability_is_accepted() {
        let s = Signal::builder("sub_1")
            .tenant("tenant-1")
            .capability("council-summary")
            .idempotency("k")
            .run("run-1")
            .attributed_to("council-summary/product", AttributionSource::Explicit)
            .build();
        assert_eq!(
            s.role_key().unwrap().map(|k| k.step_type().to_string()),
            Some("product".to_string())
        );
        assert!(s.is_promotable());
    }

    #[test]
    fn test_legacy_row_without_the_new_fields_still_deserializes_unpromotable() {
        // Rows appended before run attribution existed have no run_id/role/attribution_source.
        // They must still load -- and must land unpromotable rather than
        // defaulting into a role they never had.
        let legacy = serde_json::json!({
            "id": "sig_legacy",
            "subject_id": "sub_1",
            "tenant_id": "tenant-1",
            "agent_id": "agent-1",
            "capability": "copy",
            "source": "rating",
            "source_version": "1.0",
            "kind": "Rating",
            "value": 1.0,
            "raw": {},
            "confidence": 1.0,
            "latency_class": "Immediate",
            "observed_at": "2026-08-01T00:00:00Z",
            "ingested_at": "2026-08-01T00:00:00Z",
            "idempotency_key": "legacy-1"
        });
        let s: Signal = serde_json::from_value(legacy).expect("legacy rows still deserialize");
        assert_eq!(s.run_id, "");
        assert_eq!(s.role, None);
        assert_eq!(s.attribution_source, AttributionSource::None);
        assert!(
            !s.is_promotable(),
            "a legacy row is not silently promotable"
        );
    }

    #[tokio::test]
    async fn test_empty_idempotency_key_rejected() {
        let store = InMemorySignalStore::new();
        let mut s = base_signal("sub_1", "rating", SignalKind::Rating);
        s.idempotency_key = "   ".to_string();
        let err = store.append(s).await.unwrap_err();
        assert!(matches!(err, ReedeError::SpecValidationFailed { .. }));
    }

    #[tokio::test]
    async fn test_tenant_isolation() {
        let store = InMemorySignalStore::new();
        let s = base_signal("sub_1", "rating", SignalKind::Rating);
        store.append(s).await.unwrap();

        assert!(
            store
                .by_subject("tenant-2", "sub_1")
                .await
                .unwrap()
                .is_empty(),
            "tenant-B sees nothing"
        );
        assert!(
            store.get("tenant-2", "sub_1").await.unwrap().is_none(),
            "tenant-B cannot fetch a tenant-A signal by id"
        );
    }

    #[tokio::test]
    async fn test_cohort_query_shapes_index_and_ordering() {
        let store = InMemorySignalStore::new();
        let _ = store
            .append(base_signal("sub_1", "poller", SignalKind::Metric))
            .await;
        let _ = store
            .append(base_signal("sub_2", "poller", SignalKind::Metric))
            .await;
        // A different capability that must not appear.
        let mut other = base_signal("sub_3", "poller", SignalKind::Metric);
        other.capability = "code".to_string();
        let _ = store.append(other).await;
        // A stale row outside the window.
        let mut stale = base_signal("sub_4", "poller", SignalKind::Metric);
        stale.observed_at = Utc::now() - Duration::days(90);
        let _ = store.append(stale).await;

        let rows = store
            .cohort(
                "tenant-1",
                "agent-1",
                "copy",
                Utc::now() - Duration::days(7),
                Utc::now() + Duration::days(7),
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 2, "only the two copy signals in the window");
        assert!(rows.iter().all(|s| s.capability == "copy"));
    }

    #[tokio::test]
    async fn test_cohort_only_flag_is_preserved_and_visible() {
        let store = InMemorySignalStore::new();
        let mut cohort = base_signal("sub_1", "analytics-poller", SignalKind::Metric);
        cohort.cohort_only = true;
        let stored = store.append(cohort).await.unwrap();
        assert!(stored.cohort_only, "cohort-only marker survives the store");
    }

    // proves the envelope genuinely carries an inquiry open-question
    // answer through the same append-only, idempotent, tenant-isolated store
    // every other signal kind goes through -- not a parallel path.
    #[tokio::test]
    async fn test_response_signal_round_trips_through_the_same_store() {
        let store = InMemorySignalStore::new();
        let response = Signal::builder("inquiry:gpx_abandon_001")
            .tenant("tenant-1")
            .agent("frogen-inquiry")
            .capability("onboarding")
            .source("frogen-moment-widget")
            .source_version("1.0")
            .kind(SignalKind::Response)
            .raw(serde_json::json!({
                "question": "Why did you not finish uploading your GPX file?",
                "answer": "It kept failing, my file was probably too big."
            }))
            .confidence(1.0)
            .latency(LatencyClass::Immediate)
            .idempotency("frogen:inquiry:gpx_abandon_001:respondent:abc123")
            .run("run-1")
            .build();

        let stored = store.append(response).await.unwrap();
        assert_eq!(stored.value, 0.0, "no rubric score applies to a response");
        assert!(stored.dimension.is_none(), "not a rubric judgement");
        assert_eq!(
            stored.raw["answer"],
            "It kept failing, my file was probably too big."
        );

        // Same query paths as every other kind -- no parallel store, no
        // inquiry-specific read path needed.
        let rows = store
            .by_subject("tenant-1", "inquiry:gpx_abandon_001")
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, SignalKind::Response);
    }

    #[tokio::test]
    async fn test_response_signal_rejects_a_smuggled_rubric_value() {
        let store = InMemorySignalStore::new();
        let mut bad = Signal::builder("inquiry:1")
            .tenant("tenant-1")
            .agent("frogen-inquiry")
            .capability("onboarding")
            .source("frogen-moment-widget")
            .kind(SignalKind::Response)
            .raw(serde_json::json!({"question": "q", "answer": "a"}))
            .latency(LatencyClass::Immediate)
            .idempotency("frogen:inquiry:1:respondent:x")
            .build();
        bad.value = -1.0;
        let err = store.append(bad).await.unwrap_err();
        assert!(matches!(err, ReedeError::SpecValidationFailed { .. }));
    }

    #[tokio::test]
    async fn test_response_signal_rejects_a_smuggled_dimension() {
        let store = InMemorySignalStore::new();
        let bad = Signal::builder("inquiry:1")
            .tenant("tenant-1")
            .agent("frogen-inquiry")
            .capability("onboarding")
            .source("frogen-moment-widget")
            .kind(SignalKind::Response)
            .dimension("hook")
            .raw(serde_json::json!({"question": "q", "answer": "a"}))
            .latency(LatencyClass::Immediate)
            .idempotency("frogen:inquiry:1:respondent:y")
            .build();
        let err = store.append(bad).await.unwrap_err();
        assert!(matches!(err, ReedeError::SpecValidationFailed { .. }));
    }
}
