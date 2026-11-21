//! The per-role memory row, and the edges that make it accountable.
//!
//! This is what the loop is *for*: a lesson a role retrieves on a later run of the
//! same kind of work. Everything before it -- attribution, the role key, the fork --
//! exists so that the row written here is about the right role's work.
//!
//! ## The edges are the deliverable
//!
//! The spec is unusually blunt about this: *"The edges are the deliverable, not
//! decoration."* For `kind = Correction`, both are mandatory:
//!
//! - `derived_from -> receipt` -- what makes a memory **attributable and sweepable**.
//!   Without it you cannot answer "where did this lesson come from", and you cannot
//!   retract a batch when the run behind it turns out to have been wrong.
//! - `promoted_to <- signal` -- what makes **retraction and the provenance view**
//!   possible. When a human withdraws their correction, this edge is how the memory
//!   it produced is found.
//!
//! A correction without both is a lesson with no provenance: it will be retrieved
//! and acted on, and nobody will be able to say why it exists or remove it when the
//! signal behind it is taken back. So [`Memory::validate`] rejects it, and the store
//! is expected to call that before writing rather than trusting its caller.
//!
//! Report and verdict rows are held to a weaker rule on purpose -- see
//! [`MemoryKind`].
//!
//! ## Scope key
//!
//! `role` alone is too coarse: a billing correction must not surface on a scheduling
//! case just because the same role handled both. `scope_key` is the second axis, and
//! what belongs in it is D4's question, deferred. Until it is answered the field is
//! carried, indexed and filtered on, with callers passing a value they choose --
//! which is enough to build and test retrieval, and does not pre-commit the answer.

use crate::error::ReedeError;
use crate::role::RoleKey;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// What kind of thing a memory row holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryKind {
    /// A role's own output, kept as context for later work.
    ///
    /// Not derived from anyone's judgement, so it has no signal to point at and the
    /// edge rule does not apply. It is also the weakest kind of memory: nothing
    /// about it says it was any good.
    Report,
    /// A human corrected this role's work. The edge rule applies in full.
    ///
    /// This is the only kind that carries supervision, which is exactly why it is
    /// the only one required to carry its provenance.
    Correction,
    /// An automated review verdict on this role's work.
    ///
    /// Derived from a signal, but from a machine's judgement rather than a human's.
    /// Held to the same edge rule as a correction would be misleading -- a verdict
    /// is reproducible from the artifact, so it is evidence you can regenerate
    /// rather than testimony you must preserve.
    Verdict,
}

impl MemoryKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            MemoryKind::Report => "report",
            MemoryKind::Correction => "correction",
            MemoryKind::Verdict => "verdict",
        }
    }

    /// Whether a row of this kind must carry both provenance edges.
    pub fn requires_provenance_edges(&self) -> bool {
        matches!(self, MemoryKind::Correction)
    }
}

impl std::fmt::Display for MemoryKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One per-role memory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Memory {
    /// Minted by the store on write; empty before then.
    pub id: String,
    pub tenant_id: String,
    /// Canonical role key (`<capability>/<step_type>`, D2). Stored as the string so
    /// the row indexes and filters without the reader needing the type.
    pub role: String,
    /// The second retrieval axis. See the module note and D4.
    pub scope_key: String,
    pub text: String,
    /// Retrieval vector. Empty is allowed and means "not embedded yet": a memory
    /// that exists but cannot be found by similarity is a worse outcome than one
    /// that was never written, so the embedding is not a precondition for storing
    /// the lesson.
    #[serde(default)]
    pub embedding: Vec<f32>,
    pub kind: MemoryKind,
    /// How strongly this memory should count when retrieved. A retraction sets it
    /// to zero rather than deleting the row, so the provenance view survives.
    pub weight: f64,
    pub written_at: DateTime<Utc>,
    /// When this memory stops being retrievable. `None` means it does not expire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// `derived_from -> receipt`: the receipt for the run this lesson came from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derived_from_receipt: Option<String>,
    /// When this lesson was last confirmed again. `None` means never;
    /// decay then runs from `written_at`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reinforced_at: Option<DateTime<Utc>>,
    /// The regression test that justifies a null `expires_at`.
    ///
    /// Expiry is the default, so a permanent memory is making a claim. This names
    /// what backs it; `hygiene::assert_permanent` is the only thing that sets it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regression_id: Option<String>,
    /// `promoted_to <- signal`: the idempotency key of the signal that produced it.
    ///
    /// The idempotency key rather than the row id, because that is the identity a
    /// withdrawal names (`Signal::derived_from`) -- so retraction can find this
    /// memory from the withdrawal alone, without a second lookup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promoted_from_signal: Option<String>,
}

/// The dimension every stored embedding must have.
///
/// 1024, because that is what the tree's Cortecs embedder produces and what every
/// HNSW index in `schema/` and `database/migrations/` is defined at. It is a
/// constant rather than a setting for the same reason those indexes are: a vector
/// column and the vectors written into it cannot disagree and still work, so there
/// is nothing to configure -- there is only a right answer and a broken store.
///
/// Migration `118_reconcile_user_knowledge_dims.surql` exists because this went
/// wrong once already: an index declared at one dimension while the embedder
/// produced another. Nothing failed loudly; the rows were simply never found.
pub const EMBEDDING_DIMENSIONS: usize = 1024;

impl Memory {
    /// Start building a memory for `role`.
    pub fn builder(role: &RoleKey, scope_key: impl Into<String>) -> MemoryBuilder {
        MemoryBuilder {
            memory: Memory {
                id: String::new(),
                tenant_id: String::new(),
                role: role.as_key(),
                scope_key: scope_key.into(),
                text: String::new(),
                embedding: Vec::new(),
                kind: MemoryKind::Report,
                weight: 1.0,
                written_at: Utc::now(),
                expires_at: None,
                last_reinforced_at: None,
                regression_id: None,
                derived_from_receipt: None,
                promoted_from_signal: None,
            },
        }
    }

    /// Whether this row is currently retrievable.
    ///
    /// Expiry and a zeroed weight are both "do not retrieve", and both leave the row
    /// in place: one because retention said so, the other because someone retracted
    /// it. Deleting either would break the provenance view the edges exist for.
    pub fn is_live(&self, now: DateTime<Utc>) -> bool {
        self.weight > 0.0 && self.expires_at.is_none_or(|at| at > now)
    }

    /// Reject a row that cannot be written.
    ///
    /// Called by the store before every write. Putting it here rather than in the
    /// store means an in-memory implementation and a SurrealDB one cannot disagree
    /// about what a valid memory is -- and the rule that matters (a correction
    /// carries both edges) is the kind of rule that gets quietly dropped when each
    /// backend owns its own copy.
    pub fn validate(&self) -> Result<(), ReedeError> {
        if self.tenant_id.trim().is_empty() {
            return Err(invalid("tenant_id is empty"));
        }
        // Parsed rather than merely non-empty: a role that is not a canonical key is
        // a scope nothing will ever retrieve from, which is the silent failure D2
        // exists to prevent.
        //
        // Parsing alone was not enough. `RoleKey::parse` lowercases and trims
        // internally, so `"Council-Summary/Product"` and a padded segment both
        // parse -- and the row then keeps the original spelling while every query
        // is built from the normalised key. The memory lands on a shelf no reader
        // looks at, which is the same silent failure with an extra step.
        let key = RoleKey::parse(&self.role)?;
        if key.as_key() != self.role {
            return Err(invalid(&format!(
                "role {:?} is not canonical; store it as {:?} or no query will find it",
                self.role,
                key.as_key()
            )));
        }
        if self.scope_key.trim().is_empty() {
            return Err(invalid("scope_key is empty"));
        }
        if self.text.trim().is_empty() {
            return Err(invalid("text is empty; there is no lesson to retrieve"));
        }
        if !self.weight.is_finite() || self.weight < 0.0 {
            return Err(invalid(&format!(
                "weight {} is not a non-negative finite number",
                self.weight
            )));
        }

        // An empty embedding is the deliberate case: a memory written before an
        // embedder was available, retrieved by recency instead. A *nonempty* one has
        // to be a real vector, and neither of these was checked.
        if !self.embedding.is_empty() {
            if self.embedding.len() != EMBEDDING_DIMENSIONS {
                return Err(invalid(&format!(
                    "embedding has {} dimensions, not {EMBEDDING_DIMENSIONS}; \
                     `cosine_similarity` returns None for a length mismatch, so this \
                     row would be silently skipped by every retrieval that ranks",
                    self.embedding.len()
                )));
            }
            if let Some(index) = self.embedding.iter().position(|v| !v.is_finite()) {
                return Err(invalid(&format!(
                    "embedding[{index}] is {}, not a finite number; \
                     `serde_json` writes NaN and infinity as `null`, and the decode \
                     of this row then fails -- taking down every retrieval for the \
                     whole scope, not just this memory",
                    self.embedding[index]
                )));
            }
        }

        if self.kind.requires_provenance_edges() {
            // The deliverable. Both, or the row does not exist.
            if self
                .derived_from_receipt
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
            {
                return Err(invalid(
                    "a correction needs derived_from -> receipt, or it cannot be \
                     attributed or swept",
                ));
            }
            if self
                .promoted_from_signal
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
            {
                return Err(invalid(
                    "a correction needs signal -> promoted_to, or it cannot be \
                     retracted and has no provenance view",
                ));
            }
        }
        Ok(())
    }
}

fn invalid(reason: &str) -> ReedeError {
    ReedeError::SpecValidationFailed {
        reason: format!("memory: {reason}"),
    }
}

/// Incremental constructor for [`Memory`].
pub struct MemoryBuilder {
    memory: Memory,
}

impl MemoryBuilder {
    pub fn tenant(mut self, v: impl Into<String>) -> Self {
        self.memory.tenant_id = v.into();
        self
    }
    pub fn text(mut self, v: impl Into<String>) -> Self {
        self.memory.text = v.into();
        self
    }
    pub fn embedding(mut self, v: Vec<f32>) -> Self {
        self.memory.embedding = v;
        self
    }
    pub fn kind(mut self, v: MemoryKind) -> Self {
        self.memory.kind = v;
        self
    }
    pub fn weight(mut self, v: f64) -> Self {
        self.memory.weight = v;
        self
    }
    pub fn written_at(mut self, v: DateTime<Utc>) -> Self {
        self.memory.written_at = v;
        self
    }
    pub fn expires_at(mut self, v: DateTime<Utc>) -> Self {
        self.memory.expires_at = Some(v);
        self
    }

    /// Set both provenance edges at once.
    ///
    /// One method rather than two, because a correction needs both and offering them
    /// separately invites writing one and forgetting the other -- which validation
    /// would then catch at the store, further from the mistake.
    pub fn promoted_from(
        mut self,
        signal_idempotency_key: impl Into<String>,
        receipt_id: impl Into<String>,
    ) -> Self {
        self.memory.promoted_from_signal = Some(signal_idempotency_key.into());
        self.memory.derived_from_receipt = Some(receipt_id.into());
        self
    }

    /// Finish, validating as we go.
    ///
    /// Fallible on purpose: the alternative is an invalid `Memory` value existing
    /// long enough to be passed somewhere, and the edge rule is precisely the thing
    /// that must not be possible to forget.
    pub fn build(self) -> Result<Memory, ReedeError> {
        self.memory.validate()?;
        Ok(self.memory)
    }
}

/// What a retrieval asks for.
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryQuery {
    pub tenant_id: String,
    pub role: String,
    pub scope_key: String,
    /// The query vector. Empty means "no similarity ranking" -- return the most
    /// recent live rows in scope instead, which is what a caller without an embedder
    /// gets rather than nothing.
    pub embedding: Vec<f32>,
    pub limit: usize,
}

impl MemoryQuery {
    pub fn new(
        tenant_id: impl Into<String>,
        role: &RoleKey,
        scope_key: impl Into<String>,
        limit: usize,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            role: role.as_key(),
            scope_key: scope_key.into(),
            embedding: Vec::new(),
            limit,
        }
    }

    pub fn with_embedding(mut self, embedding: Vec<f32>) -> Self {
        self.embedding = embedding;
        self
    }
}

/// Cosine similarity in `[-1, 1]`, or `None` when it is not defined.
///
/// `None` rather than `0.0` for a zero-length or mismatched vector: zero is a
/// legitimate similarity (orthogonal), and collapsing "not comparable" into it would
/// silently rank an unembedded row against an embedded one.
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> Option<f64> {
    if a.is_empty() || a.len() != b.len() {
        return None;
    }
    let mut dot = 0.0f64;
    let mut norm_a = 0.0f64;
    let mut norm_b = 0.0f64;
    for (x, y) in a.iter().zip(b.iter()) {
        dot += (*x as f64) * (*y as f64);
        norm_a += (*x as f64) * (*x as f64);
        norm_b += (*y as f64) * (*y as f64);
    }
    if norm_a == 0.0 || norm_b == 0.0 {
        return None;
    }
    Some(dot / (norm_a.sqrt() * norm_b.sqrt()))
}

/// Rank `candidates` against `query`, most similar first, and take the top `limit`.
///
/// The brute-force half of the spec's "measure before choosing": at per-role set
/// sizes this may well beat an HNSW traversal that cannot push the role predicate
/// down. Kept in reede so both the benchmark and any store without a vector index
/// share one definition of the answer -- otherwise the benchmark compares two
/// different rankings and calls it a performance result.
pub fn rank_by_similarity(query: &[f32], candidates: &[Memory], limit: usize) -> Vec<Memory> {
    if query.is_empty() {
        let mut rows = candidates.to_vec();
        rows.sort_by_key(|a| std::cmp::Reverse(a.written_at));
        rows.truncate(limit);
        return rows;
    }
    let mut scored: Vec<(f64, &Memory)> = candidates
        .iter()
        .filter_map(|m| cosine_similarity(query, &m.embedding).map(|s| (s, m)))
        .collect();
    // Similarity descending; `written_at` descending breaks ties, so the ordering is
    // total and a benchmark comparing two implementations is comparing like with
    // like rather than two arbitrary orders of equally-similar rows.
    scored.sort_by(|(sa, ma), (sb, mb)| {
        sb.partial_cmp(sa)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| mb.written_at.cmp(&ma.written_at))
    });
    scored
        .into_iter()
        .take(limit)
        .map(|(_, m)| m.clone())
        .collect()
}

/// Durable per-role memory.
#[async_trait::async_trait]
pub trait MemoryStore: Send + Sync {
    /// Write a memory, returning it with its minted id.
    ///
    /// Implementations must call [`Memory::validate`] and refuse rather than
    /// repairing: a correction arriving without its edges is a bug in the promotion
    /// path, and writing it with a placeholder receipt would hide that bug behind a
    /// row that looks provenanced.
    async fn write(&self, memory: Memory) -> Result<Memory, ReedeError>;

    /// Retrieve live memories in scope, most relevant first.
    async fn retrieve(&self, query: &MemoryQuery) -> Result<Vec<Memory>, ReedeError>;

    /// Every memory promoted from `signal_idempotency_key`.
    ///
    /// The retraction path: a withdrawal names the signal it cancels, and this is
    /// what turns that name into the memories to retract.
    async fn by_signal(
        &self,
        tenant_id: &str,
        signal_idempotency_key: &str,
    ) -> Result<Vec<Memory>, ReedeError>;

    /// Set a memory's weight to zero so it stops being retrieved.
    ///
    /// Not a delete, deliberately: the row and its edges are the provenance record,
    /// and "this was retracted" is a thing someone will need to see.
    async fn retract(&self, tenant_id: &str, memory_id: &str) -> Result<bool, ReedeError>;
}

/// In-memory [`MemoryStore`], the reference implementation.
///
/// Matches the pattern the crate's other traits follow (`InMemoryGoldenStore`,
/// `InMemoryConsumerStore`): a durable store lives host-side because it needs
/// SurrealDB, and reede keeps one that any test or offline caller can use without a
/// database.
///
/// It calls the same [`Memory::validate`] the durable store does, so the two cannot
/// disagree about what a valid memory is -- which matters most for the rule that a
/// correction carries both provenance edges, since that is the kind of rule a second
/// implementation quietly drops.
pub struct InMemoryMemoryStore {
    rows: std::sync::Mutex<Vec<Memory>>,
}

impl InMemoryMemoryStore {
    pub fn new() -> Self {
        Self {
            rows: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Every row, retracted and expired included. For assertions about state the
    /// retrieval path deliberately hides.
    pub fn all(&self) -> Vec<Memory> {
        self.rows.lock().unwrap().clone()
    }
}

impl Default for InMemoryMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl MemoryStore for InMemoryMemoryStore {
    async fn write(&self, memory: Memory) -> Result<Memory, ReedeError> {
        memory.validate()?;
        let mut memory = memory;
        if memory.id.trim().is_empty() {
            memory.id = format!("mem_{}", uuid::Uuid::new_v4().as_simple());
        }
        self.rows.lock().unwrap().push(memory.clone());
        Ok(memory)
    }

    async fn retrieve(&self, query: &MemoryQuery) -> Result<Vec<Memory>, ReedeError> {
        let now = Utc::now();
        let candidates: Vec<Memory> = self
            .rows
            .lock()
            .unwrap()
            .iter()
            .filter(|m| {
                m.tenant_id == query.tenant_id
                    && m.role == query.role
                    && m.scope_key == query.scope_key
                    && m.is_live(now)
            })
            .cloned()
            .collect();
        Ok(rank_by_similarity(
            &query.embedding,
            &candidates,
            query.limit,
        ))
    }

    async fn by_signal(
        &self,
        tenant_id: &str,
        signal_idempotency_key: &str,
    ) -> Result<Vec<Memory>, ReedeError> {
        // Not filtered on liveness, matching the durable store: this is the
        // provenance query, and an already-retracted memory is exactly what someone
        // asking "what did this signal produce" needs to see.
        Ok(self
            .rows
            .lock()
            .unwrap()
            .iter()
            .filter(|m| {
                m.tenant_id == tenant_id
                    && m.promoted_from_signal.as_deref() == Some(signal_idempotency_key)
            })
            .cloned()
            .collect())
    }

    async fn retract(&self, tenant_id: &str, memory_id: &str) -> Result<bool, ReedeError> {
        let mut rows = self.rows.lock().unwrap();
        for memory in rows.iter_mut() {
            if memory.tenant_id == tenant_id && memory.id == memory_id && memory.weight > 0.0 {
                memory.weight = 0.0;
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn role() -> RoleKey {
        RoleKey::new("council-summary", "product").unwrap()
    }

    fn correction() -> MemoryBuilder {
        Memory::builder(&role(), "billing")
            .tenant("tenant-1")
            .text("the balance shown must come from account-history, not the draft")
            .kind(MemoryKind::Correction)
            .promoted_from("diff-capture:run-1", "receipt-1")
    }

    // The spec's acceptance criterion: "Correction row missing either edge is
    // rejected." Both directions, one test each, because a rule that only fires on
    // one of the two edges is half a rule.
    #[test]
    fn a_correction_without_the_receipt_edge_is_rejected() {
        let mut memory = correction().build().unwrap();
        memory.derived_from_receipt = None;
        let error = memory.validate().unwrap_err().to_string();
        assert!(error.contains("derived_from"), "{error}");
        assert!(
            error.contains("swept") || error.contains("attributed"),
            "the error must say what is lost, not just which field: {error}"
        );
    }

    #[test]
    fn a_correction_without_the_signal_edge_is_rejected() {
        let mut memory = correction().build().unwrap();
        memory.promoted_from_signal = None;
        let error = memory.validate().unwrap_err().to_string();
        assert!(error.contains("promoted_to"), "{error}");
        assert!(error.contains("retracted"), "{error}");
    }

    #[test]
    fn an_empty_string_is_not_an_edge() {
        // The likelier bug than `None`: a caller threading an id through that turns
        // out to be empty. A row with `derived_from_receipt: Some("")` would satisfy
        // a presence check and point at nothing.
        let mut memory = correction().build().unwrap();
        memory.derived_from_receipt = Some("   ".to_string());
        assert!(memory.validate().is_err());
    }

    #[test]
    fn a_correction_with_both_edges_is_accepted() {
        let memory = correction().build().unwrap();
        assert_eq!(memory.kind, MemoryKind::Correction);
        assert_eq!(
            memory.promoted_from_signal.as_deref(),
            Some("diff-capture:run-1")
        );
        assert_eq!(memory.derived_from_receipt.as_deref(), Some("receipt-1"));
    }

    #[test]
    fn a_report_needs_no_edges() {
        // It is not derived from anyone's judgement, so there is no signal to point
        // at. Holding it to the correction rule would mean inventing one.
        let memory = Memory::builder(&role(), "billing")
            .tenant("tenant-1")
            .text("the customer is on the 2024 legacy plan")
            .kind(MemoryKind::Report)
            .build()
            .unwrap();
        assert!(memory.derived_from_receipt.is_none());
        assert!(!memory.kind.requires_provenance_edges());
    }

    #[test]
    fn a_verdict_needs_no_edges() {
        assert!(!MemoryKind::Verdict.requires_provenance_edges());
    }

    #[test]
    fn a_role_that_is_not_a_canonical_key_is_rejected() {
        let mut memory = correction().build().unwrap();
        memory.role = "product".to_string(); // no capability half
        assert!(
            memory.validate().is_err(),
            "a non-canonical role is a scope nothing will retrieve from"
        );
    }

    #[test]
    fn the_obvious_empties_are_rejected() {
        for mutate in [
            (|m: &mut Memory| m.tenant_id = String::new()) as fn(&mut Memory),
            |m: &mut Memory| m.scope_key = "  ".to_string(),
            |m: &mut Memory| m.text = "\n".to_string(),
            |m: &mut Memory| m.weight = -1.0,
            |m: &mut Memory| m.weight = f64::NAN,
        ] {
            let mut memory = correction().build().unwrap();
            mutate(&mut memory);
            assert!(memory.validate().is_err());
        }
    }

    #[test]
    fn a_memory_with_no_embedding_is_still_valid() {
        // Deliberate: a lesson that exists but is not yet findable by similarity
        // beats one that was never written because the embedder was down.
        let memory = correction().build().unwrap();
        assert!(memory.embedding.is_empty());
    }

    #[test]
    fn retraction_and_expiry_both_stop_retrieval_without_deleting() {
        let now = Utc::now();
        let mut retracted = correction().build().unwrap();
        retracted.weight = 0.0;
        assert!(!retracted.is_live(now));

        let expired = correction()
            .expires_at(now - Duration::seconds(1))
            .build()
            .unwrap();
        assert!(!expired.is_live(now));

        let live = correction()
            .expires_at(now + Duration::days(1))
            .build()
            .unwrap();
        assert!(live.is_live(now));
        assert!(
            correction().build().unwrap().is_live(now),
            "no expiry means live"
        );
    }

    #[test]
    fn cosine_similarity_is_not_defined_for_incomparable_vectors() {
        assert_eq!(cosine_similarity(&[], &[]), None);
        assert_eq!(cosine_similarity(&[1.0, 0.0], &[1.0]), None);
        assert_eq!(
            cosine_similarity(&[0.0, 0.0], &[1.0, 0.0]),
            None,
            "a zero vector has no direction; 0.0 would read as orthogonal"
        );
    }

    #[test]
    fn cosine_similarity_matches_the_textbook_cases() {
        let s = |a: &[f32], b: &[f32]| cosine_similarity(a, b).unwrap();
        assert!((s(&[1.0, 0.0], &[1.0, 0.0]) - 1.0).abs() < 1e-9);
        assert!(s(&[1.0, 0.0], &[0.0, 1.0]).abs() < 1e-9);
        assert!((s(&[1.0, 0.0], &[-1.0, 0.0]) + 1.0).abs() < 1e-9);
        assert!(
            (s(&[1.0, 0.0], &[5.0, 0.0]) - 1.0).abs() < 1e-9,
            "magnitude must not matter"
        );
    }

    /// A real-width embedding whose leading components are the ones under test.
    ///
    /// Zero-padding to [`EMBEDDING_DIMENSIONS`] leaves cosine similarity untouched
    /// -- it adds nothing to either dot product or norm -- so the ranking assertions
    /// mean exactly what they did when the fixtures were two-dimensional, while the
    /// rows are ones the store would actually accept.
    fn padded(head: &[f32]) -> Vec<f32> {
        let mut v = head.to_vec();
        v.resize(EMBEDDING_DIMENSIONS, 0.0);
        v
    }

    fn embedded(text: &str, embedding: Vec<f32>, written_at: DateTime<Utc>) -> Memory {
        Memory::builder(&role(), "billing")
            .tenant("tenant-1")
            .text(text)
            .kind(MemoryKind::Report)
            .embedding(padded(&embedding))
            .written_at(written_at)
            .build()
            .unwrap()
    }

    #[test]
    fn ranking_puts_the_most_similar_first_and_honours_the_limit() {
        let now = Utc::now();
        let rows = vec![
            embedded("orthogonal", vec![0.0, 1.0], now),
            embedded("exact", vec![1.0, 0.0], now),
            embedded("close", vec![0.9, 0.1], now),
        ];
        let ranked = rank_by_similarity(&padded(&[1.0, 0.0]), &rows, 2);
        assert_eq!(
            ranked.iter().map(|m| m.text.as_str()).collect::<Vec<_>>(),
            ["exact", "close"]
        );
    }

    #[test]
    fn an_unembedded_row_is_not_ranked_against_embedded_ones() {
        let now = Utc::now();
        let rows = vec![
            embedded("exact", vec![1.0, 0.0], now),
            correction().build().unwrap(), // no embedding
        ];
        let ranked = rank_by_similarity(&padded(&[1.0, 0.0]), &rows, 10);
        assert_eq!(
            ranked.len(),
            1,
            "not comparable means not returned, not last"
        );
    }

    #[test]
    fn an_empty_query_falls_back_to_most_recent() {
        let now = Utc::now();
        let rows = vec![
            embedded("older", vec![1.0, 0.0], now - Duration::days(2)),
            embedded("newer", vec![0.0, 1.0], now),
        ];
        let ranked = rank_by_similarity(&[], &rows, 10);
        assert_eq!(
            ranked.first().map(|m| m.text.as_str()),
            Some("newer"),
            "a caller with no embedder gets recency, not nothing"
        );
    }

    #[test]
    fn ranking_is_a_total_order_so_two_implementations_can_be_compared() {
        // Equally similar rows must come back in a defined order, or a benchmark
        // comparing brute force against an index is comparing two arbitrary orders.
        let now = Utc::now();
        let rows = vec![
            embedded("a", vec![1.0, 0.0], now - Duration::seconds(2)),
            embedded("b", vec![1.0, 0.0], now),
        ];
        assert_eq!(
            rank_by_similarity(&padded(&[1.0, 0.0]), &rows, 10)
                .iter()
                .map(|m| m.text.as_str())
                .collect::<Vec<_>>(),
            ["b", "a"]
        );
    }
    /// A nonempty embedding has to be a real vector.
    ///
    /// Both of these were accepted, and both fail *later* and *elsewhere*: the wrong
    /// dimension makes `cosine_similarity` return `None`, so the row is quietly
    /// skipped by every ranked retrieval; a non-finite element is written as JSON
    /// `null`, and the decode then fails for the whole scope, so one bad row takes
    /// out every retrieval for that role.
    #[test]
    fn a_nonempty_embedding_must_be_the_right_width_and_finite() {
        let build = |embedding: Vec<f32>| {
            Memory::builder(&role(), "billing")
                .tenant("tenant-1")
                .text("a lesson")
                .kind(MemoryKind::Report)
                .embedding(embedding)
                .build()
        };

        let short = build(vec![1.0, 0.0]).unwrap_err().to_string();
        assert!(short.contains("dimensions"), "{short}");

        for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let mut v = padded(&[1.0]);
            v[7] = bad;
            let err = build(v).unwrap_err().to_string();
            assert!(err.contains("finite"), "{bad}: {err}");
        }

        build(padded(&[1.0])).expect("a full-width finite vector is fine");
    }

    #[test]
    fn an_empty_embedding_is_still_allowed() {
        // The deliberate case: written before an embedder was available, retrieved
        // by recency. Tightening the vector rules must not close this off.
        Memory::builder(&role(), "billing")
            .tenant("tenant-1")
            .text("a lesson from before we had vectors")
            .kind(MemoryKind::Report)
            .build()
            .expect("no embedding is not a malformed embedding");
    }

    /// Parsing is not the same as being canonical.
    ///
    /// `RoleKey::parse` lowercases and trims, so these all parsed while the row kept
    /// its original spelling -- and every query is built from the normalised key, so
    /// the memory sits on a shelf no reader ever looks at.
    #[test]
    fn a_role_that_is_not_already_canonical_is_refused() {
        for spelling in [
            "Council-Summary/Product",
            "  council-summary/product  ",
            "council-summary/ product",
        ] {
            let mut m = Memory::builder(&role(), "billing")
                .tenant("tenant-1")
                .text("a lesson")
                .kind(MemoryKind::Report)
                .build()
                .unwrap();
            m.role = spelling.to_string();
            let err = m
                .validate()
                .expect_err("a non-canonical role must not validate")
                .to_string();
            assert!(
                err.contains("canonical") || err.contains("role key"),
                "{err}"
            );
        }
    }
}
