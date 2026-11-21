//! Durable subject identity for agent outputs.
//!
//! Every agent artifact ("subject") gets a stable, durable identifier that
//! survives into the world, so a signal arriving days, weeks, or months later
//! can be joined back to the run (and the Reede receipt) that produced it.
//!
//! The join is `subject -> run (Task) -> Reede receipt`, so the trust layer and
//! the future feedback layer share one key. The `SubjectStore` is the
//! authoritative join table; receipts remain immutable and are referenced by
//! their `content_hash`.
//!
//! This module is deliberately vertical-agnostic and free of any the host application
//! dependency. The "carry into published artifact" concern is exposed as pure
//! string helpers (`frontmatter_value`, `header_value`, `url_param_value`,
//! `pr_body_marker`) so each vertical decides where to stamp the id.
//!
//! Late writes are always accepted: a subject can be registered against a run
//! and/or external identifier at any time. Nothing ever "closes" a subject.

use crate::error::ReedeError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

/// Human-readable prefix so a subject id is recognisable at a glance and can be
/// grepped across logs, frontmatter and analytics URLs.
pub const SUBJECT_ID_PREFIX: &str = "sub";

/// Which kind of published artifact a subject represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactKind {
    /// Markdown / long-form article.
    Article,
    /// Outbound email draft.
    Email,
    /// Code patch / pull request.
    PullRequest,
    /// Generated image (sharepic).
    Sharepic,
    /// Generated route.
    Route,
    /// Anything not covered above.
    Other,
}

impl ArtifactKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ArtifactKind::Article => "article",
            ArtifactKind::Email => "email",
            ArtifactKind::PullRequest => "pull_request",
            ArtifactKind::Sharepic => "sharepic",
            ArtifactKind::Route => "route",
            ArtifactKind::Other => "other",
        }
    }
}

impl std::fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A durable subject identity for one agent artifact.
///
/// A subject is minted per artifact (article slug, sent email, PR, sharepic,
/// generated route), *not* per run. A single run may produce several subjects,
/// and a single subject is normally produced by one run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Subject {
    /// Immutable, minted-once id. Prefix `sub_` plus a UUID v4.
    pub id: String,
    pub tenant_id: String,
    pub artifact_kind: ArtifactKind,
    /// External identifiers the artifact can be looked up by in the world:
    /// article slug, URL, email Message-Id, PR number, sharepic CDN path, etc.
    #[serde(default)]
    pub external_identifiers: Vec<String>,
    /// The Reede run (Task) that produced this artifact.
    #[serde(default)]
    pub producing_task_id: Option<Uuid>,
    /// The Reede receipt chain hash of the producing run. Stored rather than the
    /// full receipt so the receipt itself stays immutable and the chain hash is
    /// the stable reference.
    #[serde(default)]
    pub producing_receipt_hash: Option<String>,
    /// Attribution confidence. Rows created via the backfill path (best-effort
    /// match against pre-existing artifacts) are low confidence until confirmed.
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    /// Set when this row was created by the backfill path rather than at
    /// publish time.
    #[serde(default)]
    pub backfilled: bool,
    pub created_at: DateTime<Utc>,
}

fn default_confidence() -> f64 {
    1.0
}

impl Subject {
    /// Mint a new subject; keep calling this instead of constructing by hand so
    /// the id prefix convention is applied in exactly one place.
    pub fn mint(tenant_id: impl Into<String>, artifact_kind: ArtifactKind) -> Self {
        Self {
            id: format!("{SUBJECT_ID_PREFIX}_{}", Uuid::new_v4()),
            tenant_id: tenant_id.into(),
            artifact_kind,
            external_identifiers: Vec::new(),
            producing_task_id: None,
            producing_receipt_hash: None,
            confidence: default_confidence(),
            backfilled: false,
            created_at: Utc::now(),
        }
    }

    /// Attach a run (task) and the producing receipt's chain hash to this
    /// subject. Idempotent: re-binding the same task just overwrites.
    pub fn bind_to_run(&mut self, task_id: Uuid, receipt_hash: impl Into<String>) {
        self.producing_task_id = Some(task_id);
        self.producing_receipt_hash = Some(receipt_hash.into());
        self.confidence = 1.0;
        self.backfilled = false;
    }

    /// Attach an external identifier (slug, URL, header value, ...). Dedupes.
    pub fn add_external_identifier(&mut self, identifier: impl Into<String>) {
        let id = identifier.into();
        if id.trim().is_empty() {
            return;
        }
        if !self.external_identifiers.iter().any(|x| x == &id) {
            self.external_identifiers.push(id);
        }
    }
}

// --- Card-carrying helpers --------------------------------------------------
// Pure string helpers so a vertical can stamp the id wherever it naturally
// lives: frontmatter, an email header, a URL param, or a PR body marker.

/// Value to embed in article frontmatter, e.g. `subject_id: sub_<uuid>`.
pub fn frontmatter_value(subject_id: &str) -> String {
    format!("subject_id: {subject_id}")
}

/// Value for an RFC-style outbound header, e.g. `X-Reede-Subject: sub_<uuid>`.
pub fn header_value(subject_id: &str) -> String {
    format!("X-Reede-Subject: {subject_id}")
}

/// Subject id from a header line; accepts the neutral `X-Reede-Subject` and the legacy
/// `X-Tectic-Subject` name (case-insensitive, as header names are).
pub fn subject_from_header(line: &str) -> Option<&str> {
    let (name, value) = line.split_once(':')?;
    let name = name.trim();
    (name.eq_ignore_ascii_case("X-Reede-Subject") || name.eq_ignore_ascii_case("X-Tectic-Subject"))
        .then(|| value.trim())
        .filter(|v| !v.is_empty())
}

/// Value for a URL query parameter, e.g. `subject_id=sub_<uuid>`.
pub fn url_param_value(subject_id: &str) -> String {
    format!("subject_id={subject_id}")
}

/// Marker line to inject into a PR body so the produced code is resolvable.
pub fn pr_body_marker(subject_id: &str) -> String {
    format!("<!-- subject_id: {subject_id} -->")
}

/// Canonical form of an external identifier, used for every lookup.
///
/// Public because it is part of the [`SubjectStore`] contract, not an
/// implementation detail of one store: every implementation must canonicalize
/// identically or the same artifact resolves in one store and not in another.
/// A durable store that indexes identifiers for SQL lookup has to apply this at
/// write time (see `reede-store-surreal`'s `external_canonical` column).
pub fn canonicalize_external(identifier: &str) -> String {
    identifier.trim().to_string()
}

/// The authoritative `subject -> run -> receipt` join store.
#[async_trait]
pub trait SubjectStore: Send + Sync {
    /// Persist a subject (create or update). Late writes are always accepted.
    async fn save(&self, subject: &Subject) -> Result<(), ReedeError>;

    /// Look up a subject directly by its `sub_<uuid>` id (scoped to tenant).
    async fn get(&self, tenant_id: &str, subject_id: &str) -> Result<Option<Subject>, ReedeError>;

    /// Resolve a subject from an external identifier (slug, URL, header value).
    /// This is the acceptance path: any artifact in the world resolved
    /// back to its producing run + receipt.
    async fn resolve_by_external(
        &self,
        tenant_id: &str,
        external_identifier: &str,
    ) -> Result<Option<Subject>, ReedeError>;

    /// Resolve the subject(s) that a run (Task) produced.
    async fn resolve_by_task(
        &self,
        tenant_id: &str,
        task_id: Uuid,
    ) -> Result<Vec<Subject>, ReedeError>;

    /// Best-effort backfill for artifacts published before subject ids existed.
    /// Matches by external identifier only (no run binding), marks the row
    /// low confidence and `backfilled = true` for later confirmation.
    async fn backfill(
        &self,
        tenant_id: &str,
        external_identifier: &str,
        artifact_kind: ArtifactKind,
    ) -> Result<Subject, ReedeError>;
}

/// In-memory implementation (matching `InMemoryReceiptStore` style). The
/// production binding to SurrealDB lands with the append-only signal store
/// this keeps the identity semantics provable now.
pub struct InMemorySubjectStore {
    /// subject_id -> subject, keyed globally; every read method below filters
    /// on tenant_id itself (see `get`, `resolve_by_external`,
    /// `resolve_by_task`), matching how the rest of Reede scopes in-memory
    /// stores.
    by_id: Mutex<HashMap<String, Subject>>,
}

impl InMemorySubjectStore {
    pub fn new() -> Self {
        Self {
            by_id: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemorySubjectStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SubjectStore for InMemorySubjectStore {
    async fn save(&self, subject: &Subject) -> Result<(), ReedeError> {
        let mut map = self.by_id.lock().unwrap();
        map.insert(subject.id.clone(), subject.clone());
        Ok(())
    }

    async fn get(&self, tenant_id: &str, subject_id: &str) -> Result<Option<Subject>, ReedeError> {
        let map = self.by_id.lock().unwrap();
        Ok(map
            .get(subject_id)
            .filter(|s| s.tenant_id == tenant_id)
            .cloned())
    }

    async fn resolve_by_external(
        &self,
        tenant_id: &str,
        external_identifier: &str,
    ) -> Result<Option<Subject>, ReedeError> {
        let needle = canonicalize_external(external_identifier);
        let map = self.by_id.lock().unwrap();
        Ok(map
            .values()
            .filter(|s| s.tenant_id == tenant_id)
            .find(|s| {
                s.external_identifiers
                    .iter()
                    .any(|e| canonicalize_external(e) == needle)
            })
            .cloned())
    }

    async fn resolve_by_task(
        &self,
        tenant_id: &str,
        task_id: Uuid,
    ) -> Result<Vec<Subject>, ReedeError> {
        let map = self.by_id.lock().unwrap();
        let mut subjects: Vec<Subject> = map
            .values()
            .filter(|s| s.tenant_id == tenant_id && s.producing_task_id == Some(task_id))
            .cloned()
            .collect();
        subjects.sort_by_key(|s| s.created_at);
        Ok(subjects)
    }

    async fn backfill(
        &self,
        tenant_id: &str,
        external_identifier: &str,
        artifact_kind: ArtifactKind,
    ) -> Result<Subject, ReedeError> {
        let needle = canonicalize_external(external_identifier);
        if needle.is_empty() {
            return Err(ReedeError::SpecValidationFailed {
                reason: "backfill requires a non-empty external identifier".to_string(),
            });
        }

        // Re-use an existing backfilled subject for the same id if present.
        {
            let map = self.by_id.lock().unwrap();
            if let Some(existing) = map
                .values()
                .filter(|s| s.tenant_id == tenant_id && s.backfilled)
                .find(|s| {
                    s.external_identifiers
                        .iter()
                        .any(|e| canonicalize_external(e) == needle)
                })
            {
                return Ok(existing.clone());
            }
        }

        let mut subject = Subject::mint(tenant_id, artifact_kind);
        subject.backfilled = true;
        subject.confidence = 0.4; // best-effort match, unconfirmed
        subject.add_external_identifier(needle);
        self.save(&subject).await?;
        Ok(subject)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mint_produces_prefixed_unique_ids() {
        let a = Subject::mint("tenant-1", ArtifactKind::Article);
        let b = Subject::mint("tenant-1", ArtifactKind::Article);
        assert!(a.id.starts_with("sub_"));
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn test_bind_run_and_external_identifier_are_deduplicating() {
        let mut subject = Subject::mint("tenant-1", ArtifactKind::Article);
        let task_id = Uuid::new_v4();
        subject.bind_to_run(task_id, "hash-abc");
        subject.bind_to_run(task_id, "hash-abc"); // idempotent
        subject.add_external_identifier("my-article-slug");
        subject.add_external_identifier("my-article-slug"); // dedup
        subject.add_external_identifier("   "); // ignored

        assert_eq!(subject.producing_task_id, Some(task_id));
        assert_eq!(subject.producing_receipt_hash.as_deref(), Some("hash-abc"));
        assert_eq!(subject.external_identifiers.len(), 1);
    }

    #[test]
    fn test_card_carrying_helpers() {
        let sid = "sub_123";
        assert_eq!(frontmatter_value(sid), "subject_id: sub_123");
        assert_eq!(header_value(sid), "X-Reede-Subject: sub_123");
        assert_eq!(
            subject_from_header("X-Reede-Subject: sub_123"),
            Some("sub_123")
        );
        assert_eq!(
            subject_from_header("x-tectic-subject:sub_123"),
            Some("sub_123")
        );
        assert_eq!(subject_from_header("X-Other: sub_123"), None);
        assert_eq!(url_param_value(sid), "subject_id=sub_123");
        assert_eq!(pr_body_marker(sid), "<!-- subject_id: sub_123 -->");
    }

    #[tokio::test]
    async fn test_resolve_external_to_subject_to_run_after_late_write() {
        let store = InMemorySubjectStore::new();
        let mut subject = Subject::mint("tenant-1", ArtifactKind::Article);
        subject.add_external_identifier("https://example.eu/a/deep-hook");
        store.save(&subject).await.unwrap();

        // Late write: bind the run + receipt days after publication, then
        // resolve from the external identifier alone.
        let task_id = Uuid::new_v4();
        let mut fetched = store
            .resolve_by_external("tenant-1", "https://example.eu/a/deep-hook")
            .await
            .unwrap()
            .expect("resolved by external id");
        fetched.bind_to_run(task_id, "receipt-hash-42".to_string());
        store.save(&fetched).await.unwrap();

        let resolved = store
            .resolve_by_external("tenant-1", "https://example.eu/a/deep-hook")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resolved.producing_task_id, Some(task_id));
        assert_eq!(
            resolved.producing_receipt_hash.as_deref(),
            Some("receipt-hash-42")
        );

        // And from run back to subject.
        let by_task = store.resolve_by_task("tenant-1", task_id).await.unwrap();
        assert_eq!(by_task.len(), 1);
        assert_eq!(by_task[0].id, resolved.id);
    }

    #[tokio::test]
    async fn test_tenant_isolation() {
        let store = InMemorySubjectStore::new();
        let mut subject = Subject::mint("tenant-A", ArtifactKind::Article);
        subject.add_external_identifier("tenant-a-only-slug");
        store.save(&subject).await.unwrap();

        assert!(store
            .resolve_by_external("tenant-B", &subject.external_identifiers[0])
            .await
            .unwrap()
            .is_none());
        assert!(store.get("tenant-B", &subject.id).await.unwrap().is_none());
        assert!(store.get("tenant-A", &subject.id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_backfill_marks_low_confidence_and_dedupes() {
        let store = InMemorySubjectStore::new();
        let first = store
            .backfill("tenant-1", "legacy-article-slug", ArtifactKind::Article)
            .await
            .unwrap();
        assert!(first.backfilled);
        assert!(first.confidence < 1.0);
        assert!(first.producing_task_id.is_none());

        // Re-running backfill for the same id returns the same subject.
        let second = store
            .backfill("tenant-1", "legacy-article-slug", ArtifactKind::Article)
            .await
            .unwrap();
        assert_eq!(first.id, second.id);
    }
}
