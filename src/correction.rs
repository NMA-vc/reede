//! Diff-capture producer (the highest-value signal).
//!
//! Captures what a human actually changed in an agent output before shipping
//! it. This is free, specific, instance-level supervision that is normally
//! thrown away, and it beats a thumbs rating by a wide margin.
//!
//! `SectionedDiff` snapshots an output at handoff and again at publish/send and
//! produces a *structured* diff: which sections changed, were added, deleted,
//! or reordered - not a bare edit distance. Publishing an edited
//! article therefore produces one correction signal per changed section, with
//! the before and after text, all scoped to the tenant's namespace.
//!
//! A "document" here is any text that can be split into discrete sections
//! (markdown article, outbound email draft, code patch). We split on
//! `## `-style (level-two or above) headings and treat each heading plus its
//! body as a section; the lead block before the first heading is its own
//! section keyed `:lead`. Sections are matched across the two snapshots by
//! their heading key (stable identity), so recognition does not depend on
//! position or edit distance.
//!
//! Privacy: correction signals and their before/after payloads are produced
//! tenant-scoped and never cross tenants (none of this code reads any
//! cross-tenant state).

use crate::signal::{AttributionSource, LatencyClass, Signal, SignalKind};

/// A discrete section of a document with a stable identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// Stable identity used to match a section across snapshots (its heading or
    /// `:lead` for the pre-heading block).
    pub key: String,
    /// The section body (heading text excluded from the comparison and the
    /// before/after payload; we keep them apart so the diff targets the passage
    /// the human rewrote, not the heading).
    pub content: String,
    /// Zero-based position in the source document.
    pub order: usize,
}

/// How one section changed between handoff and publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SectionChangeKind {
    /// Present in publish only.
    Added,
    /// Present in handoff only.
    Deleted,
    /// Present in both but the body text differs.
    Modified,
    /// Present in both and unchanged in text but moved relative to neighbours.
    Reordered,
}

/// One structured change for a section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionChange {
    pub key: String,
    pub kind: SectionChangeKind,
    /// The handoff (before) body, if present there.
    pub before: Option<String>,
    /// The published (after) body, if present there.
    pub after: Option<String>,
    pub order_before: Option<usize>,
    pub order_after: Option<usize>,
}

impl SectionChange {
    pub fn is_empty(&self) -> bool {
        self.before.is_none() && self.after.is_none()
    }
}

/// Split a document into ordered sections by `## `/`### ` headings.
///
/// Markdown headings are preserved as identity keys (the body comparison
/// excludes the heading line so a reworded body still matches its section).
pub fn sectionize(document: &str) -> Vec<Section> {
    let mut sections: Vec<Section> = Vec::new();
    let mut lead = String::new();
    let mut current_key: Option<String> = None;
    let mut current_body = String::new();
    let mut index = 0usize;

    fn push(sections: &mut Vec<Section>, index: &mut usize, key: String, content: &str) {
        let trimmed = content.trim();
        if trimmed.is_empty() {
            return;
        }
        sections.push(Section {
            key,
            content: trimmed.to_string(),
            order: *index,
        });
        *index += 1;
    }

    for line in document.lines() {
        if line.starts_with("## ") || line.starts_with("### ") {
            // Flush whatever section was being accumulated.
            match current_key.take() {
                Some(key) => push(&mut sections, &mut index, key, &current_body),
                None if !lead.is_empty() => {
                    push(&mut sections, &mut index, ":lead".to_string(), &lead)
                }
                None => {}
            }
            current_body.clear();
            let heading = if let Some(rest) = line.strip_prefix("### ") {
                rest
            } else {
                line.strip_prefix("## ").unwrap_or(line)
            };
            current_key = Some(heading.trim().to_string());
        } else if current_key.is_some() {
            if !current_body.is_empty() {
                current_body.push('\n');
            }
            current_body.push_str(line);
        } else {
            if !lead.is_empty() {
                lead.push('\n');
            }
            lead.push_str(line);
        }
    }

    if let Some(key) = current_key {
        push(&mut sections, &mut index, key, &current_body);
    } else if !lead.trim().is_empty() {
        push(&mut sections, &mut index, ":lead".to_string(), &lead);
    }

    sections
}

/// A normalized token-ish key for body comparison (lowercase + collapsed
/// whitespace). Exact on the collapsed text, so whitespace-only edits are
/// ignored (not treated as a rewrite).
fn normalized(content: &str) -> String {
    content
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// The keys shared by `sections` and `other_by_key`, in `sections`' own
/// document order, with duplicates collapsed to their first occurrence. A
/// document with two sections under the same heading is a known, documented
/// lossy case (see `test_duplicate_heading_collapses_to_last_section`) - this
/// dedup keeps that collision from also duplicating diff work, it does not
/// resolve the collision itself.
fn common_ordered_keys<'a>(
    sections: &'a [Section],
    other_by_key: &std::collections::HashMap<&str, &Section>,
) -> Vec<&'a str> {
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    sections
        .iter()
        .map(|s| s.key.as_str())
        .filter(|k| other_by_key.contains_key(k) && seen.insert(k))
        .collect()
}

/// Longest-common-subsequence membership: the keys that keep the same
/// relative order in both `before_keys` and `after_keys`. A key present in
/// both sequences but *not* in this set moved relative to its similarly-kept
/// neighbours - a real reorder, not an artifact of something else being
/// inserted or deleted elsewhere in the document (which shifts every later
/// section's *absolute* index without moving anything relative to its
/// neighbours).
fn lcs_stationary_keys(
    before_keys: &[&str],
    after_keys: &[&str],
) -> std::collections::HashSet<String> {
    let n = before_keys.len();
    let m = after_keys.len();
    let mut dp = vec![vec![0usize; m + 1]; n + 1];
    for i in 1..=n {
        for j in 1..=m {
            dp[i][j] = if before_keys[i - 1] == after_keys[j - 1] {
                dp[i - 1][j - 1] + 1
            } else {
                dp[i - 1][j].max(dp[i][j - 1])
            };
        }
    }
    let mut stationary = std::collections::HashSet::new();
    let (mut i, mut j) = (n, m);
    while i > 0 && j > 0 {
        if before_keys[i - 1] == after_keys[j - 1] {
            stationary.insert(before_keys[i - 1].to_string());
            i -= 1;
            j -= 1;
        } else if dp[i - 1][j] >= dp[i][j - 1] {
            i -= 1;
        } else {
            j -= 1;
        }
    }
    stationary
}

/// Compute a structured diff between a handoff snapshot and a published one.
pub fn sectioned_diff(before_doc: &str, after_doc: &str) -> Vec<SectionChange> {
    let before = sectionize(before_doc);
    let after = sectionize(after_doc);

    let before_by_key: std::collections::HashMap<&str, &Section> =
        before.iter().map(|s| (s.key.as_str(), s)).collect();
    let after_by_key: std::collections::HashMap<&str, &Section> =
        after.iter().map(|s| (s.key.as_str(), s)).collect();

    // Reorder is decided relative to the sections common to both snapshots,
    // not by comparing raw indices - inserting or deleting one section must
    // not cascade a false "Reordered" onto every later, untouched section.
    let before_keys_common = common_ordered_keys(&before, &after_by_key);
    let after_keys_common = common_ordered_keys(&after, &before_by_key);
    let stationary = lcs_stationary_keys(&before_keys_common, &after_keys_common);

    let mut changes: Vec<SectionChange> = Vec::new();

    // Every key present in either snapshot, in after-then-before order so the
    // result reads left-to-right in the published document first. Deduped so
    // a duplicate heading (a known lossy case, see before_by_key/after_by_key
    // above) produces at most one change instead of double-processing it.
    let mut seen_keys: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut keys: Vec<&str> = Vec::new();
    for s in &after {
        if seen_keys.insert(s.key.as_str()) {
            keys.push(s.key.as_str());
        }
    }
    for s in &before {
        if !after_by_key.contains_key(s.key.as_str()) && seen_keys.insert(s.key.as_str()) {
            keys.push(s.key.as_str());
        }
    }

    for key in keys {
        match (before_by_key.get(key), after_by_key.get(key)) {
            (Some(b), Some(a)) => {
                if normalized(&b.content) != normalized(&a.content) {
                    changes.push(SectionChange {
                        key: key.to_string(),
                        kind: SectionChangeKind::Modified,
                        before: Some(b.content.clone()),
                        after: Some(a.content.clone()),
                        order_before: Some(b.order),
                        order_after: Some(a.order),
                    });
                } else if !stationary.contains(key) {
                    changes.push(SectionChange {
                        key: key.to_string(),
                        kind: SectionChangeKind::Reordered,
                        before: Some(b.content.clone()),
                        after: Some(a.content.clone()),
                        order_before: Some(b.order),
                        order_after: Some(a.order),
                    });
                }
            }
            (Some(b), None) => {
                changes.push(SectionChange {
                    key: key.to_string(),
                    kind: SectionChangeKind::Deleted,
                    before: Some(b.content.clone()),
                    after: None,
                    order_before: Some(b.order),
                    order_after: None,
                });
            }
            (None, Some(a)) => {
                changes.push(SectionChange {
                    key: key.to_string(),
                    kind: SectionChangeKind::Added,
                    before: None,
                    after: Some(a.content.clone()),
                    order_before: None,
                    order_after: Some(a.order),
                });
            }
            // `keys` is built only from after's keys and before's keys not in
            // after_by_key, so every entry resolves in at least one map.
            (None, None) => unreachable!("every key present in at least one snapshot"),
        }
    }

    changes
}

/// Facts shared by every correction signal produced from one structured diff.
#[derive(Debug, Clone, Copy)]
pub struct CorrectionSignalContext<'a> {
    pub tenant_id: &'a str,
    pub subject_id: &'a str,
    pub agent_id: &'a str,
    pub capability: &'a str,
    pub source_version: &'a str,
    pub run_id: &'a str,
    pub role: &'a str,
}

/// Turn a structured diff into one `Correction` signal per changed section.
///
/// Value is normalized to -1 (a rewrite is supervision on a weak passage).
/// The before/after text travels in the raw payload so the specific rewrite is
/// preserved. Late writes are accepted by the store; nothing here closes a
/// subject.
#[allow(clippy::too_many_arguments)] // Preserve the established public positional API.
pub fn correction_signals(
    tenant_id: &str,
    subject_id: &str,
    agent_id: &str,
    capability: &str,
    source_version: &str,
    run_id: &str,
    role: &str,
    changes: &[SectionChange],
) -> Vec<Signal> {
    correction_signals_with_context(
        CorrectionSignalContext {
            tenant_id,
            subject_id,
            agent_id,
            capability,
            source_version,
            run_id,
            role,
        },
        changes,
    )
}

/// Context-based additive form of [`correction_signals`].
pub fn correction_signals_with_context(
    context: CorrectionSignalContext<'_>,
    changes: &[SectionChange],
) -> Vec<Signal> {
    let CorrectionSignalContext {
        tenant_id,
        subject_id,
        agent_id,
        capability,
        source_version,
        run_id,
        role,
    } = context;
    let mut out = Vec::new();
    for (i, change) in changes.iter().enumerate() {
        let idem = format!("{subject_id}:{capability}:section:{i}:{}", change.key);
        let raw = serde_json::json!({
            "before": change.before,
            "after": change.after,
            "kind": match change.kind {
                SectionChangeKind::Added => "added",
                SectionChangeKind::Deleted => "deleted",
                SectionChangeKind::Modified => "modified",
                SectionChangeKind::Reordered => "reordered",
            },
            "order_before": change.order_before,
            "order_after": change.order_after,
        });
        let signal = Signal::builder(subject_id)
            .tenant(tenant_id)
            .agent(agent_id)
            .capability(capability)
            .source("diff-capture")
            .source_version(source_version)
            .kind(SignalKind::Correction)
            .value(-1.0)
            .raw(raw)
            .confidence(1.0)
            .latency(LatencyClass::Immediate)
            .idempotency(idem)
            .run(run_id)
            // Explicit by construction: one signal per changed section means the
            // section the human edited *is* the attribution, so nothing has to
            // be inferred afterwards (D5).
            .attributed_to(role, AttributionSource::Explicit)
            .build();
        out.push(signal);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const HANDOFF: &str = "\
Intro lead paragraph that stays the same.

## Hook
The original meh opening line.

## Body
Original body paragraph one.

## CTA
Original call to action.
";

    #[test]
    fn test_sectionize_splits_by_headings_with_lead() {
        let sections = sectionize(HANDOFF);
        assert_eq!(sections.len(), 4, "lead + 3 headings");
        assert_eq!(sections[0].key, ":lead");
        assert_eq!(sections[1].key, "Hook");
        assert_eq!(sections[2].key, "Body");
        assert_eq!(sections[3].key, "CTA");
        assert!(sections[1].content.contains("meh opening"));
    }

    #[test]
    fn test_diff_reports_modified_heading_body() {
        let published = HANDOFF.replace(
            "The original meh opening line.",
            "The improved, sharper opening line.",
        );
        let changes = sectioned_diff(HANDOFF, &published);
        let hook = changes
            .iter()
            .find(|c| c.kind == SectionChangeKind::Modified)
            .expect("one modified");
        assert_eq!(hook.key, "Hook");
        assert!(hook.before.as_ref().unwrap().contains("meh"));
        assert!(hook.after.as_ref().unwrap().contains("sharper"));
    }

    #[test]
    fn test_diff_reports_added_and_deleted_sections() {
        let added_section = "## New Section\nBrand new content the human wrote.\n";
        let published = format!("{HANDOFF}\n{added_section}");
        // Delete the CTA heading in the published doc.
        let published = published.replace("## CTA\nOriginal call to action.\n", "");

        let changes = sectioned_diff(HANDOFF, &published);
        let added = changes
            .iter()
            .any(|c| c.kind == SectionChangeKind::Added && c.key == "New Section");
        let deleted = changes
            .iter()
            .any(|c| c.kind == SectionChangeKind::Deleted && c.key == "CTA");
        assert!(added, "added section detected");
        assert!(deleted, "deleted section detected");
    }

    #[test]
    fn test_diff_reports_reorder_as_reordered_not_modified() {
        // Reorder the two body sections; content unchanged.
        let published = "\
Intro lead paragraph that stays the same.

## CTA
Original call to action.

## Hook
The original meh opening line.

## Body
Original body paragraph one.
";
        let changes = sectioned_diff(HANDOFF, published);
        let reordered: Vec<&SectionChange> = changes
            .iter()
            .filter(|c| c.kind == SectionChangeKind::Reordered)
            .collect();
        assert!(
            reordered.iter().any(|c| c.key == "CTA"),
            "CTA reorder detected"
        );
        // No Modified section from a pure reorder.
        assert!(
            !changes
                .iter()
                .any(|c| c.kind == SectionChangeKind::Modified),
            "no false modified"
        );
        // Only the section that actually moved relative to its neighbours is
        // flagged - Hook and Body kept their order relative to each other
        // (CTA jumped past both of them), so a naive absolute-index compare
        // would wrongly flag all three; the LCS-based compare flags only CTA.
        assert_eq!(
            reordered.len(),
            1,
            "only the section that structurally moved is reordered, not everything whose absolute index shifted as a side effect"
        );
    }

    #[test]
    fn test_mid_document_insertion_does_not_cascade_false_reorders() {
        // Insert one new section between Hook and Body. Every later section's
        // absolute index shifts by one, but nothing moved relative to its
        // neighbours - only the inserted section should produce a signal.
        let published = "\
Intro lead paragraph that stays the same.

## Hook
The original meh opening line.

## New Middle
Freshly inserted content the human wrote.

## Body
Original body paragraph one.

## CTA
Original call to action.
";
        let changes = sectioned_diff(HANDOFF, published);
        assert_eq!(
            changes.len(),
            1,
            "a single mid-document insertion must not cascade a false Reordered onto later untouched sections"
        );
        assert_eq!(changes[0].kind, SectionChangeKind::Added);
        assert_eq!(changes[0].key, "New Middle");
    }

    #[test]
    fn test_duplicate_heading_collapses_to_last_section() {
        // Two sections share the same heading key. This is a known, documented
        // lossy case: the earlier section under that heading is dropped from
        // comparison entirely (HashMap collapse in before_by_key/after_by_key),
        // and the dedup in sectioned_diff's `keys` list means it is processed
        // at most once, never twice. Pinning the current behavior rather than
        // silently letting it drift.
        let before = "\
## Hook
First hook text.

## Hook
Second hook text, same heading.
";
        let after = "\
## Hook
First hook text.

## Hook
Rewritten second hook text.
";
        let sections = sectionize(before);
        assert_eq!(
            sections.len(),
            2,
            "sectionize keeps both duplicate-heading sections"
        );

        let changes = sectioned_diff(before, after);
        assert_eq!(
            changes.len(),
            1,
            "duplicate heading key produces exactly one change, not two"
        );
        assert_eq!(changes[0].kind, SectionChangeKind::Modified);
        // The map collapse keeps the LAST section under a duplicate heading.
        assert_eq!(
            changes[0].before.as_deref(),
            Some("Second hook text, same heading.")
        );
        assert_eq!(
            changes[0].after.as_deref(),
            Some("Rewritten second hook text.")
        );
    }

    #[test]
    fn test_whitespace_only_edit_is_not_a_rewrite() {
        let published = HANDOFF.replace(
            "The original meh opening line.",
            "  The original meh   opening line.  ",
        );
        let changes = sectioned_diff(HANDOFF, &published);
        assert!(
            changes
                .iter()
                .all(|c| c.kind != SectionChangeKind::Modified),
            "whitespace-only edits are not treated as a rewrite"
        );
    }

    #[test]
    fn test_correction_signals_per_changed_section() {
        let published = HANDOFF.replace(
            "The original meh opening line.",
            "The rewritten opening line.",
        );
        let changes = sectioned_diff(HANDOFF, &published);
        let signals = correction_signals_with_context(
            CorrectionSignalContext {
                tenant_id: "tenant-1",
                subject_id: "sub_article_1",
                agent_id: "agent-1",
                capability: "copy",
                source_version: "1.0",
                run_id: "run-1",
                role: "copy/summarize",
            },
            &changes,
        );
        assert_eq!(
            signals.len(),
            1,
            "one correction signal per changed section"
        );
        let s = &signals[0];
        assert_eq!(s.kind, SignalKind::Correction);
        assert_eq!(s.subject_id, "sub_article_1");
        assert_eq!(s.tenant_id, "tenant-1");
        assert_eq!(s.source, "diff-capture");
        assert_eq!(s.value, -1.0);
        assert_eq!(
            s.raw["before"].as_str().unwrap(),
            "The original meh opening line."
        );
        assert_eq!(
            s.raw["after"].as_str().unwrap(),
            "The rewritten opening line."
        );
    }

    #[tokio::test]
    async fn test_correction_signals_are_idempotent_and_immutable_landing() {
        use crate::signal::InMemorySignalStore;
        use crate::signal::SignalStore;

        let store = InMemorySignalStore::new();
        let published = HANDOFF.replace(
            "The original meh opening line.",
            "The rewritten opening line.",
        );
        let changes = sectioned_diff(HANDOFF, &published);
        let signals = correction_signals_with_context(
            CorrectionSignalContext {
                tenant_id: "tenant-1",
                subject_id: "sub_1",
                agent_id: "agent-1",
                capability: "copy",
                source_version: "1.0",
                run_id: "run-1",
                role: "copy/summarize",
            },
            &changes,
        );

        // First landing: one row per changed section, into the tenant namespace.
        let first_ids: Vec<String> = {
            let mut ids = Vec::new();
            for sig in &signals {
                let stored = store.append(sig.clone()).await.unwrap();
                ids.push(stored.id.clone());
            }
            ids
        };
        // Re-appending the exact same corrections dedupes on the idempotency key,
        // returning the same stored rows (append-only) rather than new ones.
        let second_ids: Vec<String> = {
            let mut ids = Vec::new();
            for sig in &signals {
                let stored = store.append(sig.clone()).await.unwrap();
                ids.push(stored.id.clone());
            }
            ids
        };
        assert_eq!(
            first_ids, second_ids,
            "idempotent landing returns the same rows"
        );

        let rows = store.by_subject("tenant-1", "sub_1").await.unwrap();
        assert_eq!(rows.len(), 1, "no duplicate rows");
        assert_eq!(rows[0].source, "diff-capture");
        assert!(rows[0].raw["after"].as_str().unwrap().contains("rewritten"));
    }
}
