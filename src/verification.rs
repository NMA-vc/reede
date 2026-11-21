//! Strict, offline receipt verification for automation and SDK bindings.
//!
//! This proves the signed content and links of the supplied export. A trusted
//! expected head/count is required to establish export completeness. reede-v2
//! signs `sequence_no` and `timestamp`, so a chain of v2 receipts is also held to
//! the structural chain rules (`verify_chain`). reede-v1 does not sign them: its
//! sequence_no and timestamp are unauthenticated metadata, and `sequence_authenticated`
//! in the report says so.
use crate::receipt::{verify_chain, verify_receipt, ExecutionReceipt, REEDE_V2_FORMAT};
use crate::ReedeError;
use ed25519_dalek::VerifyingKey;
use serde::Serialize;

#[derive(Debug, Default)]
pub struct VerificationPolicy<'a> {
    pub expected_tenant: Option<&'a str>,
    pub expected_head: Option<&'a str>,
    pub expected_count: Option<usize>,
    pub require_genesis: bool,
}

#[derive(Debug, Serialize)]
pub struct VerificationReport {
    pub schema: &'static str,
    pub authentic: bool,
    pub chain_verified: bool,
    /// True only when every receipt is reede-v2, so `sequence_no` is covered by the signature.
    pub sequence_authenticated: bool,
    pub receipt_count: usize,
    pub tenant_id: String,
    pub head: String,
    pub completeness: &'static str,
    pub timestamp: &'static str,
    pub legally_qualified: Option<bool>,
}

fn refused(reason: &str) -> ReedeError {
    ReedeError::ReceiptVerificationFailed {
        reason: reason.into(),
    }
}

pub fn verify_export(
    chain: &[ExecutionReceipt],
    key: &VerifyingKey,
    policy: &VerificationPolicy<'_>,
) -> Result<VerificationReport, ReedeError> {
    let first = chain
        .first()
        .ok_or_else(|| refused("empty receipt export"))?;
    if let Some(tenant) = policy.expected_tenant {
        if first.tenant_id != tenant {
            return Err(refused("unexpected tenant"));
        }
    }
    let all_v2 = chain
        .iter()
        .all(|r| r.format.as_deref() == Some(REEDE_V2_FORMAT));
    // Genesis means no predecessor; under reede-v2 it also means a signed sequence_no of 1.
    if policy.require_genesis && (first.prev_hash.is_some() || (all_v2 && first.sequence_no != 1)) {
        return Err(refused("export does not start at genesis"));
    }
    for (index, receipt) in chain.iter().enumerate() {
        if receipt.tenant_id != first.tenant_id {
            return Err(refused("mixed-tenant receipt export"));
        }
        // Reuse the canonical cryptographic implementation. No SDK-specific hash
        // or signature encoding is introduced here.
        verify_receipt(receipt, key)?;
        if index > 0 && receipt.prev_hash.as_deref() != Some(&chain[index - 1].content_hash) {
            return Err(refused("missing or mismatched predecessor"));
        }
    }
    // sequence_no is only meaningful once signed: contiguity and repeated-hash rules
    // reuse verify_chain for reede-v2; reede-v1 keeps the predecessor-link rule above.
    if all_v2 {
        verify_chain(chain, None)?;
    }
    let head = &chain[chain.len() - 1].content_hash;
    if policy
        .expected_head
        .is_some_and(|expected| expected != head)
    {
        return Err(refused("unexpected receipt head"));
    }
    if policy
        .expected_count
        .is_some_and(|expected| expected != chain.len())
    {
        return Err(refused("unexpected receipt count"));
    }
    Ok(VerificationReport {
        schema: "reede-verification-v1",
        authentic: true,
        chain_verified: true,
        sequence_authenticated: all_v2,
        receipt_count: chain.len(),
        tenant_id: first.tenant_id.clone(),
        head: head.clone(),
        completeness: if policy.expected_head.is_some()
            && policy.expected_count.is_some()
            && policy.require_genesis
        {
            "verified_against_trusted_boundary"
        } else {
            "supplied_segment_only"
        },
        timestamp: if chain.iter().any(|r| r.tsa_token.is_some()) {
            "present_not_validated"
        } else {
            "absent"
        },
        legally_qualified: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::{recompute_content_hash_reede_v1, InMemoryReceiptSigner, ReceiptSigner};
    use ed25519_dalek::SigningKey;

    fn receipts() -> (Vec<ExecutionReceipt>, VerifyingKey) {
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/reede-v1-vector.json")).unwrap();
        let mut first: ExecutionReceipt = serde_json::from_value(doc["receipt"].clone()).unwrap();
        let signer = InMemoryReceiptSigner::new(SigningKey::from_bytes(&[7; 32]));
        first.signature = hex::encode(signer.sign(first.content_hash.as_bytes()).unwrap());
        let mut second = first.clone();
        second.prev_hash = Some(first.content_hash.clone());
        second.payload_summary = "second".into();
        second.content_hash = recompute_content_hash_reede_v1(&second);
        second.signature = hex::encode(signer.sign(second.content_hash.as_bytes()).unwrap());
        (vec![first, second], signer.verifying_key())
    }

    #[test]
    fn strict_export_checks_authenticity_and_trusted_boundaries() {
        let (chain, key) = receipts();
        let policy = VerificationPolicy {
            expected_tenant: Some(&chain[0].tenant_id),
            expected_head: Some(&chain[1].content_hash),
            expected_count: Some(2),
            require_genesis: true,
        };
        assert_eq!(
            verify_export(&chain, &key, &policy).unwrap().completeness,
            "verified_against_trusted_boundary"
        );
        assert!(verify_export(&chain[..1], &key, &policy).is_err());
        assert!(verify_export(&[], &key, &policy).is_err());
        assert!(verify_export(&chain[1..], &key, &policy).is_err());
        for field in ["prev_hash", "tenant_id", "format", "signature"] {
            let mut broken = serde_json::to_value(&chain).unwrap();
            broken[1][field] = if field == "prev_hash" {
                serde_json::Value::Null
            } else {
                serde_json::json!("invalid")
            };
            let broken: Vec<ExecutionReceipt> = serde_json::from_value(broken).unwrap();
            assert!(verify_export(&broken, &key, &VerificationPolicy::default()).is_err());
        }
    }
    #[test]
    fn security_property_signed_fields_and_rehashed_tampering_always_fail() {
        let (chain, key) = receipts();
        let original = &chain[0];
        for field in [
            "tenant_id",
            "task_id",
            "payload_summary",
            "credits_spent",
            "tokens_used",
            "reservation_credits",
            "prev_hash",
        ] {
            for variant in 0..16u128 {
                let mut value = serde_json::to_value(original).unwrap();
                value[field] = match field {
                    "task_id" => serde_json::json!(uuid::Uuid::from_u128(variant + 1000)),
                    "credits_spent" | "tokens_used" | "reservation_credits" => {
                        serde_json::json!(variant + 10000)
                    }
                    _ => serde_json::json!(format!("mutated-{field}-{variant}")),
                };
                let mut tampered: ExecutionReceipt = serde_json::from_value(value).unwrap();
                assert!(
                    verify_export(&[tampered.clone()], &key, &VerificationPolicy::default())
                        .is_err(),
                    "{field}/{variant}"
                );
                // Updating the hash is not authority to produce a matching signature.
                tampered.content_hash = recompute_content_hash_reede_v1(&tampered);
                assert!(
                    verify_export(&[tampered], &key, &VerificationPolicy::default()).is_err(),
                    "rehashed {field}/{variant}"
                );
            }
        }
        for offset in 0..64 {
            let mut tampered = original.clone();
            let mut signature = hex::decode(&tampered.signature).unwrap();
            signature[offset] ^= 1;
            tampered.signature = hex::encode(signature);
            assert!(verify_export(&[tampered], &key, &VerificationPolicy::default()).is_err());
        }
    }

    #[test]
    fn security_property_valid_signatures_do_not_hide_chain_truncation_or_reordering() {
        let (mut chain, key) = receipts();
        let signer = InMemoryReceiptSigner::new(SigningKey::from_bytes(&[7; 32]));
        for index in 2..8 {
            let mut next = chain[0].clone();
            next.prev_hash = Some(chain.last().unwrap().content_hash.clone());
            next.payload_summary = format!("property receipt {index}");
            next.content_hash = recompute_content_hash_reede_v1(&next);
            next.signature = hex::encode(signer.sign(next.content_hash.as_bytes()).unwrap());
            chain.push(next);
        }
        let policy = VerificationPolicy {
            expected_head: Some(&chain.last().unwrap().content_hash),
            expected_count: Some(chain.len()),
            require_genesis: true,
            ..Default::default()
        };
        assert!(verify_export(&chain, &key, &policy).is_ok());
        for position in 0..chain.len() {
            let mut removed = chain.clone();
            removed.remove(position);
            assert!(verify_export(&removed, &key, &policy).is_err());
            if position > 0 {
                assert!(verify_export(&chain[..position], &key, &policy).is_err());
                assert!(verify_export(&chain[position..], &key, &policy).is_err());
            }
            let mut reordered = chain.clone();
            reordered.swap(position, (position + 1) % chain.len());
            assert!(verify_export(&reordered, &key, &VerificationPolicy::default()).is_err());
        }
    }

    #[test]
    fn security_property_outer_metadata_never_becomes_a_signed_or_qualified_claim() {
        let (mut chain, key) = receipts();
        for receipt in &mut chain {
            receipt.sequence_no = u64::MAX;
            receipt.timestamp = "2099-01-01T00:00:00Z".parse().unwrap();
            receipt.subject_id = Some("metadata-only-subject".into());
            receipt.tsa_token = Some("unvalidated-token".into());
        }
        let report = verify_export(&chain, &key, &VerificationPolicy::default()).unwrap();
        assert!(report.authentic);
        assert_eq!(report.completeness, "supplied_segment_only");
        assert_eq!(report.timestamp, "present_not_validated");
        assert_eq!(report.legally_qualified, None);
    }

    /// Genuine reede-v2 chain of `n` receipts from seq 1, signed with the test key.
    fn v2_chain(n: u64) -> (Vec<ExecutionReceipt>, VerifyingKey) {
        let signer = InMemoryReceiptSigner::new(SigningKey::from_bytes(&[7; 32]));
        let (base, _) = receipts();
        let mut chain: Vec<ExecutionReceipt> = Vec::new();
        for seq in 1..=n {
            let mut r = base[0].clone();
            r.format = Some(REEDE_V2_FORMAT.into());
            r.sequence_no = seq;
            r.prev_hash = chain.last().map(|p| p.content_hash.clone());
            r.payload_summary = format!("run {seq}");
            r.timestamp = chrono::SubsecRound::trunc_subsecs(r.timestamp, 6);
            seal(&mut r, &signer);
            chain.push(r);
        }
        (chain, signer.verifying_key())
    }

    fn seal(r: &mut ExecutionReceipt, signer: &InMemoryReceiptSigner) {
        r.content_hash = crate::receipt::recompute_content_hash_reede_v2(r);
        r.signature = hex::encode(signer.sign(r.content_hash.as_bytes()).unwrap());
    }

    #[test]
    fn strict_v2_enforces_sequence_rules_and_genesis() {
        let signer = InMemoryReceiptSigner::new(SigningKey::from_bytes(&[7; 32]));
        let (chain, key) = v2_chain(4);
        let genesis = VerificationPolicy {
            expected_head: Some(&chain[3].content_hash),
            expected_count: Some(4),
            require_genesis: true,
            ..Default::default()
        };
        let ok = verify_export(&chain, &key, &genesis).unwrap();
        assert!(ok.sequence_authenticated);
        assert_eq!(ok.completeness, "verified_against_trusted_boundary");

        // Gap: seq 3 renumbered to 4 and re-signed, links intact.
        let mut gap = chain.clone();
        gap[2].sequence_no = 4;
        seal(&mut gap[2], &signer);
        gap[3].prev_hash = Some(gap[2].content_hash.clone());
        seal(&mut gap[3], &signer);
        let err = verify_export(&gap, &key, &VerificationPolicy::default()).unwrap_err();
        assert!(err.to_string().contains("contiguous"), "{err}");

        // Duplicate: a receipt repeated after itself breaks links/sequence.
        let mut dup = chain.clone();
        dup.insert(2, dup[1].clone());
        assert!(verify_export(&dup, &key, &VerificationPolicy::default()).is_err());

        // Non-1 genesis: a head with null prev_hash but signed seq 2.
        let mut head = chain[0].clone();
        head.sequence_no = 2;
        seal(&mut head, &signer);
        let err = verify_export(&[head], &key, &genesis).unwrap_err();
        assert!(err.to_string().contains("genesis"), "{err}");

        // A tail segment verifies as a segment, never as a whole history.
        let seg = verify_export(&chain[2..], &key, &VerificationPolicy::default()).unwrap();
        assert_eq!(seg.completeness, "supplied_segment_only");
        assert!(verify_export(&chain[2..], &key, &genesis).is_err());
    }

    #[test]
    fn strict_v1_reports_sequence_unauthenticated() {
        let (chain, key) = receipts();
        let report = verify_export(&chain, &key, &VerificationPolicy::default()).unwrap();
        assert!(!report.sequence_authenticated);
    }
}
