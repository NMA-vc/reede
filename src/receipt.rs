use crate::error::ReedeError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

/// Injective length-prefixed field encoding primitive (standalone, zero the host application dependency).
/// Format: for each string field, emit `<len_hex>:<field_bytes>`.
pub fn encode_fields_injective(fields: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for f in fields {
        let bytes = f.as_bytes();
        let len_header = format!("{:x}:", bytes.len());
        out.extend_from_slice(len_header.as_bytes());
        out.extend_from_slice(bytes);
    }
    out
}

/// The format marker of the 7-field injective encoding, emitted before reede-v2.
pub const REEDE_V1_FORMAT: &str = "reede-v1";
/// The reede-v1 fields plus `sequence_no`, `timestamp`, `subject_id` and `signer_key_id`
/// (11-field encoding). What [`emit_execution_receipt_timestamped`] writes.
pub const REEDE_V2_FORMAT: &str = "reede-v2";
const MAX_RECEIPT_APPEND_ATTEMPTS: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecutionReceipt {
    pub task_id: Uuid,
    pub tenant_id: String,
    pub sequence_no: u64,
    pub credits_spent: i64,
    pub tokens_used: u32,
    pub reservation_credits: i64,
    pub content_hash: String,
    pub prev_hash: Option<String>,
    pub signature: String,
    pub tsa_token: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub payload_summary: String,
    /// Receipt format marker. `"reede-v1"` means the 7-field injective encoding,
    /// `"reede-v2"` the 11-field one; absent/other values mean the verifier cannot
    /// recompute content_hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// durable subject identity this run's artifact carried, when the
    /// producing vertical stamped it. Optional and metadata-only here; the
    /// authoritative `subject -> run -> receipt` join lives in `SubjectStore`.
    /// Absent for legacy receipts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    /// Which Ed25519 key signed this receipt: the first 16 hex characters of SHA-256 over
    /// the public key ([`signer_key_id`]). Hashed by reede-v2 only; absent on reede-v1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key_id: Option<String>,
}

/// Recompute the content_hash for a `reede-v1` receipt from its fields.
/// Returns the hex-encoded SHA-256 digest.
pub fn recompute_content_hash_reede_v1(r: &ExecutionReceipt) -> String {
    use sha2::{Digest, Sha256};
    let task_id_str = r.task_id.to_string();
    let credits_spent_str = r.credits_spent.to_string();
    let tokens_used_str = r.tokens_used.to_string();
    let res_credits_str = r.reservation_credits.to_string();
    let prev_hash_str = r.prev_hash.as_deref().unwrap_or("");
    let fields = vec![
        r.tenant_id.as_str(),
        task_id_str.as_str(),
        r.payload_summary.as_str(),
        credits_spent_str.as_str(),
        tokens_used_str.as_str(),
        res_credits_str.as_str(),
        prev_hash_str,
    ];
    let canonical_bytes = encode_fields_injective(&fields);
    hex::encode(Sha256::digest(&canonical_bytes))
}

/// Recompute the content_hash for a `reede-v2` receipt: the seven reede-v1 fields, then
/// `sequence_no` (decimal), `timestamp` (RFC 3339, UTC, exactly 6 fractional digits, `Z`),
/// `subject_id` and `signer_key_id` (empty string when absent), same injective encoding.
pub fn recompute_content_hash_reede_v2(r: &ExecutionReceipt) -> String {
    use sha2::{Digest, Sha256};
    let task_id_str = r.task_id.to_string();
    let credits_spent_str = r.credits_spent.to_string();
    let tokens_used_str = r.tokens_used.to_string();
    let res_credits_str = r.reservation_credits.to_string();
    let sequence_no_str = r.sequence_no.to_string();
    let timestamp_str = r
        .timestamp
        .to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let fields = [
        r.tenant_id.as_str(),
        task_id_str.as_str(),
        r.payload_summary.as_str(),
        credits_spent_str.as_str(),
        tokens_used_str.as_str(),
        res_credits_str.as_str(),
        r.prev_hash.as_deref().unwrap_or(""),
        sequence_no_str.as_str(),
        timestamp_str.as_str(),
        r.subject_id.as_deref().unwrap_or(""),
        r.signer_key_id.as_deref().unwrap_or(""),
    ];
    hex::encode(Sha256::digest(encode_fields_injective(&fields)))
}

/// The content_hash rule the receipt's own `format` selects, or `None` for a format the
/// offline verifier cannot recompute.
pub fn recompute_content_hash(r: &ExecutionReceipt) -> Option<String> {
    match r.format.as_deref() {
        Some(REEDE_V1_FORMAT) => Some(recompute_content_hash_reede_v1(r)),
        Some(REEDE_V2_FORMAT) => Some(recompute_content_hash_reede_v2(r)),
        _ => None,
    }
}

/// The signer key id a writer stamps on a reede-v2 receipt: the first 16 hex characters of
/// SHA-256 over the signer's Ed25519 public key, or `None` when the signer cannot name it.
pub fn signer_key_id(signer: &dyn ReceiptSigner) -> Option<String> {
    use sha2::{Digest, Sha256};
    signer
        .verifying_key_bytes()
        .map(|key| hex::encode(Sha256::digest(key))[..16].to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthorizationReceipt {
    pub execution: ExecutionReceipt,
    pub lease_id: Option<String>,
    pub policy_ref: String,
    pub decision_context: String,
}

#[async_trait]
pub trait ReceiptSigner: Send + Sync {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, ReedeError>;
    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<bool, ReedeError>;

    /// The Ed25519 public key that verifies this signer's signatures, when the signer can name
    /// it. A receipt writer derives a signer key id from it, so an auditor holding several
    /// public keys knows which one verifies a receipt (F4 K8). `None` (the default) means the
    /// signer cannot say, and a writer that needs the id refuses such a signer.
    fn verifying_key_bytes(&self) -> Option<[u8; 32]> {
        None
    }
}

pub struct InMemoryReceiptSigner {
    signing_key: SigningKey,
}

impl InMemoryReceiptSigner {
    pub fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    pub fn generate_random() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let signing_key = SigningKey::from_bytes(&bytes);
        Self { signing_key }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl ReceiptSigner for InMemoryReceiptSigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, ReedeError> {
        let sig: Signature = self.signing_key.sign(payload);
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<bool, ReedeError> {
        let sig_bytes: [u8; 64] =
            signature
                .try_into()
                .map_err(|_| ReedeError::ReceiptSigningFailed {
                    reason: "Invalid signature byte length (expected 64 bytes)".to_string(),
                })?;
        let sig = Signature::from_bytes(&sig_bytes);
        Ok(self
            .signing_key
            .verifying_key()
            .verify(payload, &sig)
            .is_ok())
    }

    fn verifying_key_bytes(&self) -> Option<[u8; 32]> {
        Some(self.signing_key.verifying_key().to_bytes())
    }
}

#[async_trait]
pub trait ReceiptStore: Send + Sync {
    async fn append(&self, receipt: ExecutionReceipt) -> Result<(), ReedeError>;
    async fn chain(&self, tenant_id: &str) -> Result<Vec<ExecutionReceipt>, ReedeError>;
    async fn latest_hash(&self, tenant_id: &str) -> Result<Option<String>, ReedeError>;
    async fn latest_sequence(&self, tenant_id: &str) -> Result<u64, ReedeError>;
}

pub struct InMemoryReceiptStore {
    chains: Mutex<HashMap<String, Vec<ExecutionReceipt>>>,
}

impl InMemoryReceiptStore {
    pub fn new() -> Self {
        Self {
            chains: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryReceiptStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ReceiptStore for InMemoryReceiptStore {
    async fn append(&self, receipt: ExecutionReceipt) -> Result<(), ReedeError> {
        let mut chains = self.chains.lock().unwrap();
        let chain = chains.entry(receipt.tenant_id.clone()).or_default();

        if let Some(last) = chain.last() {
            if receipt.prev_hash != Some(last.content_hash.clone()) {
                return Err(ReedeError::ReceiptHeadConflict {
                    reason: format!(
                        "Chain break: expected prev_hash {:?}, got {:?}",
                        Some(&last.content_hash),
                        receipt.prev_hash
                    ),
                });
            }
        } else if receipt.prev_hash.is_some() {
            // First receipt in chain should have prev_hash None
            return Err(ReedeError::ReceiptSigningFailed {
                reason: "Initial receipt in chain must have prev_hash None".to_string(),
            });
        }

        chain.push(receipt);
        Ok(())
    }

    async fn chain(&self, tenant_id: &str) -> Result<Vec<ExecutionReceipt>, ReedeError> {
        let chains = self.chains.lock().unwrap();
        Ok(chains.get(tenant_id).cloned().unwrap_or_default())
    }

    async fn latest_hash(&self, tenant_id: &str) -> Result<Option<String>, ReedeError> {
        let chains = self.chains.lock().unwrap();
        Ok(chains
            .get(tenant_id)
            .and_then(|c| c.last())
            .map(|r| r.content_hash.clone()))
    }

    async fn latest_sequence(&self, tenant_id: &str) -> Result<u64, ReedeError> {
        let chains = self.chains.lock().unwrap();
        Ok(chains
            .get(tenant_id)
            .and_then(|c| c.last())
            .map(|r| r.sequence_no)
            .unwrap_or(0))
    }
}

/// Trusted-timestamp hook for the emit path (H8 Tier 2, fail-open). Given a
/// freshly signed receipt's `content_hash`, return the base64 RFC 3161 token to
/// attach as `tsa_token`, or `None` to leave the receipt pending. The token is
/// not a hashed field and is not covered by the signature, so it can be
/// attached after signing without changing what the verifier recomputes; the
/// offline `reede-verify` binary validates it against `content_hash` with
/// `openssl ts -verify`. Implementations must never fail the emit: an
/// unreachable authority is `None`, per the fail-open timestamping contract.
#[async_trait]
pub trait ReceiptTimestamper: Send + Sync {
    async fn stamp(&self, content_hash: &str) -> Option<String>;
}

/// The default hook: never attaches a token (every receipt stays pending).
pub struct NoTimestamper;

#[async_trait]
impl ReceiptTimestamper for NoTimestamper {
    async fn stamp(&self, _content_hash: &str) -> Option<String> {
        None
    }
}

/// Mint, sign, and append one chained `ExecutionReceipt` — at end-of-task, or
/// for a single governed action mid-run (a feedback-subsystem outbound write, a
/// lesson-delta apply, ...). Since the host deleted the `TaskRunner`
/// that used to inline its own copy of this, it is the *only* place a receipt
/// is encoded, signed and chained, so every receipt in a tenant chain comes out
/// of one choke point. It writes `reede-v2` (`recompute_content_hash_reede_v2`,
/// pinned by `tests/fixtures/reede-v2-vector.json`); `reede-v1` receipts written
/// before stay verifiable by their own rule. `store.append`
/// atomically enforces chain linkage; a bounded head-conflict retry rereads and
/// re-signs rather than forking the chain or unnecessarily losing a distinct
/// concurrent send.
///
/// Receipts emitted here carry no trusted timestamp (`tsa_token: None`); use
/// [`emit_execution_receipt_timestamped`] to attach one at the same choke point.
#[allow(clippy::too_many_arguments)]
pub async fn emit_execution_receipt(
    signer: &dyn ReceiptSigner,
    store: &dyn ReceiptStore,
    task_id: Uuid,
    tenant_id: &str,
    payload_summary: impl Into<String>,
    credits_spent: i64,
    tokens_used: u32,
    reservation_credits: i64,
    subject_id: Option<String>,
) -> Result<ExecutionReceipt, ReedeError> {
    emit_execution_receipt_timestamped(
        signer,
        store,
        &NoTimestamper,
        task_id,
        tenant_id,
        payload_summary,
        credits_spent,
        tokens_used,
        reservation_credits,
        subject_id,
    )
    .await
}

/// [`emit_execution_receipt`] with a trusted-timestamp hook: after the receipt
/// is hashed and signed, `timestamper.stamp(content_hash)` runs and its result
/// becomes `tsa_token` before the append. The hook is consulted on the first
/// attempt only: a head-conflict retry re-signs a different `content_hash`, so the
/// earlier token no longer matches, and stamping per attempt cost up to
/// `MAX_RECEIPT_APPEND_ATTEMPTS` paid tokens for one receipt. A retried receipt is
/// appended pending (fail-open). It is not stamped after the append because the
/// stored receipt is immutable (`receipt_json` is READONLY, migration 116). This is
/// the single place a production writer builds a chained, signed, optionally
/// timestamped receipt; writers must not re-implement the hash/sign/chain steps.
#[allow(clippy::too_many_arguments)]
pub async fn emit_execution_receipt_timestamped(
    signer: &dyn ReceiptSigner,
    store: &dyn ReceiptStore,
    timestamper: &dyn ReceiptTimestamper,
    task_id: Uuid,
    tenant_id: &str,
    payload_summary: impl Into<String>,
    credits_spent: i64,
    tokens_used: u32,
    reservation_credits: i64,
    subject_id: Option<String>,
) -> Result<ExecutionReceipt, ReedeError> {
    let payload_summary = payload_summary.into();
    // A concurrent tenant send can win the unique tenant+sequence claim after
    // this call reads the head. Re-read and rebuild the signed receipt a small,
    // bounded number of times so both distinct side effects can finalize while
    // never accepting a fork. Non-conflict storage/signing errors fail closed.
    for attempt in 0..MAX_RECEIPT_APPEND_ATTEMPTS {
        let latest_hash = store.latest_hash(tenant_id).await?;
        let latest_seq = store.latest_sequence(tenant_id).await?;
        let mut receipt = ExecutionReceipt {
            task_id,
            tenant_id: tenant_id.to_string(),
            sequence_no: latest_seq + 1,
            credits_spent,
            tokens_used,
            reservation_credits,
            content_hash: String::new(),
            prev_hash: latest_hash,
            signature: String::new(),
            tsa_token: None,
            // reede-v2 hashes the timestamp at microsecond precision: store exactly what is hashed.
            timestamp: chrono::SubsecRound::trunc_subsecs(Utc::now(), 6),
            payload_summary: payload_summary.clone(),
            format: Some(REEDE_V2_FORMAT.to_string()),
            subject_id: subject_id.clone(),
            signer_key_id: signer_key_id(signer),
        };
        receipt.content_hash = recompute_content_hash_reede_v2(&receipt);
        let sig_bytes = signer.sign(receipt.content_hash.as_bytes())?;
        receipt.signature = hex::encode(sig_bytes);
        if attempt == 0 {
            receipt.tsa_token = timestamper.stamp(&receipt.content_hash).await;
        }
        match store.append(receipt.clone()).await {
            Ok(()) => return Ok(receipt),
            Err(ReedeError::ReceiptHeadConflict { .. })
                if attempt + 1 < MAX_RECEIPT_APPEND_ATTEMPTS =>
            {
                continue
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("bounded receipt append retry always returns")
}

/// Structural check of an exported chain, oldest first: one tenant, `sequence_no`
/// strictly contiguous (+1 per link), no repeated `content_hash`, and every link's
/// `prev_hash` naming the link before it. The head's own `prev_hash` is not checked
/// here: a head that links to an earlier receipt is a valid *segment*, and only the
/// caller can say whether a segment is what it expected (the `reede-verify` report
/// prints the head's `sequence_no` and `prev_hash` for exactly that reason).
pub fn verify_chain(
    chain: &[ExecutionReceipt],
    cutoff_timestamp: Option<DateTime<Utc>>,
) -> Result<(), ReedeError> {
    let chain_break = |reason: String| ReedeError::ReceiptSigningFailed { reason };
    let mut seen = std::collections::HashSet::new();
    for (i, current) in chain.iter().enumerate() {
        if current.tenant_id != chain[0].tenant_id {
            return Err(chain_break(format!(
                "Chain break at seq {}: tenant {:?} in a chain of tenant {:?}",
                current.sequence_no, current.tenant_id, chain[0].tenant_id
            )));
        }
        if !seen.insert(current.content_hash.as_str()) {
            return Err(chain_break(format!(
                "Chain break at seq {}: content_hash {} appears twice",
                current.sequence_no, current.content_hash
            )));
        }
        if i == 0 {
            continue;
        }
        let prev = &chain[i - 1];
        if prev.sequence_no.checked_add(1) != Some(current.sequence_no) {
            return Err(chain_break(format!(
                "Chain break: seq {} follows seq {} (sequence must be contiguous)",
                current.sequence_no, prev.sequence_no
            )));
        }
        match &current.prev_hash {
            Some(prev_hash) => {
                if prev_hash != &prev.content_hash {
                    return Err(ReedeError::ReceiptSigningFailed {
                        reason: format!(
                            "Chain break at seq {}: prev_hash {} != preceding hash {}",
                            current.sequence_no, prev_hash, prev.content_hash
                        ),
                    });
                }
            }
            None => {
                // Post-cutoff None prev_hash is a chain break vulnerability (fix for receipt.rs:246)
                if let Some(cutoff) = cutoff_timestamp {
                    if current.timestamp >= cutoff {
                        return Err(ReedeError::ReceiptSigningFailed {
                            reason: format!(
                                "Chain break at seq {}: null prev_hash after cutoff date {}",
                                current.sequence_no, cutoff
                            ),
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

/// [`verify_chain`] for a chain that claims to be a tenant's whole history: it must also
/// start at `sequence_no` 1. Dropping the first receipts of an export leaves a valid
/// segment that `verify_chain` accepts; this rejects it. Under reede-v2 the head's
/// `sequence_no` is signed, so a truncated chain cannot be renumbered to start at 1.
pub fn verify_chain_from_genesis(
    chain: &[ExecutionReceipt],
    cutoff_timestamp: Option<DateTime<Utc>>,
) -> Result<(), ReedeError> {
    verify_chain(chain, cutoff_timestamp)?;
    match chain.first() {
        Some(head) if head.sequence_no != 1 => Err(ReedeError::ReceiptSigningFailed {
            reason: format!(
                "chain starts at seq {}, not 1: receipts 1..{} are missing",
                head.sequence_no,
                head.sequence_no.saturating_sub(1)
            ),
        }),
        _ => Ok(()),
    }
}

/// R3a — the single offline verification an external auditor runs on a receipt:
/// recompute the `content_hash` from the receipt's own fields, check it equals
/// the stored hash, then verify the Ed25519 signature over the content_hash
/// bytes with the producer's public key. host-independent by construction (only the
/// injective encoding + SHA-256 + ed25519), so it ships in the open-source
/// verifier. The receipt's `format` selects the hash rule (`reede-v1` or
/// `reede-v2`). Chain linkage is a separate concern - see `verify_chain`.
pub fn verify_receipt(
    r: &ExecutionReceipt,
    verifying_key: &VerifyingKey,
) -> Result<(), ReedeError> {
    // Only known formats can be recomputed offline; anything else is
    // reported as unverifiable rather than silently "passing".
    let Some(recomputed) = recompute_content_hash(r) else {
        return Err(ReedeError::ReceiptVerificationFailed {
            reason: format!(
                "unverifiable receipt format {:?} (expected {REEDE_V1_FORMAT} or {REEDE_V2_FORMAT})",
                r.format
            ),
        });
    };

    // 1. Content-hash integrity: the stored hash must equal a fresh recompute.
    if recomputed != r.content_hash {
        return Err(ReedeError::ReceiptVerificationFailed {
            reason: format!(
                "content_hash mismatch: stored {} != recomputed {}",
                r.content_hash, recomputed
            ),
        });
    }

    // 2. Signature: ed25519 over the content_hash ASCII bytes (matches the runner).
    let sig_raw = hex::decode(&r.signature).map_err(|e| ReedeError::ReceiptVerificationFailed {
        reason: format!("signature is not valid hex: {e}"),
    })?;
    let sig_bytes: [u8; 64] =
        sig_raw
            .as_slice()
            .try_into()
            .map_err(|_| ReedeError::ReceiptVerificationFailed {
                reason: format!("signature is {} bytes, expected 64", sig_raw.len()),
            })?;
    let sig = Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify(r.content_hash.as_bytes(), &sig)
        .map_err(|_| ReedeError::ReceiptVerificationFailed {
            reason: "ed25519 signature does not verify against the provided key".to_string(),
        })?;

    Ok(())
}

/// Timestamp qualification tier (H8). A receipt's evidentiary strength has two
/// separable tiers: authenticity (fail-closed, `verify_receipt`) and *timestamp
/// qualification* (fail-open, below). Timestamping is fail-open by contract
/// (TSA unreachable -> mark pending, proceed), so a genuine, correctly-signed
/// receipt may still lack a trusted timestamp. This tier records that state so a
/// pending receipt is never silently presented as fully qualified evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimestampTier {
    /// No TSA token attached: signed but not timestamped. Fail-open pending state.
    Pending,
    /// A TSA token is attached but this offline check did not cryptographically
    /// validate it (no trusted CA material was supplied). Not yet qualified.
    Present,
    /// A TSA token is attached and was validated against trusted CA material.
    /// Only this state is fully qualified timestamped evidence.
    Timestamped,
}

impl TimestampTier {
    /// Human-readable, stable label surfaced by the verifier (H8 visible states).
    pub fn label(&self) -> &'static str {
        match self {
            TimestampTier::Pending => "PENDING (signed, not timestamped)",
            TimestampTier::Present => "TOKEN PRESENT (not validated)",
            TimestampTier::Timestamped => "TIMESTAMPED (RFC 3161 validated)",
        }
    }
}

/// Combined two-tier verdict for one receipt (H8/O5).
///
/// - Tier 1 (authenticity, fail-closed): content-hash integrity + Ed25519
///   signature. If this fails the receipt is REJECTED and no verdict is produced.
/// - Tier 2 (timestamp qualification, fail-open): whether a trusted timestamp is
///   attached. A missing/unvalidated timestamp NEVER rejects the receipt; it only
///   downgrades the combined verdict so pending evidence is visibly distinct from
///   fully qualified evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptVerdict {
    /// Tier 1 passed: the receipt is authentic (hash + signature).
    pub authentic: bool,
    /// Tier 2: the timestamp qualification of the receipt.
    pub timestamp: TimestampTier,
}

impl ReceiptVerdict {
    /// Tier 1: the receipt's content and signature are intact.
    pub fn is_authentic(&self) -> bool {
        self.authentic
    }

    /// The receipt is authentic but its timestamp never landed (H8 pending state).
    /// Such a receipt is valid evidence of *what happened* but not independently
    /// timestamped, and must never be presented as fully qualified.
    pub fn is_pending_timestamp(&self) -> bool {
        self.authentic && self.timestamp == TimestampTier::Pending
    }

    /// Fully qualified evidence: authentic AND carrying a validated trusted
    /// timestamp. This is the only state that may be presented as complete proof.
    pub fn is_fully_qualified(&self) -> bool {
        self.authentic && self.timestamp == TimestampTier::Timestamped
    }
}

/// Two-tier offline verification of a single receipt (H8/O5).
///
/// Runs Tier 1 (`verify_receipt`, fail-closed) first: if the content hash or the
/// Ed25519 signature does not check out, the receipt is rejected with `Err` and no
/// verdict is returned. On success, Tier 2 (fail-open) classifies the timestamp.
///
/// The library performs no network I/O and does not validate an RFC 3161 token
/// against a CA (that requires trusted CA material and belongs to the `reede-verify`
/// binary), so it emits only `Pending` (no token) or `Present` (token attached,
/// not yet validated). A `Timestamped` verdict is produced by the binary after it
/// validates the token. Either way, `is_fully_qualified()` is false until a token
/// is validated, which is the H8 guarantee: a signed-but-not-timestamped receipt is
/// authentic yet never fully qualified.
pub fn verify_receipt_two_tier(
    r: &ExecutionReceipt,
    verifying_key: &VerifyingKey,
) -> Result<ReceiptVerdict, ReedeError> {
    // Tier 1 - fail closed. Any tamper or bad signature rejects here.
    verify_receipt(r, verifying_key)?;

    // Tier 2 - fail open. Presence-only classification in the library.
    let timestamp = match r.tsa_token {
        None => TimestampTier::Pending,
        Some(_) => TimestampTier::Present,
    };

    Ok(ReceiptVerdict {
        authentic: true,
        timestamp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_injective_field_encoding() {
        let fields = vec!["tenant-1", "run-100", "50.00"];
        let encoded = encode_fields_injective(&fields);
        let encoded_str = String::from_utf8(encoded).unwrap();
        assert_eq!(encoded_str, "8:tenant-17:run-1005:50.00");
    }

    /// A signer names the key that verifies it when it can; one that cannot answers `None` by
    /// default, so existing implementations compile unchanged and are recognisable.
    #[test]
    fn a_signer_names_its_verifying_key_or_answers_none() {
        let signer = InMemoryReceiptSigner::new(SigningKey::from_bytes(&[42u8; 32]));
        assert_eq!(
            signer.verifying_key_bytes(),
            Some(signer.verifying_key().to_bytes())
        );

        struct Opaque;
        impl ReceiptSigner for Opaque {
            fn sign(&self, _payload: &[u8]) -> Result<Vec<u8>, ReedeError> {
                Ok(vec![])
            }
            fn verify(&self, _payload: &[u8], _signature: &[u8]) -> Result<bool, ReedeError> {
                Ok(false)
            }
        }
        assert_eq!(Opaque.verifying_key_bytes(), None);
    }

    #[tokio::test]
    async fn test_receipt_store_and_chain_verification() {
        let store = InMemoryReceiptStore::new();
        let tenant = "tenant-a";
        let task_id = Uuid::new_v4();

        let r1 = ExecutionReceipt {
            task_id,
            tenant_id: tenant.to_string(),
            sequence_no: 1,
            credits_spent: 0,
            tokens_used: 0,
            reservation_credits: 0,
            content_hash: "hash-1".to_string(),
            prev_hash: None,
            signature: "sig-1".to_string(),
            tsa_token: None,
            timestamp: Utc::now(),
            payload_summary: "step 1".to_string(),
            format: None,
            subject_id: None,
            signer_key_id: None,
        };

        store.append(r1.clone()).await.unwrap();

        let r2 = ExecutionReceipt {
            task_id,
            tenant_id: tenant.to_string(),
            sequence_no: 2,
            credits_spent: 0,
            tokens_used: 0,
            reservation_credits: 0,
            content_hash: "hash-2".to_string(),
            prev_hash: Some("hash-1".to_string()),
            signature: "sig-2".to_string(),
            tsa_token: None,
            timestamp: Utc::now(),
            payload_summary: "step 2".to_string(),
            format: None,
            subject_id: None,
            signer_key_id: None,
        };

        store.append(r2.clone()).await.unwrap();

        let chain = store.chain(tenant).await.unwrap();
        assert_eq!(chain.len(), 2);
        assert!(verify_chain(&chain, None).is_ok());
    }

    #[tokio::test]
    async fn test_receipt_chain_break_detection() {
        let store = InMemoryReceiptStore::new();
        let tenant = "tenant-b";
        let task_id = Uuid::new_v4();

        let r1 = ExecutionReceipt {
            task_id,
            tenant_id: tenant.to_string(),
            sequence_no: 1,
            credits_spent: 0,
            tokens_used: 0,
            reservation_credits: 0,
            content_hash: "hash-1".to_string(),
            prev_hash: None,
            signature: "sig-1".to_string(),
            tsa_token: None,
            timestamp: Utc::now(),
            payload_summary: "step 1".to_string(),
            format: None,
            subject_id: None,
            signer_key_id: None,
        };
        store.append(r1).await.unwrap();

        let broken_r2 = ExecutionReceipt {
            task_id,
            tenant_id: tenant.to_string(),
            sequence_no: 2,
            credits_spent: 0,
            tokens_used: 0,
            reservation_credits: 0,
            content_hash: "hash-2".to_string(),
            prev_hash: Some("wrong-hash".to_string()),
            signature: "sig-2".to_string(),
            tsa_token: None,
            timestamp: Utc::now(),
            payload_summary: "step 2".to_string(),
            format: None,
            subject_id: None,
            signer_key_id: None,
        };

        let err = store.append(broken_r2).await.unwrap_err();
        assert!(matches!(err, ReedeError::ReceiptHeadConflict { .. }));
    }

    /// Shared receipt test vector. A fully-pinned `reede-v1` receipt
    /// hashes to a fixed value. If the injective encoding, field order, or hash
    /// primitive ever changes, this breaks — and any writer claiming `reede-v1`
    /// MUST reproduce this exact content_hash for these fields. This is the
    /// offline verifier's contract that downstream consumers depend on.
    #[test]
    fn reede_v1_content_hash_golden_vector() {
        let r = ExecutionReceipt {
            task_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            tenant_id: "tenant-golden".to_string(),
            sequence_no: 1,
            credits_spent: 250,
            tokens_used: 1234,
            reservation_credits: 500,
            content_hash: String::new(), // not an input to the recompute
            prev_hash: None,
            signature: String::new(),
            tsa_token: None,
            timestamp: DateTime::<Utc>::from_timestamp(0, 0).unwrap(), // not hashed
            payload_summary: "battlecard:acme".to_string(),
            format: Some(REEDE_V1_FORMAT.to_string()),
            subject_id: None,
            signer_key_id: None,
        };
        // SHA-256 of the 7-field injective encoding of
        //   [tenant-golden, 000…0001, battlecard:acme, 250, 1234, 500, ""]
        // == "d:tenant-golden24:000…0001f:battlecard:acme3:2504:12343:5000:"
        assert_eq!(
            recompute_content_hash_reede_v1(&r),
            "c61c46e4831cc1bef79ed703c3b88aa03d2ecbd244a7b544db92d492ebed5245",
            "reede-v1 content_hash vector drifted — the canonical encoding changed"
        );
    }

    /// Verify the chain across the writer/verifier (crypto) boundary:
    /// each receipt's stored content_hash equals what the offline verifier
    /// recomputes, the chain links under REAL recomputed hashes (not the
    /// placeholder strings the other tests use), and any field mutation is
    /// caught by a recompute mismatch.
    #[test]
    fn reede_v1_recompute_matches_stored_and_chains_and_detects_tamper() {
        fn mk(seq: u64, credits: i64, prev: Option<String>) -> ExecutionReceipt {
            let mut r = ExecutionReceipt {
                task_id: Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
                tenant_id: "tenant-855".to_string(),
                sequence_no: seq,
                credits_spent: credits,
                tokens_used: 100,
                reservation_credits: 0,
                content_hash: String::new(),
                prev_hash: prev,
                signature: String::new(),
                tsa_token: None,
                timestamp: DateTime::<Utc>::from_timestamp(seq as i64, 0).unwrap(),
                payload_summary: format!("step-{seq}"),
                format: Some(REEDE_V1_FORMAT.to_string()),
                subject_id: None,
                signer_key_id: None,
            };
            r.content_hash = recompute_content_hash_reede_v1(&r);
            r
        }

        let r1 = mk(1, 10, None);
        let r2 = mk(2, 20, Some(r1.content_hash.clone()));

        // Writer hash == verifier recompute (the boundary the offline checker crosses).
        assert_eq!(recompute_content_hash_reede_v1(&r1), r1.content_hash);
        assert_eq!(recompute_content_hash_reede_v1(&r2), r2.content_hash);

        // The chain links under real hashes.
        verify_chain(&[r1.clone(), r2.clone()], None).expect("real-hash chain must verify");

        // Tamper: mutating a metering field changes the recomputed hash.
        let mut tampered = r1.clone();
        tampered.credits_spent += 1;
        assert_ne!(
            recompute_content_hash_reede_v1(&tampered),
            r1.content_hash,
            "a mutated field must change the recomputed content_hash"
        );
    }

    /// R3a — a real reede-v1 receipt (content_hash recomputed and signed exactly
    /// the way the runner does) verifies end-to-end offline; tampering, a wrong
    /// key, and a non-reede-v1 format are all rejected. This is the offline
    /// verifier being *real*: it verifies what the reede runtime writes.
    #[test]
    fn verify_receipt_end_to_end_and_rejects_tamper_wrongkey_format() {
        let signer = InMemoryReceiptSigner::generate_random();
        let vk = signer.verifying_key();

        let mut r = ExecutionReceipt {
            task_id: Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap(),
            tenant_id: "tenant-verify".to_string(),
            sequence_no: 1,
            credits_spent: 42,
            tokens_used: 7,
            reservation_credits: 0,
            content_hash: String::new(),
            prev_hash: None,
            signature: String::new(),
            tsa_token: None,
            timestamp: DateTime::<Utc>::from_timestamp(0, 0).unwrap(),
            payload_summary: "verify-me".to_string(),
            format: Some(REEDE_V1_FORMAT.to_string()),
            subject_id: None,
            signer_key_id: None,
        };
        // Produce exactly like the runner: recompute the hash, sign its bytes.
        r.content_hash = recompute_content_hash_reede_v1(&r);
        r.signature = hex::encode(signer.sign(r.content_hash.as_bytes()).unwrap());

        // Full offline verification passes.
        verify_receipt(&r, &vk).expect("a well-formed reede-v1 receipt must verify offline");

        // Tampered metering → content_hash mismatch.
        let mut tampered = r.clone();
        tampered.credits_spent += 1;
        assert!(
            verify_receipt(&tampered, &vk).is_err(),
            "a mutated field must fail verification"
        );

        // Wrong key → signature fails.
        let other = InMemoryReceiptSigner::generate_random();
        assert!(
            verify_receipt(&r, &other.verifying_key()).is_err(),
            "verification with the wrong key must fail"
        );

        // Non-reede-v1 format → unverifiable.
        let mut no_format = r.clone();
        no_format.format = None;
        assert!(
            verify_receipt(&no_format, &vk).is_err(),
            "an unknown receipt format must be reported unverifiable"
        );
    }

    /// Helper: a genuine, signed `reede-v1` receipt with the given tsa_token.
    fn genuine_receipt(
        signer: &InMemoryReceiptSigner,
        seq: u64,
        credits: i64,
        prev: Option<String>,
        tsa: Option<String>,
    ) -> ExecutionReceipt {
        let mut r = ExecutionReceipt {
            task_id: Uuid::parse_str("00000000-0000-0000-0000-000000000004").unwrap(),
            tenant_id: "tenant-two-tier".to_string(),
            sequence_no: seq,
            credits_spent: credits,
            tokens_used: 3,
            reservation_credits: 0,
            content_hash: String::new(),
            prev_hash: prev,
            signature: String::new(),
            tsa_token: tsa,
            timestamp: DateTime::<Utc>::from_timestamp(seq as i64, 0).unwrap(),
            payload_summary: format!("two-tier-{seq}"),
            format: Some(REEDE_V1_FORMAT.to_string()),
            subject_id: None,
            signer_key_id: None,
        };
        r.content_hash = recompute_content_hash_reede_v1(&r);
        r.signature = hex::encode(signer.sign(r.content_hash.as_bytes()).unwrap());
        r
    }

    /// H8 Tier 2 (fail-open): a genuine receipt with NO TSA token is authentic but
    /// classified `Pending` — never fully qualified. This is the core H8 guarantee:
    /// a signed-but-not-timestamped receipt is real evidence yet visibly not complete.
    #[test]
    fn two_tier_pending_is_authentic_but_not_fully_qualified() {
        let signer = InMemoryReceiptSigner::generate_random();
        let r = genuine_receipt(&signer, 1, 10, None, None);

        let verdict = verify_receipt_two_tier(&r, &signer.verifying_key())
            .expect("a genuine receipt must pass Tier 1 authenticity");

        assert_eq!(verdict.timestamp, TimestampTier::Pending);
        assert!(verdict.is_authentic(), "Tier 1 must pass");
        assert!(verdict.is_pending_timestamp(), "no TSA token => pending");
        assert!(
            !verdict.is_fully_qualified(),
            "a pending receipt must NEVER be reported as fully qualified (H8)"
        );
    }

    /// H8 Tier 2: a TSA token that this offline library did not validate against a CA
    /// is `Present`, still not fully qualified. Only binary-side CA validation upgrades
    /// it to `Timestamped`.
    #[test]
    fn two_tier_token_present_but_unvalidated_is_not_fully_qualified() {
        let signer = InMemoryReceiptSigner::generate_random();
        let r = genuine_receipt(&signer, 1, 10, None, Some("dGVzdA==".to_string()));

        let verdict = verify_receipt_two_tier(&r, &signer.verifying_key()).unwrap();

        assert_eq!(verdict.timestamp, TimestampTier::Present);
        assert!(verdict.is_authentic());
        assert!(
            !verdict.is_fully_qualified(),
            "an unvalidated TSA token is not yet qualified evidence"
        );
    }

    /// Tier 1 fail-closed, structural/content class: mutating a hashed body field
    /// breaks the content-hash recompute and rejects the receipt outright — no verdict.
    #[test]
    fn two_tier_rejects_tampered_body() {
        let signer = InMemoryReceiptSigner::generate_random();
        let mut r = genuine_receipt(&signer, 1, 10, None, None);
        r.credits_spent += 1; // hashed field mutated; content_hash now stale

        let err = verify_receipt_two_tier(&r, &signer.verifying_key())
            .expect_err("a tampered body must be rejected by Tier 1");
        match err {
            ReedeError::ReceiptVerificationFailed { reason } => {
                assert!(reason.contains("content_hash"), "reason: {reason}")
            }
            other => panic!("expected content_hash mismatch, got {other:?}"),
        }
    }

    /// Tier 1 fail-closed, cryptographic class: a forged/altered signature (here,
    /// verification against the wrong key) is rejected — the body is intact but the
    /// authenticity tier still fails independently of the structural tier.
    #[test]
    fn two_tier_rejects_forged_signature() {
        let signer = InMemoryReceiptSigner::generate_random();
        let r = genuine_receipt(&signer, 1, 10, None, None);

        // Wrong key: content_hash still recomputes fine, only the signature tier fails.
        let attacker = InMemoryReceiptSigner::generate_random();
        assert!(
            verify_receipt_two_tier(&r, &attacker.verifying_key()).is_err(),
            "a signature that does not verify under the presented key must be rejected"
        );

        // Also reject a receipt whose signature bytes were altered in place.
        let mut altered = r.clone();
        let mut sig_bytes = hex::decode(&altered.signature).unwrap();
        sig_bytes[0] ^= 0xFF;
        altered.signature = hex::encode(sig_bytes);
        assert!(
            verify_receipt_two_tier(&altered, &signer.verifying_key()).is_err(),
            "a tampered signature must be rejected even under the correct key"
        );
    }

    /// Chain/structural tier: reordering genuine interior links breaks `prev_hash`
    /// linkage even though each receipt is individually authentic. (A three-link
    /// chain is used so the reorder moves a link that carries a `Some(prev_hash)`;
    /// `verify_chain` only tolerates a null `prev_hash` at the head, or pre-cutoff
    /// for legacy receipts.)
    #[test]
    fn verify_chain_detects_reorder() {
        let signer = InMemoryReceiptSigner::generate_random();
        let r1 = genuine_receipt(&signer, 1, 10, None, None);
        let r2 = genuine_receipt(&signer, 2, 20, Some(r1.content_hash.clone()), None);
        let r3 = genuine_receipt(&signer, 3, 30, Some(r2.content_hash.clone()), None);

        verify_chain(&[r1.clone(), r2.clone(), r3.clone()], None)
            .expect("ordered chain must verify");
        // Swap the two interior/tail links: r3 now sits where its prev_hash no
        // longer points at the preceding link.
        assert!(
            verify_chain(&[r1, r3, r2], None).is_err(),
            "a reordered chain must fail the linkage check"
        );
    }

    struct FixedTimestamper(Option<String>);

    #[async_trait]
    impl ReceiptTimestamper for FixedTimestamper {
        async fn stamp(&self, _content_hash: &str) -> Option<String> {
            self.0.clone()
        }
    }

    /// The timestamp hook attaches `tsa_token` after signing without touching what
    /// the verifier recomputes: the receipt still verifies (Tier 1), and the tier-2
    /// classification is `Present` with a token and `Pending` without one.
    #[tokio::test]
    async fn emit_timestamped_attaches_token_without_changing_hash_or_signature() {
        let signer = InMemoryReceiptSigner::generate_random();
        let vk = signer.verifying_key();
        let store = InMemoryReceiptStore::new();
        let task_id = Uuid::new_v4();

        let stamped = emit_execution_receipt_timestamped(
            &signer,
            &store,
            &FixedTimestamper(Some("dGVzdA==".to_string())),
            task_id,
            "tenant-ts",
            "stamped",
            5,
            50,
            0,
            None,
        )
        .await
        .unwrap();
        assert_eq!(stamped.tsa_token.as_deref(), Some("dGVzdA=="));
        assert_eq!(stamped.format.as_deref(), Some(REEDE_V2_FORMAT));
        assert_eq!(
            stamped.content_hash,
            recompute_content_hash_reede_v2(&stamped)
        );
        let verdict = verify_receipt_two_tier(&stamped, &vk).unwrap();
        assert_eq!(verdict.timestamp, TimestampTier::Present);

        // No token -> pending, chained to the stamped one, still authentic.
        let pending = emit_execution_receipt_timestamped(
            &signer,
            &store,
            &FixedTimestamper(None),
            task_id,
            "tenant-ts",
            "pending",
            5,
            50,
            0,
            None,
        )
        .await
        .unwrap();
        assert_eq!(pending.tsa_token, None);
        assert_eq!(
            pending.prev_hash.as_deref(),
            Some(stamped.content_hash.as_str())
        );
        assert!(verify_receipt_two_tier(&pending, &vk)
            .unwrap()
            .is_pending_timestamp());

        // The default (untimestamped) emit is the same path with no token.
        let plain = emit_execution_receipt(
            &signer,
            &store,
            task_id,
            "tenant-ts",
            "plain",
            1,
            1,
            0,
            None,
        )
        .await
        .unwrap();
        assert_eq!(plain.tsa_token, None);
        verify_chain(&store.chain("tenant-ts").await.unwrap(), None).unwrap();
    }

    /// Chain/structural tier: splicing a foreign genuine link into the middle breaks
    /// the linkage — each link is individually authentic, the chain is not.
    #[test]
    fn verify_chain_detects_inserted_link() {
        let signer = InMemoryReceiptSigner::generate_random();
        let r1 = genuine_receipt(&signer, 1, 10, None, None);
        let r2 = genuine_receipt(&signer, 2, 20, Some(r1.content_hash.clone()), None);
        // A genuine but unrelated receipt whose prev_hash does not point at r1.
        let intruder = genuine_receipt(&signer, 9, 99, Some("deadbeef".to_string()), None);

        assert!(
            verify_chain(&[r1, intruder, r2], None).is_err(),
            "an inserted link with a non-matching prev_hash must fail the chain check"
        );
    }

    /// The reede-v2 shared vector was generated outside this crate (Python hashlib +
    /// cryptography, test-only seed named in the fixture). The Rust recompute, signer key id and Ed25519
    /// signature must reproduce it byte for byte, and a JSON round trip must not move
    /// the timestamp off the hashed form.
    #[test]
    fn reede_v2_shared_vector_reproduces() {
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/reede-v2-vector.json")).unwrap();
        let r: ExecutionReceipt = serde_json::from_value(doc["receipt"].clone()).unwrap();
        let expected = doc["expected_content_hash"].as_str().unwrap();
        assert_eq!(r.format.as_deref(), Some(REEDE_V2_FORMAT));
        assert_eq!(recompute_content_hash_reede_v2(&r), expected);
        assert_eq!(recompute_content_hash(&r).as_deref(), Some(expected));

        // The fixture's test-only key: seed = 32 bytes of 0x07 (see its _comment).
        let signer = InMemoryReceiptSigner::new(SigningKey::from_bytes(&[7u8; 32]));
        assert_eq!(
            hex::encode(signer.verifying_key().to_bytes()),
            doc["pubkey_hex"].as_str().unwrap()
        );
        assert_eq!(signer_key_id(&signer), r.signer_key_id);
        assert_eq!(
            hex::encode(signer.sign(expected.as_bytes()).unwrap()),
            r.signature
        );
        verify_receipt(&r, &signer.verifying_key()).expect("v2 vector verifies");

        let again: ExecutionReceipt =
            serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(recompute_content_hash_reede_v2(&again), expected);

        // v2 binds what v1 left out; v1's own rule is unchanged for v1 receipts.
        for edit in [
            |r: &mut ExecutionReceipt| r.sequence_no += 1,
            |r: &mut ExecutionReceipt| r.timestamp += chrono::Duration::microseconds(1),
            |r: &mut ExecutionReceipt| r.subject_id = None,
            |r: &mut ExecutionReceipt| r.signer_key_id = Some("0000000000000000".into()),
        ] {
            let mut t = r.clone();
            edit(&mut t);
            assert!(verify_receipt(&t, &signer.verifying_key()).is_err());
            assert_eq!(
                recompute_content_hash_reede_v1(&t),
                recompute_content_hash_reede_v1(&r)
            );
        }
    }

    fn signed_v2(
        signer: &InMemoryReceiptSigner,
        seq: u64,
        prev: Option<String>,
    ) -> ExecutionReceipt {
        let mut r = genuine_receipt(signer, seq, 1, prev, None);
        r.format = Some(REEDE_V2_FORMAT.to_string());
        r.content_hash = recompute_content_hash_reede_v2(&r);
        r.signature = hex::encode(signer.sign(r.content_hash.as_bytes()).unwrap());
        r
    }

    fn linked(signer: &InMemoryReceiptSigner, n: u64) -> Vec<ExecutionReceipt> {
        let mut chain: Vec<ExecutionReceipt> = Vec::new();
        for seq in 1..=n {
            let prev = chain.last().map(|p| p.content_hash.clone());
            chain.push(signed_v2(signer, seq, prev));
        }
        chain
    }

    /// Every tenant's chain crosses this boundary on the deploy that starts emitting v2.
    #[test]
    fn a_v1_chain_continued_by_v2_receipts_verifies() {
        let signer = InMemoryReceiptSigner::generate_random();
        let vk = signer.verifying_key();
        let v1 = genuine_receipt(&signer, 1, 1, None, None);
        assert_eq!(v1.format.as_deref(), Some(REEDE_V1_FORMAT));
        let v2 = signed_v2(&signer, 2, Some(v1.content_hash.clone()));
        let next = signed_v2(&signer, 3, Some(v2.content_hash.clone()));
        let chain = vec![v1, v2, next];
        for receipt in &chain {
            verify_receipt(receipt, &vk).expect("each link verifies by its own format");
        }
        verify_chain_from_genesis(&chain, None).expect("the format change is not a chain break");

        let mut tampered = chain.clone();
        tampered[0].credits_spent += 1;
        assert!(verify_receipt(&tampered[0], &vk).is_err());
        let mut relinked = chain;
        relinked[1].prev_hash = Some("not-the-v1-head".to_string());
        assert!(verify_chain(&relinked, None).is_err());
    }

    #[test]
    fn verify_chain_requires_contiguous_sequence() {
        let signer = InMemoryReceiptSigner::generate_random();
        let chain = linked(&signer, 4);
        verify_chain(&chain, None).expect("contiguous chain verifies");
        // Same links, one renumbered: linkage still holds, the sequence does not.
        let mut skipped = chain.clone();
        skipped[3].sequence_no = 5;
        let err = verify_chain(&skipped, None).unwrap_err();
        assert!(err.to_string().contains("seq 5 follows seq 3"), "{err}");
    }

    #[test]
    fn verify_chain_requires_one_tenant() {
        let signer = InMemoryReceiptSigner::generate_random();
        let chain = linked(&signer, 3);
        verify_chain(&chain, None).unwrap();
        let mut mixed = chain.clone();
        mixed[1].tenant_id = "tenant-other".to_string();
        assert!(verify_chain(&mixed, None)
            .unwrap_err()
            .to_string()
            .contains("tenant"));
    }

    #[test]
    fn verify_chain_rejects_a_repeated_content_hash() {
        let signer = InMemoryReceiptSigner::generate_random();
        let chain = linked(&signer, 2);
        verify_chain(&chain, None).unwrap();
        // A link whose prev_hash names itself, numbered next: only the duplicate check sees it.
        let mut looped = chain.clone();
        let mut copy = chain[1].clone();
        copy.sequence_no = 3;
        copy.prev_hash = Some(copy.content_hash.clone());
        looped.push(copy);
        assert!(verify_chain(&looped, None)
            .unwrap_err()
            .to_string()
            .contains("appears twice"));
    }

    #[test]
    fn verify_chain_from_genesis_rejects_a_cut_at_the_start() {
        let signer = InMemoryReceiptSigner::generate_random();
        let chain = linked(&signer, 5);
        verify_chain_from_genesis(&chain, None).expect("full chain verifies");
        // The segment is structurally sound, which is why verify_chain alone accepts it.
        verify_chain(&chain[2..], None).expect("a segment links");
        let err = verify_chain_from_genesis(&chain[2..], None).unwrap_err();
        assert!(
            err.to_string().contains("chain starts at seq 3, not 1"),
            "{err}"
        );
    }

    /// Finding 16: the TSA used to be called on every append attempt (up to 16 paid tokens
    /// and 16 round trips for one receipt under head contention). It is now called once;
    /// a retried receipt goes out pending and still verifies.
    #[tokio::test]
    async fn emit_stamps_once_under_head_contention() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct Counting(AtomicUsize);
        #[async_trait]
        impl ReceiptTimestamper for Counting {
            async fn stamp(&self, _content_hash: &str) -> Option<String> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Some("dGVzdA==".to_string())
            }
        }

        /// Loses the head race `conflicts` times, then appends normally.
        struct Contended {
            inner: InMemoryReceiptStore,
            conflicts: AtomicUsize,
        }
        #[async_trait]
        impl ReceiptStore for Contended {
            async fn append(&self, receipt: ExecutionReceipt) -> Result<(), ReedeError> {
                // compare_exchange, not fetch_update: newer stable deprecates fetch_update
                // (renamed try_update), which does not exist on the 1.89 MSRV.
                let mut left = self.conflicts.load(Ordering::SeqCst);
                let lost = loop {
                    let Some(next) = left.checked_sub(1) else {
                        break false;
                    };
                    match self.conflicts.compare_exchange(
                        left,
                        next,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    ) {
                        Ok(_) => break true,
                        Err(actual) => left = actual,
                    }
                };
                if lost {
                    return Err(ReedeError::ReceiptHeadConflict {
                        reason: "lost the race".to_string(),
                    });
                }
                self.inner.append(receipt).await
            }
            async fn chain(&self, t: &str) -> Result<Vec<ExecutionReceipt>, ReedeError> {
                self.inner.chain(t).await
            }
            async fn latest_hash(&self, t: &str) -> Result<Option<String>, ReedeError> {
                self.inner.latest_hash(t).await
            }
            async fn latest_sequence(&self, t: &str) -> Result<u64, ReedeError> {
                self.inner.latest_sequence(t).await
            }
        }

        let signer = InMemoryReceiptSigner::generate_random();
        let tsa = Counting(AtomicUsize::new(0));

        // Uncontended: one call, token attached.
        let calm = Contended {
            inner: InMemoryReceiptStore::new(),
            conflicts: AtomicUsize::new(0),
        };
        let r = emit_execution_receipt_timestamped(
            &signer,
            &calm,
            &tsa,
            Uuid::new_v4(),
            "t",
            "calm",
            1,
            1,
            0,
            None,
        )
        .await
        .unwrap();
        assert_eq!(tsa.0.load(Ordering::SeqCst), 1);
        assert_eq!(r.tsa_token.as_deref(), Some("dGVzdA=="));

        // Five lost races: still exactly one more call, and the appended receipt is pending.
        let busy = Contended {
            inner: InMemoryReceiptStore::new(),
            conflicts: AtomicUsize::new(5),
        };
        let r = emit_execution_receipt_timestamped(
            &signer,
            &busy,
            &tsa,
            Uuid::new_v4(),
            "t",
            "busy",
            1,
            1,
            0,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            tsa.0.load(Ordering::SeqCst),
            2,
            "one stamp per receipt, not per attempt"
        );
        assert_eq!(
            r.tsa_token, None,
            "a retried receipt is appended pending (fail-open)"
        );
        assert!(verify_receipt_two_tier(&r, &signer.verifying_key())
            .unwrap()
            .is_pending_timestamp());
    }
}
