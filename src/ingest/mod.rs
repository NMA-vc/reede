//! `reede serve`: a local OTLP/HTTP trace ingest that seals each span into a signed reede-v2
//! receipt. The "reported" tier: the receipt proves what the agent reported and when this
//! machine sealed it, not that the report is true. No trusted timestamp (no TSA) is attached.
//!
//! Layout under the output directory: `chain.json` (what `reede verify --chain` reads),
//! `spans/<seq>.json` (the sealed span, so a third party can recompute the summary),
//! `pubkey.hex`, `signing.key` (hex Ed25519 seed, mode 0600).
//!
//! Span summary (documented in docs/ingest.md): `payload_summary` = lowercase hex SHA-256 of the
//! canonical JSON of the span file: UTF-8, object keys sorted bytewise, no whitespace. Same
//! bytes as Python `json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
//! for integer-free-of-exponent values (doubles with exponent forms may differ across languages;
//! the check recomputes from the stored file, so it is self-consistent).

mod http;
pub mod otlp;
mod seal;

pub use http::Server;
pub use seal::{decode_protobuf, seal_batch, seal_span, subject_id as reported_subject_id};

use crate::receipt::{ExecutionReceipt, InMemoryReceiptSigner, InMemoryReceiptStore, ReceiptStore};
use crate::verification::{verify_export, VerificationPolicy};
use ed25519_dalek::{SigningKey, VerifyingKey};
use otlp::SealedSpan;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Canonical JSON text: sorted keys, compact.
pub fn canonical_json(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", Value::String(k.clone()), canonical_json(&map[k])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", parts.join(","))
        }
        other => other.to_string(),
    }
}

/// The receipt `payload_summary` for a stored span value.
pub fn span_summary(v: &Value) -> String {
    hex::encode(Sha256::digest(canonical_json(v).as_bytes()))
}

use seal::subject_id;

/// Create a file readable only by the owner (mode 0600 on unix), failing if it exists.
fn create_private(path: &Path) -> std::io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    opts.open(path)
}

/// Temp file (0600), fsync, rename: a reader never sees a half-written file, and a crash after
/// the rename cannot leave an empty one.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    let mut f = create_private(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|e| format!("write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("rename to {}: {e}", path.display()))
}

/// Create `dir` (and parents) with mode 0700 on unix. An existing directory is left as is.
fn create_private_dir(dir: &Path) -> Result<(), String> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(dir)
        .map_err(|e| format!("create {}: {e}", dir.display()))
}

/// The highest `spans/<n>.json` sequence number present (0 when none).
fn max_span_seq(dir: &Path) -> Result<usize, String> {
    let entries = fs::read_dir(dir.join("spans")).map_err(|e| format!("spans dir: {e}"))?;
    Ok(entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.strip_suffix(".json")?.parse::<usize>().ok()
        })
        .max()
        .unwrap_or(0))
}

fn read_chain(dir: &Path) -> Result<Vec<ExecutionReceipt>, String> {
    let text =
        fs::read_to_string(dir.join("chain.json")).map_err(|e| format!("chain.json: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("chain.json is not a receipt array: {e}"))
}

fn read_pubkey(dir: &Path) -> Result<VerifyingKey, String> {
    let text =
        fs::read_to_string(dir.join("pubkey.hex")).map_err(|e| format!("pubkey.hex: {e}"))?;
    let bytes = hex::decode(text.trim()).map_err(|e| format!("pubkey.hex: {e}"))?;
    VerifyingKey::try_from(bytes.as_slice()).map_err(|e| format!("pubkey.hex: {e}"))
}

/// The open output directory: signer, and the chain so far. Appends go through `seal`, which
/// callers serialize behind one lock so sequence numbers stay contiguous.
pub struct Ingest {
    dir: PathBuf,
    tenant: String,
    signer: InMemoryReceiptSigner,
    store: InMemoryReceiptStore,
}

impl Ingest {
    /// Open (creating on first run) `dir`. An existing chain must verify, else this refuses.
    pub async fn open(dir: &Path, tenant: &str) -> Result<Ingest, String> {
        create_private_dir(&dir.join("spans"))?;
        let key_path = dir.join("signing.key");
        let signer = if key_path.exists() {
            let text = fs::read_to_string(&key_path).map_err(|e| format!("signing.key: {e}"))?;
            let seed: [u8; 32] = hex::decode(text.trim())
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or("signing.key is not a 32-byte hex seed")?;
            InMemoryReceiptSigner::new(SigningKey::from_bytes(&seed))
        } else {
            let mut seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
            write_key(&key_path, &hex::encode(seed))?;
            InMemoryReceiptSigner::new(SigningKey::from_bytes(&seed))
        };
        let pubkey_hex = hex::encode(signer.verifying_key().to_bytes());
        let pubkey_path = dir.join("pubkey.hex");
        match fs::read_to_string(&pubkey_path) {
            Ok(old) if old.trim() != pubkey_hex => {
                return Err("pubkey.hex does not match signing.key; refusing to continue".into())
            }
            Ok(_) => {}
            Err(_) => write_atomic(&pubkey_path, pubkey_hex.as_bytes())?,
        }

        let store = InMemoryReceiptStore::new();
        if dir.join("chain.json").exists() {
            let chain = read_chain(dir)?;
            if !chain.is_empty() {
                let policy = VerificationPolicy {
                    expected_tenant: Some(tenant),
                    require_genesis: true,
                    ..Default::default()
                };
                verify_export(&chain, &signer.verifying_key(), &policy).map_err(|e| {
                    format!("existing chain failed verification, refusing to append: {e}")
                })?;
                for r in chain {
                    store
                        .append(r)
                        .await
                        .map_err(|e| format!("existing chain: {e}"))?;
                }
            }
        }
        // Receipts missing while their span files exist (chain.json deleted, truncated or
        // behind): appending would restart at genesis and overwrite spans/1.json. Refuse.
        let sealed = store
            .latest_sequence(tenant)
            .await
            .map_err(|e| e.to_string())? as usize;
        let on_disk = max_span_seq(dir)?;
        if on_disk > sealed {
            return Err(format!(
                "spans/ holds span {on_disk} but the chain holds {sealed} receipt(s): chain.json is missing or behind; refusing to start (restore it, or move spans/ aside to start a new chain)"
            ));
        }
        Ok(Ingest {
            dir: dir.to_path_buf(),
            tenant: tenant.to_string(),
            signer,
            store,
        })
    }

    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.signer.verifying_key().to_bytes())
    }

    /// Seal each span into one receipt; returns the sequence range. chain.json is rewritten
    /// (temp file + rename) once per call, also when a span fails part way.
    pub async fn seal(&self, spans: Vec<SealedSpan>) -> Result<Option<(u64, u64)>, String> {
        let mut range: Option<(u64, u64)> = None;
        let mut failure = None;
        for sealed in spans {
            match self.seal_one(&sealed).await {
                Ok(seq) => range = Some((range.map_or(seq, |r| r.0), seq)),
                Err(e) => {
                    failure = Some(e);
                    break;
                }
            }
        }
        if range.is_some() {
            let chain = self
                .store
                .chain(&self.tenant)
                .await
                .map_err(|e| e.to_string())?;
            let json = serde_json::to_vec_pretty(&chain).map_err(|e| e.to_string())?;
            write_atomic(&self.dir.join("chain.json"), &json)?;
        }
        match failure {
            Some(e) => Err(e),
            None => Ok(range),
        }
    }

    async fn seal_one(&self, sealed: &SealedSpan) -> Result<u64, String> {
        let span = &sealed.span;
        let seq = self
            .store
            .latest_sequence(&self.tenant)
            .await
            .map_err(|e| e.to_string())?
            + 1;
        let value = serde_json::to_value(sealed).map_err(|e| e.to_string())?;
        let pretty = serde_json::to_vec_pretty(&value).map_err(|e| e.to_string())?;
        write_atomic(&self.dir.join("spans").join(format!("{seq}.json")), &pretty)?;
        seal_span(&self.signer, &self.store, &self.tenant, span, &value).await
    }
}

fn write_key(path: &Path, seed_hex: &str) -> Result<(), String> {
    use std::io::Write;
    let mut f = create_private(path).map_err(|e| format!("create signing.key: {e}"))?;
    f.write_all(seed_hex.as_bytes())
        .map_err(|e| format!("write signing.key: {e}"))
}

/// `reede ingest check`: the chain verifies against `pubkey.hex` from genesis, and every
/// receipt's summary equals the hash recomputed from its span file. Returns the receipt count.
///
/// `pubkey_hex` pins the key you were told to expect; without it `pubkey.hex` from the same
/// directory is trusted, which only proves the directory is self-consistent.
pub fn check(dir: &Path, pubkey_hex: Option<&str>) -> Result<usize, String> {
    let chain = read_chain(dir)?;
    let key = match pubkey_hex {
        Some(h) => hex::decode(h.trim())
            .ok()
            .and_then(|b| VerifyingKey::try_from(b.as_slice()).ok())
            .ok_or("--pubkey is not a valid Ed25519 public key in hex")?,
        None => read_pubkey(dir)?,
    };
    verify_export(
        &chain,
        &key,
        &VerificationPolicy {
            require_genesis: true,
            ..Default::default()
        },
    )
    .map_err(|e| format!("chain does not verify: {e}"))?;
    for r in &chain {
        let seq = r.sequence_no;
        let path = dir.join("spans").join(format!("{seq}.json"));
        let text = fs::read_to_string(&path).map_err(|e| format!("seq {seq}: span file: {e}"))?;
        let value: Value =
            serde_json::from_str(&text).map_err(|e| format!("seq {seq}: span file: {e}"))?;
        if span_summary(&value) != r.payload_summary {
            return Err(format!(
                "seq {seq}: span file does not match the receipt summary"
            ));
        }
        let id = |k: &str| value["span"][k].as_str().unwrap_or("").to_string();
        let (trace, span) = (id("traceId"), id("spanId"));
        if r.subject_id.as_deref() != Some(subject_id(&trace, &span).as_str()) {
            return Err(format!(
                "seq {seq}: subject_id does not match the span file ids"
            ));
        }
        if Uuid::parse_str(&trace).ok() != Some(r.task_id) {
            return Err(format!(
                "seq {seq}: task_id does not match the span trace id"
            ));
        }
    }
    // A span file past the chain head means a receipt was dropped (or a crash left an orphan).
    let top = max_span_seq(dir)?;
    if top > chain.len() {
        return Err(format!(
            "span file {top}.json has no receipt (chain holds {})",
            chain.len()
        ));
    }
    Ok(chain.len())
}
