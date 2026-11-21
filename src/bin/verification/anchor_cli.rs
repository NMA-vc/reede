#![allow(dead_code)] // compiled into the `verify` binary too, which has no anchor verb

//! `reede anchor verify`: offline check of a hosted BYOA proof. See reede/docs/anchor.md.
//!
//! Exit codes: 0 only when chain, signatures (key pinned), inclusion AND anchoring are all
//! verified; 1 when anything is tampered or malformed; 2 when everything present verifies but
//! the proof is incomplete (PENDING, FAILED, NOT ANCHORED, token not validated, key not pinned,
//! reede-v1 receipts).

use super::verify_chain_report;
use base64::{engine::general_purpose::STANDARD, Engine};
use reede::anchor::{
    entry_digest_hex, inclusion_ok, tsa_label, AnchorEntry, ProofDoc, PROOF_SCHEMA,
};
use reede::receipt::{recompute_content_hash, ExecutionReceipt, REEDE_V1_FORMAT};
use std::fs;

const HELP: &str = "\
Offline anchor verification
Usage:
  reede anchor verify --proof <proof.json> [--pubkey <hex>] [--expected-chain-key <key>]
                      [--cafile <ca.pem>]

Checks the chain slice (linkage, signatures, content hashes), each receipt's Merkle inclusion
in its anchor, and with --cafile the RFC 3161 token over the anchor digest (needs `openssl`).
--pubkey pins the signing key; without it the key inside the proof is used and the output says
so. --expected-chain-key refuses a proof for any other chain.

Exit codes:
  0  chain, signatures (pinned key), inclusion and anchoring all verified (token validated)
  1  tampered or malformed proof (bad chain, signature, inclusion, digest or token)
  2  incomplete: ANCHORING is PENDING, FAILED, NOT ANCHORED or TOKEN NOT VALIDATED, the key
     is not pinned, or a receipt is reede-v1 (sequence_no is not authenticated)";

pub fn run(args: &[String]) -> i32 {
    // args[0] = "anchor", args[1] = "verify"
    if args.get(1).map(String::as_str) != Some("verify") {
        eprintln!("{HELP}");
        return 1;
    }
    let (mut proof, mut cafile, mut pubkey, mut chain_key) = (None, None, None, None);
    let mut i = 2;
    while i < args.len() {
        let value = args.get(i + 1);
        match (args[i].as_str(), value) {
            ("--proof", Some(v)) => proof = Some(v.as_str()),
            ("--cafile", Some(v)) => cafile = Some(v.as_str()),
            ("--pubkey", Some(v)) => pubkey = Some(v.as_str()),
            ("--expected-chain-key", Some(v)) => chain_key = Some(v.as_str()),
            ("--help" | "-h", _) => {
                println!("{HELP}");
                return 0;
            }
            _ => {
                eprintln!("unknown or incomplete option\n{HELP}");
                return 1;
            }
        }
        i += 2;
    }
    let Some(path) = proof else {
        eprintln!("Error: missing --proof\n{HELP}");
        return 1;
    };
    let doc: ProofDoc = match fs::read_to_string(path)
        .map_err(|e| e.to_string())
        .and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
    {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading proof '{path}': {e}");
            return 1;
        }
    };
    match verify(&doc, pubkey, chain_key, cafile) {
        Ok((out, complete)) => {
            print!("{out}");
            if complete {
                0
            } else {
                2
            }
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

/// Weakest first, so the overall state is the minimum.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Rank {
    NotAnchored,
    Failed,
    Pending,
    NotValidated,
    Anchored,
}

fn fail<T>(msg: String) -> Result<T, String> {
    Err(format!("FAIL: {msg}"))
}

/// A receipt whose sequence_no is covered by its hash and signature (reede-v2): only then does
/// an inclusion path prove its position.
fn positional(r: &ExecutionReceipt) -> bool {
    r.format.as_deref() != Some(REEDE_V1_FORMAT) && recompute_content_hash(r).is_some()
}

fn verify(
    doc: &ProofDoc,
    pubkey: Option<&str>,
    expected_chain_key: Option<&str>,
    cafile: Option<&str>,
) -> Result<(String, bool), String> {
    if doc.schema != PROOF_SCHEMA {
        return fail(format!("unknown proof schema '{}'", doc.schema));
    }
    if doc.receipts.is_empty() {
        return fail("proof holds no receipts".into());
    }
    if let Some(want) = expected_chain_key {
        if doc.chain_key != want {
            return fail(format!(
                "proof is for chain '{}', expected '{want}'",
                doc.chain_key
            ));
        }
    }
    if doc.chain_key.contains('\0') {
        return fail("chain key contains NUL".into());
    }
    if let Some(r) = doc.receipts.iter().find(|r| r.tenant_id != doc.chain_key) {
        return fail(format!(
            "receipt seq {} belongs to chain '{}', not '{}'",
            r.sequence_no, r.tenant_id, doc.chain_key
        ));
    }
    let pinned = pubkey.is_some();
    let key = pubkey.unwrap_or(&doc.pubkey_hex);

    let mut out = format!("PROOF:      {} chain {}\n", doc.chain, doc.chain_key);
    out.push_str(&if pinned {
        "KEY:        pinned (--pubkey)\n".to_string()
    } else {
        "KEY:        taken from proof, NOT pinned (pass --pubkey)\n".to_string()
    });
    // Structure, signatures and hashes. The report's own TIMESTAMP and VERDICT lines are about
    // per-receipt tokens; they are replaced by the AUTHENTIC and ANCHORING lines below.
    let report = verify_chain_report(&doc.receipts, Some(key), None, true)?;
    for line in report
        .lines()
        .filter(|l| !l.starts_with("TIMESTAMP:") && !l.starts_with("VERDICT:"))
    {
        out.push_str(line);
        out.push('\n');
    }

    let mut caveats: Vec<String> = Vec::new();
    if let Some(prev) = &doc.receipts[0].prev_hash {
        caveats.push(format!(
            "SEGMENT: starts at seq {} after {prev}; earlier receipts are not in this proof",
            doc.receipts[0].sequence_no
        ));
    }
    let v1 = doc
        .receipts
        .iter()
        .filter(|r| r.format.as_deref() == Some(REEDE_V1_FORMAT))
        .count();
    if v1 > 0 {
        caveats.push(format!(
            "reede-v1 on {v1} receipt(s): sequence_no, timestamp and subject_id are not covered by hash or signature"
        ));
    }
    let unhashed = doc
        .receipts
        .iter()
        .filter(|r| recompute_content_hash(r).is_none())
        .count();
    if unhashed > 0 {
        caveats.push(format!(
            "content_hash not recomputable on {unhashed} receipt(s)"
        ));
    }
    let all_positional = doc.receipts.iter().all(positional);
    let authentic = if !pinned {
        "AUTHENTIC:  NOT ESTABLISHED (signatures checked only against the key inside the proof file)"
    } else if all_positional {
        "AUTHENTIC:  YES (pinned key; chain, signatures and content hashes verified)"
    } else {
        "AUTHENTIC:  PARTIAL (pinned key; see CAVEAT lines)"
    };
    out.push_str(authentic);
    out.push('\n');
    for c in &caveats {
        out.push_str(&format!("CAVEAT:     {c}\n"));
    }

    // Anchors that cover at least one receipt are checked; the rest are ignored.
    let covering = |seq: u64| {
        doc.anchors
            .iter()
            .position(|a| a.from_seq <= seq && seq <= a.to_seq)
    };
    let mut anchor_state: Vec<Option<(Rank, Option<String>)>> = vec![None; doc.anchors.len()];
    let mut worst = Rank::Anchored;
    let mut included = 0usize;
    for r in &doc.receipts {
        let Some(ai) = covering(r.sequence_no) else {
            worst = worst.min(Rank::NotAnchored);
            continue;
        };
        let a = &doc.anchors[ai];
        let span = a
            .to_seq
            .checked_sub(a.from_seq)
            .and_then(|d| d.checked_add(1));
        if span != u64::try_from(a.leaf_count).ok() {
            return fail(format!(
                "anchor {}..{} leaf_count {} does not match its range",
                a.from_seq, a.to_seq, a.leaf_count
            ));
        }
        let inc = a
            .inclusion
            .iter()
            .find(|i| i.sequence_no == r.sequence_no)
            .ok_or_else(|| {
                format!(
                    "FAIL: no inclusion path for receipt seq {} in anchor {}..{}",
                    r.sequence_no, a.from_seq, a.to_seq
                )
            })?;
        let offset = r.sequence_no.checked_sub(a.from_seq);
        if offset != u64::try_from(inc.index).ok() || !inclusion_ok(a, inc, &r.content_hash) {
            return fail(format!(
                "receipt seq {} is not included in the root of anchor {}..{}",
                r.sequence_no, a.from_seq, a.to_seq
            ));
        }
        included += 1;
        if !positional(r) {
            // The leaf is under the root, but its sequence_no is unauthenticated: not a proof
            // of position, so the receipt counts as not anchored.
            worst = worst.min(Rank::NotAnchored);
            continue;
        }
        if anchor_state[ai].is_none() {
            anchor_state[ai] = Some(anchor_rank(&doc.chain_key, a, cafile)?);
        }
        worst = worst.min(anchor_state[ai].as_ref().map(|s| s.0).unwrap());
    }
    out.push_str(&format!(
        "INCLUSION:  VERIFIED ({included}/{} receipts{})\n",
        doc.receipts.len(),
        if all_positional {
            ""
        } else {
            "; reede-v1 receipts are NOT proof of position"
        }
    ));
    for (a, st) in doc.anchors.iter().zip(&anchor_state) {
        let Some((rank, gen)) = st else { continue };
        let state = match (rank, gen) {
            (Rank::Anchored, Some(t)) => format!("token VALID, genTime {t}"),
            (Rank::Anchored, None) => "token VALID".to_string(),
            (Rank::NotValidated, _) => "token present, NOT VALIDATED".to_string(),
            (Rank::Failed, _) => "FAILED".to_string(),
            _ => "no token (pending)".to_string(),
        };
        out.push_str(&format!(
            "ANCHOR:     seq {}..{} root {} tsa {} ({}) {state}\n",
            a.from_seq,
            a.to_seq,
            a.merkle_root,
            a.tsa_url,
            tsa_label(a.tsa_qualified)
        ));
    }
    // The weakest label among the anchors in use.
    let label = if anchor_state
        .iter()
        .zip(&doc.anchors)
        .any(|(s, a)| s.is_some() && !a.tsa_qualified)
    {
        tsa_label(false)
    } else {
        tsa_label(true)
    };
    out.push_str(&match worst {
        Rank::Anchored => format!("ANCHORING:  ANCHORED ({label})\n"),
        Rank::NotValidated => {
            format!("ANCHORING:  TOKEN NOT VALIDATED (pass --cafile; {label})\n")
        }
        Rank::Pending => {
            "ANCHORING:  PENDING (no validated timestamp yet; receipts are signed, not anchored)\n"
                .into()
        }
        Rank::Failed => "ANCHORING:  FAILED (the anchorer gave up on an anchor; receipts are signed, not anchored)\n".into(),
        Rank::NotAnchored => {
            "ANCHORING:  NOT ANCHORED (some receipts are covered by no usable anchor)\n".into()
        }
    });
    let complete = worst == Rank::Anchored && pinned && all_positional;
    Ok((out, complete))
}

/// Rank one anchor; with a CA, validate its token over the structured digest (Err = tamper).
fn anchor_rank(
    chain_key: &str,
    a: &AnchorEntry,
    cafile: Option<&str>,
) -> Result<(Rank, Option<String>), String> {
    if a.status == "failed" {
        return Ok((Rank::Failed, None));
    }
    let token = match (a.status.as_str(), a.tsa_token.as_deref()) {
        ("anchored", Some(t)) if !t.is_empty() => t,
        // pending, or "anchored" without a token: nothing to validate.
        _ => return Ok((Rank::Pending, None)),
    };
    let Some(ca) = cafile else {
        return Ok((Rank::NotValidated, None));
    };
    let digest = entry_digest_hex(chain_key, a).ok_or_else(|| {
        format!(
            "FAIL: anchor {}..{} has a malformed root",
            a.from_seq, a.to_seq
        )
    })?;
    match verify_token(token, &digest, ca) {
        Some(gen) => Ok((Rank::Anchored, Some(gen))),
        None => Err(format!(
            "FAIL: TSA token of anchor {}..{} does not verify against {ca} over the anchor digest",
            a.from_seq, a.to_seq
        )),
    }
}

/// `openssl ts -verify` of the token (bare token or full `TimeStampResp`) over `digest_hex`
/// (checks signature, chain to the CA, and that the message imprint equals the digest).
/// Returns the token's genTime on success.
fn verify_token(token_b64: &str, digest_hex: &str, cafile: &str) -> Option<String> {
    let bytes = STANDARD.decode(token_b64).ok().filter(|b| !b.is_empty())?;
    let file = std::env::temp_dir().join(format!("reede_tsa_{}.der", uuid::Uuid::new_v4()));
    fs::write(&file, bytes).ok()?;
    let ts = |extra: &[&str], verify: bool| {
        let mut c = std::process::Command::new("openssl");
        c.arg("ts");
        if verify {
            c.args(["-verify", "-digest", digest_hex, "-in"]).arg(&file);
            c.args(["-CAfile", cafile]);
        } else {
            c.args(["-reply", "-text", "-in"]).arg(&file);
        }
        c.args(extra);
        c.output().ok()
    };
    let result = [&["-token_in"][..], &[][..]].iter().find_map(|form| {
        let ok = ts(form, true).is_some_and(|o| {
            o.status.success() && String::from_utf8_lossy(&o.stdout).contains("Verification: OK")
        });
        ok.then(|| {
            ts(form, false)
                .and_then(|o| {
                    String::from_utf8_lossy(&o.stdout)
                        .lines()
                        .find_map(|l| l.strip_prefix("Time stamp: ").map(str::to_string))
                })
                .unwrap_or_else(|| "unavailable".into())
        })
    });
    let _ = fs::remove_file(&file);
    result
}
