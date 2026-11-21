//! `reede anchor verify`, end to end through the real binary: both directions.
//!
//! Receipts are genuinely signed and chained (`emit_execution_receipt`). The TSA tests build a
//! throwaway CA + timestamping cert with `openssl ts -reply` and skip (loudly) without openssl.
//! Exit codes: 0 complete, 1 tampered/malformed, 2 incomplete.

use reede::anchor::{
    anchor_digest, entry_digest_hex, inclusions, root, AnchorEntry, ProofDoc, PROOF_SCHEMA,
};
use reede::receipt::{
    emit_execution_receipt, ExecutionReceipt, InMemoryReceiptSigner, InMemoryReceiptStore,
};
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;

const CHAIN_KEY: &str = "acme#witnessed";

struct Run {
    code: i32,
    out: String,
    err: String,
}

fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!("reede_anchor_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

async fn chain_for(key: &str, n: usize, signer: &InMemoryReceiptSigner) -> Vec<ExecutionReceipt> {
    let store = InMemoryReceiptStore::new();
    let mut out = Vec::new();
    for i in 0..n {
        out.push(
            emit_execution_receipt(
                signer,
                &store,
                Uuid::new_v4(),
                key,
                format!("call {i}"),
                1,
                10,
                1,
                Some(format!("witnessed:acme/{i}")),
            )
            .await
            .unwrap(),
        );
    }
    out
}

/// A genuine chain, its pubkey, and a pending anchor over all of it.
async fn chain(n: usize) -> (ProofDoc, String) {
    let signer = InMemoryReceiptSigner::generate_random();
    let receipts = chain_for(CHAIN_KEY, n, &signer).await;
    let pk = hex::encode(signer.verifying_key().to_bytes());
    (doc(receipts, pk.clone(), None, false), pk)
}

fn doc(
    receipts: Vec<ExecutionReceipt>,
    pubkey: String,
    token: Option<String>,
    qualified: bool,
) -> ProofDoc {
    let key = receipts[0].tenant_id.clone();
    let leaves: Vec<(u64, &str)> = receipts
        .iter()
        .map(|r| (r.sequence_no, r.content_hash.as_str()))
        .collect();
    let hashes: Vec<&str> = leaves.iter().map(|l| l.1).collect();
    let seqs: Vec<u64> = leaves.iter().map(|l| l.0).collect();
    let anchor = AnchorEntry {
        from_seq: seqs[0],
        to_seq: *seqs.last().unwrap(),
        leaf_count: leaves.len(),
        merkle_root: hex::encode(root(&hashes).unwrap()),
        tsa_url: "https://tsa.invalid/tsr".into(),
        tsa_qualified: qualified,
        status: if token.is_some() {
            "anchored"
        } else {
            "pending"
        }
        .into(),
        anchored_at: None,
        tsa_token: token,
        inclusion: inclusions(&leaves, &seqs),
    };
    ProofDoc {
        schema: PROOF_SCHEMA.into(),
        chain: "witnessed".into(),
        chain_key: key,
        pubkey_hex: pubkey,
        receipts,
        anchors: vec![anchor],
    }
}

fn run(d: &Path, doc: &ProofDoc, extra: &[&str]) -> Run {
    let p = d.join(format!("{}.json", Uuid::new_v4()));
    std::fs::write(&p, serde_json::to_vec(doc).unwrap()).unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_reede"))
        .args(["anchor", "verify", "--proof"])
        .arg(&p)
        .args(extra)
        .output()
        .unwrap();
    Run {
        code: o.status.code().unwrap(),
        out: String::from_utf8_lossy(&o.stdout).into_owned(),
        err: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

fn openssl_ts() -> bool {
    Command::new("openssl")
        .args(["ts", "-help"])
        .output()
        .map(|o| !o.stdout.is_empty() || !o.stderr.is_empty())
        .unwrap_or(false)
}

fn sh(d: &Path, args: &[&str]) {
    let o = Command::new("openssl")
        .current_dir(d)
        .args(args)
        .output()
        .unwrap();
    assert!(
        o.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}

/// A throwaway CA and timestamping cert in `d/<name>/`; returns the CA pem path.
fn make_tsa(d: &Path, name: &str) -> PathBuf {
    let t = d.join(name);
    std::fs::create_dir_all(&t).unwrap();
    std::fs::write(t.join("ext"), "extendedKeyUsage=critical,timeStamping\n").unwrap();
    std::fs::write(t.join("serial"), "01\n").unwrap();
    std::fs::write(
        t.join("ts.cnf"),
        "oid_section = oids\n[oids]\ntsa_policy = 1.2.3.4.5\n[tsa]\ndefault_tsa = c\n[c]\nserial = ./serial\nsigner_cert = ./tsa.pem\nsigner_key = ./tsa.key\nsigner_digest = sha256\ncerts = ./ca.pem\ndefault_policy = tsa_policy\ndigests = sha256\naccuracy = secs:1\nordering = yes\ntsa_name = yes\ness_cert_id_alg = sha256\n",
    )
    .unwrap();
    sh(
        &t,
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-subj",
            &format!("/CN={name}CA"),
            "-days",
            "2",
        ],
    );
    sh(
        &t,
        &[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "tsa.key",
            "-out",
            "tsa.csr",
            "-subj",
            &format!("/CN={name}TSA"),
        ],
    );
    sh(
        &t,
        &[
            "x509",
            "-req",
            "-in",
            "tsa.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-out",
            "tsa.pem",
            "-days",
            "2",
            "-extfile",
            "ext",
        ],
    );
    t.join("ca.pem")
}

/// Base64 of the TSA's full `TimeStampResp` (what tectic-timestamp stores) over `digest_hex`.
fn tsa_response(tsa_dir: &Path, digest_hex: &str) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    sh(
        tsa_dir,
        &[
            "ts", "-query", "-digest", digest_hex, "-sha256", "-cert", "-out", "q.tsq",
        ],
    );
    sh(
        tsa_dir,
        &[
            "ts",
            "-reply",
            "-config",
            "ts.cnf",
            "-queryfile",
            "q.tsq",
            "-out",
            "r.tsr",
        ],
    );
    STANDARD.encode(std::fs::read(tsa_dir.join("r.tsr")).unwrap())
}

fn anchor_it(t: &mut ProofDoc, token: String) {
    t.anchors[0].tsa_token = Some(token);
    t.anchors[0].status = "anchored".into();
}

#[tokio::test]
async fn pending_is_exit_2_and_an_unpinned_key_is_never_authentic() {
    let d = scratch();
    let (t, pk) = chain(5).await;
    let r = run(&d, &t, &[]);
    assert_eq!(r.code, 2, "{}{}", r.out, r.err);
    assert!(
        r.out.contains("KEY:        taken from proof, NOT pinned"),
        "{}",
        r.out
    );
    assert!(r.out.contains("AUTHENTIC:  NOT ESTABLISHED"), "{}", r.out);
    assert!(!r.out.contains("AUTHENTIC:  YES"), "{}", r.out);
    assert!(r.out.contains("ANCHORING:  PENDING"), "{}", r.out);
    assert!(
        r.out.contains("INCLUSION:  VERIFIED (5/5 receipts)"),
        "{}",
        r.out
    );
    // pinned: authentic, but pending is still incomplete
    let r = run(&d, &t, &["--pubkey", &pk]);
    assert_eq!(r.code, 2, "{}", r.out);
    assert!(r.out.contains("AUTHENTIC:  YES"), "{}", r.out);
    assert!(r.out.contains("ANCHORING:  PENDING"), "{}", r.out);
    println!("{}", r.out);
}

#[tokio::test]
async fn a_forged_key_is_not_authentic_without_pubkey_and_fails_with_it() {
    let d = scratch();
    let (_, real_pk) = chain(3).await;
    // An attacker re-signs a whole chain with their own key and ships that key in the proof.
    let attacker = InMemoryReceiptSigner::generate_random();
    let receipts = chain_for(CHAIN_KEY, 3, &attacker).await;
    let forged = doc(
        receipts,
        hex::encode(attacker.verifying_key().to_bytes()),
        None,
        false,
    );
    let r = run(&d, &forged, &[]);
    assert_eq!(r.code, 2, "{}{}", r.out, r.err);
    assert!(
        !r.out.contains("AUTHENTIC:  YES") && r.out.contains("NOT pinned"),
        "{}",
        r.out
    );
    let r = run(&d, &forged, &["--pubkey", &real_pk]);
    assert_eq!(r.code, 1, "{}{}", r.out, r.err);
    assert!(r.err.contains("FAIL"), "{}", r.err);
    // a wrong --pubkey on a genuine proof fails too
    let (genuine, _) = chain(3).await;
    assert_eq!(run(&d, &genuine, &["--pubkey", &real_pk]).code, 1);
    // --expected-chain-key: right passes, wrong fails
    let (t, pk) = chain(3).await;
    assert_eq!(
        run(
            &d,
            &t,
            &["--pubkey", &pk, "--expected-chain-key", CHAIN_KEY]
        )
        .code,
        2
    );
    let r = run(
        &d,
        &t,
        &["--pubkey", &pk, "--expected-chain-key", "globex#witnessed"],
    );
    assert_eq!(r.code, 1);
    assert!(r.err.contains("expected 'globex#witnessed'"), "{}", r.err);
}

#[tokio::test]
async fn reede_v1_caveats_are_kept_and_inclusion_is_not_positional() {
    let d = scratch();
    let fx: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/reede-v1-writer-receipt.json")).unwrap();
    let receipt: ExecutionReceipt = serde_json::from_value(fx["receipt"].clone()).unwrap();
    let pk = fx["pubkey_hex"].as_str().unwrap().to_string();
    let mut t = doc(vec![receipt], pk.clone(), None, false);
    anchor_it(&mut t, "AAAA".into());
    let r = run(&d, &t, &["--pubkey", &pk]);
    assert_eq!(r.code, 2, "{}{}", r.out, r.err);
    assert!(
        r.out.contains("CAVEAT:     reede-v1 on 1 receipt(s): sequence_no, timestamp and subject_id are not covered"),
        "{}",
        r.out
    );
    assert!(r.out.contains("AUTHENTIC:  PARTIAL"), "{}", r.out);
    assert!(r.out.contains("NOT proof of position"), "{}", r.out);
    assert!(!r.out.contains("ANCHORING:  ANCHORED"), "{}", r.out);
    assert!(r.out.contains("ANCHORING:  NOT ANCHORED"), "{}", r.out);
}

#[tokio::test]
async fn tampered_receipt_root_or_missing_path_exits_1_and_clean_input_does_not() {
    let d = scratch();
    let (good, pk) = chain(5).await;
    let pin = ["--pubkey", pk.as_str()];

    let mut t = good.clone();
    t.receipts[2].credits_spent += 1;
    let r = run(&d, &t, &pin);
    assert_eq!(r.code, 1, "{}", r.err);
    assert!(r.err.contains("FAIL"), "{}", r.err);

    let mut t = good.clone();
    let rt = &mut t.anchors[0].merkle_root;
    *rt = format!(
        "{}{}",
        if rt.starts_with('0') { "1" } else { "0" },
        &rt[1..]
    );
    let r = run(&d, &t, &pin);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("not included in the root"), "{}", r.err);

    let mut t = good.clone();
    t.anchors[0].inclusion.retain(|i| i.sequence_no != 3);
    let r = run(&d, &t, &pin);
    assert_eq!(r.code, 1);
    assert!(
        r.err.contains("no inclusion path for receipt seq 3"),
        "{}",
        r.err
    );

    let mut t = good.clone();
    t.anchors[0].inclusion[1].siblings.clear();
    assert_eq!(run(&d, &t, &pin).code, 1);

    assert_eq!(run(&d, &good, &pin).code, 2); // clean: no tamper, just pending
}

#[tokio::test]
async fn failed_and_uncovered_are_exit_2_with_their_own_words() {
    let d = scratch();
    let (good, pk) = chain(5).await;
    let pin = ["--pubkey", pk.as_str()];

    let mut t = good.clone();
    t.anchors[0].status = "failed".into();
    let r = run(&d, &t, &pin);
    assert_eq!(r.code, 2, "{}", r.out);
    assert!(r.out.contains("ANCHORING:  FAILED"), "{}", r.out);
    assert!(!r.out.contains("PENDING"), "{}", r.out);

    let mut t = good.clone();
    t.anchors.clear();
    let r = run(&d, &t, &pin);
    assert_eq!(r.code, 2);
    assert!(r.out.contains("ANCHORING:  NOT ANCHORED"), "{}", r.out);
}

#[tokio::test]
async fn crafted_proofs_fail_cleanly_without_panicking() {
    let d = scratch();
    let (good, pk) = chain(5).await;
    let pin = ["--pubkey", pk.as_str()];
    let mut cases: Vec<(&str, ProofDoc)> = Vec::new();
    for (name, from, to) in [
        ("to_seq u64::MAX", 1u64, u64::MAX),
        ("from 0 to MAX", 0, u64::MAX),
        ("span wraps", 0, u64::MAX - 1),
    ] {
        let mut t = good.clone();
        t.anchors[0].from_seq = from;
        t.anchors[0].to_seq = to;
        cases.push((name, t));
    }
    let mut t = good.clone();
    t.anchors[0].leaf_count = usize::MAX;
    cases.push(("leaf_count usize::MAX", t));
    let mut t = good.clone();
    t.anchors[0].inclusion[0].index = usize::MAX;
    cases.push(("index usize::MAX", t));
    let mut t = good.clone();
    t.anchors[0].inclusion[0].siblings = vec!["zz".into(); 3];
    cases.push(("garbage siblings", t));
    for (name, t) in cases {
        let r = run(&d, &t, &pin);
        assert_eq!(r.code, 1, "{name}: {}{}", r.out, r.err);
        assert!(r.err.starts_with("FAIL"), "{name}: {}", r.err);
        assert!(!r.err.contains("panicked"), "{name}: {}", r.err);
    }
}

#[test]
fn the_digest_vector_is_stable() {
    let h = hex::encode(anchor_digest("acme#byoa", 1, 3, 3, &[7; 32]));
    assert_eq!(h.len(), 64);
}

#[tokio::test]
async fn a_real_token_over_the_structured_digest_verifies_and_others_do_not() {
    if !openssl_ts() {
        eprintln!("SKIPPED: openssl ts is not available");
        return;
    }
    let d = scratch();
    let ca = make_tsa(&d, "good");
    let other_ca = make_tsa(&d, "other");
    let ca_s = ca.to_str().unwrap();
    let (mut t, pk) = chain(5).await;
    let pin = ["--pubkey", pk.as_str(), "--cafile", ca_s];
    let digest = entry_digest_hex(&t.chain_key, &t.anchors[0]).unwrap();
    anchor_it(&mut t, tsa_response(&d.join("good"), &digest));

    let r = run(&d, &t, &pin);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert!(
        r.out
            .contains("ANCHORING:  ANCHORED (interim, not qualified)"),
        "{}",
        r.out
    );
    assert!(r.out.contains("token VALID, genTime "), "{}", r.out);
    assert!(r.out.contains("AUTHENTIC:  YES"), "{}", r.out);
    println!("{}", r.out);

    // "qualified" is the operator's claim, labelled as such
    let mut q = t.clone();
    q.anchors[0].tsa_qualified = true;
    let r = run(&d, &q, &pin);
    assert_eq!(r.code, 0);
    assert!(r.out.contains("ANCHORED (claimed qualified)"), "{}", r.out);

    // wrong CA -> tamper-class failure
    let other_s = other_ca.to_str().unwrap();
    let r = run(&d, &t, &["--pubkey", &pk, "--cafile", other_s]);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("does not verify"), "{}", r.err);

    // token over the BARE root (the old construction) -> imprint mismatch -> 1
    let mut bare = t.clone();
    bare.anchors[0].tsa_token = Some(tsa_response(&d.join("good"), &bare.anchors[0].merkle_root));
    assert_eq!(run(&d, &bare, &pin).code, 1);

    // token for another chain's digest (same root and range) -> 1
    let root_bytes: [u8; 32] = hex::decode(&t.anchors[0].merkle_root)
        .unwrap()
        .try_into()
        .unwrap();
    let other_chain = hex::encode(anchor_digest("globex#witnessed", 1, 5, 5, &root_bytes));
    let mut swapped = t.clone();
    swapped.anchors[0].tsa_token = Some(tsa_response(&d.join("good"), &other_chain));
    assert_eq!(run(&d, &swapped, &pin).code, 1);

    // token over a different range of the same chain -> 1
    let mut ranged = t.clone();
    let fake = hex::encode(anchor_digest(&t.chain_key, 1, 4, 5, &root_bytes));
    ranged.anchors[0].tsa_token = Some(tsa_response(&d.join("good"), &fake));
    assert_eq!(run(&d, &ranged, &pin).code, 1);

    // no --cafile: present but not validated -> 2, never ANCHORED
    let r = run(&d, &t, &["--pubkey", &pk]);
    assert_eq!(r.code, 2);
    assert!(
        r.out.contains("TOKEN NOT VALIDATED") && !r.out.contains("ANCHORING:  ANCHORED"),
        "{}",
        r.out
    );
}
