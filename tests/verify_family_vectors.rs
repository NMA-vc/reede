//! Fixed receipt-family vectors and a genuine, runtime-issued offline RFC 3161 proof.
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, SigningKey};
use reede::receipt::{
    emit_execution_receipt, verify_chain, verify_receipt, ExecutionReceipt, InMemoryReceiptSigner,
    InMemoryReceiptStore, ReceiptStore,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

const PUBKEY: &str = "197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61";
const FIXTURES: [&str; 4] = [
    "reede-v1-run-v3-vector.json",
    "reede-v1-hitl-decision-vector.json",
    "reede-v1-qc-vector.json",
    "reede-v1-timestamped-vector.json",
];

#[derive(Deserialize)]
struct Vector {
    expected_content_hash: String,
    pubkey_hex: String,
    receipt: ExecutionReceipt,
}

fn fixture(name: &str) -> Vector {
    serde_json::from_str(
        &fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(name),
        )
        .unwrap(),
    )
    .unwrap()
}

fn independent_hash(r: &ExecutionReceipt) -> String {
    let numbers = [
        r.credits_spent.to_string(),
        r.tokens_used.to_string(),
        r.reservation_credits.to_string(),
    ];
    let task = r.task_id.to_string();
    let fields = [
        r.tenant_id.as_str(),
        task.as_str(),
        r.payload_summary.as_str(),
        &numbers[0],
        &numbers[1],
        &numbers[2],
        r.prev_hash.as_deref().unwrap_or(""),
    ];
    let mut wire = Vec::new();
    for field in fields {
        wire.extend_from_slice(format!("{:x}:", field.len()).as_bytes());
        wire.extend_from_slice(field.as_bytes());
    }
    hex::encode(Sha256::digest(wire))
}

fn write_chain(dir: &Path, name: &str, chain: &[ExecutionReceipt]) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, serde_json::to_vec_pretty(chain).unwrap()).unwrap();
    path
}

fn verify_binary(path: &Path, ca: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_verify"));
    command.args(["--chain", path.to_str().unwrap(), "--pubkey", PUBKEY]);
    if let Some(ca) = ca {
        command.args(["--cafile", ca.to_str().unwrap()]);
    }
    bounded_output(command, Duration::from_secs(20)).expect("offline verifier must execute")
}

fn bounded_output(mut command: Command, timeout: Duration) -> std::io::Result<Output> {
    // Files cannot fill a pipe while we poll. The private capture directory is
    // removed on every return, including spawn errors and timeout/panic paths.
    let capture = PrivateDir::new();
    let stdout_path = capture.0.join("stdout");
    let stderr_path = capture.0.join("stderr");
    command
        .stdin(Stdio::null())
        .stdout(fs::File::create(&stdout_path)?)
        .stderr(fs::File::create(&stderr_path)?);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = ChildGuard(Some(command.spawn()?));
    let started = Instant::now();
    loop {
        if let Some(status) = child.0.as_mut().unwrap().try_wait()? {
            child.0.take(); // try_wait has already reaped the successful child.
            return Ok(Output {
                status,
                stdout: read_capture(&stdout_path)?,
                stderr: read_capture(&stderr_path)?,
            });
        }
        if started.elapsed() >= timeout {
            // Kill the process group before reaping the child so verifier-owned
            // OpenSSL descendants cannot continue past this test's deadline.
            child.stop()?;
            return Err(std::io::Error::new(
                ErrorKind::TimedOut,
                format!(
                    "child timed out after {timeout:?}: {}",
                    bounded(&read_capture(&stderr_path)?)
                ),
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn read_capture(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(64 * 1024)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

struct ChildGuard(Option<Child>);
impl ChildGuard {
    fn stop(&mut self) -> std::io::Result<()> {
        let Some(mut child) = self.0.take() else {
            return Ok(());
        };
        #[cfg(unix)]
        {
            unsafe extern "C" {
                fn kill(pid: i32, signal: i32) -> i32;
            }
            // SAFETY: this child was spawned in its own process group; a
            // negative PID targets only that group. SIGKILL is 9 on Unix.
            unsafe {
                kill(-(child.id() as i32), 9);
            }
        }
        let _ = child.kill();
        // Do not replace the main deadline with an unbounded wait after kill.
        // try_wait reaps the child; inability to establish cleanup is an error.
        let started = Instant::now();
        loop {
            if child.try_wait()?.is_some() {
                return Ok(());
            }
            if started.elapsed() >= Duration::from_secs(2) {
                return Err(std::io::Error::new(
                    ErrorKind::TimedOut,
                    "failed to reap terminated child within two seconds",
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            eprintln!("test-child cleanup failed: {error}");
            if !std::thread::panicking() {
                panic!("test child was not reaped");
            }
        }
    }
}

fn openssl(dir: &Path, args: &[&str]) -> Output {
    let mut command = Command::new("openssl");
    command.current_dir(dir).args(args);
    let output = bounded_output(command, Duration::from_secs(20))
        .expect("OpenSSL was already proven available");
    assert!(
        output.status.success(),
        "openssl {:?} failed: {}",
        args,
        bounded(&output.stderr)
    );
    output
}

fn bounded(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(4096)]).into_owned()
}

struct PrivateDir(PathBuf);
impl PrivateDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("reede-family-{}", Uuid::new_v4()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        }
        #[cfg(not(unix))]
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for PrivateDir {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            if error.kind() != ErrorKind::NotFound {
                eprintln!("private test-directory cleanup failed: {error}");
                if !std::thread::panicking() {
                    panic!("generated test material was not removed");
                }
            }
        }
    }
}

// This helper is invoked only in a child process with a command-local setting.
// It exercises output beyond pipe capacity and a process that exceeds its bound.
#[test]
fn process_helper_child() {
    match std::env::var("REEDE_FAMILY_HELPER_CHILD").as_deref() {
        Ok("flood") => {
            use std::io::Write;
            let bytes = vec![b'x'; 128 * 1024];
            std::io::stdout().write_all(&bytes).unwrap();
            std::io::stderr().write_all(&bytes).unwrap();
        }
        Ok("timeout") => {
            eprintln!("helper pid: {}", std::process::id());
            thread::sleep(Duration::from_secs(5));
        }
        _ => {}
    }
}

#[test]
fn process_bounds_survive_full_output_and_reap_timeout() {
    let child_command = |mode: &str| {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", "process_helper_child", "--nocapture"]);
        command.env("REEDE_FAMILY_HELPER_CHILD", mode);
        command
    };
    let flood = bounded_output(child_command("flood"), Duration::from_secs(2)).unwrap();
    assert!(flood.status.success());
    assert_eq!(flood.stdout.len(), 64 * 1024);
    assert_eq!(flood.stderr.len(), 64 * 1024);
    let started = Instant::now();
    let timeout = bounded_output(child_command("timeout"), Duration::from_millis(200)).unwrap_err();
    assert_eq!(timeout.kind(), ErrorKind::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(2));
    #[cfg(unix)]
    {
        let message = timeout.to_string();
        let pid: i32 = message
            .split("helper pid: ")
            .nth(1)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        unsafe extern "C" {
            fn kill(pid: i32, signal: i32) -> i32;
        }
        // SAFETY: signal 0 only probes existence. The timed-out child must be gone.
        assert_eq!(unsafe { kill(pid, 0) }, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(3));
    }
    let outer = PrivateDir::new();
    let path = outer.0.clone();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    let failure = std::panic::catch_unwind(|| {
        let guard = outer;
        fs::write(guard.0.join("generated-test-material"), b"synthetic").unwrap();
        panic!("intentional cleanup probe");
    });
    assert!(failure.is_err());
    assert!(!path.exists());
}

#[test]
fn fixed_vectors_recompute_and_verify_independently() {
    let key =
        ed25519_dalek::VerifyingKey::from_bytes(&hex::decode(PUBKEY).unwrap().try_into().unwrap())
            .unwrap();
    for name in FIXTURES {
        let vector = fixture(name);
        assert_eq!(vector.pubkey_hex, PUBKEY, "{name}");
        assert_eq!(
            independent_hash(&vector.receipt),
            vector.expected_content_hash,
            "{name}"
        );
        assert_eq!(
            vector.receipt.content_hash, vector.expected_content_hash,
            "{name}"
        );
        verify_receipt(&vector.receipt, &key).unwrap();
        let signature =
            Signature::from_slice(&hex::decode(&vector.receipt.signature).unwrap()).unwrap();
        key.verify_strict(vector.expected_content_hash.as_bytes(), &signature)
            .unwrap();
    }
    let pending = fixture(FIXTURES[3]);
    assert!(pending.receipt.tsa_token.is_none());
}

#[test]
fn legacy_terminal_summary_receipt_still_verifies() {
    let key =
        ed25519_dalek::VerifyingKey::from_bytes(&hex::decode(PUBKEY).unwrap().try_into().unwrap())
            .unwrap();
    let doc: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/reede-v1-legacy-terminal-summary-receipt.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let receipt: ExecutionReceipt = serde_json::from_value(doc["receipt"].clone()).unwrap();
    assert_eq!(independent_hash(&receipt), receipt.content_hash);
    verify_receipt(&receipt, &key).unwrap();
}

#[tokio::test]
async fn vectors_exercise_real_binary_chain_and_authenticity_negatives() {
    let dir = PrivateDir::new();
    let signer = InMemoryReceiptSigner::new(SigningKey::from_bytes(&[42; 32]));
    for (index, name) in FIXTURES.into_iter().enumerate() {
        let first = fixture(name).receipt;
        let second_id = Uuid::from_u128(0x100 + index as u128);
        let mut second_summary = first.payload_summary.clone();
        let summary: serde_json::Value = serde_json::from_str(&second_summary).unwrap();
        if summary["version"] == 3 {
            second_summary = second_summary.replace(
                &format!(r#""id":"{}""#, first.task_id),
                &format!(r#""id":"{second_id}""#),
            );
        }
        let store = InMemoryReceiptStore::new();
        store.append(first.clone()).await.unwrap();
        let second = emit_execution_receipt(
            &signer,
            &store,
            second_id,
            "vector-tenant",
            second_summary,
            first.credits_spent,
            first.tokens_used,
            first.reservation_credits,
            first.subject_id.clone(),
        )
        .await
        .unwrap();
        assert_eq!(second.task_id, second_id);
        assert_eq!(second.tenant_id, first.tenant_id);
        assert_eq!(second.sequence_no, first.sequence_no + 1);
        assert_eq!(
            second.prev_hash.as_deref(),
            Some(first.content_hash.as_str())
        );
        // The writer emits reede-v2 (the v2 rule is pinned cross-language by
        // tests/fixtures/reede-v2-vector.json); the v1 fixtures above keep the independent check.
        assert_eq!(second.format.as_deref(), Some("reede-v2"));
        assert_eq!(
            reede::receipt::recompute_content_hash(&second).as_deref(),
            Some(second.content_hash.as_str())
        );
        let key = ed25519_dalek::VerifyingKey::from_bytes(
            &hex::decode(PUBKEY).unwrap().try_into().unwrap(),
        )
        .unwrap();
        key.verify_strict(
            second.content_hash.as_bytes(),
            &Signature::from_slice(&hex::decode(&second.signature).unwrap()).unwrap(),
        )
        .unwrap();
        let second_value: serde_json::Value =
            serde_json::from_str(&second.payload_summary).unwrap();
        if summary.get("run_id").is_some() {
            // E1 decision/QC links name their parent run, while task_id names
            // this separate event. Both events here concern the same fixed run.
            assert_eq!(second_value["run_id"], summary["run_id"]);
            assert_eq!(
                second_value["run_id"],
                "00000000-0000-0000-0000-0000000000f4"
            );
        }
        if summary["version"] == 3 {
            assert_eq!(second_value["reservation"]["id"], second_id.to_string());
        }
        let chain = vec![first.clone(), second];
        verify_chain(&chain, None).unwrap();
        let path = write_chain(&dir.0, &format!("{name}.chain.json"), &chain);
        let output = verify_binary(&path, None);
        assert!(
            output.status.success(),
            "{name}: {}",
            bounded(&output.stderr)
        );
        assert!(bounded(&output.stdout).contains("VERDICT:    SIGNED, NOT TIMESTAMPED"));

        for (label, mutate) in [
            ("tenant", 0_u8),
            ("summary", 1),
            ("signature", 2),
            ("prev_hash", 3),
        ] {
            let mut bad = chain.clone();
            match mutate {
                0 => bad[0].tenant_id.push('x'),
                1 => bad[0].payload_summary.push('x'),
                2 => corrupt_signature(&mut bad[0]),
                _ => bad[1].prev_hash = Some("00".repeat(32)),
            }
            let bad_path = write_chain(&dir.0, &format!("{name}.{label}.json"), &bad);
            let rejected = verify_binary(&bad_path, None);
            assert!(
                !rejected.status.success(),
                "{name}/{label} must fail authenticity"
            );
            let reason = bounded(&rejected.stderr);
            assert!(
                // A tenant edit on one link now fails the one-tenant-per-chain check before
                // the hash recompute; it is rejected either way.
                reason.contains(if mutate == 3 || mutate == 0 {
                    "FAIL: Receipt chain verification failed"
                } else if mutate == 2 {
                    "FAIL: Signature verification failed"
                } else {
                    "FAIL: content_hash mismatch"
                }),
                "{name}/{label}: {reason}"
            );
            if mutate == 3 {
                assert!(verify_chain(&bad, None).is_err());
            }
        }
    }
}

fn issue_token(dir: &Path, hash: &str, stem: &str) -> String {
    let req = format!("{stem}.tsq");
    let resp = format!("{stem}.tsr");
    let token = format!("{stem}.token");
    openssl(
        dir,
        &[
            "ts", "-query", "-digest", hash, "-sha256", "-cert", "-out", &req,
        ],
    );
    openssl(
        dir,
        &[
            "ts",
            "-reply",
            "-config",
            "tsa.cnf",
            "-queryfile",
            &req,
            "-out",
            &resp,
        ],
    );
    openssl(
        dir,
        &[
            "ts",
            "-verify",
            "-in",
            &resp,
            "-queryfile",
            &req,
            "-CAfile",
            "ca.crt",
        ],
    );
    openssl(
        dir,
        &["ts", "-reply", "-in", &resp, "-token_out", "-out", &token],
    );
    STANDARD.encode(fs::read(dir.join(token)).unwrap())
}

fn corrupt_signature(receipt: &mut ExecutionReceipt) {
    let mut bytes = hex::decode(&receipt.signature).unwrap();
    bytes[0] ^= 1;
    receipt.signature = hex::encode(bytes);
}

fn assert_binary_rejects(path: &Path, ca: &Path, reason: &str) {
    let output = verify_binary(path, Some(ca));
    let stderr = bounded(&output.stderr);
    assert!(!output.status.success(), "negative unexpectedly succeeded");
    assert!(stderr.contains(reason), "wrong rejection: {stderr}");
    assert!(!bounded(&output.stdout).contains("VERDICT:    FULLY QUALIFIED"));
    println!("negative verdict: {stderr}");
}

#[tokio::test]
async fn runtime_tsa_proves_full_qualification_and_negative_verdicts() {
    let mut availability = Command::new("openssl");
    availability.arg("version");
    match bounded_output(availability, Duration::from_secs(20)) {
        Err(error) if error.kind() == ErrorKind::NotFound => {
            eprintln!("UNEXECUTED: OpenSSL is missing; runtime TSA proof did not run");
            return;
        }
        Err(error) => panic!("OpenSSL availability check failed: {error}"),
        Ok(output) => assert!(
            output.status.success(),
            "OpenSSL is present but broken: {}",
            bounded(&output.stderr)
        ),
    }
    let dir = PrivateDir::new();
    fs::write(dir.0.join("tsa.cnf"), "[ tsa ]\ndefault_tsa = tsa_config\n[ tsa_config ]\nserial = tsa.serial\ncrypto_device = builtin\nsigner_cert = tsa.crt\ncerts = ca.crt\nsigner_key = tsa.key\nsigner_digest = sha256\ndefault_policy = 1.2.3\ndigests = sha256\naccuracy = secs:1\nordering = yes\ntsa_name = yes\ness_cert_id_chain = no\ness_cert_id_alg = sha256\n[ ca_ext ]\nbasicConstraints = critical,CA:true\nkeyUsage = critical,keyCertSign,cRLSign\n[ tsa_ext ]\nbasicConstraints = critical,CA:false\nkeyUsage = critical,digitalSignature\nextendedKeyUsage = critical,timeStamping\n").unwrap();
    fs::write(dir.0.join("tsa.serial"), "01\n").unwrap();
    openssl(
        &dir.0,
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-days",
            "2",
            "-subj",
            "/CN=reede-family-test-ca",
            "-keyout",
            "ca.key",
            "-out",
            "ca.crt",
            "-extensions",
            "ca_ext",
            "-config",
            "tsa.cnf",
        ],
    );
    openssl(
        &dir.0,
        &[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-subj",
            "/CN=reede-family-test-tsa",
            "-keyout",
            "tsa.key",
            "-out",
            "tsa.csr",
        ],
    );
    openssl(
        &dir.0,
        &[
            "x509",
            "-req",
            "-in",
            "tsa.csr",
            "-CA",
            "ca.crt",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "2",
            "-sha256",
            "-extfile",
            "tsa.cnf",
            "-extensions",
            "tsa_ext",
            "-out",
            "tsa.crt",
        ],
    );

    let signer = InMemoryReceiptSigner::new(SigningKey::from_bytes(&[42; 32]));
    let mut first = fixture(FIXTURES[3]).receipt;
    let store = InMemoryReceiptStore::new();
    store.append(first.clone()).await.unwrap();
    let mut second = emit_execution_receipt(
        &signer,
        &store,
        Uuid::parse_str("00000000-0000-0000-0000-000000000076").unwrap(),
        "vector-tenant",
        first.payload_summary.clone(),
        0,
        0,
        0,
        None,
    )
    .await
    .unwrap();
    let first_signed = (
        first.payload_summary.clone(),
        first.content_hash.clone(),
        first.signature.clone(),
    );
    let second_signed = (
        second.payload_summary.clone(),
        second.content_hash.clone(),
        second.signature.clone(),
    );
    first.tsa_token = Some(issue_token(&dir.0, &first.content_hash, "first"));
    second.tsa_token = Some(issue_token(&dir.0, &second.content_hash, "second"));
    assert_eq!(
        first_signed,
        (
            first.payload_summary.clone(),
            first.content_hash.clone(),
            first.signature.clone()
        )
    );
    assert_eq!(
        second_signed,
        (
            second.payload_summary.clone(),
            second.content_hash.clone(),
            second.signature.clone()
        )
    );
    let full_path = write_chain(
        &dir.0,
        "fully-qualified.json",
        &[first.clone(), second.clone()],
    );
    let full = verify_binary(&full_path, Some(&dir.0.join("ca.crt")));
    let stdout = bounded(&full.stdout);
    println!("{stdout}");
    assert!(full.status.success(), "{}", bounded(&full.stderr));
    assert!(stdout.contains("TIMESTAMP:  RFC 3161 SIGNATURE OK (2/2 links)"));
    assert!(stdout.contains("VERDICT:    FULLY QUALIFIED"));

    let partial_path = write_chain(
        &dir.0,
        "partial.json",
        &[
            first.clone(),
            ExecutionReceipt {
                tsa_token: None,
                ..second.clone()
            },
        ],
    );
    let partial = verify_binary(&partial_path, Some(&dir.0.join("ca.crt")));
    assert!(partial.status.success());
    let partial_stdout = bounded(&partial.stdout);
    assert!(partial_stdout.contains("TIMESTAMP:  RFC 3161 SIGNATURE OK PARTIAL (1/2 links)"));
    assert!(partial_stdout.contains("VERDICT:    SIGNED, NOT TIMESTAMPED"));
    println!("{partial_stdout}");
    assert!(!bounded(&partial.stdout).contains("VERDICT:    FULLY QUALIFIED"));

    let wrong_digest = "11".repeat(32);
    let mut wrong_imprint = first.clone();
    wrong_imprint.tsa_token = Some(issue_token(&dir.0, &wrong_digest, "wrong-imprint"));
    let corrupt = {
        let mut r = first.clone();
        r.tsa_token = Some(STANDARD.encode(b"not DER"));
        r
    };
    for (name, receipt) in [("wrong-imprint", wrong_imprint), ("corrupt", corrupt)] {
        let path = write_chain(&dir.0, &format!("{name}.json"), &[receipt]);
        assert_binary_rejects(&path, &dir.0.join("ca.crt"), "FAIL: TSA token verification");
    }
    openssl(
        &dir.0,
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-days",
            "2",
            "-subj",
            "/CN=wrong-ca",
            "-keyout",
            "wrong.key",
            "-out",
            "wrong.crt",
        ],
    );
    assert_binary_rejects(
        &full_path,
        &dir.0.join("wrong.crt"),
        "FAIL: TSA token verification",
    );
    let mut bad_hash = first.clone();
    bad_hash.credits_spent += 1;
    assert_binary_rejects(
        &write_chain(&dir.0, "bad-hash.json", &[bad_hash]),
        &dir.0.join("ca.crt"),
        "FAIL: content_hash mismatch",
    );
    let mut bad_sig = first;
    corrupt_signature(&mut bad_sig);
    assert_binary_rejects(
        &write_chain(&dir.0, "bad-signature.json", &[bad_sig]),
        &dir.0.join("ca.crt"),
        "FAIL: Signature verification failed",
    );
}
