//! Opt-in source SDK transport and shipping-verifier conformance. No shell or package install.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output};

const PYTHON_CASES: &[&str] = &[
    "test_configuration_rejects_unsafe_destinations_and_path_injection",
    "test_reads_retry_but_writes_and_redirects_do_not",
    "test_routes_and_authorization_without_tenant_override",
    "test_rpc_operations_match_implemented_contract",
    "test_shared_vectors_and_tamper_against_shipping_core",
    "test_closed_stdout_does_not_disable_process_deadline",
    "test_inherited_stdout_readers_keep_capacity_until_descendants_close",
    "test_invalid_process_arguments_do_not_consume_verifier_capacity",
    "test_large_stderr_is_discarded_without_deadlock_or_diagnostics_leak",
    "test_output_at_the_exact_limit_is_allowed",
    "test_stdout_flood_is_refused_at_the_cap",
    "test_trickle_stdout_cannot_extend_the_deadline",
];
const NODE_CASES: &[&str] = &[
    "lifecycle routes use bearer authority and reject redirects",
    "transient reads retry; mutations do not and errors omit response content",
    "host RPC matches implemented operations and preserves invocation identity",
    "large integer responses preserve source decimals",
    "unsafe URLs and path injection fail before network access",
    "shared Rust offline verifier accepts vector and rejects tamper",
];

fn python_report_complete(report: &str) -> bool {
    let count = report.lines().find_map(|line| {
        line.strip_prefix("Ran ")?
            .split_whitespace()
            .next()?
            .parse::<usize>()
            .ok()
    });
    count.is_some_and(|count| count >= PYTHON_CASES.len())
        && report.lines().any(|line| line == "OK")
        && !report.contains("skipped=")
        && PYTHON_CASES.iter().all(|name| {
            report.lines().any(|line| {
                line.starts_with(name)
                    && line[name.len()..].starts_with(" (")
                    && line.ends_with(" ... ok")
            })
        })
}

fn tap_count(report: &str, name: &str) -> Option<usize> {
    report.lines().find_map(|line| {
        line.strip_prefix("# ")?
            .strip_prefix(name)?
            .strip_prefix(' ')?
            .parse()
            .ok()
    })
}

fn node_report_complete(report: &str) -> bool {
    tap_count(report, "tests").is_some_and(|count| count >= NODE_CASES.len())
        && tap_count(report, "pass") == tap_count(report, "tests")
        && ["fail", "cancelled", "skipped", "todo"]
            .iter()
            .all(|name| tap_count(report, name) == Some(0))
        && NODE_CASES.iter().all(|name| {
            report.lines().any(|line| {
                line.starts_with("ok ")
                    && line
                        .split_once(" - ")
                        .is_some_and(|(_, actual)| actual == *name)
            })
        })
}

fn require_supported_platform() {
    const {
        assert!(
            cfg!(unix),
            "sdk-conformance requires a POSIX host for subprocess resource tests; default Rust tests do not require it"
        )
    };
    assert!(
        Path::new(env!("CARGO_BIN_EXE_verify")).is_file(),
        "sdk-conformance requires Cargo's matching verify binary"
    );
}

fn execute(command: &mut Command, requirement: &str) -> Output {
    command.output().unwrap_or_else(|_| {
        panic!(
            "sdk-conformance could not launch {requirement}; install the supported runtime on PATH"
        )
    })
}

fn emit_report(output: &Output) {
    // Direct writes make the actual named language cases visible in ordinary Cargo CI,
    // whose libtest capture otherwise hides successful child reports.
    let _ = std::io::stdout().lock().write_all(&output.stdout);
    let _ = std::io::stderr().lock().write_all(&output.stderr);
}

#[test]
fn python_sdk_http_and_matching_rust_verifier() {
    require_supported_platform();
    let version = execute(
        Command::new("python3").args([
            "-c",
            "import sys;sys.exit(0 if sys.version_info >= (3,10) else 1)",
        ]),
        "Python 3.10+ (python3)",
    );
    assert!(
        version.status.success(),
        "sdk-conformance requires Python 3.10+"
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = execute(
        Command::new("python3")
            .current_dir(root)
            .args(["-m", "unittest", "discover", "-s", "sdk/python/tests", "-v"])
            .env("PYTHONPATH", root.join("sdk/python"))
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env("NO_COLOR", "1")
            .env("REEDE_VERIFY_BIN", env!("CARGO_BIN_EXE_verify")),
        "Python 3.10+ (python3)",
    );
    emit_report(&output);
    assert!(
        output.status.success()
            && python_report_complete(&String::from_utf8_lossy(&output.stderr)),
        "Python SDK conformance failed: require successful named HTTP/verifier/resource cases with no skips; loopback socket binds must be allowed"
    );
}

#[test]
fn node_sdk_http_and_matching_rust_verifier() {
    require_supported_platform();
    let version = execute(
        Command::new("node").args([
            "--test-isolation=none",
            "--eval",
            "process.exit(Number(process.versions.node.split('.')[0]) >= 22 ? 0 : 1)",
        ]),
        "Node 22+ supporting --test-isolation=none (recommend Node 24)",
    );
    assert!(
        version.status.success(),
        "sdk-conformance requires Node 22+ supporting --test-isolation=none; use Node 24"
    );
    let output = execute(
        Command::new("node")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args([
                "--test",
                "--test-isolation=none",
                "--test-reporter=tap",
                "sdk/typescript/test/client.test.js",
            ])
            .env_remove("REEDE_SDK_NODE_MODULE")
            .env("REEDE_VERIFY_BIN", env!("CARGO_BIN_EXE_verify")),
        "Node 22+ supporting --test-isolation=none (recommend Node 24)",
    );
    emit_report(&output);
    assert!(
        output.status.success() && node_report_complete(&String::from_utf8_lossy(&output.stdout)),
        "Node SDK conformance failed: require successful named HTTP/verifier cases with no skips; loopback socket binds must be allowed"
    );
}

#[test]
fn report_validation_rejects_empty_skipped_and_file_container_success() {
    assert!(!python_report_complete("Ran 0 tests in 0.001s\n\nOK\n"));
    assert!(!python_report_complete(
        "Ran 12 tests in 0.001s\n\nOK (skipped=1)\n"
    ));
    assert!(!node_report_complete(
        "ok 1 - sdk/typescript/test/client.test.js\n# tests 1\n# pass 1\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n"
    ));
    assert!(!node_report_complete(
        "# tests 0\n# pass 0\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n"
    ));
}

#[test]
fn report_validation_requires_every_named_case_and_clean_summary() {
    let python = format!(
        "{}\nRan 12 tests in 0.001s\n\nOK\n",
        PYTHON_CASES
            .iter()
            .map(|name| format!("{name} (test_client.Cases.{name}) ... ok"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(python_report_complete(&python));
    assert!(!python_report_complete(
        &python.replace(PYTHON_CASES[0], "not_the_required_case")
    ));
    let node = format!(
        "{}\n# tests 6\n# pass 6\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n",
        NODE_CASES
            .iter()
            .enumerate()
            .map(|(index, name)| format!("ok {} - {name}", index + 1))
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(node_report_complete(&node));
    assert!(!node_report_complete(
        &node.replace(NODE_CASES[0], "file-container")
    ));
    assert!(!node_report_complete(
        &node.replace("# skipped 0", "# skipped 1")
    ));
    assert!(!node_report_complete(
        &node.replace("# cancelled 0", "# cancelled 1")
    ));
}
