use std::process::{Command, Output};

fn run(binary: &str, args: &[&str]) -> Output {
    Command::new(binary).args(args).output().unwrap()
}

#[test]
fn standalone_help_and_version_are_available() {
    for (binary, help_args, version_args, label) in [
        (
            env!("CARGO_BIN_EXE_reede"),
            &["--help"][..],
            &["--version"][..],
            "reede",
        ),
        (
            env!("CARGO_BIN_EXE_verify"),
            &["-h"][..],
            &["-V"][..],
            "verify",
        ),
    ] {
        let help = run(binary, help_args);
        assert!(help.status.success());
        let help_text = String::from_utf8_lossy(&help.stdout);
        assert!(help_text.contains("--strict"));
        assert!(help_text.contains("--json"));
        assert!(help_text.contains("--expected-head"));
        assert!(help_text.contains("--expected-tenant"));
        assert!(help_text.contains("--expected-count"));
        assert!(help_text.contains("--require-genesis"));

        let version = run(binary, version_args);
        assert!(version.status.success());
        assert_eq!(
            String::from_utf8_lossy(&version.stdout).trim(),
            format!("{label} {}", env!("CARGO_PKG_VERSION"))
        );
    }
}

#[test]
fn receipt_verify_has_its_own_help_and_version() {
    let binary = env!("CARGO_BIN_EXE_reede");
    let help = run(binary, &["receipt", "verify", "--help"]);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("--expected-count"));

    let version = run(binary, &["receipt", "verify", "-V"]);
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8_lossy(&version.stdout).trim(),
        format!("reede receipt verify {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn help_value_after_chain_is_treated_as_a_filename() {
    for (binary, args) in [
        (env!("CARGO_BIN_EXE_verify"), &["--chain", "--help"][..]),
        (
            env!("CARGO_BIN_EXE_reede"),
            &["receipt", "verify", "--chain", "--help"][..],
        ),
    ] {
        let output = run(binary, args);
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stdout).contains("Usage:"));
        assert!(String::from_utf8_lossy(&output.stderr).contains("--help"));
    }
}
