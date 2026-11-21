//! Cargo's actual semver implementation; unsupported prereleases fail explicitly.
use semver::{Version, VersionReq};
use std::io::{self, BufRead};
const TOOL: &str = "reede-cargo-semver-query-v1 semver=1.0.28";
fn evaluate(version: &str, requirement: &str) -> Result<bool, &'static str> {
    let version = Version::parse(version).map_err(|_| "invalid_version")?;
    let requirement = VersionReq::parse(requirement).map_err(|_| "unsupported_requirement")?;
    // RustSec's OSV conversion has additional prerelease semantics. This narrow
    // checker refuses that scope rather than approximating it with npm/Python.
    if !version.pre.is_empty() {
        return Err("unsupported_prerelease");
    }
    Ok(requirement.matches(&version))
}
fn main() {
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("{TOOL}");
        return;
    }
    for line in io::stdin().lock().lines() {
        let line = line.expect("read query");
        let Some((version, requirement)) = line.split_once('\t') else {
            println!("error\tmalformed_query");
            continue;
        };
        if requirement.contains('\t') {
            println!("error\tmalformed_query");
            continue;
        }
        match evaluate(version, requirement) {
            Ok(result) => println!("ok\t{result}"),
            Err(error) => println!("error\t{error}"),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_stable_boundaries_and_conjunctions() {
        assert_eq!(evaluate("0.23.45", ">= 0.23.46"), Ok(false));
        assert_eq!(evaluate("0.23.46", ">= 0.23.46"), Ok(true));
        assert_eq!(evaluate("0.21.12", ">= 0.23.46"), Ok(false));
        assert_eq!(evaluate("1.2.3+vendor.1", ">=1.2.3, <1.3"), Ok(true));
    }
    #[test]
    fn cargo_caret_zero_minor_and_partial_comparator_semantics() {
        assert_eq!(evaluate("0.2.9", "0.2"), Ok(true));
        assert_eq!(evaluate("0.3.0", "0.2"), Ok(false));
        assert_eq!(evaluate("0.0.4", "^0.0.3"), Ok(false));
        assert_eq!(evaluate("1.2.99", ">1.2"), Ok(false));
        assert_eq!(evaluate("1.3.0", ">1.2"), Ok(true));
    }
    #[test]
    fn prereleases_and_non_cargo_requirements_are_not_approximated() {
        assert_eq!(
            evaluate("1.3.0-beta.1", ">=1.2"),
            Err("unsupported_prerelease")
        );
        assert_eq!(evaluate("1.3.0", ">=1.3.0-beta.1"), Ok(true));
        assert_eq!(
            evaluate("0.103.15", ">=0.103.12, <0.104.0-alpha.1"),
            Ok(true)
        );
        assert_eq!(
            evaluate("1.3.0", ">=1.2 || <1.0"),
            Err("unsupported_requirement")
        );
        assert_eq!(evaluate("v1.3.0", ">=1.2"), Err("invalid_version"));
    }
}
