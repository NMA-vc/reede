#!/usr/bin/env python3
"""Validate the full-profile Reede candidate through its installed HTTP SDKs."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sys
import tempfile
import tomllib

if sys.version_info < (3, 12):
    raise SystemExit("installed full-profile validation requires Python 3.12+")

ROOT = Path(__file__).resolve().parents[1]
BASE_PATH = ROOT / "scripts/validate-installed-release.py"
_spec = importlib.util.spec_from_file_location("reede_installed_base", BASE_PATH)
if _spec is None or _spec.loader is None:
    raise SystemExit("could not load bounded installed-release helpers")
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)

PYTHON_CASES = {
    "test_routes_and_authorization_without_tenant_override",
    "test_reads_retry_but_writes_and_redirects_do_not",
    "test_rpc_operations_match_implemented_contract",
    "test_configuration_rejects_unsafe_destinations_and_path_injection",
    "test_token_callback_inherits_caller_contextvars",
    "test_slow_token_callback_cannot_dispatch_after_deadline",
    "test_total_deadline_and_bounded_worker_cleanup",
    "test_shared_vectors_and_tamper_against_shipping_core",
    "test_large_stderr_is_discarded_without_deadlock_or_diagnostics_leak",
    "test_stdout_flood_is_refused_at_the_cap",
    "test_trickle_stdout_cannot_extend_the_deadline",
    "test_closed_stdout_does_not_disable_process_deadline",
    "test_invalid_process_arguments_do_not_consume_verifier_capacity",
    "test_inherited_stdout_readers_keep_capacity_until_descendants_close",
    "test_output_at_the_exact_limit_is_allowed",
}
NODE_CASES = {
    "lifecycle routes use bearer authority and reject redirects",
    "transient reads retry; mutations do not and errors omit response content",
    "host RPC matches implemented operations and preserves invocation identity",
    "large integer responses preserve source decimals",
    "unsafe URLs and path injection fail before network access",
    "shared Rust offline verifier accepts vector and rejects tamper",
}


def python_full_report(report: str) -> list[str]:
    count_lines = re.findall(r"^Ran (\d+) tests? in .+$", report, re.M)
    cases = re.findall(r"^(test_\w+) \([^)]+\) \.\.\. ok$", report, re.M)
    if (len(count_lines) != 1 or int(count_lines[0]) != len(PYTHON_CASES)
            or len(cases) != len(PYTHON_CASES) or len(cases) != len(set(cases))
            or set(cases) != PYTHON_CASES or report.rstrip().splitlines()[-1:] != ["OK"]
            or re.search(r"skipped|unexpected success|failures=|errors=", report, re.I)):
        raise ValueError("Python full-profile report is incomplete or has skips/failures")
    return cases


def node_full_report(report: str) -> list[str]:
    counts = {}
    for key in ("tests", "pass", "fail", "cancelled", "skipped", "todo"):
        values = re.findall(rf"^# {key} (\d+)$", report, re.M)
        if len(values) != 1:
            raise ValueError("Node TAP summary is missing or ambiguous")
        counts[key] = int(values[0])
    cases = re.findall(r"^ok \d+ - (.+)$", report, re.M)
    if (counts != {"tests": 6, "pass": 6, "fail": 0, "cancelled": 0, "skipped": 0, "todo": 0}
            or len(cases) != len(NODE_CASES) or len(cases) != len(set(cases))
            or set(cases) != NODE_CASES):
        raise ValueError("Node full-profile report is incomplete or has skips/failures")
    return cases


def require_full_profile(candidate: Path, manifest: dict) -> dict[str, Path]:
    if manifest.get("profile") != "full":
        raise ValueError("full profile required; offline-verification candidates are unsupported")
    if manifest.get("source_dirty") is not False:
        raise ValueError("full candidate must declare a clean source tree")
    scope = manifest.get("build_scope")
    if not isinstance(scope, dict) or scope.get("native_binaries") != ["verify", "reede"]:
        raise ValueError("full profile must declare both verify and reede native binaries")
    if scope.get("cargo_flags") != ["--features", "cli,ingest", "--bins"]:
        raise ValueError("candidate build flags do not match the supported full profile")
    selection = scope.get("dependency_selection")
    if (not isinstance(selection, dict)
            or selection.get("root_features") != ["cli", "default", "ingest", "sdk-conformance"]
            or selection.get("target") is not None):
        raise ValueError("candidate feature/target selection is not the supported full profile")
    version = manifest.get("version")
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("unsupported candidate version")
    paths = {
        "verify": candidate / "linux-x86_64/verify",
        "reede": candidate / "linux-x86_64/reede",
        "wheel": candidate / f"reede_client-{version}-py3-none-any.whl",
        "npm": candidate / f"reede-client-{version}.tgz",
        "source": candidate / f"reede-{version}-source.tar.gz",
        "sdist": candidate / f"reede_client-{version}.tar.gz",
    }
    declared = {item.get("path") for item in manifest.get("artifacts", []) if isinstance(item, dict)}
    if not {p.relative_to(candidate).as_posix() for p in paths.values()} <= declared:
        raise ValueError("full candidate inventory is missing a required profile artifact")
    for name in ("verify", "reede"):
        if not paths[name].is_file() or not os.access(paths[name], os.X_OK):
            raise ValueError(f"full candidate {name} executable is missing or not executable")
    for name in ("wheel", "npm", "source", "sdist"):
        if not paths[name].is_file():
            raise ValueError(f"full candidate {name} artifact is missing")
    wheels = list(candidate.glob(f"reede_client-{version}-*.whl"))
    if wheels != [paths["wheel"]]:
        raise ValueError("candidate must contain exactly the supported Python wheel")
    return paths


def installed_python_path(path: str, venv: Path) -> Path:
    module = Path(path).resolve(strict=True)
    if not module.is_file() or not module.is_relative_to(venv.resolve()):
        raise ValueError("Python test import did not select the freshly installed wheel")
    return module


def installed_node_path(path: Path, prefix: Path) -> Path:
    expected = (prefix / "node_modules/@reede/client/src/index.js").resolve(strict=True)
    observed = path.resolve(strict=True)
    if observed != expected or not observed.is_file():
        raise ValueError("Node conformance would not use the freshly installed npm package")
    return observed


def run_report(runner, argv, cwd: Path, *, extra_env: dict, parser):
    """A failed, timed-out, or incomplete command can never produce case evidence."""
    stdout, stderr = runner.run(argv, cwd, extra_env=extra_env)
    return parser(stdout + "\n" + stderr)


def candidate_snapshot(candidate: Path, manifest: dict) -> dict:
    entries = {}
    for item in manifest["artifacts"]:
        name = item["path"]
        path = candidate / name
        entries[name] = {"sha256": base.sha(path), "size": path.stat().st_size}
    return {"release_json_sha256": base.sha(candidate / "release.json"),
            "sums_sha256": base.sha(candidate / "SHA256SUMS"), "artifacts": entries}


def cleanup_temporary(runner, report: dict) -> None:
    try:
        shutil.rmtree(runner.temporary)
        report["stages"]["cleanup"] = "passed"
    except Exception as error:
        report["stages"]["cleanup"] = "failed"
        report["status"] = "failed"
        report["failures"].append(f"temporary cleanup: {type(error).__name__}: {error}")
    report["full_validation"] = (
        "passed" if report["status"] == "passed"
        and all(value == "passed" for value in report["stages"].values()) else "failed"
    )


def validate(candidate: Path, output: Path) -> dict:
    candidate = candidate.resolve(strict=True)
    output = output.resolve()
    if candidate == output or candidate in output.parents or output.exists():
        raise ValueError("output must be a new directory outside the immutable candidate")
    output.mkdir(parents=True, mode=0o700)
    try:
        runner = base.Runner(output)
    except BaseException:
        # Runner may have created tmp before a later initialization write fails.
        temporary = output / "tmp"
        if temporary.exists():
            shutil.rmtree(temporary)
        raise
    report = {
        "schema": "reede-installed-http-validation-v1", "candidate": str(candidate),
        "status": "failed", "publication_ready": False, "authenticity": "not_established",
        "http_fixtures": "not_run", "full_validation": "not_run",
        "stages": {key: "not_run" for key in ("integrity", "profile", "extract", "install",
                    "identity", "python_http_conformance", "node_http_conformance", "unchanged_after", "cleanup")},
        "failures": [], "commands": runner.commands,
        "runtime": {"python": sys.version, "platform": sys.platform},
        "named_case_requirements": {"python": sorted(PYTHON_CASES), "node": sorted(NODE_CASES)},
        "http_scope": "Candidate test HTTP fixtures against installed SDKs and the native verifier; not a native HTTP CLI server end-to-end test.",
    }
    active_stage = "integrity"
    try:
        if os.name != "posix" or platform.system() != "Linux" or platform.machine() != "x86_64":
            raise ValueError("this validator supports Linux x86_64 native candidates on POSIX only")
        for tool in ("node", "npm"):
            if not shutil.which(tool):
                raise ValueError(f"missing required runtime on PATH: {tool}")

        stdout, _ = runner.run([sys.executable, ROOT / "scripts/verify-release.py", candidate], runner.temporary)
        integrity_before = json.loads(stdout)
        if integrity_before.get("integrity") != "verified":
            raise ValueError("candidate integrity was not verified")
        manifest = json.loads((candidate / "release.json").read_text())
        before = candidate_snapshot(candidate, manifest)
        report["integrity"] = integrity_before
        report["candidate_snapshot_before"] = before
        report["stages"]["integrity"] = "passed"

        active_stage = "profile"
        paths = require_full_profile(candidate, manifest)
        report["candidate_profile"] = manifest["profile"]
        report["source_commit"] = manifest.get("source_commit")
        report["native_executables"] = {
            name: {"path": str(path), "sha256": base.sha(path), "size": path.stat().st_size}
            for name, path in (("verify", paths["verify"]), ("reede", paths["reede"]))
        }
        report["stages"]["profile"] = "passed"

        active_stage = "extract"
        work = runner.temporary / "work"
        work.mkdir(mode=0o700)
        base.extract(paths["source"], work / "source")
        version = manifest["version"]
        source = work / "source" / f"reede-{version}"
        base.extract(paths["sdist"], work / "sdist")
        sdist = work / "sdist" / f"reede_client-{version}"
        python_project = tomllib.loads((source / "sdk/python/pyproject.toml").read_text())["project"]
        node_project = json.loads((source / "sdk/typescript/package.json").read_text())
        if (python_project.get("name") != "reede-client" or python_project.get("version") != version
                or node_project.get("name") != "@reede/client" or node_project.get("version") != version):
            raise ValueError("SDK source identities/version do not match the full candidate")
        report["source_archive_sdk_identity"] = {"python": python_project["name"], "node": node_project["name"], "version": version}
        report["stages"]["extract"] = "passed"

        active_stage = "install"
        py = work / "python"
        runner.run([sys.executable, "-m", "venv", py], work)
        python = py / "bin/python"
        runner.run([python, "-m", "pip", "--isolated", "install", "--no-index", "--no-deps", "--no-cache-dir", paths["wheel"]], work)
        node_prefix = work / "node"
        runner.run(["npm", "install", "--prefix", node_prefix, "--cache", work / "npm-cache",
                    "--offline", "--ignore-scripts", "--no-audit", "--no-fund", paths["npm"]], work)
        report["stages"]["install"] = "passed"

        active_stage = "identity"
        py_json, _ = runner.run([python, "-c",
            "import json,reede_client,importlib.metadata as m;d=m.distribution('reede-client');"
            "print(json.dumps({'module':reede_client.__file__,'names':d.metadata.get_all('Name'),"
            "'versions':d.metadata.get_all('Version'),'distribution_module':str(d.locate_file('reede_client/__init__.py'))}))"], work)
        py_identity = json.loads(py_json)
        base.python_identity(py_identity, version)
        py_module = installed_python_path(py_identity["module"], py)
        if Path(py_identity["distribution_module"]).resolve(strict=True) != py_module:
            raise ValueError("installed distribution metadata does not identify imported Python SDK")
        node_package = node_prefix / "node_modules/@reede/client"
        node_meta = json.loads((node_package / "package.json").read_text())
        if node_meta.get("name") != "@reede/client" or node_meta.get("version") != version:
            raise ValueError("installed npm package metadata disagrees with candidate")
        node_module = installed_node_path(node_package / "src/index.js", node_prefix)
        report["installed_python_module"] = str(py_module)
        report["installed_python_module_sha256"] = base.sha(py_module)
        report["installed_node_module"] = str(node_module)
        report["installed_node_module_sha256"] = base.sha(node_module)
        report["installed_source_files_verified"] = base.check_files(source, sdist, py_module.parent.parent, node_package)
        node_version, _ = runner.run(["node", "--test-isolation=none", "--eval",
            "if(Number(process.versions.node.split('.')[0])<22)process.exit(1);console.log(process.versions.node)"], work)
        report["runtime"]["node"] = node_version.strip()
        report["runtime"]["npm"] = runner.run(["npm", "--version"], work)[0].strip()
        report["stages"]["identity"] = "passed"

        active_stage = "python_http_conformance"
        report["python_cases"] = run_report(runner,
            [python, "-m", "unittest", "discover", "-s", "sdk/python/tests", "-v"], source,
            extra_env={"PYTHONPATH": str(py_module.parent.parent), "REEDE_VERIFY_BIN": str(paths["verify"])},
            parser=python_full_report)
        report["stages"]["python_http_conformance"] = "passed"

        active_stage = "node_http_conformance"
        report["node_cases"] = run_report(runner,
            ["node", "--test", "--test-isolation=none", "--test-reporter=tap",
             source / "sdk/typescript/test/client.test.js"], work,
            extra_env={"REEDE_VERIFY_BIN": str(paths["verify"]),
                       "REEDE_SDK_NODE_MODULE": node_module.as_uri()}, parser=node_full_report)
        report["stages"]["node_http_conformance"] = "passed"
        report["http_fixtures"] = "passed"

        active_stage = "unchanged_after"
        stdout, _ = runner.run([sys.executable, ROOT / "scripts/verify-release.py", candidate], work)
        integrity_after = json.loads(stdout)
        after_manifest = json.loads((candidate / "release.json").read_text())
        after = candidate_snapshot(candidate, after_manifest)
        if integrity_after.get("integrity") != "verified" or after != before:
            raise ValueError("candidate changed during installed validation")
        report["integrity_after"] = integrity_after
        report["candidate_snapshot_after"] = after
        report["stages"]["unchanged_after"] = "passed"
        report["status"] = "passed"
    except Exception as error:
        report["stages"][active_stage] = "failed"
        report["failures"].append(f"{type(error).__name__}: {error}")
        for key, value in report["stages"].items():
            if value == "not_run":
                report["stages"][key] = "skipped_due_to_prior_failure"
    finally:
        if "candidate_snapshot_before" in report and report["stages"]["unchanged_after"] != "passed":
            try:
                stdout, _ = runner.run([sys.executable, ROOT / "scripts/verify-release.py", candidate], runner.temporary)
                integrity_after = json.loads(stdout)
                manifest_after = json.loads((candidate / "release.json").read_text())
                after = candidate_snapshot(candidate, manifest_after)
                if integrity_after.get("integrity") != "verified" or after != report["candidate_snapshot_before"]:
                    raise ValueError("candidate changed during installed validation")
                report["integrity_after"] = integrity_after
                report["candidate_snapshot_after"] = after
                report["stages"]["unchanged_after"] = "passed"
            except Exception as error:
                report["stages"]["unchanged_after"] = "failed"
                report["failures"].append(f"post-validation integrity: {type(error).__name__}: {error}")
                report["status"] = "failed"
        cleanup_temporary(runner, report)
        (output / "installed-http-validation.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path, help="explicit trusted local full-profile candidate")
    parser.add_argument("--output", type=Path, required=True, help="new evidence directory outside candidate")
    args = parser.parse_args()
    try:
        report = validate(args.candidate, args.output)
    except Exception as error:
        parser.exit(1, f"installed full-profile validation failed: {error}\n")
    print(json.dumps({"status": report["status"], "report": str(args.output / "installed-http-validation.json"),
                      "publication_ready": False, "failures": report["failures"]}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
