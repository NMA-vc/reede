"""Offline negative fixtures for the full-profile installed HTTP validator."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

SCRIPT = Path(__file__).with_name("validate-installed-http.py")
spec = importlib.util.spec_from_file_location("installed_http_validator", SCRIPT)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class ReportFixtures(unittest.TestCase):
    def python_success(self):
        lines = [f"{case} (test_client.Fixture.{case}) ... ok" for case in sorted(validator.PYTHON_CASES)]
        return "\n".join(lines) + "\nRan 15 tests in 0.001s\n\nOK\n"

    def node_success(self):
        lines = [f"ok {index} - {case}" for index, case in enumerate(sorted(validator.NODE_CASES), 1)]
        return "\n".join(lines) + "\n# tests 6\n# pass 6\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n"

    def test_full_named_python_and_node_reports_pass(self):
        self.assertEqual(set(validator.python_full_report(self.python_success())), validator.PYTHON_CASES)
        self.assertEqual(set(validator.node_full_report(self.node_success())), validator.NODE_CASES)

    def test_missing_and_skipped_named_cases_fail_closed(self):
        python_missing = self.python_success().replace(next(iter(validator.PYTHON_CASES)), "missing_case", 1)
        with self.assertRaises(ValueError):
            validator.python_full_report(python_missing)
        with self.assertRaises(ValueError):
            validator.python_full_report(self.python_success().replace("Ran 15 tests", "Ran 14 tests").replace("OK\n", "OK (skipped=1)\n"))
        node_missing = self.node_success().replace(next(iter(validator.NODE_CASES)), "not-the-required-case", 1)
        with self.assertRaises(ValueError):
            validator.node_full_report(node_missing)
        with self.assertRaises(ValueError):
            validator.node_full_report(self.node_success().replace("# skipped 0", "# skipped 1").replace("# pass 6", "# pass 5"))

    def test_nonzero_and_timeout_commands_cannot_yield_success_evidence(self):
        class Failed:
            def __init__(self, error):
                self.error = error
            def run(self, *_args, **_kwargs):
                raise self.error
        for error in (RuntimeError("nonzero"), TimeoutError("deadline")):
            with self.subTest(error=type(error).__name__), self.assertRaises(type(error)):
                validator.run_report(Failed(error), ["fixture"], Path("."), extra_env={}, parser=validator.node_full_report)


class IdentityAndProfileFixtures(unittest.TestCase):
    def full_manifest(self):
        return {
            "profile": "full", "version": "0.1.0", "source_dirty": False,
            "build_scope": {
                "native_binaries": ["verify", "reede"],
                "cargo_flags": ["--features", "cli,ingest", "--bins"],
                "dependency_selection": {"root_features": ["cli", "default", "ingest", "sdk-conformance"], "target": None},
            },
            "artifacts": [{"path": name} for name in (
                "linux-x86_64/verify", "linux-x86_64/reede", "reede_client-0.1.0-py3-none-any.whl",
                "reede-client-0.1.0.tgz", "reede-0.1.0-source.tar.gz", "reede_client-0.1.0.tar.gz")],
        }

    def test_offline_profile_and_wrong_artifact_identity_rejected(self):
        manifest = self.full_manifest()
        manifest["profile"] = "offline-verification"
        with tempfile.TemporaryDirectory() as tmp, self.assertRaisesRegex(ValueError, "full profile required"):
            validator.require_full_profile(Path(tmp), manifest)
        manifest = self.full_manifest()
        manifest["build_scope"]["native_binaries"] = ["verify"]
        with tempfile.TemporaryDirectory() as tmp, self.assertRaisesRegex(ValueError, "both verify and reede"):
            validator.require_full_profile(Path(tmp), manifest)

    def test_source_tree_python_and_node_fallbacks_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            venv = root / "venv"
            source_module = root / "source/sdk/python/reede_client/__init__.py"
            source_module.parent.mkdir(parents=True)
            source_module.touch()
            with self.assertRaisesRegex(ValueError, "freshly installed wheel"):
                validator.installed_python_path(str(source_module), venv)
            prefix = root / "node"
            installed = prefix / "node_modules/@reede/client/src/index.js"
            installed.parent.mkdir(parents=True)
            installed.touch()
            source_node = root / "source/sdk/typescript/src/index.js"
            source_node.parent.mkdir(parents=True)
            source_node.touch()
            with self.assertRaisesRegex(ValueError, "freshly installed npm package"):
                validator.installed_node_path(source_node, prefix)
            self.assertEqual(validator.installed_node_path(installed, prefix), installed.resolve())


class FinalizationFixtures(unittest.TestCase):
    def report(self):
        return {"status": "passed", "full_validation": "not_run", "failures": [],
                "stages": {"unchanged_after": "passed", "cleanup": "not_run"}}

    def test_cleanup_failure_cannot_report_full_validation_success(self):
        report = self.report()
        with patch.object(validator.shutil, "rmtree", side_effect=OSError("injected cleanup failure")):
            validator.cleanup_temporary(SimpleNamespace(temporary=Path("fixture")), report)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["stages"]["cleanup"], "failed")
        self.assertEqual(report["full_validation"], "failed")

    def test_integrity_failure_stays_failed_after_successful_cleanup(self):
        report = self.report()
        report["status"] = "failed"
        report["stages"]["unchanged_after"] = "failed"
        with tempfile.TemporaryDirectory() as tmp:
            temporary = Path(tmp) / "owned"
            temporary.mkdir()
            validator.cleanup_temporary(SimpleNamespace(temporary=temporary), report)
            self.assertFalse(temporary.exists())
        self.assertEqual(report["full_validation"], "failed")

    def test_partial_runner_initialization_removes_owned_temporary_files(self):
        def fail_after_temporary_creation(output):
            temporary = output / "tmp"
            temporary.mkdir()
            (temporary / "user.npmrc").write_text("")
            raise OSError("injected constructor write failure")
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "candidate"
            candidate.mkdir()
            output = Path(tmp) / "output"
            with patch.object(validator.base, "Runner", side_effect=fail_after_temporary_creation):
                with self.assertRaisesRegex(OSError, "constructor write failure"):
                    validator.validate(candidate, output)
            self.assertFalse((output / "tmp").exists())


if __name__ == "__main__":
    unittest.main()
