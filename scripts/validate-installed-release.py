#!/usr/bin/env python3
"""Check installed SDKs in a trusted, immutable Linux offline-verifier candidate."""
from __future__ import annotations

import sys

if sys.version_info < (3, 12):
    raise SystemExit("installed release validation requires Python 3.12+")

import argparse
from contextlib import contextmanager
from email.parser import Parser
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import selectors
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time
import tomllib

ROOT = Path(__file__).resolve().parents[1]
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
MAX_OUTPUT = 1024 * 1024  # Per stream; enforced while a command runs.
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 4 * 1024 * 1024
PYTHON_CASES = {
    "test_shared_vectors_and_tamper_against_shipping_core",
    "test_closed_stdout_does_not_disable_process_deadline",
    "test_inherited_stdout_readers_keep_capacity_until_descendants_close",
    "test_invalid_process_arguments_do_not_consume_verifier_capacity",
    "test_large_stderr_is_discarded_without_deadlock_or_diagnostics_leak",
    "test_output_at_the_exact_limit_is_allowed",
    "test_stdout_flood_is_refused_at_the_cap",
    "test_trickle_stdout_cannot_extend_the_deadline",
}
NODE_CASES = {
    "unsafe URLs and path injection fail before network access",
    "shared Rust offline verifier accepts vector and rejects tamper",
}


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class Runner:
    """Bounded POSIX child groups; retain exact commands and bounded raw logs."""

    def __init__(self, output: Path):
        self.logs = output / "logs"
        self.logs.mkdir()
        self.temporary = output / "tmp"
        self.temporary.mkdir(mode=0o700)
        self.npm_user = self.temporary / "user.npmrc"
        self.npm_global = self.temporary / "global.npmrc"
        self.npm_user.write_text("")
        self.npm_global.write_text("")
        self.commands: list[dict] = []

    def run(self, argv, cwd: Path, *, extra_env=None, timeout=120, limit=MAX_OUTPUT):
        argv = [str(arg) for arg in argv]
        index = len(self.commands) + 1
        stdout_path = self.logs / f"{index:02d}.stdout.log"
        stderr_path = self.logs / f"{index:02d}.stderr.log"
        entry = {"argv": argv, "cwd": str(cwd), "status": "failed",
                 "timeout_seconds": timeout, "output_limit_per_stream": limit,
                 "stdout_log": str(stdout_path), "stderr_log": str(stderr_path)}
        self.commands.append(entry)
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith(("PIP_", "NPM_CONFIG_")) and k not in {
            "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONSAFEPATH",
            "REEDE_VERIFY_BIN", "REEDE_SDK_NODE_MODULE", "NODE_OPTIONS", "NODE_PATH",
            "PYTHONUSERBASE",
        }}
        env.update({"PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
                    "PIP_CONFIG_FILE": os.devnull, "PIP_NO_INDEX": "1",
                    "PIP_DISABLE_PIP_VERSION_CHECK": "1", "npm_config_audit": "false"})
        env.update({"TMPDIR": str(self.temporary), "TMP": str(self.temporary), "TEMP": str(self.temporary),
                    "NPM_CONFIG_USERCONFIG": str(self.npm_user),
                    "NPM_CONFIG_GLOBALCONFIG": str(self.npm_global),
                    "NPM_CONFIG_CACHE": str(self.temporary / "npm-cache"),
                    "NPM_CONFIG_OFFLINE": "true", "NPM_CONFIG_UPDATE_NOTIFIER": "false"})
        env.update(extra_env or {})
        started = time.monotonic()
        deadline = started + timeout
        proc = None
        selector = selectors.DefaultSelector()
        buffers = [bytearray(), bytearray()]
        try:
            proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    start_new_session=True)
            for index, stream in enumerate((proc.stdout, proc.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, index)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("command/output deadline exceeded")
                for key, _ in selector.select(min(remaining, 0.1)):
                    block = os.read(key.fd, 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    buffer = buffers[key.data]
                    available = limit - len(buffer)
                    buffer.extend(block[:available])
                    if len(block) > available:
                        raise ValueError("command output limit exceeded")
            proc.wait(timeout=max(0.001, deadline - time.monotonic()))
            if proc.returncode:
                raise RuntimeError(f"command exited {proc.returncode}; see bounded command logs")
            entry["status"] = "passed"
            return tuple(bytes(buffer).decode("utf-8", "replace") for buffer in buffers)
        except BaseException as error:
            entry["error"] = f"{type(error).__name__}: {error}"
            raise
        finally:
            if proc is not None:
                # Also stop descendants retaining pipes after the direct child exits.
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=2)
                finally:
                    for stream in (proc.stdout, proc.stderr):
                        if stream:
                            stream.close()
                entry["returncode"] = proc.returncode
            selector.close()
            stdout_path.write_bytes(buffers[0])
            stderr_path.write_bytes(buffers[1])
            entry["elapsed_seconds"] = round(time.monotonic() - started, 3)


def python_report(report: str) -> list[str]:
    summaries = re.findall(r"^Ran (\d+) tests? in .+$", report, re.M)
    cases = re.findall(r"^(test_\w+) \([^)]+\) \.\.\. ok$", report, re.M)
    if (len(summaries) != 1 or int(summaries[0]) != len(cases)
            or len(cases) != len(set(cases)) or not PYTHON_CASES.issubset(cases)
            or report.rstrip().splitlines()[-1:] != ["OK"]
            or re.search(r"skipped|unexpected success", report, re.I)):
        raise ValueError("Python report lacks complete successful named cases with zero skips")
    return cases


def node_report(report: str) -> list[str]:
    counts = {}
    for key in ("tests", "pass", "fail", "cancelled", "skipped", "todo"):
        values = re.findall(rf"^# {key} (\d+)$", report, re.M)
        if len(values) != 1:
            raise ValueError("Node TAP summary is missing or ambiguous")
        counts[key] = int(values[0])
    cases = re.findall(r"^ok \d+ - (.+)$", report, re.M)
    if (counts["tests"] != len(cases) or counts["pass"] != len(cases)
            or len(cases) != len(set(cases)) or not NODE_CASES.issubset(cases)
            or any(counts[key] for key in ("fail", "cancelled", "skipped", "todo"))):
        raise ValueError("Node report lacks complete successful named cases with zero skips")
    return cases


class LimitedTarReader:
    """Reject oversized metadata reads/seeks before TarFile allocates them."""

    def __init__(self, stream):
        self.stream = stream

    def read(self, size=-1):
        if size < 0 or size > MAX_MEMBER_BYTES:
            raise ValueError("tar metadata read exceeds limit")
        return self.stream.read(size)

    def tell(self):
        return self.stream.tell()

    def seek(self, offset, whence=0):
        if whence != 0 or not 0 <= offset <= MAX_ARCHIVE_BYTES:
            raise ValueError("tar seek exceeds expanded archive limit")
        return self.stream.seek(offset)


@contextmanager
def bounded_archive(path: Path, scratch: Path):
    # Bound all inflated bytes, including GNU/PAX metadata, before parsing headers.
    with tempfile.TemporaryFile(dir=scratch) as expanded:
        total = 0
        with gzip.open(path, "rb") as compressed:
            while block := compressed.read(min(65536, MAX_ARCHIVE_BYTES + 1 - total)):
                total += len(block)
                if total > MAX_ARCHIVE_BYTES:
                    raise ValueError("expanded archive bytes exceed limit")
                expanded.write(block)
        expanded.seek(0)
        with tarfile.open(fileobj=LimitedTarReader(expanded), mode="r:") as archive:
            yield archive


def archive_members(archive: tarfile.TarFile):
    members, seen, total = [], set(), 0
    for member in archive:
        if len(members) >= 4096:
            raise ValueError("archive member count exceeds limit")
        path = PurePosixPath(member.name)
        normalized = path.as_posix()
        if (path.is_absolute() or ".." in path.parts or "\\" in member.name
                or normalized in seen or not path.parts
                or not (member.isfile() or member.isdir())
                or member.size < 0 or member.size > MAX_MEMBER_BYTES):
            raise ValueError("unsafe, duplicate or oversized archive member")
        seen.add(normalized)
        members.append(member)
        total += member.size
        if total > MAX_ARCHIVE_BYTES:
            raise ValueError("archive expanded size exceeds limit")
    return members


def extract(archive: Path, destination: Path):
    destination.mkdir(mode=0o700)
    with bounded_archive(archive, destination) as bundle:
        members = archive_members(bundle)
        bundle.extractall(destination, members=members, filter="data")


def inventory_key(item):
    name, version = item.get("name"), item.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        raise ValueError("inventory component identity is missing")
    return name, version


def sbom_inventory(document):
    result = {}
    if not isinstance(document.get("components"), list) or not document["components"]:
        raise ValueError("empty or invalid SBOM")
    for item in document["components"]:
        key = inventory_key(item)
        if key in result or item.get("purl") != f"pkg:cargo/{key[0]}@{key[1]}":
            raise ValueError("duplicate or unsupported SBOM component identity")
        hashes = [h["content"] for h in item.get("hashes", []) if h.get("alg") == "SHA-256"]
        if len(hashes) > 1 or any(not re.fullmatch(r"[a-f0-9]{64}", h) for h in hashes):
            raise ValueError("invalid or duplicate SBOM checksum")
        result[key] = hashes[0] if hashes else None
    return result


def check_inventories(candidate: Path, source: Path, manifest: dict):
    root_identity = ("reede", manifest["version"])
    package = tomllib.loads((source / "Cargo.toml").read_text())["package"]
    if inventory_key(package) != root_identity:
        raise ValueError("source Rust package identity/version disagrees with candidate")
    lock = tomllib.loads((source / "Cargo.lock").read_text())
    locked, sources = {}, {}
    for item in lock["package"]:
        key = inventory_key(item)
        if key in locked or item.get("source") not in (None, CRATES_IO):
            raise ValueError("duplicate identity or unsupported source in source lock")
        checksum = item.get("checksum")
        if item.get("source") and (not isinstance(checksum, str) or not re.fullmatch(r"[a-f0-9]{64}", checksum)):
            raise ValueError("registry source lock checksum missing")
        locked[key], sources[key] = checksum, item.get("source")
    source_sbom = json.loads((candidate / "sbom.cdx.json").read_text())
    build_sbom = json.loads((candidate / "build-dependencies.cdx.json").read_text())
    source_ids, build_ids = sbom_inventory(source_sbom), sbom_inventory(build_sbom)
    if (root_identity not in build_ids or sources.get(root_identity, "missing") is not None
            or [key for key, origin in sources.items() if origin is None] != [root_identity]):
        raise ValueError("selected build must contain the local Reede source root")
    if source_ids != locked or any(key not in locked or locked[key] != digest for key, digest in build_ids.items()):
        raise ValueError("source/build SBOM identity or checksum disagrees with source lock")
    license_doc = json.loads((candidate / "license-evidence.json").read_text())
    license_ids, expected = set(), {}
    for component in license_doc["components"]:
        key = inventory_key(component)
        if key in license_ids or key not in sources or component.get("source") != sources[key]:
            raise ValueError("license inventory identity/source mismatch")
        license_ids.add(key)
        for notice in component["texts"]:
            path, digest = notice["archive_path"], notice["sha256"]
            if path in expected or not re.fullmatch(r"[a-f0-9]{64}", digest):
                raise ValueError("duplicate notice path or invalid notice checksum")
            expected[path] = digest
    if license_ids != set(build_ids) or license_doc["component_count"] != len(license_ids):
        raise ValueError("selected-build and license inventory disagree")
    selection = manifest["build_scope"]["dependency_selection"]
    properties = {item["name"]: item["value"] for item in build_sbom["metadata"]["properties"]}
    if (license_doc.get("selection") != selection
            or json.loads(properties["cargo:selection"]) != selection
            or selection.get("dependency_scope") != "selected-build"
            or selection.get("root_features") != []
            or selection.get("target") != "x86_64-unknown-linux-gnu"
            or selection.get("development_dependencies_included") is not False
            or selection.get("exact_linked_binary_inventory") is not False):
        raise ValueError("selected-build scope disagrees across candidate evidence")
    actual = {}
    with bounded_archive(candidate / "THIRD_PARTY_LICENSES.tar.gz", source.parent) as bundle:
        for member in archive_members(bundle):
            if not member.isfile():
                continue
            with bundle.extractfile(member) as stream:
                actual[member.name] = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != expected or license_doc["license_text_count"] != len(actual):
        raise ValueError("notice archive inventory or checksum mismatch")
    return {"source_lock_components": len(locked), "selected_build_components": len(build_ids),
            "license_components": len(license_ids), "notice_files_verified": len(actual),
            "license_collection_review_items": sum(bool(c["review_items"]) for c in license_doc["components"]),
            "selection": selection, "source_and_build_lock_match": True,
            "resolved_dependency_closure": "not_independently_recomputed"}


def check_files(source: Path, sdist: Path, installed_python: Path, installed_node: Path):
    pairs = []
    for name in ("reede_client/__init__.py", "reede_client/py.typed"):
        pairs.append((source / "sdk/python" / name, installed_python / name))
        pairs.append((source / "sdk/python" / name, sdist / name))
    for name in ("pyproject.toml", "README.md"):
        pairs.append((source / "sdk/python" / name, sdist / name))
    for name in ("src/index.js", "src/index.d.ts", "package.json", "README.md"):
        pairs.append((source / "sdk/typescript" / name, installed_node / name))
    for original, packaged in pairs:
        if sha(original) != sha(packaged):
            raise ValueError(f"installed/sdist source mismatch: {packaged.name}")
    return len(pairs)


def python_identity(identity: dict, version: str):
    names, versions = identity.get("names"), identity.get("versions")
    if (not isinstance(names, list) or len(names) != 1 or not isinstance(names[0], str)
            or re.sub(r"[-_.]+", "-", names[0]).lower() != "reede-client"
            or versions != [version]):
        raise ValueError("Python distribution metadata disagrees with source/candidate")
    return {"name": names[0], "version": versions[0]}


def validate(candidate: Path, output: Path):
    candidate, output = candidate.resolve(strict=True), output.resolve()
    if candidate == output or candidate in output.parents:
        raise ValueError("output must be outside immutable candidate")
    if output.exists():
        raise ValueError("output directory must not already exist")
    output.mkdir(parents=True, mode=0o700)
    work = output / "work"
    work.mkdir(mode=0o700)
    runner = Runner(output)
    report = {"schema": "reede-installed-validation-v1", "candidate": str(candidate),
              "status": "failed", "publication_ready": False, "authenticity": "not_established",
              "http_fixtures": "not_run", "full_validation": "not_run",
              "advisory_scan": "not_run", "legal_review": "not_run", "failures": [],
              "commands": runner.commands, "runtime": {"python": sys.version, "platform": sys.platform}}
    try:
        if os.name != "posix" or platform.system() != "Linux" or platform.machine() != "x86_64":
            raise ValueError("this validator supports Linux x86_64 native candidates on POSIX only")
        for executable in ("node", "npm"):
            if not shutil.which(executable):
                raise ValueError(f"missing required runtime on PATH: {executable}")
        out, _ = runner.run([sys.executable, ROOT / "scripts/verify-release.py", candidate], work)
        report["integrity"] = json.loads(out)
        if report["integrity"].get("integrity") != "verified":
            raise ValueError("candidate integrity was not verified")
        manifest = json.loads((candidate / "release.json").read_text())
        version = manifest["version"]
        if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
            raise ValueError("unsupported candidate version format")
        if manifest.get("profile") != "offline-verification" or manifest["build_scope"]["native_binaries"] != ["verify"]:
            raise ValueError("an explicit offline-verification candidate is required")
        source_archive = candidate / f"reede-{version}-source.tar.gz"
        wheels = list(candidate.glob(f"reede_client-{version}-*.whl"))
        if len(wheels) != 1:
            raise ValueError("exactly one matching SDK wheel is required")
        wheel = wheels[0]
        npm_archive = candidate / f"reede-client-{version}.tgz"
        sdist_archive = candidate / f"reede_client-{version}.tar.gz"
        verifier = candidate / "linux-x86_64/verify"
        if not verifier.is_file() or not os.access(verifier, os.X_OK):
            raise ValueError("candidate verifier missing or not executable")
        extract(source_archive, work / "source")
        source = work / "source" / f"reede-{version}"
        extract(sdist_archive, work / "sdist")
        sdist = work / "sdist" / f"reede_client-{version}"
        python_project = tomllib.loads((source / "sdk/python/pyproject.toml").read_text())["project"]
        node_project = json.loads((source / "sdk/typescript/package.json").read_text())
        if (re.sub(r"[-_.]+", "-", python_project["name"]).lower() != "reede-client"
                or python_project["version"] != version
                or node_project["name"] != "@reede/client" or node_project["version"] != version):
            raise ValueError("SDK/source candidate versions disagree")
        sdist_metadata = Parser().parsestr((sdist / "PKG-INFO").read_text())
        report["sdist_python_distribution"] = python_identity({"names": sdist_metadata.get_all("Name"),
            "versions": sdist_metadata.get_all("Version")}, version)
        report.update(check_inventories(candidate, source, manifest))
        node_version, _ = runner.run(["node", "--test-isolation=none", "--eval",
            "if(Number(process.versions.node.split('.')[0])<22)process.exit(1);console.log(process.versions.node)"], work)
        report["runtime"]["node"] = node_version.strip()
        report["runtime"]["npm"] = runner.run(["npm", "--version"], work)[0].strip()
        py = work / "python"
        runner.run([sys.executable, "-m", "venv", py], work)
        python = py / "bin/python"
        runner.run([python, "-m", "pip", "--isolated", "install", "--no-index", "--no-deps", "--no-cache-dir", wheel], work)
        node = work / "node"
        runner.run(["npm", "install", "--prefix", node, "--cache", work / "npm-cache",
                    "--offline", "--ignore-scripts", "--no-audit", "--no-fund", npm_archive], work)
        identity_json, _ = runner.run([python, "-c",
            "import json,reede_client,importlib.metadata as m;d=m.distribution('reede-client');"
            "print(json.dumps({'module':reede_client.__file__,'names':d.metadata.get_all('Name'),'versions':d.metadata.get_all('Version'),"
            "'distribution_module':str(d.locate_file('reede_client/__init__.py'))}))"], work)
        identity = json.loads(identity_json)
        report["installed_python_distribution"] = python_identity(identity, version)
        module = Path(identity["module"]).resolve(strict=True)
        if Path(identity["distribution_module"]).resolve(strict=True) != module:
            raise ValueError("installed distribution does not identify the imported SDK implementation")
        if not module.is_relative_to(py.resolve()):
            raise ValueError("Python import did not select the fresh venv package")
        report["installed_source_files_verified"] = check_files(
            source, sdist, module.parent.parent, node / "node_modules/@reede/client")
        report["installed_python_module"] = str(module)
        _, python_output = runner.run([python, "-m", "unittest", "-v",
            "test_client.OfflineVerificationTests", "test_verifier_resources"], source / "sdk/python/tests",
            extra_env={"REEDE_VERIFY_BIN": str(verifier)})
        report["python_cases"] = python_report(python_output)
        node_output, _ = runner.run(["node", "--test", "--test-isolation=none", "--test-reporter=tap",
            "--test-name-pattern=unsafe URLs|shared Rust offline verifier",
            source / "sdk/typescript/test/client.test.js"], work,
            extra_env={"REEDE_VERIFY_BIN": str(verifier),
                       "REEDE_SDK_NODE_MODULE": (node / "node_modules/@reede/client/src/index.js").as_uri()})
        report["node_cases"] = node_report(node_output)
        report.update({"source_commit": manifest["source_commit"], "source_dirty": manifest["source_dirty"],
                       "verifier_sha256": sha(verifier), "candidate_profile": manifest["profile"],
                       "status": "passed"})
    except Exception as error:
        report["failures"].append(f"{type(error).__name__}: {error}")
    (output / "installed-validation.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path, help="explicitly trusted local offline-verification candidate")
    parser.add_argument("--output", type=Path, required=True, help="new output directory outside the candidate")
    args = parser.parse_args()
    try:
        report = validate(args.candidate, args.output)
    except Exception as error:
        parser.exit(1, f"installed validation failed: {error}\n")
    print(json.dumps({"status": report["status"], "report": str(args.output / "installed-validation.json"),
                      "publication_ready": False, "failures": report["failures"]}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
