#!/usr/bin/env python3
"""Build an allowlisted Reede source/SDK release candidate, never publish it.

Uses only the standard library for staging. --validate additionally executes
standalone Rust tests and resolved dependency checks. --build builds native
binaries and SDK distributions. Unsigned output remains a release candidate.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile
import tomllib

ROOT_FILES = {"Cargo.toml", "Cargo.lock", "README.md", "CHANGELOG.md", "LICENSE", "NOTICE"}
OPTIONAL_ROOT_FILES = {"CONTRIBUTING.md", "SECURITY.md"}
ROOT_DIRS = {"src", "tests", "examples", "docs", "scripts", "sdk", "skills", ".github"}
EXCLUDED = {"__pycache__", "node_modules", "target", "build", "dist", ".git", ".DS_Store"}


def public_files(source: Path) -> list[Path]:
    result = []
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if relative.parts[0] not in ROOT_FILES | OPTIONAL_ROOT_FILES | ROOT_DIRS:
            continue
        if any(part in EXCLUDED or part.endswith(".egg-info") or part.startswith(".env") for part in relative.parts):
            continue
        if path.is_symlink():
            raise ValueError(f"symlink is not allowed in a public source release: {relative}")
        if path.is_file() and path.suffix not in {".pyc", ".tgz", ".whl"}:
            result.append(relative)
    for required in ROOT_FILES:
        if Path(required) not in result:
            raise ValueError(f"missing release input: {required}")
    return result


def source_archive(source: Path, destination: Path, prefix: str, files: list[Path], epoch: int) -> None:
    with destination.open("wb") as stream, gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=epoch) as compressed, tarfile.open(fileobj=compressed, mode="w") as archive:
        for relative in files:
            data = (source / relative).read_bytes()
            info = tarfile.TarInfo(f"{prefix}/{relative.as_posix()}")
            info.size, info.mtime = len(data), epoch
            info.mode = 0o755 if os.access(source / relative, os.X_OK) else 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(data))


def run(args: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> None:
    subprocess.run(args, cwd=cwd, env=env, check=True)


def release_plan(profile: str, target: str | None = None) -> dict:
    if profile == "full":
        return {"profile": profile, "test_flags": ["--all-features"],
                "build_flags": ["--features", "cli,ingest", "--bins"],
                "metadata_flags": ["--all-features"], "binaries": ["verify", "reede"],
                "license_scope": "metadata-inventory", "target": None}
    if profile == "offline-verification":
        return {"profile": profile, "test_flags": ["--no-default-features"],
                "build_flags": ["--no-default-features", "--bin", "verify"],
                "metadata_flags": ["--no-default-features", *(["--filter-platform", target] if target else [])],
                "binaries": ["verify"], "license_scope": "selected-build", "target": target}
    raise ValueError("unsupported release profile")


def load_script(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def locked_build_packages(packages: list[dict], lock: dict) -> list[dict]:
    locked = {(p["name"], p["version"], p.get("source")): p for p in lock["package"]}
    result = []
    for package in packages:
        identity = (package["name"], package["version"], package.get("source"))
        if identity not in locked:
            raise ValueError("selected metadata package does not match the source lockfile")
        result.append({**package, **({"checksum": locked[identity]["checksum"]} if locked[identity].get("checksum") else {})})
    return result


def sbom_inventory(packages: list[dict], version: str, scope: str, declared_licenses: dict,
                   *, selection: dict | None = None) -> dict:
    components = []
    for package in packages:
        identity = (package["name"], package["version"], package.get("source"))
        item = {"type": "library", "name": package["name"], "version": package["version"],
                "purl": f"pkg:cargo/{package['name']}@{package['version']}"}
        if package.get("checksum"):
            item["hashes"] = [{"alg": "SHA-256", "content": package["checksum"]}]
        if declared_licenses.get(identity):
            item["properties"] = [{"name": "cargo:declared-license-expression", "value": declared_licenses[identity]}]
        components.append(item)
    properties = [{"name": "scope", "value": scope}]
    if selection:
        properties.append({"name": "cargo:selection", "value": json.dumps(selection, sort_keys=True)})
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "library", "name": "reede", "version": version},
                         "properties": properties}, "components": components}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--profile", choices=["full", "offline-verification"], default="full",
                        help="full builds HTTP CLI plus verifier; offline-verification explicitly builds only verifier and SDK packages")
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--licenses", action="store_true", help="collect standalone Cargo license declarations and available notice files (also enabled by --build)")
    parser.add_argument("--offline", action="store_true", help="use cached Rust dependencies and installed Python build tools without registry access")
    parser.add_argument("--allow-dirty", action="store_true", help="development candidate only; never ready for publication")
    args = parser.parse_args()
    build_env = os.environ.copy()
    if args.offline:
        build_env["CARGO_NET_OFFLINE"] = "true"
    target = None
    if args.profile == "offline-verification" and (args.build or args.licenses or args.validate):
        compiler = subprocess.check_output(["rustc", "-vV"], env=build_env, text=True)
        target = next((line.removeprefix("host: ") for line in compiler.splitlines() if line.startswith("host: ")), None)
        if not target:
            parser.error("Rust compiler did not report its native host target")
    plan = release_plan(args.profile, target)
    if args.build and build_env.get("CARGO_BUILD_TARGET"):
        parser.error("native release builds require CARGO_BUILD_TARGET to be unset")
    source, out = args.source.resolve(), args.out.resolve()
    if out == source or source in out.parents:
        parser.error("output must be outside the source tree")
    package = tomllib.loads((source / "Cargo.toml").read_text())["package"]
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain", "--", "."], cwd=source, text=True).strip())
    if dirty and not args.allow_dirty:
        parser.error("source is dirty; commit it or explicitly build a development candidate")
    epoch = int(subprocess.check_output(["git", "show", "-s", "--format=%ct", "HEAD"], cwd=source, text=True))
    tracked = {Path(name) for name in subprocess.check_output(
        ["git", "ls-files", "-z", "--", "."], cwd=source, text=True
    ).split("\0") if name}
    # Ignored local files can contain credentials even inside a public directory.
    # Only version-controlled inputs may enter a release archive.
    files = [path for path in public_files(source) if path in tracked]
    if not {Path(name) for name in ROOT_FILES}.issubset(files):
        parser.error("required release inputs must be version-controlled")
    out.mkdir(parents=True, exist_ok=False)
    prefix = f"reede-{package['version']}"
    source_archive(source, out / f"{prefix}-source.tar.gz", prefix, files, epoch)
    checks = {"standalone_tests": "not_run", "dependency_boundary": "not_run", "sdk_distributions": "not_built", "license_collection": "not_run", "legal_review": "not_run", "advisory_scan": "not_run", "native_binaries": "not_built"}
    with tempfile.TemporaryDirectory(prefix="reede-release-", dir=os.environ.get("TMPDIR", "/tmp")) as tmp:
        stage = Path(tmp)
        for relative in files:
            staged_file = stage / relative
            staged_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / relative, staged_file)
        if args.validate:
            run(["cargo", "test", "--locked", *plan["test_flags"]], cwd=stage, env=build_env)
            checks["standalone_tests"] = "passed"
            if args.profile == "full":
                run(["python3", "scripts/check-one-way-dependency.py"], cwd=stage, env=build_env)
                checks["dependency_boundary"] = "passed"
        if args.build:
            run(["cargo", "build", "--locked", "--release", *plan["build_flags"]], cwd=stage, env=build_env)
            native_target = Path(build_env.get("CARGO_TARGET_DIR", str(stage / "target")))
            if not native_target.is_absolute():
                native_target = stage / native_target
            native = out / f"{platform.system().lower()}-{platform.machine()}"
            native.mkdir()
            for binary in plan["binaries"]:
                executable = binary + (".exe" if os.name == "nt" else "")
                shutil.copy2(native_target / "release" / executable, native / executable)
            checks["native_binaries"] = "built"
            pip_flags = ["--no-index", "--no-build-isolation"] if args.offline else []
            run(["python3", "-m", "pip", "wheel", *pip_flags, "--no-deps", "--wheel-dir", str(out), "sdk/python"], cwd=stage, env=build_env)
            # Use the declared backend directly; offline machines need no build frontend.
            run(["python3", "-c", "import sys, setuptools.build_meta as backend; backend.build_sdist(sys.argv[1])", str(out)],
                cwd=stage / "sdk/python", env=build_env)
            npm_flags = ["--offline"] if args.offline else []
            run(["npm", "pack", *npm_flags, "--ignore-scripts", "--pack-destination", str(out)], cwd=stage / "sdk/typescript", env=build_env)
            checks["sdk_distributions"] = "built"
        lock = tomllib.loads((stage / "Cargo.lock").read_text())
        declared_licenses = {}
        selection = None
        if args.licenses or args.build or (args.validate and args.profile == "offline-verification"):
            metadata = json.loads(subprocess.check_output(
                ["cargo", "metadata", "--format-version=1", "--locked", *plan["metadata_flags"]],
                cwd=stage, env=build_env,
            ))
            license_module = load_script(stage / "scripts/license-inventory.py", "release_license_inventory")
            build_metadata = license_module.build_closure(metadata)
            selection = license_module.selection_scope(build_metadata, "selected-build", target)
            if args.validate and args.profile == "offline-verification":
                boundary = load_script(stage / "scripts/check-one-way-dependency.py", "release_dependency_boundary")
                boundary.check_graph(build_metadata, stage)
                checks["dependency_boundary"] = "passed_selected_profile"
            if args.licenses or args.build:
                evidence = license_module.collect(metadata, out, epoch,
                    dependency_scope=plan["license_scope"], target=target)
                declared_licenses = {(p["name"], p["version"], p["source"]): p["declared_license"]
                                     for p in evidence["components"]}
                checks["license_collection"] = "collected_not_reviewed"
                checks["license_review_items"] = sum(bool(p["review_items"]) for p in evidence["components"])
            build_sbom = sbom_inventory(locked_build_packages(build_metadata["packages"], lock), package["version"],
                "selected-feature Cargo normal/build dependency closure; includes build tools; not an exact linked-binary inventory",
                declared_licenses, selection=selection)
            (out / "build-dependencies.cdx.json").write_text(json.dumps(build_sbom, indent=2) + "\n")
        sbom = sbom_inventory(lock["package"], package["version"],
            "source lockfile inventory; includes optional/development/target dependencies; not a built-binary closure",
            declared_licenses)
        (out / "sbom.cdx.json").write_text(json.dumps(sbom, indent=2) + "\n")
    manifest = {
        "schema": "reede-release-candidate-v1", "version": package["version"], "source_commit": commit,
        "source_dirty": dirty, "profile": args.profile,
        "build_scope": {"cargo_flags": plan["build_flags"], "native_binaries": plan["binaries"] if args.build else [], "dependency_selection": selection},
        "checks": checks, "offline_build": args.offline, "publication_ready": False,
        "signatures": "not_signed", "commercial_runtime_included": False,
        "artifacts": [{"path": p.relative_to(out).as_posix(), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(out.rglob("*")) if p.is_file()],
    }
    (out / "release.json").write_text(json.dumps(manifest, indent=2) + "\n")
    sums = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(out).as_posix()}" for p in sorted(out.rglob("*")) if p.is_file()]
    (out / "SHA256SUMS").write_text("\n".join(sums) + "\n")
    print(out)


if __name__ == "__main__":
    main()
