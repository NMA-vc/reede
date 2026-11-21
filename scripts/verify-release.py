#!/usr/bin/env python3
"""Check a local candidate's inventory and hashes; this does not authenticate its publisher."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

MAX_MANIFEST = 1024 * 1024
MAX_SUMS = 64 * 1024
MAX_ARTIFACTS = 128


def checked_path(root: Path, name: object) -> Path:
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.+/-]+", name):
        raise ValueError("unsupported artifact path")
    relative = PurePosixPath(name)
    if relative.is_absolute() or any(part in {".", ".."} for part in name.split("/")):
        raise ValueError("artifact path must be normalized and relative")
    if relative.as_posix() != name:
        raise ValueError("artifact path must be normalized")
    path = root.joinpath(*relative.parts)
    for parent in [path, *path.parents]:
        if parent == root:
            break
        if parent.is_symlink():
            raise ValueError("artifact symlinks are not allowed")
    if not path.is_file():
        raise ValueError(f"missing artifact: {name}")
    return path


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            value.update(block)
    return value.hexdigest()


def bounded_json(path: Path) -> dict:
    with path.open("rb") as stream:
        data = stream.read(MAX_MANIFEST + 1)
    if len(data) > MAX_MANIFEST:
        raise ValueError("release manifest exceeds size limit")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("release manifest must be an object")
    return value


def verify(candidate: Path) -> dict:
    if candidate.is_symlink():
        raise ValueError("candidate directory must not be a symlink")
    root = candidate.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("candidate must be a directory")
    manifest_path = checked_path(root, "release.json")
    manifest = bounded_json(manifest_path)
    if manifest.get("schema") != "reede-release-candidate-v1":
        raise ValueError("unsupported release manifest schema")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= MAX_ARTIFACTS:
        raise ValueError("invalid artifact count")
    expected = {}
    for item in artifacts:
        if not isinstance(item, dict):
            raise ValueError("invalid artifact entry")
        name, checksum = item.get("path"), item.get("sha256")
        if not isinstance(name, str) or name in expected or name in {"release.json", "SHA256SUMS"}:
            raise ValueError("duplicate or reserved artifact path")
        if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise ValueError("invalid SHA-256 digest")
        path = checked_path(root, name)
        if digest(path) != checksum:
            raise ValueError(f"artifact checksum mismatch: {name}")
        expected[name] = checksum

    sums_path = checked_path(root, "SHA256SUMS")
    with sums_path.open("rb") as stream:
        sums_data = stream.read(MAX_SUMS + 1)
    if len(sums_data) > MAX_SUMS:
        raise ValueError("checksum list exceeds size limit")
    sums = {}
    for line in sums_data.decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.+/-]+)", line)
        if not match or match[2] in sums:
            raise ValueError("invalid or duplicate checksum entry")
        checked_path(root, match[2])
        sums[match[2]] = match[1]
    expected["release.json"] = digest(manifest_path)
    if sums != expected:
        raise ValueError("checksum list and manifest inventory disagree")

    actual = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("candidate contains a symlink")
        if not path.is_dir():
            if not path.is_file():
                raise ValueError("candidate contains a special file")
            actual.add(path.relative_to(root).as_posix())
            if len(actual) > MAX_ARTIFACTS + 2:
                raise ValueError("candidate contains too many files")
    if actual != set(expected) | {"SHA256SUMS"}:
        raise ValueError("candidate contains unlisted files")
    return {
        "schema": "reede-candidate-integrity-v1",
        "integrity": "verified",
        "authenticity": "not_established",
        "artifact_count": len(artifacts),
        "declared_source_commit": manifest.get("source_commit"),
        "declared_source_dirty": manifest.get("source_dirty"),
        "publication_ready": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path)
    args = parser.parse_args()
    try:
        report = verify(args.candidate)
    except (ValueError, OSError) as error:
        parser.exit(1, f"candidate verification failed: {error}\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
