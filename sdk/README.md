# Reede service SDKs

The [Python client](python/README.md) and
[JavaScript/TypeScript client](typescript/README.md) are Apache-2.0 release
candidates. They use the implemented [SDK protocol contract](../docs/sdk-api-contract.md).
They connect to the managed runtime; the commercial server implementation is
not part of these packages. They do not embed the Rust execution engine.

Both clients support tenant-authenticated task listing, status, cancellation
and lease inspection. The separate agent-host client supports submission,
start/status/cancel, pending reviews and approve/reject. Only safe transient GET
responses are automatically retried. Both languages invoke the same Rust core
for strict offline receipt verification.

Validation from the Reede root:

```sh
PYTHONPATH=sdk/python REEDE_VERIFY_BIN=/absolute/path/verify \
  python3 -m unittest discover -s sdk/python/tests -v
REEDE_VERIFY_BIN=/absolute/path/verify node --test sdk/typescript/test/*.test.js
python3 -m pip wheel --no-deps --wheel-dir /tmp/reede-dist sdk/python
npm pack --ignore-scripts --pack-destination /tmp/reede-dist --prefix sdk/typescript
```

To test installed distributions instead of the source clients, set
`REEDE_SDK_PYTHONPATH` to the installed Python site-packages directory and
`REEDE_SDK_NODE_MODULE` to the installed module's `file://` URL for this gate.

Build an allowlisted release candidate from a committed checkout:

```sh
python3 scripts/package-release.py --out /absolute/path/reede-release-candidate \
  --validate --build
```

The default `full` profile runs all-feature standalone tests and both dependency
boundaries when `--validate` is supplied. It builds the native verifier/HTTP CLI
plus Python wheel/source distribution and npm tarball with `--build`, and emits
source, checksums, dependency inventories and validation metadata. It excludes internal
CLAUDE instructions, commercial crates, environment files, symlinks and build
outputs. Output remains an unsigned candidate requiring independent security,
license, registry ownership and signing review before publication.

Verify the candidate's complete inventory and hashes before installation:

```sh
python3 scripts/verify-release.py /absolute/path/reede-release-candidate
```

This rejects missing, modified, unlisted and symlinked artifacts. It checks local
integrity against the accompanying manifest and checksum list; it does not
authenticate their publisher. Its JSON report always keeps publication readiness
false. Obtain a separately authenticated signature before treating checksums as
publisher evidence. See [SECURITY.md](../SECURITY.md) and
[CONTRIBUTING.md](../CONTRIBUTING.md).

On a machine with cached Rust dependencies and installed Python build tools
(`setuptools>=68` and `wheel`), add `--offline` to the builder. It disables Cargo
registry access and Python build isolation/downloads and packs npm locally.
Omitting `--validate` leaves validation marked `not_run`; offline packaging does
not imply that network-dependent tests ran or that publication gates passed.

Builds additionally collect standalone Cargo license declarations and common
license/notice texts into `license-evidence.json` and `THIRD_PARTY_LICENSES.tar.gz`.
Use `--licenses` to collect them with a source-only candidate. The SBOM records
the raw declared expressions without treating them as validated SPDX or legal
approval. The full profile evidence includes development/target-specific packages.
Feature selection is recorded explicitly; neither evidence profile is an exact
linked-binary inventory. Missing texts and nested third-party notices
require review. Legal review and advisory scanning remain explicitly `not_run`.


For a native verifier and SDK package candidate without the optional Rust HTTP
CLI, select the separate `offline-verification` profile:

```sh
python3 scripts/package-release.py --out /absolute/path/reede-offline-candidate \
  --profile offline-verification --offline --build
```

This builds only `verify` with `--no-default-features`, together with the current
Python wheel/source distribution and npm tarball. It includes the complete
allowlisted source, including optional CLI source; it contains **no native HTTP
CLI** and does not claim full-profile validation. Profile selection controls
artifact/features; `--offline` separately prevents dependency downloads. An
installed SDK can invoke this verifier locally or connect to a separately
configured service through its own HTTP implementation.

`sbom.cdx.json` remains the whole source lockfile inventory, including optional
and target-specific packages which may not be built. `build-dependencies.cdx.json`
and `license-evidence.json` record the selected root features and native host
platform. In this profile, the collector follows only normal/build dependency
edges from Reede, excluding development and unused optional dependencies. It
includes build tools and metadata-derived packages, so it is not an attestation
of exact linked machine code. Source-lock entries without selected-profile
license texts are not silently covered by old all-feature evidence.

Add `--validate` only where the selected Rust suite can run, including local
listener tests; otherwise the manifest keeps standalone validation `not_run`.
Explicit source SDK conformance uses the optional
[`sdk-conformance` gate](../docs/sdk-conformance.md). Candidate validation should
also install its actual wheel/npm tarball and run shared-vector/tamper checks
against the candidate's actual `verify` executable. Python source tests can use
installed site-packages through `PYTHONPATH`; Node tests can set
`REEDE_SDK_NODE_MODULE` to the installed module's `file://` URL. The Cargo source
gate deliberately uses source SDKs, and is separate from installed-package proof.

```sh
python3 scripts/package-release.py --out /absolute/path/reede-offline-candidate \
  --profile offline-verification --offline --build
```

The profile never changes `publication_ready=false`, unsigned state, independent
legal/security review or publisher-authentication requirements. Missing notice
texts remain review items. A narrower successful build does not establish that
the full optional HTTP CLI builds or that its TLS dependencies are cleared.
