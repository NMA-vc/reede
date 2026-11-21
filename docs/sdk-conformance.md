# SDK transport conformance

The opt-in `sdk-conformance` Cargo feature runs the source Python and JavaScript
SDK suites, including their real loopback HTTP fixtures and strict receipt-vector
and tamper checks against the matching Rust `verify` binary. It adds no dependency
and is enabled by the existing all-feature Reede CI jobs. Default-feature Rust
builds and tests do not compile or invoke this integration target and need neither
Node nor Python.

From the repository root (or an extracted Reede checkout):

```sh
cargo test -p reede --locked --features sdk-conformance --test sdk_conformance
```

Requirements:

- A POSIX host; Python's subprocess-resource checks exercise POSIX descendant
  cleanup, so this explicit gate refuses unsupported platforms rather than skipping.
- Python 3.10 or newer available as `python3`.
- Node 22 or newer with `--test-isolation=none` support available as `node`.
  Node 24 is recommended. Unsupported Node versions fail with an actionable error.
- Permission to bind and connect to ephemeral `127.0.0.1` ports. No remote service,
  registry, production credential, npm installation or pip installation is needed.

The runner supplies `REEDE_VERIFY_BIN` from Cargo's `CARGO_BIN_EXE_verify`, fixes
`PYTHONPATH` to this checkout's `sdk/python`, and clears the Node installed-module
override. It invokes each interpreter directly with structured arguments, without
a shell. The Python suite currently runs 12 named cases; Node runs six. The runner
requires all expected named cases, a nonzero complete report and zero skipped,
cancelled or pending cases. A successful file-container report is not accepted.
Actual named language reports are emitted even with ordinary Cargo test capture.

The shared verification case uses the reede-v2 vector as the primary receipt
(accepted as a trusted-head segment, rejected under `require_genesis`, and
rejected after tampering with credits, sequence_no or timestamp) and keeps the
reede-v1 vector to show legacy receipts are still recomputed and accepted.

The tests preserve the clients' authority, route/UUID validation, immutable tool
review, redirect refusal, read-only retry, opaque error and offline verification
checks. They also exercise Python verifier subprocess deadlines, output limits
and resource reclamation. This is fixture conformance, not evidence that a remote
deployment or external effect works.

For an explicitly selected installed Node package, the same source test file
accepts `REEDE_SDK_NODE_MODULE=file:///absolute/path/to/installed/src/index.js`.
Python tests use the package selected by `PYTHONPATH`. Only use trusted local
packages and a trusted matching verifier for these separate installed-package
checks; the Cargo gate deliberately tests this checkout's sources.

Socket-restricted environments must not report this gate as passed. They can
compile it with `cargo test -p reede --locked --features sdk-conformance --test
sdk_conformance --no-run`, run its `report_validation` tests, and separately run
the named no-socket language tests. Those checks do not replace the complete
HTTP gate. Missing runtimes, socket failures, skipped verifier checks and zero-test
successes are failures whenever `sdk-conformance` is explicitly enabled.
