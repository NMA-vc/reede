# Installed release validation

Run this opt-in command on an explicitly trusted local candidate:

```sh
python3 reede/scripts/validate-installed-release.py \
  /path/to/reede-offline-verification-candidate \
  --output /path/to/new-validation-directory
```

The command currently supports the `offline-verification` profile on **Linux
x86_64**, with Python **3.12+**, venv/pip, npm and Node **22+ supporting
`--test-isolation=none`** (Node 24 recommended). Other platforms/profiles and
prerelease version formats fail explicitly. No Rust compiler, registry downloads,
account or production credentials are used. A supported runtime and installed
package are still requirements; this command does not install Node or Python.

The output directory must be new and outside the candidate, including through
symlinks. The candidate remains unchanged. The validator first uses
`verify-release.py` to check its exact artifact inventory/hashes, then safely
extracts the source and Python sdist. It checks source-lock/SBOM identities and
checksums, selected-build/license identities and scope, and every notice hash.
It installs the wheel into a fresh venv and the npm tarball into a fresh project,
offline with no dependencies fetched and npm lifecycle scripts disabled. npm uses
a writable local cache. Installed implementation/declaration files, package docs
and sdist source/metadata are compared to the extracted source. Installed wheel
and sdist distribution names/versions must match the source projects and candidate.
Inherited pip/npm configuration overrides are cleared; pip uses isolated mode,
and subprocess temporary directories stay under the supplied output directory.

Eight mandatory named Python offline/resource cases and two mandatory named Node
offline cases run against those installed SDKs and the candidate's exact verifier.
Missing/partial/file-container reports and skipped tests fail. The verifier path
is selected explicitly for both languages; inherited SDK-path overrides are
cleared. Commands use a 120-second process/output deadline, at most 1 MiB retained
per output stream, and POSIX process-group cleanup. Source/notice extraction is
bounded to 4,096 entries, 4 MiB per file/metadata read and 64 MiB inflated tar bytes
per archive, including GNU/PAX headers, before those headers are parsed.

The supplemental `installed-validation.json` records exact command arguments,
return codes, bounded raw log paths, runtimes, source identity, tested case names,
inventory results and failures. Its workspace and logs stay under the supplied
output directory for inspection. Initial output-path/runtime invocation errors
exit nonzero; failures after report setup also write a failed report. The command
never overwrites an existing report or changes the candidate manifest.

Use only trusted candidate binaries, SDKs and source tests: checksums establish
integrity, not publisher authenticity. The report always retains
`publication_ready=false` and `authenticity=not_established`. Full HTTP fixtures,
full standalone validation, advisory scanning and legal review remain explicitly
`not_run`. Passing this subset does not establish production release readiness.
The dependency closure is not independently recomputed without Cargo: this command
checks the declared source/build/license inventories, local root, scope and lock
checksums, not binary linkage or completeness of the selected dependency graph.
