#!/usr/bin/env bash
# Start `reede serve`, run the LangGraph agent against it, then check the sealed chain.
# Needs a reede binary built with the ingest feature:
#   cargo build --features ingest --bin reede   (then REEDE_BIN=<target>/debug/reede)
# or `cargo install --path . --features ingest` (then it is just `reede` on PATH).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
reede="${REEDE_BIN:-reede}"
work="${WORK_DIR:-$(mktemp -d)}"
out="$work/ingest"
mkdir -p "$work"

if [ ! -x "$work/venv/bin/python" ]; then
  python3 -m venv "$work/venv"
  "$work/venv/bin/pip" install --quiet -r "$here/requirements.txt"
fi

"$reede" serve --out "$out" >"$work/serve.log" 2>&1 &
server=$!
trap 'kill "$server" 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do
  grep -q "listening on" "$work/serve.log" 2>/dev/null && break
  kill -0 "$server" 2>/dev/null || { cat "$work/serve.log"; exit 1; }
  sleep 0.1
done

"$work/venv/bin/python" "$here/agent.py"
sleep 1 # the server answers before it returns, but keep the log read race-free

cat "$work/serve.log"
# Pinning the key from the same directory only shows the form; a real verifier pins a key it got elsewhere.
"$reede" ingest check --out "$out" --pubkey "$(cat "$out/pubkey.hex")"
"$reede" receipt verify --chain "$out/chain.json" --pubkey "$(cat "$out/pubkey.hex")"
echo "chain, span files and key are in $out"
