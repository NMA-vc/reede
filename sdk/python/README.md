# Reede Python client

Python 3.10+, no runtime dependencies. Install the wheel or use `pip install .`.
The package name is a release candidate; registry publication is separate.

```python
import os
from reede_client import ReedeClient, AgentHostClient, verify_file

client = ReedeClient(os.environ["REEDE_API_URL"], lambda: os.environ["REEDE_TOKEN"])
runs = client.list_tasks(limit=10)

host = AgentHostClient(os.environ["REEDE_HOST_URL"], lambda: os.environ["REEDE_TOKEN"])
run = host.submit("my-agent", {"topic": "spring"}, invocation_id="my-stable-request-id")
host.start(run["task_id"])
view = host.status(run["task_id"])

report = verify_file("receipts.json", os.environ["REEDE_PUBLIC_KEY"],
                     verifier="/trusted/path/verify", require_genesis=True,
                     expected_head=os.environ["EXPECTED_RECEIPT_HEAD"], expected_count=3)
```

`ReedeClient` implements `list_tasks(limit=50)`, `get_task(task_id)`,
`cancel_task(task_id)` and `list_leases(task_id)`. `AgentHostClient` implements
`submit(agent_id, input, invocation_id=None)`, `start`, `status`, `cancel`,
`recover`, `pending`, `pending_tools(task_id=None, limit=100)`,
`decide_tool(approval_key, decision)` and
`decide(approval_key, decision, edited_output=None)`. Task IDs are UUID strings;
decisions are `approve` or `reject`; pending tool limits are 1..100. The
`proposals` entries expose `approval_key`, `task_id`, `qualified_tool`,
`arguments`, `arguments_sha256`, `expires_at` and `status`. Review those exact
arguments; changing them means requesting a new proposal. Reviewer identity is
derived from authentication.

Task views use snake_case field names (`task_id`, `agent_id`, `receipt_hash`,
`stop_reason`, `pending_review`) while their `state` values retain Rust enum
casing: `Admitted`, `Running`, `AwaitingReview`, `Succeeded`, `Failed`,
`Killed`, `BudgetExhausted` or `ReconciliationRequired`.
Recovery outcomes are `restarted_before_execution`,
`reconciliation_required` and `finalization_unknown`. The latter two mean
effects or finalization are uncertain and require reconciliation; they do not
authorize automatic replay. After an ambiguous decision or mutation response,
check status/pending state before taking another action.

`AsyncReedeClient` provides async wrappers only for the four `ReedeClient`
operations; agent-host operations have no async wrapper.

Use durable tool review only when a reviewer has selected a proposal. Inspect
its exact tool and arguments before deciding; an empty queue requires no action.

```python
reviews = host.pending_tools(task_id=run["task_id"], limit=20)
for proposal in reviews["proposals"]:
    print(proposal["approval_key"], proposal["qualified_tool"], proposal["arguments"])
# Set these from the proposal and decision the reviewer actually selected.
selected_approval_key = "reviewer-selected-key"
reviewer_decision = "approve"  # or "reject"
host.decide_tool(selected_approval_key, reviewer_decision)
```

For an agent output awaiting review, pass the reviewer-selected approval key and
decision. Recovery is an explicit operator action after an interruption or
uncertain status; inspect the returned outcome and reconcile uncertain effects.

```python
host.decide("reviewer-selected-key", "approve", edited_output="reviewed result")
recovery = host.recover(run["task_id"])
print(recovery["outcome"])
```

`ReedeClient` uses the existing `/api/v1/reede/tasks` read/cancel/lease service.
`AgentHostClient` uses the separate agent host `/mcp` JSON-RPC service. They can
have different base URLs. No caller-supplied tenant identity overrides the token.
HTTPS is required; loopback HTTP needs `allow_local_http=True` for tests.
Redirects are refused to prevent credential forwarding.

Only GET responses with 429/502/503/504 are retried, up to two times by default.
Mutations and ambiguous transport failures are never automatically retried.
Reuse `invocation_id` when explicitly retrying an agent submission. There is no
client method for an endpoint that the current server does not implement.

The configured `timeout` is a total caller deadline for each HTTP operation,
including read retries and their backoff. urllib cannot interrupt a socket read
when a peer keeps trickling bytes, so at most four request workers may remain
active after a caller receives `transport_timeout`; each retains a slot until
urllib returns. Further calls fail promptly with `transport_busy` while all
slots are occupied. This bounds abandoned workers but cannot force-stop a
blocked system DNS lookup or a stalled urllib operation. The underlying
operation may still reach the server after the caller's deadline, so mutations
remain ambiguous and are never automatically retried. `AsyncReedeClient` uses
`asyncio.to_thread`; cancelling its await does not retract an accepted remote
run. Request remote run cancellation explicitly. Tokens and response payloads
are absent from errors.

Offline verification uses the shared Rust verifier, installed separately from
the same release (for example, `cargo install reede --bin verify` after registry
publication). It requires no account or network. The report distinguishes
signed supplied content from completeness established against a trusted head
and count. Receipts Reede emits are reede-v2, which signs sequence_no,
timestamp, subject_id and signer_key_id; those are not signed in legacy reede-v1
receipts (see `docs/receipt-wire-v2.md`). Valid RFC 3161 timestamping alone does not establish legal provider qualification.

The offline helper retains at most 1 MiB of verifier stdout, discards stderr,
and imposes a 30-second process/output deadline plus up to one second for cleanup.
It permits at most four outstanding verifier/pipe-reader pairs in this Python
process; excess calls fail with `verifier_busy`. Overflow and deadline failures
are `verifier_output_too_large` and `verifier_timeout`. It kills the direct
verifier process on failure, not arbitrary wrapper descendants. A descendant
holding stdout open keeps its slot until EOF, preventing unbounded reader growth.
Use the trusted matching verifier binary directly. These limits do not bound the
Rust verifier's memory while parsing the input export.
