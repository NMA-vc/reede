# Implemented SDK contract, version 0.1

This contract describes the routes the current SDKs actually call. The broader
control-plane OpenAPI document is a target specification, not proof that every
listed operation is deployed. Service base URLs are caller-configured and may
include a deployment prefix. HTTPS and a tenant bearer token are required.

## Lifecycle service

| Operation | Method and path | Success response |
|---|---|---|
| list tasks | GET `/api/v1/reede/tasks?limit=N` | array of Reede Task records |
| get task | GET `/api/v1/reede/tasks/{uuid}` | Reede Task record |
| request cancel | POST `/api/v1/reede/tasks/{uuid}/cancel` | 202, Task with cancel_requested_at |
| inspect leases | GET `/api/v1/reede/tasks/{uuid}/leases` | array of CredentialLease records |

Limit is 1..500. Task identity, state, budget, lease/receipt references and
timestamps follow the Rust Task serialization. A cancellation request is not a
terminal state. A terminal run may refuse cancellation with 409. Lease records
contain references and expiry/revocation state, never credential values.

The host-runs lifecycle service returns 501 for task creation/submission at
this path; the clients deliberately use the agent-host protocol for those.

## Agent-host service

POST `/mcp`, JSON-RPC 2.0 with a fresh request id. Responses must match that id
and contain exactly a supported result or an error. The server authenticates
the caller and derives the tenant; clients supply no tenant authority override.

| Method | Params |
|---|---|
| task.submit | agent_id, input object, optional stable invocation_id |
| task.start | task_id UUID |
| task.status | task_id UUID |
| task.cancel | task_id UUID |
| task.recover | task_id UUID |
| task.pending | empty object |
| task.decide | approval_key, decision (`approve` or `reject`), optional edited_output |
| task.tool_pending | optional task_id UUID, limit (1..100, default 100) |
| task.tool_decide | approval_key, decision (`approve` or `reject`) |

Task methods return the host TaskView projection (task_id, agent_id, state,
result, receipt_hash, stop_reason and pending_review). Pending returns the
server's pending-review list. RPC correlation ids are not idempotency keys;
submission invocation_id provides explicit retry identity. A timed-out or
cancelled HTTP request may already have been accepted by the server.

`recover` returns task_id and outcome (`restarted_before_execution`,
`reconciliation_required` or `finalization_unknown`). Recovery requires an expired
owner and current server-side authorization. It can restart before execution
began; possible external effects and incomplete finalization require
reconciliation. It does not blindly replay active work. Status exposes
`ReconciliationRequired` for these uncertain outcomes. Recovery writes are not
retried automatically and require a host with active ownership recovery enabled.

`pending_tools`/`pendingTools` returns an object with `proposals`, each containing
approval_key, task_id, qualified_tool, arguments, arguments_sha256, expires_at and
status. `decide_tool`/`decideTool` returns approval_key, task_id, status and
already_decided. These require a host with durable tool review enabled. The
reviewer inspects the exact immutable arguments; changing a proposal requires a
new proposal. Reviewer identity and tenant authority come from authentication.
Decision writes are not retried automatically; query pending state after an
uncertain response. Older hosts return an RPC error for unsupported methods.

SDK errors expose a stable local code and HTTP status/request id where present,
without server response bodies or credentials. Redirects are refused. Only GET
429/502/503/504 responses are retried automatically, with bounded attempts and
delay. Pagination, streams, deployment, secret mutation and policy/log endpoints
are not advertised by these clients because no matching shipping contract was
validated for this release.

## Offline verification

SDKs execute the matching trusted Rust verifier with `--json`; no shell, account
or network is used. The stable report schema is `reede-verification-v1`.
Authenticity requires a supplied trusted Ed25519 key, supported nonempty chain,
recomputed content hashes and unbroken predecessor links. Completeness requires
a trusted expected head/count and a genesis boundary. Timestamp presence is not
timestamp validity or legal provider qualification. Sequence numbers and outer
timestamps are signed in reede-v2 (what Reede emits) and unsigned metadata in
legacy reede-v1 receipts; see `receipt-wire-v2.md`. Evidence asserts what the signer
recorded; it cannot establish that a compromised signer told the truth.
