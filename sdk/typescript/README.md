# Reede JavaScript / TypeScript client

Node 22+, native fetch, zero runtime dependencies. The package includes TypeScript
declarations. Build a release candidate with `npm pack`; publication and registry
namespace ownership are separate release steps.

```typescript
import { ReedeClient, AgentHostClient, verifyFile } from '@reede/client';
import type { JsonValue } from '@reede/client';

const client = new ReedeClient(process.env.REEDE_API_URL!, () => process.env.REEDE_TOKEN!);
const tasks = await client.listTasks({ limit: 10 });
const host = new AgentHostClient(process.env.REEDE_HOST_URL!, () => process.env.REEDE_TOKEN!);
const task = await host.submit('my-agent', { topic: 'spring' }, { invocationId: 'stable-request-id' });
await host.start(task.task_id as string);
const view = await host.status(task.task_id as string);
const proof = await verifyFile('receipts.json', process.env.REEDE_PUBLIC_KEY!, {
  verifier: '/trusted/path/verify', requireGenesis: true,
  expectedHead: process.env.EXPECTED_RECEIPT_HEAD!, expectedCount: 3,
});
```

`ReedeClient` implements `listTasks({ limit? })`, `getTask(id)`,
`cancelTask(id)` and `listLeases(id)`. `AgentHostClient` implements
`submit(agentId, input, { invocationId?, signal? })`, `start(id)`, `status(id)`,
`cancel(id)`, `recover(id)`, `pending()`,
`pendingTools({ taskId?, limit?, signal? })`, `decideTool(approvalKey, decision)`
and `decide(approvalKey, decision, { editedOutput? })`. Task IDs are UUIDs;
decisions are `'approve'` or `'reject'`; tool review limits are 1..100. Pending
tool results have a `proposals` array with `approval_key`, `task_id`,
`qualified_tool`, `arguments`, `arguments_sha256`, `expires_at` and `status`.
Review those exact immutable arguments. Reviewer identity comes from
authentication.

Task view field names are snake_case (`task_id`, `agent_id`, `receipt_hash`,
`stop_reason`, `pending_review`), and state values keep Rust enum casing, such
as `Admitted`, `Running`, `AwaitingReview`, `Succeeded`, `Failed`, `Killed`,
`BudgetExhausted` and `ReconciliationRequired`. Recovery outcomes are
`restarted_before_execution`, `reconciliation_required` and
`finalization_unknown`. Uncertain effects or finalization require reconciliation;
they do not authorize automatic replay. After an ambiguous mutation response,
query status or pending state before deciding what to do next. `AbortSignal`
cancels only the HTTP request; the server may already have accepted it.

For durable tool review, inspect the exact proposal selected by the reviewer.
The queue can be empty; do not decide on a proposal automatically.

```typescript
const review = await host.pendingTools({ taskId: task.task_id as string, limit: 20 });
for (const proposal of review.proposals as Array<{
  approval_key: string; qualified_tool: string; arguments: JsonValue;
}>) {
  console.log(proposal.approval_key, proposal.qualified_tool, proposal.arguments);
}
// Use the key and decision selected by the reviewer after inspecting the proposal.
await host.decideTool('reviewer-selected-key', 'approve'); // or 'reject'
```

For an agent output awaiting review, use the reviewer-selected key and decision.
Recovery is an explicit operator action after interruption or uncertain status;
inspect its outcome and reconcile uncertain effects.

```typescript
await host.decide('reviewer-selected-key', 'approve', { editedOutput: 'reviewed result' });
const recovery = await host.recover(task.task_id as string);
console.log(recovery.outcome);
```

The lifecycle `/api/v1/reede/tasks` service and agent-host `/mcp` JSON-RPC service
may have different URLs. Identity comes from the token. HTTPS is required except
explicit `allowLocalHttp: true` on loopback. Redirects are refused. `AbortSignal`
cancels the HTTP request; use the run cancel operation to cancel accepted work.

Only GETs with 429/502/503/504 responses are retried, twice by default. Mutations
and ambiguous transport failures are not retried. Preserve invocation IDs when
explicitly retrying submission. Large JSON integers are returned as decimal
strings so signed numeric values are never silently rounded.

Offline verification invokes the separately installed Rust verifier from the
same release using execFile (no shell). No account or network is used. Supply a
trusted absolute verifier path. Its structured report separates supplied-segment
integrity from completeness against a trusted head/count and does not infer
legal qualification from timestamp presence. The SDK does not embed the engine
or expose hypothetical control-plane endpoints.
