export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };
export interface RequestOptions { signal?: AbortSignal; }
export interface ClientOptions { timeoutMs?: number; readRetries?: number; allowLocalHttp?: boolean; }
export type TokenProvider = string | (() => string | Promise<string>);
export class ReedeError extends Error { readonly code: string; readonly status?: number; readonly requestId?: string; }
export class ReedeClient {
  constructor(baseUrl: string, token: TokenProvider, options?: ClientOptions);
  readonly baseUrl: string;
  listTasks(options?: RequestOptions & { limit?: number }): Promise<JsonObject[]>;
  getTask(id: string, options?: RequestOptions): Promise<JsonObject>;
  cancelTask(id: string, options?: RequestOptions): Promise<JsonObject>;
  listLeases(id: string, options?: RequestOptions): Promise<JsonObject[]>;
}
export class AgentHostClient extends ReedeClient {
  submit(agentId: string, input: JsonObject, options?: RequestOptions & { invocationId?: string }): Promise<JsonObject>;
  start(id: string, options?: RequestOptions): Promise<JsonObject>;
  status(id: string, options?: RequestOptions): Promise<JsonObject>;
  cancel(id: string, options?: RequestOptions): Promise<JsonObject>;
  recover(id: string, options?: RequestOptions): Promise<RecoveryReport>;
  pending(options?: RequestOptions): Promise<JsonValue>;
  pendingTools(options?: RequestOptions & { taskId?: string; limit?: number }): Promise<JsonObject>;
  decideTool(approvalKey: string, decision: "approve" | "reject", options?: RequestOptions): Promise<JsonObject>;
  decide(approvalKey: string, decision: "approve" | "reject", options?: RequestOptions & { editedOutput?: string }): Promise<JsonObject>;
}
export interface RecoveryReport {
  task_id: string;
  outcome: "restarted_before_execution" | "reconciliation_required" | "finalization_unknown";
}
export interface VerificationOptions {
  verifier?: string; expectedHead?: string; expectedCount?: number; expectedTenant?: string; requireGenesis?: boolean;
}
export interface VerificationReport {
  schema: "reede-verification-v1"; authentic: true; chain_verified: true;
  receipt_count: number; tenant_id: string; head: string;
  completeness: "verified_against_trusted_boundary" | "supplied_segment_only";
  timestamp: "absent" | "present_not_validated"; legally_qualified: null;
}
export function verifyFile(chain: string, publicKey: string, options?: VerificationOptions): Promise<VerificationReport>;
