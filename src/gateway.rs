use crate::error::ReedeError;
use crate::policy::DerivedPolicy;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskContext {
    pub task_id: Uuid,
    pub tenant_id: String,
    pub agent_spec_id: String,
    pub policy: DerivedPolicy,
    pub lease_id: Option<String>,
    pub receipt_chain_head: Option<String>,
    /// Whether the observed dispatch may persist (redacted) prompt/response
    /// content for this task. Carried on the context rather than assumed:
    /// the host-side `Gateway` impl reads it in place of the process-wide
    /// default so a manifest that opted into content capture keeps that
    /// behaviour once its model calls route through the gateway. Defaults to
    /// false (never persist raw content) for any caller that does not set it.
    #[serde(default)]
    pub capture_content: bool,
    /// Optional task-scoped token budget. Skipped from wire serialization; the
    /// in-process gateway owns the live reservation state.
    #[serde(skip)]
    pub token_budget: Option<std::sync::Arc<crate::token_budget::TokenBudget>>,
}

/// A tool the model may call -- reede-native, with its JSON schema carried as
/// a `serde_json::Value` so reede depends on nothing host-side. The the host application
/// impl maps this to/from `mcp_core::types::Tool`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

/// A tool call the model emitted (or an assistant history turn replays) --
/// reede-native. The the host application impl maps this to/from
/// `the host application::messages::ToolCall`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMessage {
    pub role: String,
    pub content: String,
    /// Set on a `role = "tool"` message: the id of the assistant tool call
    /// this message carries the result for. Required for the provider to link
    /// a tool result back to its call; `None` on every other role.
    #[serde(default)]
    pub tool_call_id: Option<String>,
    /// Set on a replayed `role = "assistant"` message that itself issued tool
    /// calls, so multi-turn history round-trips without dropping the calls.
    /// Empty on every other role.
    #[serde(default)]
    pub tool_calls: Vec<ToolCall>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelRequest {
    pub model: String,
    pub messages: Vec<ModelMessage>,
    #[serde(default)]
    pub temperature: Option<f32>,
    /// The tools the model is permitted to call this turn. Empty = no tools
    /// (backward-compatible: the host application impl passes `None` to the provider).
    #[serde(default)]
    pub tools: Vec<ToolSpec>,
    /// Provider output ceiling used as a hint; the task budget still reserves
    /// the full remaining task capacity because input tokens are also counted.
    #[serde(default)]
    pub max_tokens: Option<u32>,
    /// A JSON Schema the response must satisfy (native structured output). `None` = free text,
    /// the behaviour of every request written before this field existed. Carried as a plain
    /// `serde_json::Value` so reede depends on nothing host-side. A gateway that cannot
    /// honour it must fail the call rather than silently return unconstrained text. Note that a
    /// provider's structured-output path may not accept an output ceiling, so `max_tokens` is a
    /// hint only for such a request; the task token budget still reserves and settles the call.
    /// A reply is checked only partly (it is JSON, an object when the schema says so, and carries
    /// every `required` key); property types, enums and nested objects are not validated.
    ///
    /// Skipped on the wire when `None`, so a request without a schema serializes to exactly the
    /// bytes it had before this field existed (the gateway sizes a request from those bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_schema: Option<serde_json::Value>,
    /// The label a provider needs next to `response_schema` (for example an OpenAI-style
    /// `json_schema.name`). Ignored when `response_schema` is `None`; a gateway uses a fixed
    /// default when it is absent. Skipped on the wire when `None`, like `response_schema`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_schema_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelResponse {
    pub content: String,
    pub model: String,
    pub tokens_in: u32,
    pub tokens_out: u32,
    pub duration_ms: u64,
    /// The tool calls the model requested. Empty = the model returned text
    /// (a final answer), not a call.
    #[serde(default)]
    pub tool_calls: Vec<ToolCall>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResponse {
    pub output: Value,
    pub duration_ms: u64,
    pub hosts_contacted: Vec<String>,
}

#[async_trait]
pub trait Gateway: Send + Sync {
    /// Authorize a tool before a durable outbound claim is acquired.
    async fn authorize_tool(&self, ctx: &TaskContext, tool: &str) -> Result<(), ReedeError> {
        if crate::grant_permits(&ctx.policy.resource_grants, tool, "invoke") {
            Ok(())
        } else {
            Err(ReedeError::GrantDenied {
                resource: tool.to_string(),
                action: "invoke".to_string(),
            })
        }
    }

    async fn call_model(
        &self,
        ctx: &TaskContext,
        req: ModelRequest,
    ) -> Result<ModelResponse, ReedeError>;

    async fn call_tool(
        &self,
        ctx: &TaskContext,
        tool: &str,
        input: Value,
    ) -> Result<ToolResponse, ReedeError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Both-directions (rule 3): the tool schema on a request survives a
    // serde round-trip, and a request written before this field existed (no
    // `tools` key) still deserializes -- to an empty tool list, never an
    // error -- so the added field is backward-compatible.
    #[test]
    fn tools_round_trip_and_default_empty() {
        let req = ModelRequest {
            model: "m".into(),
            messages: vec![],
            temperature: None,
            tools: vec![ToolSpec {
                name: "search".into(),
                description: "search the web".into(),
                input_schema: serde_json::json!({"type": "object"}),
            }],
            max_tokens: None,
            response_schema: None,
            response_schema_name: None,
        };
        let wire = serde_json::to_string(&req).unwrap();
        let back: ModelRequest = serde_json::from_str(&wire).unwrap();
        assert_eq!(back.tools.len(), 1);
        assert_eq!(back.tools[0].name, "search");

        // A pre-tools payload (no `tools` key) defaults to empty.
        let legacy: ModelRequest = serde_json::from_str(r#"{"model":"m","messages":[]}"#).unwrap();
        assert!(legacy.tools.is_empty());
    }

    // The structured-output schema survives a round-trip, and a request written before the
    // field existed (no `response_schema` key) deserializes to `None`, never an error.
    #[test]
    fn response_schema_round_trips_and_defaults_to_none() {
        let req = ModelRequest {
            model: "m".into(),
            messages: vec![],
            temperature: None,
            tools: vec![],
            max_tokens: None,
            response_schema: Some(serde_json::json!({"type": "object", "required": ["a"]})),
            response_schema_name: Some("out".into()),
        };
        let back: ModelRequest =
            serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(back.response_schema, req.response_schema);
        assert_eq!(back.response_schema_name.as_deref(), Some("out"));

        let legacy: ModelRequest = serde_json::from_str(r#"{"model":"m","messages":[]}"#).unwrap();
        assert_eq!(legacy.response_schema, None);
        assert_eq!(legacy.response_schema_name, None);
    }

    // The serialized bytes of a request that carries no schema are the bytes
    // it had before `response_schema` existed. `CapabilityGateway::call_model` sizes every
    // request from `serde_json::to_vec(&req)` against the token budget, so two extra `null`
    // keys would shift that size for every existing caller. Pinned literally, not recomputed.
    #[test]
    fn a_request_without_a_schema_serializes_to_the_pre_f2b_bytes() {
        let minimal = ModelRequest {
            model: "m".into(),
            messages: vec![],
            temperature: None,
            tools: vec![],
            max_tokens: None,
            response_schema: None,
            response_schema_name: None,
        };
        assert_eq!(
            serde_json::to_string(&minimal).unwrap(),
            r#"{"model":"m","messages":[],"temperature":null,"tools":[],"max_tokens":null}"#
        );

        let with_message = ModelRequest {
            messages: vec![ModelMessage {
                role: "user".into(),
                content: "hi".into(),
                tool_call_id: None,
                tool_calls: vec![],
            }],
            temperature: Some(0.5),
            max_tokens: Some(64),
            ..minimal
        };
        assert_eq!(
            serde_json::to_string(&with_message).unwrap(),
            concat!(
                r#"{"model":"m","messages":[{"role":"user","content":"hi","tool_call_id":null,"tool_calls":[]}],"#,
                r#""temperature":0.5,"tools":[],"max_tokens":64}"#
            )
        );
    }

    // A response's tool calls survive a round-trip, and a legacy response
    // with no `tool_calls` key deserializes to an empty list (final answer).
    #[test]
    fn tool_calls_round_trip_and_default_empty() {
        let resp = ModelResponse {
            content: String::new(),
            model: "m".into(),
            tokens_in: 1,
            tokens_out: 2,
            duration_ms: 3,
            tool_calls: vec![ToolCall {
                id: "call_1".into(),
                name: "search".into(),
                arguments: serde_json::json!({"q": "X"}),
            }],
        };
        let wire = serde_json::to_string(&resp).unwrap();
        let back: ModelResponse = serde_json::from_str(&wire).unwrap();
        assert_eq!(back.tool_calls, resp.tool_calls);

        let legacy: ModelResponse = serde_json::from_str(
            r#"{"content":"hi","model":"m","tokens_in":0,"tokens_out":0,"duration_ms":0}"#,
        )
        .unwrap();
        assert!(legacy.tool_calls.is_empty());
    }

    // A tool-result message carries its `tool_call_id`; an assistant replay
    // carries its `tool_calls`; a plain message omits both and still parses.
    #[test]
    fn message_tool_fields_round_trip() {
        let tool_msg = ModelMessage {
            role: "tool".into(),
            content: "{\"hits\":3}".into(),
            tool_call_id: Some("call_1".into()),
            tool_calls: vec![],
        };
        let back: ModelMessage =
            serde_json::from_str(&serde_json::to_string(&tool_msg).unwrap()).unwrap();
        assert_eq!(back.tool_call_id.as_deref(), Some("call_1"));

        let legacy: ModelMessage =
            serde_json::from_str(r#"{"role":"user","content":"hi"}"#).unwrap();
        assert_eq!(legacy.tool_call_id, None);
        assert!(legacy.tool_calls.is_empty());
    }
}
