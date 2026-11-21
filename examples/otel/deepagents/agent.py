"""A Deep Agents agent that delegates to one subagent, on a scripted fake chat model, traced
through LangSmith's OpenTelemetry integration (spans go to the OTLP endpoint only). No API key
and no network model call: the model replays three canned replies in order (the main agent
calls the `task` tool, the subagent answers, the main agent finishes).

Real-model variant (not run here): replace FakeChat with
  ChatOpenAI(base_url="https://api.cortecs.ai/v1", api_key=os.environ["CORTECS_API_KEY"], model=<a Cortecs model id>)
from langchain-openai. Do not point it at an OpenAI, Anthropic or Gemini endpoint.
"""
import os

os.environ.setdefault("LANGSMITH_TRACING", "true")
os.environ.setdefault("LANGSMITH_TRACING_MODE", "otel")
os.environ.setdefault("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")
os.environ.setdefault("OTEL_EXPORTER_OTLP_HEADERS", "x-reede-example=1")
os.environ.setdefault("OTEL_SERVICE_NAME", "reede-deepagents-example")

from typing import Any, List, Optional

from deepagents import create_deep_agent
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult

SCRIPT = [
    AIMessage(
        content="",
        tool_calls=[{"name": "task", "id": "call_1", "args": {"description": "Find what a reported receipt proves.", "subagent_type": "researcher"}}],
        usage_metadata={"input_tokens": 30, "output_tokens": 10, "total_tokens": 40},
    ),
    AIMessage(content="It proves what the agent reported.", usage_metadata={"input_tokens": 20, "output_tokens": 8, "total_tokens": 28}),
    AIMessage(content="A reported receipt proves what was reported.", usage_metadata={"input_tokens": 50, "output_tokens": 9, "total_tokens": 59}),
]


class FakeChat(BaseChatModel):
    calls: int = 0

    @property
    def _llm_type(self) -> str:
        return "fake-chat"

    def bind_tools(self, tools: Any, **kw: Any) -> "FakeChat":
        return self

    def _generate(self, messages: List[BaseMessage], stop: Optional[List[str]] = None, run_manager: Any = None, **kw: Any) -> ChatResult:
        msg = SCRIPT[self.calls]
        self.calls += 1
        return ChatResult(generations=[ChatGeneration(message=msg)])


agent = create_deep_agent(
    model=FakeChat(),
    system_prompt="Delegate research to the researcher, then answer briefly.",
    subagents=[{"name": "researcher", "description": "Looks things up.", "system_prompt": "Answer in one sentence."}],
)

if __name__ == "__main__":
    out = agent.invoke({"messages": [{"role": "user", "content": "What does a reported receipt prove?"}]})
    print(out["messages"][-1].content)
    from langsmith import Client

    Client().flush()
    from opentelemetry import trace

    provider = trace.get_tracer_provider()
    if hasattr(provider, "force_flush"):
        provider.force_flush()
