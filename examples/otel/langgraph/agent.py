"""A two-step LangGraph agent on a fake chat model, traced through LangSmith's OpenTelemetry
integration. LANGSMITH_TRACING_MODE=otel sends spans to the OTLP endpoint only; nothing goes
to LangSmith. No API key is needed (the fake model makes no network call).

Real-model variant (not run here): replace FakeChat with
  ChatOpenAI(base_url="https://api.cortecs.ai/v1", api_key=os.environ["CORTECS_API_KEY"], model=<a Cortecs model id>)
from langchain-openai. That is the OpenAI-compatible wire format Cortecs serves; no OpenAI
endpoint is used.
"""
import os

os.environ.setdefault("LANGSMITH_TRACING", "true")
os.environ.setdefault("LANGSMITH_TRACING_MODE", "otel")
os.environ.setdefault("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")
# A non-empty headers value stops LangSmith from adding an x-api-key header.
os.environ.setdefault("OTEL_EXPORTER_OTLP_HEADERS", "x-reede-example=1")
os.environ.setdefault("OTEL_SERVICE_NAME", "reede-langgraph-example")

from typing import Any, List, Optional, TypedDict

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langgraph.graph import END, START, StateGraph


class FakeChat(BaseChatModel):
    """Deterministic model that also reports token usage, like a real provider would."""

    @property
    def _llm_type(self) -> str:
        return "fake-chat"

    def _generate(self, messages: List[BaseMessage], stop: Optional[List[str]] = None, run_manager: Any = None, **kw: Any) -> ChatResult:
        msg = AIMessage(
            content=f"echo: {messages[-1].content}",
            usage_metadata={"input_tokens": 12, "output_tokens": 7, "total_tokens": 19},
        )
        return ChatResult(generations=[ChatGeneration(message=msg)])


model = FakeChat()


class State(TypedDict):
    question: str
    draft: str
    answer: str


def draft(state: State) -> dict:
    return {"draft": model.invoke([HumanMessage(state["question"])]).content}


def finalize(state: State) -> dict:
    return {"answer": model.invoke([HumanMessage(state["draft"])]).content}


graph = StateGraph(State)
graph.add_node("draft", draft)
graph.add_node("finalize", finalize)
graph.add_edge(START, "draft")
graph.add_edge("draft", "finalize")
graph.add_edge("finalize", END)
app = graph.compile()

if __name__ == "__main__":
    print(app.invoke({"question": "What does a reported receipt prove?"})["answer"])
    from langsmith import Client

    Client().flush()  # let queued runs reach the span processor
    from opentelemetry import trace

    provider = trace.get_tracer_provider()
    if hasattr(provider, "force_flush"):
        provider.force_flush()
