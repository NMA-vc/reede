//! Spans -> runs: a pure mapping from the stored span JSON (`spans/<seq>.json`, or a hosted
//! `byoa_spans.body`) to one readable run tree per trace. Docs: docs/ingest.md ("Runs").
//!
//! Every node is one of [`Kind`]. A trace root is always a `Run`. What else becomes a `Run`, a
//! `Step`, a `Model` call or a `Tool` call is decided per framework from the spans' own
//! attributes (see [`classify`]); everything that is none of these (middleware wrappers, stream
//! chunks, processors) is `Internal`: it is removed from the tree, its children move up to the
//! nearest kept ancestor, and its name and attributes are kept on that ancestor under
//! `internal`. Nothing a span carried is dropped: attributes the mapping does not read stay in
//! `attributes` verbatim.
//!
//! Tokens are summed from `Model` nodes only (`gen_ai.usage.input_tokens` / `output_tokens`), so
//! a parent span that also reports a rolled-up count is not counted twice. A node's `tokens` is
//! the sum over its subtree, child runs included. `cost_eur` is never invented: it is a cost
//! attribute the span carries, else a price from the host's [`Prices`] for the span's model, else
//! `None`.

use super::otlp::{AnyValue, KeyValue, SealedSpan, Value as Av};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Run,
    Step,
    Model,
    Tool,
    Internal,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Tokens {
    pub input: u64,
    pub output: u64,
}

/// A span folded into its nearest kept ancestor.
#[derive(Debug, Clone, Serialize)]
pub struct Folded {
    pub span_id: String,
    pub name: String,
    pub attributes: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Node {
    pub span_id: String,
    pub kind: Kind,
    pub name: String,
    /// Agent name for a `Run` (a subagent's own name), when the spans carry one.
    pub agent: Option<String>,
    pub model: Option<String>,
    pub started_unix_nano: u64,
    pub ended_unix_nano: u64,
    /// `ok`, `error` or `unset`.
    pub status: &'static str,
    pub tokens: Tokens,
    pub cost_eur: Option<f64>,
    /// Attributes the mapping did not consume, verbatim.
    pub attributes: Map<String, Value>,
    pub internal: Vec<Folded>,
    pub children: Vec<Node>,
    /// Model calls below (or this node, for a model call), and how many of them are priced.
    #[serde(skip)]
    models: usize,
    #[serde(skip)]
    priced: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceRun {
    pub trace_id: String,
    /// `deepagents`, `langgraph`, `mastra`, `genai` (gen_ai.* only) or `unknown`.
    pub framework: &'static str,
    pub span_count: usize,
    /// One entry per trace root; more than one only when a span's parent never arrived (then the
    /// orphan is a root of its own and `problems` says so).
    pub runs: Vec<Node>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub traces: Vec<TraceRun>,
    /// Spans that could not be mapped or were suspicious, never silently dropped.
    pub problems: Vec<String>,
}

/// Host-supplied EUR prices per million tokens, keyed by model name. Empty by default.
#[derive(Debug, Clone, Default)]
pub struct Prices(pub BTreeMap<String, (f64, f64)>);

struct Sp {
    span_id: String,
    parent: String,
    name: String,
    start: u64,
    end: u64,
    status: &'static str,
    attrs: Vec<(String, Value)>,
    scope: String,
}

impl Sp {
    fn get(&self, k: &str) -> Option<&Value> {
        self.attrs.iter().find(|(key, _)| key == k).map(|(_, v)| v)
    }
    fn str(&self, k: &str) -> Option<&str> {
        self.get(k)?.as_str()
    }
    fn num(&self, k: &str) -> Option<u64> {
        match self.get(k)? {
            Value::Number(n) => n.as_u64().or_else(|| {
                n.as_f64()
                    .filter(|f| f.is_finite() && *f >= 0.0 && f.fract() == 0.0)
                    .map(|f| f as u64)
            }),
            _ => None,
        }
    }
    fn float(&self, k: &str) -> Option<f64> {
        self.get(k)?.as_f64().filter(|f| f.is_finite() && *f >= 0.0)
    }
}

fn any_json(v: &AnyValue) -> Value {
    match &v.value {
        None => Value::Null,
        Some(Av::StringValue(s)) => json!(s),
        Some(Av::BoolValue(b)) => json!(b),
        Some(Av::IntValue(i)) => json!(i),
        Some(Av::DoubleValue(d)) => json!(d),
        Some(Av::ArrayValue(a)) => Value::Array(a.values.iter().map(any_json).collect()),
        Some(Av::KvlistValue(l)) => Value::Object(kv_map(&l.values)),
        Some(Av::BytesValue(b)) => json!(hex::encode(b)),
    }
}

fn kv_map(kvs: &[KeyValue]) -> Map<String, Value> {
    kvs.iter()
        .map(|kv| {
            (
                kv.key.clone(),
                kv.value.as_ref().map_or(Value::Null, any_json),
            )
        })
        .collect()
}

/// Attribute keys the mapping reads. They are removed from `Node::attributes`; the typed
/// fields carry them instead.
const CONSUMED: &[&str] = &[
    "gen_ai.operation.name",
    "gen_ai.agent.name",
    "gen_ai.tool.name",
    "gen_ai.request.model",
    "gen_ai.response.model",
    "gen_ai.usage.input_tokens",
    "gen_ai.usage.output_tokens",
    "gen_ai.usage.cost_eur",
    "reede.cost_eur",
    "langsmith.span.kind",
    "langsmith.metadata.langgraph_node",
    "langsmith.metadata.lc_agent_name",
    "langsmith.metadata.ls_model_name",
    "mastra.span.type",
];

fn framework(spans: &[Sp]) -> &'static str {
    let any = |k: &str| spans.iter().any(|s| s.get(k).is_some());
    if any("mastra.span.type") || spans.iter().any(|s| s.scope.starts_with("@mastra/")) {
        "mastra"
    } else if any("langsmith.span.kind") {
        let deep = spans
            .iter()
            .any(|s| s.str("langsmith.metadata.ls_integration") == Some("deepagents"));
        if deep {
            "deepagents"
        } else {
            "langgraph"
        }
    } else if spans
        .iter()
        .any(|s| s.get("gen_ai.operation.name").is_some())
    {
        "genai"
    } else {
        "unknown"
    }
}

/// The kind of one span given its already-resolved parent (`None` for a trace root) and the
/// agent name of the nearest enclosing run.
fn classify(s: &Sp, parent: Option<Kind>, run_agent: Option<&str>) -> Kind {
    if parent.is_none() {
        return Kind::Run;
    }
    let op = s.str("gen_ai.operation.name").unwrap_or("");
    // Mastra: its own span type is the precise signal.
    if let Some(t) = s.str("mastra.span.type") {
        return match t {
            "agent_run" | "workflow_run" => Kind::Run,
            "workflow_step" | "model_generation" | "model_step" => Kind::Step,
            "model_inference" => Kind::Model,
            "tool_call" | "mcp_tool_call" => Kind::Tool,
            _ => Kind::Internal,
        };
    }
    // LangSmith (LangGraph, Deep Agents).
    if let Some(k) = s.str("langsmith.span.kind") {
        return match k {
            "llm" => Kind::Model,
            "tool" => Kind::Tool,
            "chain" => {
                let agent = s.str("langsmith.metadata.lc_agent_name");
                if agent.is_some() && agent != run_agent && is_agent_root(s) {
                    Kind::Run
                } else if parent == Some(Kind::Run)
                    && s.get("langsmith.metadata.langgraph_node").is_some()
                {
                    Kind::Step
                } else {
                    Kind::Internal
                }
            }
            _ => Kind::Internal,
        };
    }
    // Plain GenAI conventions.
    match op {
        "invoke_agent" | "create_agent" | "invoke_workflow" => Kind::Run,
        "chat" | "text_completion" | "generate_content" | "embeddings" => Kind::Model,
        "execute_tool" => Kind::Tool,
        _ => Kind::Internal,
    }
}

/// A LangSmith subagent run span is the one whose name IS its agent name (Deep Agents names
/// the subagent's graph after it); the spans below it only carry the name as metadata.
fn is_agent_root(s: &Sp) -> bool {
    s.str("langsmith.metadata.lc_agent_name") == Some(s.name.as_str())
}

fn status_of(code: i32) -> &'static str {
    match code {
        1 => "ok",
        2 => "error",
        _ => "unset",
    }
}

fn to_sp(s: &SealedSpan) -> Sp {
    let sp = &s.span;
    Sp {
        span_id: hex::encode(&sp.span_id),
        parent: hex::encode(&sp.parent_span_id),
        name: sp.name.clone(),
        start: sp.start_time_unix_nano,
        end: sp.end_time_unix_nano,
        status: status_of(sp.status.as_ref().map_or(0, |st| st.code)),
        attrs: sp
            .attributes
            .iter()
            .map(|kv| {
                (
                    kv.key.clone(),
                    kv.value.as_ref().map_or(Value::Null, any_json),
                )
            })
            .collect(),
        scope: s.scope.as_ref().map_or(String::new(), |c| c.name.clone()),
    }
}

/// Map labelled stored-span values (label = file name or row id, used in problem messages) to
/// runs. Never panics: a value that is not a sealed span, or a span that repeats a span id, is
/// listed in `problems` and skipped.
pub fn map_runs(items: &[(String, Value)], prices: &Prices) -> Report {
    let mut problems = Vec::new();
    let mut by_trace: BTreeMap<String, Vec<Sp>> = BTreeMap::new();
    for (label, v) in items {
        let sealed: SealedSpan = match serde_json::from_value(v.clone()) {
            Ok(s) => s,
            Err(e) => {
                problems.push(format!("{label}: not a stored span ({e})"));
                continue;
            }
        };
        if sealed.span.span_id.is_empty() || sealed.span.trace_id.is_empty() {
            problems.push(format!("{label}: span without trace or span id"));
            continue;
        }
        by_trace
            .entry(hex::encode(&sealed.span.trace_id))
            .or_default()
            .push(to_sp(&sealed));
    }
    let traces = by_trace
        .into_iter()
        .map(|(trace_id, spans)| map_trace(trace_id, spans, prices, &mut problems))
        .collect();
    Report { traces, problems }
}

fn map_trace(
    trace_id: String,
    spans: Vec<Sp>,
    prices: &Prices,
    problems: &mut Vec<String>,
) -> TraceRun {
    let fw = framework(&spans);
    let span_count = spans.len();
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut kept: Vec<Sp> = Vec::new();
    for s in spans {
        if index.contains_key(&s.span_id) {
            problems.push(format!(
                "trace {trace_id}: span {} appears twice, later copy ignored",
                s.span_id
            ));
            continue;
        }
        index.insert(s.span_id.clone(), kept.len());
        kept.push(s);
    }
    let mut kids: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut roots = Vec::new();
    for (i, s) in kept.iter().enumerate() {
        match index.get(&s.parent) {
            Some(&p) if p != i => kids.entry(p).or_default().push(i),
            _ if s.parent.is_empty() => roots.push(i),
            _ => {
                problems.push(format!(
                    "trace {trace_id}: span {} ({}) has parent {} that never arrived; shown as its own run",
                    s.span_id, s.name, s.parent
                ));
                roots.push(i);
            }
        }
    }
    let mut cx = Ctx {
        all: &kept,
        kids: &kids,
        prices,
        seen: 0,
        flattened: 0,
    };
    let mut runs = Vec::new();
    for r in roots {
        runs.push(build(&mut cx, r, None, None, 0));
    }
    let (seen, flattened) = (cx.seen, cx.flattened);
    if flattened > 0 {
        problems.push(format!(
            "trace {trace_id}: nesting deeper than {MAX_DEPTH}; {flattened} span(s) below that are listed flat under `internal`"
        ));
    }
    if seen < kept.len() {
        problems.push(format!(
            "trace {trace_id}: {} span(s) unreachable from any root (parent cycle), not shown",
            kept.len() - seen
        ));
    }
    runs.sort_by_key(|n| (n.started_unix_nano, n.span_id.clone()));
    TraceRun {
        trace_id,
        framework: fw,
        span_count,
        runs,
    }
}

/// Deepest nesting of spans kept as a tree. A span chain deeper than this (a tenant can send
/// thousands) is flattened into `internal` of the node at the cap, so building, serializing and
/// dropping the tree never recurse deeper than this.
pub const MAX_DEPTH: usize = 64;

struct Ctx<'a> {
    all: &'a [Sp],
    kids: &'a HashMap<usize, Vec<usize>>,
    prices: &'a Prices,
    seen: usize,
    /// Spans flattened because of [`MAX_DEPTH`].
    flattened: usize,
}

fn folded_of(s: &Sp) -> Folded {
    let mut attributes = Map::new();
    for (k, v) in &s.attrs {
        if !CONSUMED.contains(&k.as_str()) {
            attributes.insert(k.clone(), v.clone());
        }
    }
    Folded {
        span_id: s.span_id.clone(),
        name: s.name.clone(),
        attributes,
    }
}

/// Build the kept node for span `i` (a root, or a child `build_children` classified as kept).
fn build(
    cx: &mut Ctx,
    i: usize,
    parent_kind: Option<Kind>,
    run_agent: Option<&str>,
    depth: usize,
) -> Node {
    cx.seen += 1;
    let s = &cx.all[i];
    let kind = classify(s, parent_kind, run_agent);
    let agent = match kind {
        Kind::Run => s
            .str("gen_ai.agent.name")
            .or_else(|| s.str("langsmith.metadata.lc_agent_name"))
            .map(str::to_string),
        _ => None,
    };
    let my_agent = agent.as_deref().or(run_agent);
    let mut own_folded = Vec::new();
    let mut children = build_children(cx, i, kind, my_agent, depth, &mut own_folded);
    children.sort_by_key(|c| (c.started_unix_nano, c.span_id.clone()));

    let s = &cx.all[i];
    let model = s
        .str("gen_ai.response.model")
        .or_else(|| s.str("gen_ai.request.model"))
        .or_else(|| s.str("langsmith.metadata.ls_model_name"))
        .map(str::to_string);
    let mut tokens = Tokens::default();
    let mut cost_sum = 0.0;
    let (mut models, mut priced) = (0usize, 0usize);
    if kind == Kind::Model {
        // A model call counts its own tokens only; whatever hangs below it does not add.
        tokens.input = s.num("gen_ai.usage.input_tokens").unwrap_or(0);
        tokens.output = s.num("gen_ai.usage.output_tokens").unwrap_or(0);
        models = 1;
        let own = s
            .float("gen_ai.usage.cost_eur")
            .or_else(|| s.float("reede.cost_eur"))
            .or_else(|| {
                let (pin, pout) = cx.prices.0.get(model.as_deref()?)?;
                Some((tokens.input as f64 * pin + tokens.output as f64 * pout) / 1_000_000.0)
            });
        if let Some(c) = own {
            priced = 1;
            cost_sum = c;
        }
    } else {
        for c in &children {
            tokens.input += c.tokens.input;
            tokens.output += c.tokens.output;
            models += c.models;
            priced += c.priced;
            cost_sum += c.cost_eur.unwrap_or(0.0);
        }
    }
    let mut attributes = Map::new();
    for (k, v) in &s.attrs {
        if !CONSUMED.contains(&k.as_str()) {
            attributes.insert(k.clone(), v.clone());
        }
    }
    let name = match (kind, s.str("gen_ai.tool.name")) {
        (Kind::Tool, Some(t)) => t.to_string(),
        _ => s.name.clone(),
    };
    Node {
        span_id: s.span_id.clone(),
        kind,
        name,
        agent,
        model,
        started_unix_nano: s.start,
        ended_unix_nano: s.end,
        status: s.status,
        tokens,
        // Null unless EVERY model call below is priced: a partial sum would understate.
        cost_eur: (models > 0 && priced == models).then_some(cost_sum),
        models,
        priced,
        attributes,
        internal: own_folded,
        children,
    }
}

/// Children of span `i` as kept nodes: `Internal` descendants are folded into `folded` and their
/// own children are lifted to this level. At [`MAX_DEPTH`] the whole remaining subtree is folded
/// instead, iteratively.
fn build_children(
    cx: &mut Ctx,
    i: usize,
    parent_kind: Kind,
    run_agent: Option<&str>,
    depth: usize,
    folded: &mut Vec<Folded>,
) -> Vec<Node> {
    let mut out = Vec::new();
    let mut ids = cx.kids.get(&i).cloned().unwrap_or_default();
    ids.sort_by_key(|&c| (cx.all[c].start, cx.all[c].span_id.clone()));
    if depth + 1 >= MAX_DEPTH {
        let mut stack = ids;
        stack.reverse();
        while let Some(c) = stack.pop() {
            cx.seen += 1;
            cx.flattened += 1;
            folded.push(folded_of(&cx.all[c]));
            let mut sub = cx.kids.get(&c).cloned().unwrap_or_default();
            sub.sort_by_key(|&x| std::cmp::Reverse((cx.all[x].start, cx.all[x].span_id.clone())));
            stack.extend(sub);
        }
        return out;
    }
    for c in ids {
        if classify(&cx.all[c], Some(parent_kind), run_agent) == Kind::Internal {
            cx.seen += 1;
            folded.push(folded_of(&cx.all[c]));
            out.extend(build_children(
                cx,
                c,
                parent_kind,
                run_agent,
                depth + 1,
                folded,
            ));
        } else {
            out.push(build(cx, c, Some(parent_kind), run_agent, depth + 1));
        }
    }
    out
}

/// Number of `Step` nodes in a tree (a list view's "step count"). Depth is bounded by
/// [`MAX_DEPTH`], so the recursion is too.
pub fn step_count(n: &Node) -> usize {
    usize::from(n.kind == Kind::Step) + n.children.iter().map(step_count).sum::<usize>()
}

/// The report as the JSON `reede ingest runs` prints.
pub fn to_json(r: &Report) -> Value {
    serde_json::to_value(r).unwrap_or(Value::Null)
}
