//! Spans -> runs on REAL span exports captured from `reede serve` (tests/fixtures/otel/*.json:
//! LangGraph, Deep Agents and Mastra examples under examples/otel, fake models, pinned versions).

use reede::ingest::runs::{map_runs, step_count, Kind, Node, Prices, Report};
use serde_json::{json, Value};

fn fixture(name: &str) -> Vec<(String, Value)> {
    let path = format!(
        "{}/tests/fixtures/otel/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let spans: Vec<Value> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    spans
        .into_iter()
        .enumerate()
        .map(|(i, v)| (format!("{name}#{i}"), v))
        .collect()
}

fn one_run(r: &Report) -> &Node {
    assert!(r.problems.is_empty(), "{:?}", r.problems);
    assert_eq!(r.traces.len(), 1);
    assert_eq!(r.traces[0].runs.len(), 1, "one run per trace root");
    &r.traces[0].runs[0]
}

fn find<'a>(n: &'a Node, kind: Kind, out: &mut Vec<&'a Node>) {
    if n.kind == kind {
        out.push(n);
    }
    n.children.iter().for_each(|c| find(c, kind, out));
}

fn all(n: &Node, kind: Kind) -> Vec<&Node> {
    let mut v = Vec::new();
    find(n, kind, &mut v);
    v
}

fn names(v: &[&Node]) -> Vec<String> {
    v.iter().map(|n| n.name.clone()).collect()
}

#[test]
fn langgraph_nodes_are_steps() {
    let r = map_runs(&fixture("langgraph"), &Prices::default());
    let run = one_run(&r);
    assert_eq!(r.traces[0].framework, "langgraph");
    assert_eq!(run.name, "LangGraph");
    assert_eq!(
        names(&run.children.iter().collect::<Vec<_>>()),
        ["draft", "finalize"]
    );
    assert_eq!(step_count(run), 2);
    assert_eq!(all(run, Kind::Model).len(), 2);
    assert_eq!((run.tokens.input, run.tokens.output), (24, 14));
    assert_eq!(
        run.cost_eur, None,
        "no price anywhere: null, never invented"
    );
}

#[test]
fn deep_agents_subagent_is_a_child_run_under_its_task_tool() {
    let r = map_runs(&fixture("deepagents"), &Prices::default());
    let run = one_run(&r);
    assert_eq!(r.traces[0].framework, "deepagents");
    assert_eq!(r.traces[0].span_count, 33);
    let runs = all(run, Kind::Run);
    assert_eq!(names(&runs), ["LangGraph", "researcher"]);
    let sub = runs[1];
    assert_eq!(sub.agent.as_deref(), Some("researcher"));
    assert_eq!((sub.tokens.input, sub.tokens.output), (20, 8));
    // The subagent hangs under the main agent's `task` tool call, itself inside the `tools` step.
    let tools_step = run.children.iter().find(|c| c.name == "tools").unwrap();
    assert_eq!(tools_step.kind, Kind::Step);
    let task = &tools_step.children[0];
    assert_eq!((task.kind, task.name.as_str()), (Kind::Tool, "task"));
    assert_eq!(task.children[0].span_id, sub.span_id);
    // Main-agent steps in order; the subagent's steps are its own.
    assert_eq!(
        names(&run.children.iter().collect::<Vec<_>>()),
        [
            "PatchToolCallsMiddleware.before_agent",
            "model",
            "tools",
            "model",
            "_ParentNotifierMiddleware.after_agent"
        ]
    );
    assert_eq!(
        names(&sub.children.iter().collect::<Vec<_>>()),
        ["PatchToolCallsMiddleware.before_agent", "model"]
    );
    // 30+20+50 in, 10+8+9 out, child run included, each model call counted once.
    assert_eq!((run.tokens.input, run.tokens.output), (100, 27));
    assert_eq!(all(run, Kind::Model).len(), 3);
    // Middleware wrappers are folded, not dropped.
    assert!(run.children.iter().any(|c| c
        .internal
        .iter()
        .any(|f| f.name == "FilesystemMiddleware.wrap_model_call")));
}

#[test]
fn unknown_attributes_survive_verbatim() {
    let r = map_runs(&fixture("deepagents"), &Prices::default());
    let run = one_run(&r);
    assert_eq!(
        run.attributes["langsmith.metadata.ls_integration"],
        json!("deepagents")
    );
    assert_eq!(
        run.attributes["langsmith.trace.session_name"],
        json!("default")
    );
    // Consumed keys moved to typed fields, not duplicated.
    assert!(!run.attributes.contains_key("gen_ai.operation.name"));
    let r = map_runs(&fixture("mastra-agent"), &Prices::default());
    let run = one_run(&r);
    assert!(run.attributes.keys().any(|k| k.starts_with("mastra.")));
    let folded: Vec<_> = run
        .children
        .iter()
        .flat_map(|c| &c.internal)
        .chain(&run.internal)
        .collect();
    assert!(folded
        .iter()
        .any(|f| f.attributes.keys().any(|k| k.starts_with("mastra."))));
}

#[test]
fn mastra_agent_run_model_calls_and_tool() {
    let r = map_runs(&fixture("mastra-agent"), &Prices::default());
    let run = one_run(&r);
    assert_eq!(r.traces[0].framework, "mastra");
    assert_eq!(
        (run.kind, run.name.as_str(), run.agent.as_deref()),
        (Kind::Run, "invoke_agent demo", Some("demo"))
    );
    assert_eq!(names(&all(run, Kind::Tool)), ["lookup"]);
    let models = all(run, Kind::Model);
    assert_eq!(models.len(), 2);
    assert_eq!(models[0].model.as_deref(), Some("mock-model-id"));
    assert_eq!((run.tokens.input, run.tokens.output), (80, 19));
    let tool = all(run, Kind::Tool)[0];
    assert!(tool.started_unix_nano > 0 && tool.ended_unix_nano >= tool.started_unix_nano);
}

#[test]
fn mastra_workflow_steps() {
    let r = map_runs(&fixture("mastra-workflow"), &Prices::default());
    let run = one_run(&r);
    assert_eq!(run.name, "invoke_workflow shouter");
    assert_eq!(
        names(&run.children.iter().collect::<Vec<_>>()),
        ["workflow_step shout", "workflow_step exclaim"]
    );
    assert!(run.children.iter().all(|c| c.kind == Kind::Step));
    assert_eq!(run.tokens.input + run.tokens.output, 0);
}

#[test]
fn cost_comes_from_the_host_price_table_only_for_a_known_model() {
    let mut prices = Prices::default();
    prices.0.insert("mock-model-id".into(), (1.0, 2.0)); // EUR per million tokens
    let r = map_runs(&fixture("mastra-agent"), &prices);
    let c = one_run(&r).cost_eur.expect("priced model");
    assert!((c - (80.0 + 38.0) / 1e6).abs() < 1e-12);
    // The same table does not price a model it does not list.
    assert_eq!(
        one_run(&map_runs(&fixture("langgraph"), &prices)).cost_eur,
        None
    );
}

#[test]
fn a_cost_attribute_on_the_span_is_used() {
    let mut items = fixture("mastra-agent");
    for (_, v) in items.iter_mut() {
        let attrs = v["span"]["attributes"].as_array_mut().unwrap();
        if attrs.iter().any(|a| {
            a["key"] == "mastra.span.type" && a["value"]["stringValue"] == "model_inference"
        }) {
            attrs.push(json!({"key": "gen_ai.usage.cost_eur", "value": {"doubleValue": 0.25}}));
        }
    }
    let r = map_runs(&items, &Prices::default());
    assert_eq!(one_run(&r).cost_eur, Some(0.5));
}

#[test]
fn orphan_malformed_and_duplicate_spans_are_reported_not_fatal() {
    let mut items = fixture("mastra-agent");
    // Orphan: drop the root, so its children name a parent that never arrived.
    items.retain(|(_, v)| v["span"]["name"] != "invoke_agent demo");
    // Malformed: not a span at all, and a span with a trace id missing.
    items.push(("junk.json".into(), json!({"hello": 1})));
    items.push(("str.json".into(), json!("expected value at line 1")));
    // Duplicate span id.
    let dup = items[0].1.clone();
    items.push(("dup.json".into(), dup));
    let r = map_runs(&items, &Prices::default());
    let joined = r.problems.join("\n");
    assert!(joined.contains("never arrived"), "{joined}");
    assert!(joined.contains("junk.json: not a stored span"), "{joined}");
    assert!(joined.contains("str.json: not a stored span"), "{joined}");
    assert!(joined.contains("appears twice"), "{joined}");
    assert!(
        !r.traces[0].runs.is_empty(),
        "the orphan is still shown, as its own run"
    );
}

#[test]
fn clean_input_reports_no_problems() {
    for f in ["langgraph", "deepagents", "mastra-agent", "mastra-workflow"] {
        assert!(
            map_runs(&fixture(f), &Prices::default())
                .problems
                .is_empty(),
            "{f}"
        );
    }
}

fn chain_span(i: usize, op: Option<&str>) -> Value {
    let attrs: Vec<Value> = op
        .map(|o| json!({"key": "gen_ai.operation.name", "value": {"stringValue": o}}))
        .into_iter()
        .collect();
    json!({"resource": [], "scope": null, "span": {
        "traceId": "02020202020202020202020202020202",
        "spanId": format!("{:016x}", i + 1),
        "parentSpanId": if i == 0 { String::new() } else { format!("{:016x}", i) },
        "name": format!("s{i}"), "startTimeUnixNano": format!("{}", i + 1), "endTimeUnixNano": "9999",
        "attributes": attrs}})
}

/// A 5,000-deep parent chain, mapped, serialized, counted and dropped on a 256 KiB stack: the
/// tree depth is capped, so none of it recurses per span.
#[test]
fn a_5000_deep_chain_is_flattened_and_survives_a_small_stack() {
    for op in [Some("invoke_agent"), None] {
        let items: Vec<(String, Value)> = (0..5000)
            .map(|i| (format!("s{i}"), chain_span(i, op)))
            .collect();
        let problems = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || {
                let r = map_runs(&items, &Prices::default());
                let json = reede::ingest::runs::to_json(&r);
                assert!(!serde_json::to_string(&json).unwrap().is_empty());
                let _ = r.traces[0].runs.iter().map(step_count).sum::<usize>();
                r.problems.clone()
            })
            .unwrap()
            .join()
            .expect("no stack overflow");
        assert!(
            problems.iter().any(|p| p.contains("nesting deeper than")),
            "{problems:?}"
        );
    }
}

#[test]
fn a_model_call_counts_only_its_own_tokens() {
    let tok = |i: usize, n: i64| {
        let mut s = chain_span(i, Some(if i == 0 { "invoke_agent" } else { "chat" }));
        for (k, v) in [
            ("gen_ai.usage.input_tokens", n),
            ("gen_ai.usage.output_tokens", n),
        ] {
            s["span"]["attributes"]
                .as_array_mut()
                .unwrap()
                .push(json!({"key": k, "value": {"intValue": v.to_string()}}));
        }
        s
    };
    let items = vec![
        ("a".into(), chain_span(0, Some("invoke_agent"))),
        ("b".into(), tok(1, 30)),
        ("c".into(), tok(2, 5)),
    ];
    let r = map_runs(&items, &Prices::default());
    let run = one_run(&r);
    assert_eq!(
        (run.tokens.input, run.tokens.output),
        (30, 30),
        "the nested call's 5 is not added"
    );
}

#[test]
fn cost_is_null_unless_every_model_call_is_priced() {
    let mut items = fixture("mastra-agent");
    let mut done = false;
    for (_, v) in items.iter_mut() {
        let attrs = v["span"]["attributes"].as_array_mut().unwrap();
        if !done
            && attrs.iter().any(|a| {
                a["key"] == "mastra.span.type" && a["value"]["stringValue"] == "model_inference"
            })
        {
            attrs.push(json!({"key": "gen_ai.usage.cost_eur", "value": {"doubleValue": 0.25}}));
            done = true;
        }
    }
    assert_eq!(
        one_run(&map_runs(&items, &Prices::default())).cost_eur,
        None,
        "one of two calls unpriced"
    );
}

fn run_bin(args: &[&str]) -> (Option<i32>, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("reede-cli-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_reede"))
        .args(args)
        .current_dir(&dir)
        .output()
        .unwrap();
    (out.status.code(), dir)
}

#[test]
fn help_and_unknown_flags_never_start_a_server_or_write_a_key() {
    for (args, code) in [
        (vec!["serve", "--help"], 0),
        (vec!["serve", "-h"], 0),
        (vec!["ingest", "runs", "--help"], 0),
        (vec!["ingest", "check", "-h"], 0),
        (vec!["serve", "--bogus"], 2),
        (vec!["serve", "--listen"], 2),
        (vec!["ingest", "runs", "--out", "x", "--bogus"], 2),
        (vec!["ingest", "nope"], 2),
    ] {
        let (got, dir) = run_bin(&args);
        assert_eq!(got, Some(code), "{args:?}");
        assert!(
            !dir.join("reede-ingest").exists(),
            "{args:?} created the output dir"
        );
    }
}

#[test]
fn a_parent_cycle_does_not_hang_and_is_reported() {
    let a = json!({"resource": [], "scope": null, "span": {"traceId": "01010101010101010101010101010101", "spanId": "0a0a0a0a0a0a0a0a", "parentSpanId": "0b0b0b0b0b0b0b0b", "name": "a", "startTimeUnixNano": "1", "endTimeUnixNano": "2"}});
    let mut b = a.clone();
    b["span"]["spanId"] = json!("0b0b0b0b0b0b0b0b");
    b["span"]["parentSpanId"] = json!("0a0a0a0a0a0a0a0a");
    b["span"]["name"] = json!("b");
    let r = map_runs(&[("a".into(), a), ("b".into(), b)], &Prices::default());
    assert!(
        r.problems.iter().any(|p| p.contains("unreachable")),
        "{:?}",
        r.problems
    );
}
