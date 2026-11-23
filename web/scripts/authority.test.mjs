import ts from "typescript";

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

// Exercise the same pure projection used by the native view. No backend, model,
// real target, or browser is needed for these semantic checks.
const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const input = fs.readFileSync(path.join(web, "src/lib/authority.ts"), "utf8");
const compiled = ts.transpileModule(input, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const authority = {};
vm.runInNewContext(compiled, { exports: authority, URLSearchParams });

function record(overrides = {}) {
  return {
    id: 17,
    task_id: "42",
    agent_name: "worker display name",
    tool_name: "Write",
    status: "allowed",
    decision_source: "model",
    decided_by: "human",
    created_at: "2026-11-23T10:00:00Z",
    decided_at: "2026-11-23T10:00:01Z",
    audit_present: true,
    correlation: "exact",
    run_id: "run-42",
    tool_use_id: "call-17",
    input_digest: "a".repeat(64),
    config_digest: "b".repeat(64),
    model_input_digest: "c".repeat(64),
    rule_name: "Captured rule name",
    initial_action: "ask",
    effective_action: "allow",
    execution_status: "succeeded",
    execution_ended_at: "2026-11-23T10:00:02Z",
    ...overrides,
  };
}

function source(overrides = {}) {
  return {
    conversation_id: null,
    task_id: "42",
    session: "intent:9",
    seq: 91,
    items: [
      {
        seq: 91,
        kind: "tool_use",
        tool: "Write",
        tool_use_id: "call-17",
        worker: "worker display name",
      },
    ],
    ...overrides,
  };
}

function page(overrides = {}) {
  return {
    task_id: "42",
    items: [record()],
    total: 1,
    page: 1,
    size: 20,
    coverage: "recorded_interception_decisions",
    owner_grant: "not_recorded",
    independent_effect: "not_recorded",
    ...overrides,
  };
}

test("pending, allowed, denied, and timed-out decisions remain distinct", () => {
  const states = ["pending", "allowed", "denied", "timeout"].map(authority.decisionState);
  assert.equal(new Set(states.map((state) => state.label)).size, 4);
  assert.match(states[0].label, /pending|awaiting/i);
  assert.match(states[1].label, /allow/i);
  assert.match(states[2].label, /denied|deny/i);
  assert.match(states[3].label, /timed out|timeout/i);
  for (const state of states) {
    assert.doesNotMatch(state.label, /owner.authorized|verified|effect.proven/i);
  }
});

test("unknown future decision values never inherit an allow or success label", () => {
  for (const status of ["", "future-status", "Allowed", "__proto__", "constructor"]) {
    const state = authority.decisionState(status);
    assert.equal(typeof state.label, "string");
    assert.match(state.label, /unknown|unrecognized|not recorded/i);
    assert.doesNotMatch(state.label, /allowed|success|verified/i);
  }
});

test("decision source and deciding actor keep independent meanings, including missing legacy actors", () => {
  const row = record({ decision_source: "model", decided_by: "human" });
  assert.equal(authority.sourceState(row.decision_source), "Model");
  assert.equal(authority.actorState(row.decided_by), "Human");
  assert.equal(authority.sourceState("target"), "Target gate");
  assert.equal(authority.actorState("system"), "System");
  for (const value of ["", "future-value", "__proto__", "constructor"]) {
    assert.match(authority.actorState(value), /not recorded|unrecognized/i);
    assert.match(authority.sourceState(value), /not recorded|unrecognized/i);
  }
  assert.doesNotMatch(authority.actorState(""), /model|human|owner|verified/i);
});

test("execution status reports tool completion without promoting it to effect proof", () => {
  const succeeded = authority.executionState(record());
  const failed = authority.executionState(record({ execution_status: "failed" }));
  assert.match(succeeded.label, /tool.*(?:reported|reports).*success/i);
  assert.match(failed.label, /tool.*(?:reported|reports).*(?:failure|failed)/i);
  assert.doesNotMatch(succeeded.label, /verified|proven|owner authorized/i);
  assert.notEqual(succeeded.label, failed.label);
});

test("blocked, awaiting, not-started, and unknown outcomes cannot collapse into failure or success", () => {
  const denied = authority.executionState(record({ status: "denied", execution_status: "not_executed" }));
  const awaiting = authority.executionState(record({ execution_status: "awaiting_result" }));
  const notStarted = authority.executionState(record({ status: "pending", execution_status: "not_started" }));
  const unknown = authority.executionState(record({ execution_status: "unknown" }));
  assert.match(denied.label, /not executed/i);
  assert.match(awaiting.label, /awaiting/i);
  assert.match(notStarted.label, /not.*(?:started|recorded)|awaiting/i);
  assert.match(unknown.label, /unknown/i);
  for (const state of [denied, awaiting, notStarted, unknown]) {
    assert.doesNotMatch(state.label, /reported success|reported failure|verified/i);
  }
});

test("missing audit dominates populated legacy outcome and correlation fields", () => {
  const legacy = record({ audit_present: false });
  assert.match(authority.executionState(legacy).label, /not recorded|unavailable|unknown/i);
  assert.match(authority.correlationState(legacy).label, /not recorded|unavailable|unknown/i);
  assert.equal(authority.canLocateAuthoritySource(legacy), false);
  assert.equal(authority.authoritySourceHref(legacy, source(), "42"), null);
});

test("unrecognized future execution states stay unresolved", () => {
  for (const status of ["", "new-success-kind", "Succeeded", "__proto__", "constructor"]) {
    const state = authority.executionState(record({ execution_status: status }));
    assert.equal(typeof state.label, "string");
    assert.match(state.label, /unknown|unrecognized|not recorded/i);
    assert.doesNotMatch(state.label, /reported success|reported failure|verified/i);
  }
});

test("only an audited exact call identifier enables the source check", () => {
  assert.equal(authority.canLocateAuthoritySource(record()), true);
  for (const correlation of ["ambiguous", "unavailable", "not_recorded", "", "future-correlation"]) {
    const row = record({ correlation });
    assert.equal(authority.canLocateAuthoritySource(row), false, correlation);
    assert.equal(authority.authoritySourceHref(row, source(), "42"), null, correlation);
  }
  for (const tool_use_id of ["", " \t\n"]) {
    const noCall = record({ tool_use_id });
    assert.equal(authority.canLocateAuthoritySource(noCall), false);
    assert.equal(authority.authoritySourceHref(noCall, source(), "42"), null);
  }
  assert.doesNotMatch(authority.correlationState(record()).label, /verified|authenticated|proven/i);
});

test("source navigation accepts only the selected task and rejects conversations", () => {
  const row = record();
  const valid = authority.authoritySourceHref(row, source(), "42");
  assert.equal(typeof valid, "string");
  const url = new URL(valid, "https://artex.invalid");
  assert.equal(url.origin, "https://artex.invalid");
  assert.equal(url.pathname, "/function/tasks/detail");
  assert.equal(url.searchParams.get("id"), "42");
  assert.equal(url.searchParams.get("approval"), "17");
  assert.equal(url.searchParams.has("c"), false);

  assert.equal(authority.authoritySourceHref(row, source({ task_id: "43" }), "42"), null);
  assert.equal(authority.authoritySourceHref(row, source({ task_id: null }), "42"), null);
  assert.equal(authority.authoritySourceHref(row, source(), "43"), null);
  assert.equal(authority.authoritySourceHref(record({ task_id: "43" }), source(), "42"), null);
  for (const conversation_id of [0, 12]) {
    assert.equal(authority.authoritySourceHref(row, source({ conversation_id }), "42"), null);
  }
});

test("untrusted scope strings cannot add a conversation or external navigation target", () => {
  const task = "42&c=9#https://attacker.invalid";
  const href = authority.authoritySourceHref(record({ task_id: task }), source({ task_id: task }), task);
  // Rejecting malformed task IDs or encoding them as a single query value are
  // both safe; interpolation that creates another query field is not.
  if (href === null) return;
  const url = new URL(href, "https://artex.invalid");
  assert.equal(url.origin, "https://artex.invalid");
  assert.equal(url.pathname, "/function/tasks/detail");
  assert.equal(url.searchParams.get("id"), task);
  assert.equal(url.searchParams.has("c"), false);
  assert.equal(url.hash, "");
});

test("source navigation requires an actual positive position and session", () => {
  for (const seq of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, NaN, Infinity]) {
    assert.equal(authority.authoritySourceHref(record(), source({ seq }), "42"), null);
  }
  for (const session of ["", " \t\n"]) {
    assert.equal(authority.authoritySourceHref(record(), source({ session }), "42"), null);
  }
});

test("grant and effect gaps remain unresolved even after an allowed successful exact call", () => {
  const graph = authority.authorityGraph(Object.freeze(record()));
  const ids = new Set(graph.nodes.map((node) => node.id));
  for (const id of ["proposal", "decision", "outcome", "grant", "effect"]) assert.ok(ids.has(id), id);
  const grantEdges = graph.edges.filter((edge) => edge.source === "grant" || edge.target === "grant");
  const effectEdges = graph.edges.filter((edge) => edge.source === "effect" || edge.target === "effect");
  assert.ok(grantEdges.length > 0, "the missing grant must be represented");
  assert.ok(effectEdges.length > 0, "the missing effect evidence must be represented");
  for (const edge of [...grantEdges, ...effectEdges]) assert.equal(edge.kind, "unresolved");
  for (const id of ["grant", "effect"]) {
    const node = graph.nodes.find((candidate) => candidate.id === id);
    assert.match(JSON.stringify(node), /not recorded|missing|unavailable/i);
  }
});

test("ambiguous or legacy call correlation cannot draw a recorded outcome edge", () => {
  for (const row of [
    record({ correlation: "ambiguous" }),
    record({ correlation: "unavailable" }),
    record({ tool_use_id: "" }),
    record({ audit_present: false }),
  ]) {
    const graph = authority.authorityGraph(row);
    const outcomeEdges = graph.edges.filter((edge) => edge.target === "outcome");
    assert.ok(outcomeEdges.length > 0);
    for (const edge of outcomeEdges) assert.equal(edge.kind, "unresolved");
  }
});

test("all decision and completion states preserve missing grant and effect evidence", () => {
  for (const status of ["pending", "allowed", "denied", "timeout", "future-state"]) {
    for (const execution_status of [
      "not_started",
      "awaiting_result",
      "not_executed",
      "succeeded",
      "failed",
      "unknown",
      "future-state",
    ]) {
      const graph = authority.authorityGraph(record({ status, execution_status }));
      for (const edge of graph.edges) {
        if ([edge.source, edge.target].some((id) => id === "grant" || id === "effect")) {
          assert.equal(edge.kind, "unresolved", `${status}/${execution_status}`);
        }
      }
    }
  }
});

test("page validation accepts an explicit empty page without inferring that no actions occurred", () => {
  assert.equal(authority.isAuthorityPageForScope(page(), "42", 1, 20), true);
  assert.equal(authority.isAuthorityPageForScope(page({ items: [], total: 0 }), "42", 1, 20), true);
  assert.equal(
    authority.isAuthorityPageForScope(page({ items: [], total: 0, coverage: "all_actions" }), "42", 1, 20),
    false,
  );
});

test("a delayed page from another task or page cannot replace the selected scope", () => {
  assert.equal(authority.isAuthorityPageForScope(page(), "43", 1, 20), false);
  assert.equal(authority.isAuthorityPageForScope(page(), "42", 2, 20), false);
  assert.equal(authority.isAuthorityPageForScope(page(), "42", 1, 50), false);
  assert.equal(authority.isAuthorityPageForScope(page({ items: [record({ task_id: "43" })] }), "42", 1, 20), false);
  assert.equal(
    authority.isAuthorityPageForScope(
      page({ items: [record(), record({ id: 18, task_id: "43" })], total: 2 }),
      "42",
      1,
      20,
    ),
    false,
  );
});

test("pages reject duplicate, unsafe, fractional, or nonpositive record identifiers", () => {
  assert.equal(authority.isAuthorityPageForScope(page({ items: [record(), record()], total: 2 }), "42", 1, 20), false);
  for (const id of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, NaN, Infinity]) {
    assert.equal(authority.isAuthorityPageForScope(page({ items: [record({ id })] }), "42", 1, 20), false);
  }
});

test("page bounds and totals cannot advertise malformed or oversized record sets", () => {
  const items = Array.from({ length: 21 }, (_, i) => record({ id: i + 1 }));
  assert.equal(authority.isAuthorityPageForScope(page({ items, total: 21 }), "42", 1, 20), false);
  for (const total of [-1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
    assert.equal(authority.isAuthorityPageForScope(page({ total }), "42", 1, 20), false);
  }
  assert.equal(authority.isAuthorityPageForScope(page({ total: 0 }), "42", 1, 20), false);
});

test("unexpected authority or effect claims cannot be silently accepted as v1 data", () => {
  for (const metadata of [
    { coverage: "all_actions" },
    { coverage: "" },
    { owner_grant: "verified" },
    { owner_grant: "" },
    { independent_effect: "verified" },
    { independent_effect: "" },
  ]) {
    assert.equal(authority.isAuthorityPageForScope(page(metadata), "42", 1, 20), false);
  }
});

test("absent, primitive, and array page responses are rejected without rendering", () => {
  for (const response of [undefined, null, false, true, 0, "", "page", [], {}, [page()]]) {
    assert.equal(authority.isAuthorityPageForScope(response, "42", 1, 20), false);
  }
});

test("malformed record collections and non-object rows cannot enter view state", () => {
  for (const items of [undefined, null, false, 1, "items", {}, [null], [undefined], [[]], ["row"], [1]]) {
    assert.equal(authority.isAuthorityPageForScope(page({ items }), "42", 1, 20), false);
  }
  assert.equal(authority.isAuthorityPageForScope(page({ items: [record({ id: "17" })] }), "42", 1, 20), false);
});

test("each required text field rejects missing or non-text values before rendering helpers use it", () => {
  const nullableTimestamps = new Set(["decided_at", "execution_ended_at"]);
  const textFields = Object.entries(record())
    .filter(([key, value]) => typeof value === "string" && !nullableTimestamps.has(key))
    .map(([key]) => key);
  for (const field of textFields) {
    for (const value of [undefined, null, 0, false, [], {}]) {
      assert.equal(
        authority.isAuthorityPageForScope(page({ items: [record({ [field]: value })] }), "42", 1, 20),
        false,
        `${field} must remain a string`,
      );
    }
  }
});

test("audit presence requires a boolean and malformed call IDs never enable source lookup", () => {
  for (const audit_present of [undefined, null, "true", "false", 0, 1, [], {}]) {
    const row = record({ audit_present });
    assert.equal(authority.isAuthorityPageForScope(page({ items: [row] }), "42", 1, 20), false);
    assert.equal(authority.canLocateAuthoritySource(row), false);
    assert.equal(authority.authoritySourceHref(row, source(), "42"), null);
  }
  for (const tool_use_id of [undefined, null, 1, false, [], {}]) {
    const row = record({ tool_use_id });
    assert.equal(authority.canLocateAuthoritySource(row), false);
    assert.equal(authority.authoritySourceHref(row, source(), "42"), null);
  }
});

test("optional timestamps accept explicit absence while rejecting malformed non-string values", () => {
  for (const field of ["decided_at", "execution_ended_at"]) {
    assert.equal(authority.isAuthorityPageForScope(page({ items: [record({ [field]: null })] }), "42", 1, 20), true);
    for (const value of [undefined, 0, false, [], {}]) {
      assert.equal(
        authority.isAuthorityPageForScope(page({ items: [record({ [field]: value })] }), "42", 1, 20),
        false,
      );
    }
  }
});

test("missing execution responses and invalid approval IDs cannot produce source links", () => {
  for (const execution of [undefined, null, {}, [], "source"]) {
    assert.equal(authority.authoritySourceHref(record(), execution, "42"), null);
  }
  for (const id of [undefined, null, "17", 0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
    assert.equal(authority.authoritySourceHref(record({ id }), source(), "42"), null);
  }
});
