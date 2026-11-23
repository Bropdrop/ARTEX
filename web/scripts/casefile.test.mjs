import ts from "typescript";

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

// Transpile the production helper with the locked compiler. No browser or
// fixture network services are involved in this particular suite.
const source = await readFile(new URL("../src/lib/casefile.ts", import.meta.url), "utf8");
const js = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
}).outputText;
const { loadCasefile, compareCases, diagnostics, timeline, reviewerReport, CASEFILE_MAX_RECORDS, CASEFILE_MAX_BYTES } =
  await import(`data:text/javascript;base64,${Buffer.from(js).toString("base64")}`);

function record(overrides = {}) {
  return {
    id: "9223372036854775807",
    task_id: "9007199254740993",
    agent_name: "fixture",
    tool_name: "demo",
    status: "allowed",
    decision_source: "model",
    decided_by: "human",
    created_at: "2026-11-23T13:00:00Z",
    decided_at: null,
    audit_present: true,
    correlation: "exact",
    run_id: "1",
    tool_use_id: "call",
    input_digest: "",
    config_digest: "",
    model_input_digest: "",
    rule_name: "",
    initial_action: "",
    effective_action: "",
    execution_status: "succeeded",
    execution_ended_at: null,
    ...overrides,
  };
}
function capture(records = [record()], meta = {}) {
  return {
    schema: "wolftrax.authority.v1",
    producer: "Wolftrax/1",
    source_namespace: "demo",
    dataset_incarnation: "lab_1",
    task_id: "9007199254740993",
    captured_at: "2026-11-23T14:00:00.000000001Z",
    selection: "all_task_only",
    coverage: "recorded_interception_decisions",
    complete: true,
    count: records.length,
    records,
    owner_grant: "not_recorded",
    independent_effect: "not_recorded",
    origin: "UNAUTHENTICATED",
    claim: "CLAIM_NOT_ASSESSED",
    synthetic: true,
    ...meta,
  };
}
const input = (c) => new TextEncoder().encode(JSON.stringify(c));
const decode = (s) => loadCasefile(new Blob([s]));
const base = JSON.stringify(capture());

test("exact byte digest includes whitespace and import preserves int64 IDs, all fields and order", async () => {
  const bytes = new TextEncoder().encode(`\r\n ${base}\n`);
  const expected = createHash("sha256").update(bytes).digest("hex");
  const loaded = await loadCasefile(bytes, expected);
  assert.equal(loaded.digest, expected);
  assert.deepEqual(loaded.bytes, bytes);
  assert.deepEqual(JSON.parse(JSON.stringify(loaded.data)), capture());
  assert.equal((await loadCasefile(new Blob([bytes]), expected)).digest, expected);
  assert.notEqual((await decode(base)).digest, expected);
  await assert.rejects(loadCasefile(input(capture()), expected), /SHA-256 mismatch/);
  bytes.fill(0);
  assert.equal(createHash("sha256").update(loaded.bytes).digest("hex"), expected);
});

test("empty complete bounded selection and missing lineage may be inspected", async () => {
  const loaded = await loadCasefile(input(capture([], { source_namespace: null, dataset_incarnation: null })));
  assert.equal(loaded.data.count, 0);
  assert.match(reviewerReport(loaded), /selection contains no recorded interception decisions/);
});

test("rejects truncation, trailing content, comments, invalid escapes and JSON punctuation", async () => {
  for (const s of [
    "",
    base.slice(0, -1),
    `${base}X`,
    `//comment\n${base}`,
    base.replace('"demo"', '"\\x20"'),
    base.replace('"claim":', '"claim"'),
    base.replace('"synthetic":true', '"synthetic":true,'),
    base.replace('"id":', '\f"id":'),
  ]) {
    await assert.rejects(decode(s));
  }
});

test("detects duplicates including escaped nested, root and identical duplicate values", async () => {
  for (const s of [
    base.replace('"count":1', '"count":1,"\\u0063ount":1'),
    base.replace('"id":"', '"id":"1","i\\u0064":"'),
    base.replace('"synthetic":true', '"synthetic":true,"synthetic":true'),
  ]) {
    await assert.rejects(decode(s), /Duplicate/);
  }
});

test("rejects hidden/extra, mismatched scope, missing fields and elevated assurance", async () => {
  for (const c of [
    capture([record({ url: "https://invalid.example" })]),
    capture([], { __extra: "raw" }),
    capture([record({ task_id: "123" })]),
    capture([record({ id: undefined })]),
    capture([record({ audit_present: 1 })]),
    capture([record({ agent_name: { text: "s" } })]),
    capture([], { owner_grant: "recorded" }),
    capture([], { origin: "AUTHENTICATED" }),
    capture([], { claim: "VERIFIED" }),
    capture([], { independent_effect: true }),
    capture([], { complete: false }),
    capture([], { count: 1 }),
    capture([], { synthetic: "false" }),
    capture([], { source_namespace: "https://invalid.example" }),
    capture([], { dataset_incarnation: "a".repeat(129) }),
  ]) {
    await assert.rejects(loadCasefile(input(c)));
  }
  await assert.rejects(decode(base.replace('"synthetic":true', '"synthetic":true,"__proto__":{}')));
});

test("rejects unsupported schema, producer, coverage and selection with explanatory errors", async () => {
  for (const [field, value] of Object.entries({
    schema: "HAR",
    producer: "Other/2",
    selection: "page",
    coverage: "all_dispatches",
  })) {
    await assert.rejects(loadCasefile(input(capture([], { [field]: value }))), /schema|producer|selection|coverage/);
  }
});

test("rejects aliases, out-of-range IDs, duplicate record IDs and unsafe numeric tokens", async () => {
  for (const value of [1, 9007199254740992, "01", "0", "-1", "+1", "1.0", " 1", "9223372036854775808"]) {
    await assert.rejects(loadCasefile(input(capture([record({ id: value })]))));
    await assert.rejects(loadCasefile(input(capture([], { task_id: value }))));
  }
  for (const n of ["9007199254740993", "1.00000000000000001", "1e0", "01", "-0"])
    await assert.rejects(decode(base.replace('"count":1', `"count":${n}`)));
  await assert.rejects(loadCasefile(input(capture([record(), record()]))), /Duplicate.*ID/);
});

test("timestamps must be real UTC dates; fractional seconds retain nanosecond precision", async () => {
  for (const value of [
    "2026-02-29T00:00:00Z",
    "2026-02-31T00:00:00Z",
    "2026-11-23",
    "2026-11-23T24:00:00Z",
    "2026-11-23T00:00:00+05:00",
    "2026-11-23T00:00:00.1234567890Z",
    "",
  ]) {
    await assert.rejects(loadCasefile(input(capture([record({ created_at: value })]))));
  }
  await loadCasefile(input(capture([record({ created_at: "2024-02-29T00:00:00.000000009Z" })])));
  await loadCasefile(input(capture([record({ created_at: null })])));
});

test("enforces bounded UTF-8, scalar Unicode and string lengths in bytes", async () => {
  await assert.rejects(loadCasefile(new Uint8Array([0xc3, 0x28])), /UTF-8/);
  await assert.rejects(decode(`\uFEFF${base}`));
  await assert.rejects(decode(base.replace('"fixture"', '"\\ud800"')), /Unicode/);
  await assert.rejects(loadCasefile(input(capture([record({ agent_name: "🐺".repeat(1025) })]))), /4096/);
  await loadCasefile(input(capture([record({ agent_name: "🐺".repeat(1024) })])));
  await decode(base.replace('"fixture"', `"${"\\u0061".repeat(4096)}"`));
});

test("enforces byte, depth, record, container and value limits before rendering", async () => {
  await assert.rejects(loadCasefile(new Blob([new Uint8Array(CASEFILE_MAX_BYTES + 1)])), /4 MiB/);
  const maxBlob = new Blob([base, " ".repeat(CASEFILE_MAX_BYTES - Buffer.byteLength(base))]);
  assert.equal((await loadCasefile(maxBlob)).bytes.length, CASEFILE_MAX_BYTES);
  await assert.rejects(decode(`${"[".repeat(45)}0${"]".repeat(45)}`), /nesting/);
  await assert.rejects(
    decode(JSON.stringify(Object.fromEntries(Array.from({ length: 33 }, (_, i) => [i, true])))),
    /fields/,
  );
  await assert.rejects(decode(JSON.stringify(Array.from({ length: 30 }, () => Array(2000).fill(null)))), /many values/);
  const many = Array.from({ length: CASEFILE_MAX_RECORDS }, (_, i) => record({ id: String(i + 1) }));
  assert.equal((await loadCasefile(input(capture(many)))).data.count, 2000);
  await assert.rejects(loadCasefile(input(capture([...many, record()]))), /2000/);
});

test("unknown raw enum values survive, diagnostic IDs identify supporting evidence", async () => {
  const r = record({
    status: "future-allow",
    execution_status: "then-succeeded",
    decision_source: "unrecognized",
    correlation: "ambiguous",
  });
  const loaded = await loadCasefile(input(capture([r])));
  assert.equal(loaded.data.records[0].status, "future-allow");
  const notes = diagnostics(loaded.data.records);
  assert.deepEqual(
    notes.map((d) => d.rule),
    ["WT-SOURCE", "WT-LINK", "WT-DECISION", "WT-OUTCOME"],
  );
  assert.ok(notes.every((d) => d.recordIds.length === 1 && d.recordIds[0] === r.id));
  assert.ok(notes.every((d) => d.category === "advisory"));
});

test("scope checks explain refusal before any row comparison", () => {
  const a = capture();
  for (const [field, value] of Object.entries({
    schema: "v2",
    source_namespace: "other",
    dataset_incarnation: "clone",
    task_id: "1",
    selection: "subset",
    coverage: "other",
    synthetic: false,
  })) {
    const result = compareCases(a, { ...a, [field]: value });
    assert.equal(result.compatible, false);
    assert.match(result.reason, new RegExp(field));
    assert.deepEqual(result.changes, []);
  }
  for (const field of ["source_namespace", "dataset_incarnation"]) {
    const empty = { ...a, [field]: null };
    assert.equal(compareCases(empty, empty).compatible, false);
    assert.equal(compareCases(a, empty).compatible, false);
  }
});

test("aligns only by full scoped ID, distinguishes evidence fields from display, and ignores order", () => {
  const a = capture([record({ id: "100" }), record({ id: "9" }), record()]);
  const b = capture(
    [record(), record({ id: "100", agent_name: "new label", execution_status: "failed" }), record({ id: "10" })],
    { captured_at: "2026-11-24T14:00:00Z" },
  );
  const result = compareCases(a, b);
  assert.equal(result.compatible, true);
  assert.match(result.reason, /producer-asserted.*clone or restore/i);
  assert.deepEqual(
    result.changes.map((x) => [x.id, x.kind]),
    [
      ["9", "absent"],
      ["10", "added"],
      ["100", "changed"],
    ],
  );
  assert.deepEqual(
    result.changes[2].fields.map((f) => [f.field, f.before, f.after, f.category]),
    [
      ["agent_name", "fixture", "new label", "display"],
      ["execution_status", "succeeded", "failed", "evidence"],
    ],
  );
  assert.deepEqual(compareCases(a, { ...a, records: [...a.records].reverse() }).changes, []);
});

test("timeline uses recorded fields, orders exact nanoseconds, sorts ties by int64 and leaves undated entries last", () => {
  const first = "2026-11-23T10:00:00.000000001Z",
    second = "2026-11-23T10:00:00.000000002Z";
  const one = record({ id: "1", created_at: second, decided_at: second, execution_ended_at: null });
  const two = record({ id: "2", status: "pending", execution_status: "not_started", created_at: first });
  const three = record({ id: "3", status: "future", execution_status: "future", created_at: null });
  assert.deepEqual(
    timeline([three, two, one]).map((e) => [e.id, e.field, e.time]),
    [
      ["2", "created_at", first],
      ["1", "created_at", second],
      ["1", "decided_at", second],
      ["1", "execution_ended_at", null],
      ["3", "created_at", null],
    ],
  );
});

test("advisories remain deterministic for inconsistent, missing and repeated records", () => {
  const a = record({ id: "1", status: "denied", decided_at: "2026-11-23T12:59:00Z", execution_ended_at: null });
  const b = record({ id: "2", status: "pending", execution_status: "not_started" });
  const c = record({
    id: "3",
    audit_present: false,
    execution_status: "succeeded",
    correlation: "exact",
    tool_use_id: "",
  });
  const notes = diagnostics([c, b, a]);
  assert.deepEqual(notes, diagnostics([a, b, c]));
  const ids = (rule) => notes.filter((x) => x.rule === rule).flatMap((x) => x.recordIds);
  assert.deepEqual(ids("WT-CONFLICT"), ["1"]);
  assert.deepEqual(ids("WT-RECEIPT"), ["1"]);
  assert.deepEqual(ids("WT-TIME-ORDER"), ["1"]);
  assert.deepEqual(ids("WT-TIME"), ["1", "3"]);
  assert.deepEqual(ids("WT-LINK-DUPLICATE"), ["1", "2"]);
  assert.deepEqual(ids("WT-AUDIT"), ["3"]);
  assert.deepEqual(ids("WT-LINK"), ["3"]);
});

test("reviewer HTML embeds only escaped data and includes both snapshot contexts, diff and interpretation", async () => {
  const inj = "</summary><img src=x onerror=alert(1)><script>oops()</script>\"&'";
  const a = await loadCasefile(input(capture([record({ agent_name: inj, rule_name: "https://example.invalid/" })])));
  const b = await loadCasefile(input(capture([record({ id: "2", tool_name: inj })])));
  const html = reviewerReport(a, b);
  assert.doesNotMatch(html, /<(?:img|script|link|a|iframe)\b/i);
  assert.ok(!html.includes(inj));
  assert.match(html, /&lt;script&gt;/);
  for (const token of [
    "default-src 'none'",
    "Synthetic demonstration",
    "Earlier capture",
    "Later capture",
    a.digest,
    b.digest,
    "Absent from later snapshot",
    "Added in later snapshot",
    "recorded_interception_decisions",
    "all_task_only",
    "UNAUTHENTICATED",
    "CLAIM_NOT_ASSESSED",
    "WT-RECEIPT",
    "owner grants",
    "VERIFIED",
    "producer-asserted",
    "database snapshot",
  ])
    assert.ok(html.includes(token), token);
  const real = await loadCasefile(input(capture([], { synthetic: false })));
  assert.doesNotMatch(reviewerReport(real), /Synthetic demonstration/);
});
