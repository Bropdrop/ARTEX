import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { compareCases, diagnostics, loadCasefile, reviewerReport } from "../../web/src/lib/casefile.ts";

// Use either the bundled examples or a directory emitted by TestInvestigationDemo.
const dir = process.argv[2] || dirname(fileURLToPath(import.meta.url));
const cases = new Map();
for (const line of (await readFile(join(dir, "SHA256SUMS"), "utf8")).trimEnd().split("\n")) {
  const [, digest, name] = /^([a-f0-9]{64})  ([a-z]+)\.json$/.exec(line) || [];
  assert.ok(name, "unexpected checksum entry");
  const loaded = await loadCasefile(await readFile(join(dir, name + ".json")), digest);
  assert.equal(loaded.data.synthetic, true);
  cases.set(name, loaded);
}
const { before, after, restored, empty } = Object.fromEntries(cases);
assert.equal(empty.data.count, 0);
assert.equal(compareCases(after.data, restored.data).compatible, false);

const delta = compareCases(before.data, after.data);
assert.equal(delta.compatible, true);
assert.deepEqual(delta.changes.map((c) => c.kind).sort(), ["absent", "added", "changed"]);
const [changed] = delta.changes.find((c) => c.kind === "changed").fields;
assert.equal(changed.field, "execution_status");
assert.equal(changed.before, "demo_future_outcome");
assert.equal(changed.after, "failed");
const report = reviewerReport(before, after);
assert.ok(!report.includes("<script>fixtureLabel()"));
assert.ok(!report.includes("EXCLUDED_DEMO_"));
assert.ok(report.includes("Shelf count"));
console.log(`Verified ${cases.size} producer files, a three-record comparison and the reviewer report.`);

if (process.argv[3]) {
  const derived = (name) => readFile(join(process.argv[3], name + ".json")).then((bytes) => loadCasefile(bytes));
  for (const name of ["different-source", "unknown-incarnation"]) {
    assert.equal(compareCases(before.data, (await derived(name)).data).compatible, false);
  }
  const future = await derived("unknown-decision");
  assert.ok(diagnostics(future.data.records).some((d) => d.rule === "WT-DECISION"));
  for (const name of ["too-large", "too-deep", "duplicate-id", "duplicate-key", "truncated", "unsupported-schema"]) {
    // Read outside assert.rejects so a missing fixture cannot count as parser rejection.
    const bytes = await readFile(join(process.argv[3], name + ".json"));
    await assert.rejects(() => loadCasefile(bytes));
  }
  console.log("Verified three inspectable variants and six rejected inputs.");
}
