import type { AuthorityRecord } from "@/lib/types";

export const CASEFILE_MAX_BYTES = 4 * 1024 * 1024;
export const CASEFILE_MAX_RECORDS = 2000;
const maxStringBytes = 4096;
const encoder = new TextEncoder();

export type CaseRecord = Omit<AuthorityRecord, "id" | "created_at"> & { id: string; created_at: string | null };
export interface Casefile {
  schema: "wolftrax.authority.v1";
  producer: string;
  source_namespace: string | null;
  dataset_incarnation: string | null;
  task_id: string;
  captured_at: string;
  selection: "all_task_only";
  coverage: "recorded_interception_decisions";
  complete: true;
  count: number;
  records: CaseRecord[];
  owner_grant: "not_recorded";
  independent_effect: "not_recorded";
  origin: "UNAUTHENTICATED";
  claim: "CLAIM_NOT_ASSESSED";
  synthetic: boolean;
}
export interface LoadedCase {
  data: Casefile;
  digest: string;
  bytes: Uint8Array<ArrayBuffer>;
}

// JSON.parse discards earlier duplicate keys (including escape-equivalent names).
// Decode bounded structures directly, preserving duplicate detection at every level.
class CasefileJSON {
  private pos = 0;
  private nodes = 0;
  constructor(private readonly text: string) {}

  parse(): unknown {
    const value = this.value(0);
    this.space();
    if (this.pos !== this.text.length) this.invalid();
    return value;
  }

  private invalid(): never {
    throw new Error("Malformed casefile JSON.");
  }

  private space() {
    while (this.pos < this.text.length && " \t\r\n".includes(this.text[this.pos])) this.pos++;
  }

  private take(literal: string): boolean {
    if (!this.text.startsWith(literal, this.pos)) return false;
    this.pos += literal.length;
    return true;
  }

  private string(): string {
    const start = this.pos;
    if (!this.take('"')) this.invalid();
    while (this.pos < this.text.length) {
      // At most six JSON source characters per encoded UTF-8 byte (e.g. \u0061).
      if (this.pos - start > maxStringBytes * 6 + 1) throw new Error("Casefile string exceeds 4096 UTF-8 bytes.");
      const c = this.text[this.pos++];
      if (c === "\\") this.pos++;
      if (c !== '"') continue;
      let s: string;
      try {
        s = JSON.parse(this.text.slice(start, this.pos));
      } catch {
        this.invalid();
      }
      if (s.length > maxStringBytes || encoder.encode(s).length > maxStringBytes)
        throw new Error("Casefile string exceeds 4096 UTF-8 bytes.");
      // Reject unpaired UTF-16 surrogates introduced through JSON escapes.
      if (/[\uD800-\uDFFF]/u.test(s)) throw new Error("Casefile contains invalid Unicode.");
      return s;
    }
    this.invalid();
  }

  private value(depth: number): unknown {
    if (depth > 6) throw new Error("Casefile JSON nesting exceeds the limit.");
    if (++this.nodes > 48_000) throw new Error("Casefile JSON has too many values.");
    this.space();
    if (this.take("{")) {
      const object: Record<string, unknown> = Object.create(null);
      let fields = 0;
      this.space();
      if (this.take("}")) return object;
      do {
        this.space();
        const key = this.string();
        if (Object.hasOwn(object, key)) throw new Error("Duplicate casefile JSON key.");
        if (++fields > 32) throw new Error("Casefile object has too many fields.");
        this.space();
        if (!this.take(":")) this.invalid();
        object[key] = this.value(depth + 1);
        this.space();
      } while (this.take(","));
      if (!this.take("}")) this.invalid();
      return object;
    }
    if (this.take("[")) {
      const array: unknown[] = [];
      this.space();
      if (this.take("]")) return array;
      do {
        if (array.length >= CASEFILE_MAX_RECORDS) throw new Error("Casefile exceeds the 2000 record limit.");
        array.push(this.value(depth + 1));
        this.space();
      } while (this.take(","));
      if (!this.take("]")) this.invalid();
      return array;
    }
    if (this.text[this.pos] === '"') return this.string();
    if (this.take("true")) return true;
    if (this.take("false")) return false;
    if (this.take("null")) return null;
    // Count is the only numeric field in v1. Accept its unsigned integer
    // representation only, so rounding (even tiny decimal fractions) is impossible.
    const start = this.pos;
    while (this.pos < this.text.length && this.text[this.pos] >= "0" && this.text[this.pos] <= "9") this.pos++;
    if (start === this.pos || (this.text[start] === "0" && this.pos > start + 1)) this.invalid();
    const n = Number(this.text.slice(start, this.pos));
    if (!Number.isSafeInteger(n)) throw new Error("Unsafe casefile number.");
    return n;
  }
}

const envelopeKeys = [
  "schema",
  "producer",
  "source_namespace",
  "dataset_incarnation",
  "task_id",
  "captured_at",
  "selection",
  "coverage",
  "complete",
  "count",
  "records",
  "owner_grant",
  "independent_effect",
  "origin",
  "claim",
  "synthetic",
] as const;
const recordTextKeys = [
  "agent_name",
  "tool_name",
  "status",
  "decision_source",
  "decided_by",
  "correlation",
  "run_id",
  "tool_use_id",
  "input_digest",
  "config_digest",
  "model_input_digest",
  "rule_name",
  "initial_action",
  "effective_action",
  "execution_status",
] as const;
const timeKeys = ["created_at", "decided_at", "execution_ended_at"] as const;
const recordKeys = ["id", "task_id", "audit_present", ...recordTextKeys, ...timeKeys] as const;

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function exactKeys(o: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(o).length === keys.length && keys.every((key) => Object.hasOwn(o, key));
}
function compareIDs(a: string, b: string): number {
  return a.length - b.length || (a < b ? -1 : Number(a > b));
}
function id(value: unknown): boolean {
  return typeof value === "string" && /^[1-9][0-9]{0,18}$/.test(value) && compareIDs(value, "9223372036854775807") <= 0;
}
function lineage(value: unknown): boolean {
  return value === null || (typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value));
}
function timestamp(value: unknown): boolean {
  if (typeof value !== "string" || !/^\d{4}-\d\d-\d\dT(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?Z$/.test(value))
    return false;
  const millis = Date.parse(value);
  return Number.isFinite(millis) && new Date(millis).toISOString().slice(0, 19) === value.slice(0, 19);
}
function validate(value: unknown): asserts value is Casefile {
  if (!object(value) || value.schema !== "wolftrax.authority.v1")
    throw new Error("Unsupported Authority casefile schema.");
  if (!exactKeys(value, envelopeKeys)) throw new Error("Unexpected or missing casefile fields.");
  if (
    value.producer !== "Wolftrax/1" ||
    !id(value.task_id) ||
    !timestamp(value.captured_at) ||
    !lineage(value.source_namespace) ||
    !lineage(value.dataset_incarnation) ||
    typeof value.synthetic !== "boolean"
  )
    throw new Error("Invalid casefile producer, identity or capture metadata.");
  if (
    value.selection !== "all_task_only" ||
    value.coverage !== "recorded_interception_decisions" ||
    value.complete !== true
  )
    throw new Error("Unsupported casefile selection or coverage.");
  if (
    value.owner_grant !== "not_recorded" ||
    value.independent_effect !== "not_recorded" ||
    value.origin !== "UNAUTHENTICATED" ||
    value.claim !== "CLAIM_NOT_ASSESSED"
  )
    throw new Error("Unsupported casefile evidence assertions.");
  if (
    !Array.isArray(value.records) ||
    value.count !== value.records.length ||
    value.records.length > CASEFILE_MAX_RECORDS
  )
    throw new Error("Invalid casefile record count.");
  const seen = new Set<string>();
  for (const r of value.records) {
    if (
      !object(r) ||
      !exactKeys(r, recordKeys) ||
      r.task_id !== value.task_id ||
      typeof r.id !== "string" ||
      !id(r.id) ||
      typeof r.audit_present !== "boolean" ||
      !recordTextKeys.every((k) => typeof r[k] === "string") ||
      !timeKeys.every((k) => r[k] === null || timestamp(r[k]))
    )
      throw new Error("Malformed or out-of-scope casefile record.");
    if (seen.has(r.id)) throw new Error("Duplicate casefile record ID.");
    seen.add(r.id);
  }
}

export async function loadCasefile(input: Blob | Uint8Array, expectedDigest?: string): Promise<LoadedCase> {
  const size = input instanceof Uint8Array ? input.byteLength : input.size;
  if (size === 0 || size > CASEFILE_MAX_BYTES) throw new Error("Casefile must contain between 1 byte and 4 MiB.");
  const bytes = input instanceof Uint8Array ? new Uint8Array(input) : new Uint8Array(await input.arrayBuffer());
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new Error("Casefile must be valid UTF-8.");
  }
  const data = new CasefileJSON(text).parse();
  validate(data);
  if (!globalThis.crypto?.subtle) throw new Error("SHA-256 requires HTTPS or localhost.");
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const digest = Array.from(hash, (b) => b.toString(16).padStart(2, "0")).join("");
  if (expectedDigest !== undefined && expectedDigest !== digest) throw new Error("Casefile SHA-256 mismatch.");
  return { data, bytes, digest };
}

export interface FieldChange {
  field: keyof CaseRecord;
  before: CaseRecord[keyof CaseRecord];
  after: CaseRecord[keyof CaseRecord];
  category: "display" | "evidence";
}
export interface RecordChange {
  id: string;
  kind: "added" | "absent" | "changed";
  fields: FieldChange[];
}
export interface Comparison {
  compatible: boolean;
  reason: string;
  changes: RecordChange[];
}
export function compareCases(before: Casefile, after: Casefile): Comparison {
  for (const key of [
    "schema",
    "source_namespace",
    "dataset_incarnation",
    "task_id",
    "selection",
    "coverage",
    "synthetic",
  ] as const) {
    if (
      before[key] === null ||
      before[key] === "" ||
      after[key] === null ||
      after[key] === "" ||
      before[key] !== after[key]
    )
      return {
        compatible: false,
        reason: `Cannot align records. The ${key} is unknown or differs between snapshots.`,
        changes: [],
      };
  }
  const left = new Map(before.records.map((r) => [r.id, r]));
  const right = new Map(after.records.map((r) => [r.id, r]));
  const ids = Array.from(new Set([...left.keys(), ...right.keys()])).sort(compareIDs);
  const changes: RecordChange[] = [];
  for (const key of ids) {
    const a = left.get(key);
    const b = right.get(key);
    if (!a || !b) {
      changes.push({ id: key, kind: b ? "added" : "absent", fields: [] });
      continue;
    }
    const fields: FieldChange[] = [];
    for (const field of recordKeys) {
      if (a[field] !== b[field])
        fields.push({
          field,
          before: a[field],
          after: b[field],
          category: field === "agent_name" ? "display" : "evidence",
        });
    }
    if (fields.length) changes.push({ id: key, kind: "changed", fields });
  }
  return {
    compatible: true,
    reason:
      "Alignment uses producer-asserted identity metadata. An undetected clone or restore can copy these identifiers. Origin and continuity remain unverified.",
    changes,
  };
}

// PostgreSQL/Go may supply more precision than Date.parse retains. Inputs have
// already been validated as UTC; fixed-width UTC timestamps sort chronologically.
function timeKey(time: string): string {
  return time.slice(0, 19) + time.slice(19, -1).slice(1).padEnd(9, "0");
}
function compareTime(a: string | null, b: string | null): number {
  if (a === null) return b === null ? 0 : 1;
  if (b === null) return -1;
  const left = timeKey(a),
    right = timeKey(b);
  return left < right ? -1 : Number(left > right);
}
export interface TimelineEvent {
  id: string;
  field: (typeof timeKeys)[number];
  time: string | null;
}
export function timeline(records: CaseRecord[]): TimelineEvent[] {
  const events: TimelineEvent[] = [];
  for (const r of records) {
    events.push({ id: r.id, field: "created_at", time: r.created_at });
    if (r.decided_at !== null || ["allowed", "denied", "timeout"].includes(r.status))
      events.push({ id: r.id, field: "decided_at", time: r.decided_at });
    if (r.execution_ended_at !== null || (r.audit_present && ["succeeded", "failed"].includes(r.execution_status)))
      events.push({ id: r.id, field: "execution_ended_at", time: r.execution_ended_at });
  }
  return events.sort(
    (a, b) =>
      compareTime(a.time, b.time) || compareIDs(a.id, b.id) || timeKeys.indexOf(a.field) - timeKeys.indexOf(b.field),
  );
}

export interface Diagnostic {
  category: "advisory";
  rule: string;
  recordIds: string[];
  message: string;
}
export function diagnostics(records: CaseRecord[]): Diagnostic[] {
  const output: Diagnostic[] = [];
  const callIDs = new Map<string, string[]>();
  for (const r of [...records].sort((a, b) => compareIDs(a.id, b.id))) {
    const add = (rule: string, message: string) =>
      output.push({ category: "advisory", rule, recordIds: [r.id], message });
    if (!r.audit_present) add("WT-AUDIT", "Audit metadata is missing. Call linkage and tool outcomes are unresolved.");
    if (!["rule", "model", "target"].includes(r.decision_source))
      add("WT-SOURCE", "The recorded decision source is missing or unrecognized.");
    if (!r.audit_present || r.correlation !== "exact" || !r.tool_use_id.trim())
      add(
        "WT-LINK",
        r.correlation === "ambiguous"
          ? "The recorded call link is ambiguous."
          : "An exact recorded call link is unavailable.",
      );
    if (r.audit_present && r.tool_use_id.trim()) {
      const linked = callIDs.get(r.tool_use_id);
      if (linked) linked.push(r.id);
      else callIDs.set(r.tool_use_id, [r.id]);
    }
    if (!["pending", "allowed", "denied", "timeout"].includes(r.status))
      add("WT-DECISION", "The recorded decision state is unrecognized.");
    if (
      r.audit_present &&
      !["not_started", "not_executed", "awaiting_result", "succeeded", "failed", "not_recorded"].includes(
        r.execution_status,
      )
    )
      add("WT-OUTCOME", "The tool outcome is unknown or unrecognized.");
    if (
      r.audit_present &&
      ["denied", "timeout", "pending"].includes(r.status) &&
      ["succeeded", "failed"].includes(r.execution_status)
    )
      add(
        "WT-CONFLICT",
        "The decision and the reported tool completion appear inconsistent. These fields cannot establish what ran.",
      );
    if (r.audit_present && r.execution_status === "succeeded")
      add("WT-RECEIPT", "The tool reported success. An independent effect receipt was not recorded.");
    if (
      !r.created_at ||
      (!r.decided_at && ["allowed", "denied", "timeout"].includes(r.status)) ||
      (!r.execution_ended_at && r.audit_present && ["succeeded", "failed"].includes(r.execution_status))
    )
      add("WT-TIME", "An expected record timestamp is missing. Undated entries have no position in clock time.");
    const times = timeKeys.map((k) => r[k]).filter((t): t is string => t !== null);
    if (times.some((t, i) => i > 0 && compareTime(times[i - 1], t) > 0))
      add("WT-TIME-ORDER", "The recorded creation, decision and completion times conflict with their expected order.");
  }
  for (const ids of callIDs.values()) {
    if (ids.length > 1)
      output.push({
        category: "advisory",
        rule: "WT-LINK-DUPLICATE",
        recordIds: ids,
        message: "Multiple records cite the same call ID. This file cannot establish a unique source relation.",
      });
  }
  return output;
}

function html(value: string | number | boolean | null): string {
  return String(value ?? "Not recorded")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function snapshotReport(loaded: LoadedCase, title: string): string {
  const c = loaded.data;
  const metadata = envelopeKeys
    .filter((key) => key !== "records")
    .map((key) => `<dt>${key}</dt><dd>${html(c[key])}</dd>`)
    .join("");
  const records = c.records
    .map(
      (r) =>
        `<details><summary>Record ${html(r.id)} · ${html(r.tool_name)} · ${html(r.status)}</summary><dl>${recordKeys
          .map((key) => `<dt>${key}</dt><dd>${html(r[key])}</dd>`)
          .join("")}</dl></details>`,
    )
    .join("");
  const notes = diagnostics(c.records)
    .map(
      (d) =>
        `<li><strong>${html(d.rule)}</strong> · Record(s) ${html(d.recordIds.join(", "))} · ${html(d.message)}</li>`,
    )
    .join("");
  return `<section><h2>${title}${c.synthetic ? " · Synthetic demonstration" : ""}</h2><dl>${metadata}<dt>SHA-256 of original casefile bytes</dt><dd>${html(loaded.digest)}</dd></dl>
    <h3>Advisory diagnostics</h3>${notes ? `<ul>${notes}</ul>` : "<p>No advisory rules matched.</p>"}
    <h3>Recorded metadata (${c.count})</h3>${records || "<p>The complete selection contains no recorded interception decisions.</p>"}</section>`;
}

function differenceReport(a: Casefile, b: Casefile): string {
  const diff = compareCases(a, b);
  const changes = diff.changes
    .map((change) => {
      const label = { added: "Added in later snapshot", absent: "Absent from later snapshot", changed: "Changed" }[
        change.kind
      ];
      const fields = change.fields
        .map(
          (f) =>
            `<li>${html(f.field)} (${f.category}) · earlier <code>${html(f.before)}</code> · later <code>${html(f.after)}</code></li>`,
        )
        .join("");
      return `<li>Record ${html(change.id)} · ${label}${fields ? `<ul>${fields}</ul>` : ""}</li>`;
    })
    .join("");
  return `<section><h2>Snapshot comparison</h2><p>${html(diff.reason)}</p>${
    diff.compatible
      ? `<p>Absence describes membership in this snapshot. The cause of an absence is unknown.</p>${changes ? `<ul>${changes}</ul>` : "<p>No record fields changed.</p>"}`
      : ""
  }
    </section>`;
}

// All imported content is escaped into text nodes. The restrictive CSP also
// applies when this standalone document is opened from a local file.
export function reviewerReport(loaded: LoadedCase, later?: LoadedCase): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Wolftrax · Authority reviewer report</title>
<style>body{margin:2rem auto;padding:0 1rem;max-width:72rem;color:#19232b;background:#fff;font:1rem/1.5 system-ui,sans-serif;overflow-wrap:anywhere}h2,h3{margin-top:2rem}dt,strong{font-weight:bold}dd{margin:0 0 .5rem}details{border-top:1px solid #88949b;padding:.5rem 0}summary{cursor:pointer}@media(min-width:40rem){dl{display:grid;grid-template-columns:minmax(10rem,1fr) 3fr;gap:.2rem 1rem}}</style>
</head><body><main><h1>Wolftrax Authority reviewer report</h1><h2>Reading this evidence</h2>
<p>The collection covers recorded interception decisions. Other dispatches may be absent. Recorded approval describes an interception decision. Target-owner authorization remains unestablished. An agent display label does not authenticate the actor.</p>
<p>Tool-reported success describes the saved outcome. Independent effect receipts and owner grants are not recorded. Stored digests are metadata. The file digest covers exact original JSON bytes and permits a consistency check. Origin remains UNAUTHENTICATED and the security claim remains CLAIM_NOT_ASSESSED.</p>
<p>The findings referee’s VERIFIED result describes supported artifact checks with a matching external digest. Its origin and claim dimensions remain separate. This casefile has its own format.</p>
<p>Capture time comes from the producer. Freeze reads a database snapshot while subsequent writes can continue. The file remains a historical copy after archival or deletion. The database supplies no immutable external witness. Timestamp ordering cannot establish causation. Each row describes fields recorded at capture time.</p>
${later ? differenceReport(loaded.data, later.data) : ""}${snapshotReport(loaded, later ? "Earlier capture" : "Capture")}${later ? snapshotReport(later, "Later capture") : ""}</main></body></html>`;
}
