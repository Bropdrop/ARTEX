import type { AuthorityPage, AuthorityRecord, InterceptExecution } from "@/lib/types";

export type AuthorityTone = "neutral" | "info" | "warning" | "danger";
export interface AuthorityState {
  label: string;
  tone: AuthorityTone;
}

// Labels remain translation keys; this module has no browser or translation
// dependency so the evidence distinctions can be tested independently of React.
export function decisionState(status: string): AuthorityState {
  switch (status) {
    case "pending":
      return { label: "Pending approval", tone: "warning" };
    case "allowed":
      return { label: "Recorded as allowed", tone: "info" };
    case "denied":
      return { label: "Recorded as denied", tone: "danger" };
    case "timeout":
      return { label: "Approval timed out", tone: "warning" };
    default:
      return { label: "Unrecognized decision state", tone: "warning" };
  }
}

export function executionState(record: { audit_present: boolean; execution_status: string }): AuthorityState {
  if (!record.audit_present) return { label: "Audit not recorded", tone: "neutral" };
  switch (record.execution_status) {
    case "not_started":
      return { label: "Tool result not yet recorded", tone: "neutral" };
    case "not_executed":
      return { label: "Recorded as not executed", tone: "neutral" };
    case "awaiting_result":
      return { label: "Awaiting tool result", tone: "warning" };
    case "succeeded":
      return { label: "Tool reported success", tone: "info" };
    case "failed":
      return { label: "Tool reported failure", tone: "danger" };
    case "unknown":
      return { label: "Tool outcome unknown", tone: "warning" };
    case "not_recorded":
      return { label: "Tool result not recorded", tone: "neutral" };
    default:
      return { label: "Unrecognized tool outcome", tone: "warning" };
  }
}

type RecordedCorrelation = { audit_present: boolean; correlation: string; tool_use_id: string };

export function canLocateAuthoritySource(record: RecordedCorrelation): boolean {
  return (
    record.audit_present === true &&
    record.correlation === "exact" &&
    typeof record.tool_use_id === "string" &&
    record.tool_use_id.trim().length > 0
  );
}

export function correlationState(record: RecordedCorrelation): AuthorityState {
  if (!record.audit_present) return { label: "Audit not recorded", tone: "neutral" };
  if (canLocateAuthoritySource(record)) return { label: "Exact call ID recorded", tone: "info" };
  if (record.correlation === "ambiguous") return { label: "Call link ambiguous", tone: "warning" };
  if (["exact", "unavailable", "not_recorded", ""].includes(record.correlation)) {
    return { label: "Call link unavailable", tone: "neutral" };
  }
  return { label: "Unrecognized correlation state", tone: "warning" };
}

export function sourceState(source: string): string {
  switch (source) {
    case "rule":
      return "Rule";
    case "model":
      return "Model";
    case "target":
      return "Target gate";
    case "unknown":
    case "":
      return "Not recorded";
    default:
      return "Unrecognized source";
  }
}

export function actorState(actor: string): string {
  switch (actor) {
    case "human":
      return "Human";
    case "rule":
      return "Rule";
    case "model":
      return "Model";
    case "system":
      return "System";
    case "":
      return "Not recorded";
    default:
      return "Unrecognized actor";
  }
}

// The list's recorded correlation only makes a lookup eligible. Navigation is
// permitted after the execution API independently resolves a source in this task.
export function authoritySourceHref(
  record: AuthorityRecord,
  source: InterceptExecution | null | undefined,
  taskId: string,
): string | null {
  if (
    !source ||
    !canLocateAuthoritySource(record) ||
    !Number.isSafeInteger(record.id) ||
    record.id <= 0 ||
    record.task_id !== taskId ||
    source.task_id !== taskId ||
    source.conversation_id != null ||
    !Number.isSafeInteger(source.seq) ||
    source.seq <= 0 ||
    typeof source.session !== "string" ||
    source.session.trim() === ""
  )
    return null;
  const query = new URLSearchParams({ id: taskId, approval: String(record.id) });
  return `/function/tasks/detail?${query}`;
}

// Fail visibly on a mismatched or unsupported response rather than rendering
// another task's records or interpreting a future evidence contract as this one.
export function isAuthorityPageForScope(
  response: unknown,
  taskId: string,
  page: number,
  size: number,
): response is AuthorityPage {
  if (!isObject(response)) return false;
  if (
    !Number.isSafeInteger(page) ||
    page <= 0 ||
    !Number.isSafeInteger(size) ||
    size <= 0 ||
    response.task_id !== taskId ||
    response.page !== page ||
    response.size !== size ||
    response.coverage !== "recorded_interception_decisions" ||
    response.owner_grant !== "not_recorded" ||
    response.independent_effect !== "not_recorded" ||
    typeof response.total !== "number" ||
    !Number.isSafeInteger(response.total) ||
    response.total < 0 ||
    !Array.isArray(response.items) ||
    response.items.length > size ||
    response.items.length > response.total
  )
    return false;
  const ids = new Set<number>();
  return response.items.every((record) => {
    if (
      !isObject(record) ||
      record.task_id !== taskId ||
      typeof record.id !== "number" ||
      !Number.isSafeInteger(record.id) ||
      record.id <= 0 ||
      ids.has(record.id) ||
      typeof record.audit_present !== "boolean" ||
      !recordTextFields.every((field) => typeof record[field] === "string") ||
      (record.decided_at !== null && typeof record.decided_at !== "string") ||
      (record.execution_ended_at !== null && typeof record.execution_ended_at !== "string")
    ) {
      return false;
    }
    ids.add(record.id);
    return true;
  });
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

const recordTextFields = [
  "task_id",
  "agent_name",
  "tool_name",
  "status",
  "decision_source",
  "decided_by",
  "created_at",
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
];

type AuthorityNodeKind = "proposal" | "decision" | "outcome" | "grant" | "effect";
export interface AuthorityGraphNode {
  id: AuthorityNodeKind;
  kind: AuthorityNodeKind;
  title: string;
  value: string;
  valueIsLabel: boolean;
  tone: AuthorityTone;
  detail: string;
}
export interface AuthorityGraphEdge {
  id: string;
  source: AuthorityNodeKind;
  target: AuthorityNodeKind;
  label: string;
  kind: "recorded" | "unresolved";
}

export function authorityGraph(record: AuthorityRecord): { nodes: AuthorityGraphNode[]; edges: AuthorityGraphEdge[] } {
  const decision = decisionState(record.status);
  const outcome = executionState(record);
  const correlated = canLocateAuthoritySource(record);
  return {
    nodes: [
      {
        id: "proposal",
        kind: "proposal",
        title: "Tool proposal",
        value: record.tool_name || "Not recorded",
        valueIsLabel: !record.tool_name,
        tone: "info",
        detail: "Recorded agent label",
      },
      {
        id: "decision",
        kind: "decision",
        title: "Recorded decision",
        value: decision.label,
        valueIsLabel: true,
        tone: decision.tone,
        detail: "Decision source and actor are separate records.",
      },
      {
        id: "outcome",
        kind: "outcome",
        title: "Recorded tool outcome",
        value: outcome.label,
        valueIsLabel: true,
        tone: outcome.tone,
        detail: "A tool result does not independently establish an effect.",
      },
      {
        id: "grant",
        kind: "grant",
        title: "Owner grant",
        value: "Not recorded",
        valueIsLabel: true,
        tone: "warning",
        detail: "No signed owner grant is stored in these records.",
      },
      {
        id: "effect",
        kind: "effect",
        title: "Independent effect evidence",
        value: "Not recorded",
        valueIsLabel: true,
        tone: "warning",
        detail: "No independent effect receipt is stored in these records.",
      },
    ],
    edges: [
      {
        id: "proposal-decision",
        source: "proposal",
        target: "decision",
        label: "Same approval record",
        kind: "recorded",
      },
      {
        id: "decision-outcome",
        source: "decision",
        target: "outcome",
        label: correlated ? "Recorded call link" : "Unresolved call link",
        kind: correlated ? "recorded" : "unresolved",
      },
      { id: "grant-decision", source: "grant", target: "decision", label: "No recorded grant", kind: "unresolved" },
      {
        id: "outcome-effect",
        source: "outcome",
        target: "effect",
        label: "No independent receipt",
        kind: "unresolved",
      },
    ],
  };
}
