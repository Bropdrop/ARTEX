"use client";

import * as React from "react";

import { ExternalLinkIcon } from "lucide-react";

import { AuthorityGraph } from "@/components/authority-graph";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { intlLocale, t } from "@/i18n";
import {
  type AuthorityState,
  actorState,
  canLocateAuthoritySource,
  correlationState,
  decisionState,
  executionState,
  sourceState,
} from "@/lib/authority";
import type { CaseRecord, Comparison, Diagnostic } from "@/lib/casefile";
import { cn } from "@/lib/utils";

const toneClasses = {
  neutral: "border-slate-200 text-slate-600 dark:border-slate-700 dark:text-slate-300",
  info: "border-blue-200 bg-blue-50/60 text-blue-700 dark:border-blue-800 dark:bg-blue-950/30 dark:text-blue-300",
  warning:
    "border-amber-200 bg-amber-50/60 text-amber-800 dark:border-amber-800 dark:bg-amber-950/30 dark:text-amber-300",
  danger: "border-rose-200 bg-rose-50/60 text-rose-700 dark:border-rose-800 dark:bg-rose-950/30 dark:text-rose-300",
};

export function StateBadge({ state }: { state: AuthorityState }) {
  return (
    <Badge
      variant="outline"
      className={cn("h-auto min-h-5 whitespace-normal py-0.5 text-left", toneClasses[state.tone])}
    >
      {t(state.label)}
    </Badge>
  );
}

export function timestamp(value: string | null) {
  if (!value) return t("Not recorded");
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? t("Unrecognized timestamp") : date.toLocaleString(intlLocale);
}

export type LocateRecord = (record: CaseRecord) => Promise<() => void>;

export function RecordDetails({
  record,
  onLocate,
  advisories,
  change,
}: {
  record: CaseRecord;
  onLocate?: LocateRecord;
  advisories: Diagnostic[];
  change?: Comparison["changes"][number];
}) {
  const [locating, setLocating] = React.useState(false);
  const [sourceError, setSourceError] = React.useState<string | null>(null);
  const liveRef = React.useRef(true);
  React.useEffect(() => {
    liveRef.current = true;
    return () => {
      liveRef.current = false;
    };
  }, []);

  const locate = async () => {
    if (locating || !onLocate || !canLocateAuthoritySource(record)) return;
    setLocating(true);
    setSourceError(null);
    try {
      const navigate = await onLocate(record);
      if (liveRef.current) navigate();
    } catch (error) {
      if (liveRef.current)
        setSourceError(error instanceof Error ? error.message : t("Unable to locate the corresponding execution"));
    } finally {
      if (liveRef.current) setLocating(false);
    }
  };

  const facts = [
    { label: t("Recorded agent label"), value: record.agent_name || t("Not recorded") },
    { label: t("Decision state"), value: record.status || t("Not recorded") },
    { label: t("Recorded tool outcome"), value: record.execution_status || t("Not recorded") },
    { label: t("Initial action"), value: record.initial_action || t("Not recorded") },
    { label: t("Effective action"), value: record.effective_action || t("Not recorded") },
    {
      label: t("Decision source"),
      value: record.decision_source
        ? `${t(sourceState(record.decision_source))} (${record.decision_source})`
        : t("Not recorded"),
    },
    {
      label: t("Decided by"),
      value: record.decided_by ? `${t(actorState(record.decided_by))} (${record.decided_by})` : t("Not recorded"),
    },
    { label: t("Captured rule name"), value: record.rule_name || t("Not recorded") },
    { label: t("Recorded at"), value: timestamp(record.created_at) },
    { label: t("Decision recorded at"), value: timestamp(record.decided_at) },
    { label: t("Tool result recorded at"), value: timestamp(record.execution_ended_at) },
  ];
  const bindings = [
    { label: t("Run ID"), value: record.run_id },
    { label: t("Tool call ID"), value: record.tool_use_id },
    { label: t("Input digest"), value: record.input_digest },
    { label: t("Configuration digest"), value: record.config_digest },
    { label: t("Model input digest"), value: record.model_input_digest },
  ];

  return (
    <Card className="min-w-0 gap-0 py-0 [overflow-wrap:anywhere]">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b p-4">
        <div>
          <p className="text-muted-foreground text-xs">{t("Approval record #{id}", { id: record.id })}</p>
          <h3 className="mt-1 break-words font-semibold">{record.tool_name || t("Not recorded")}</h3>
        </div>
        <StateBadge state={decisionState(record.status)} />
      </div>
      {change?.kind === "changed" && (
        <section className="space-y-2 border-b p-4 text-xs">
          <h4 className="font-semibold">{t("Changed fields")}</h4>
          <dl className="space-y-2">
            {change.fields.map((diff) => (
              <div key={diff.field}>
                <dt className="font-medium">
                  {diff.field} · {diff.category === "display" ? t("Display label") : t("Recorded evidence")}
                </dt>
                <dd>
                  {t("Earlier value")}: {String(diff.before ?? t("Not recorded"))}
                </dd>
                <dd>
                  {t("Later value")}: {String(diff.after ?? t("Not recorded"))}
                </dd>
              </div>
            ))}
          </dl>
        </section>
      )}
      <AuthorityGraph record={record} />
      <div className="space-y-4 border-t p-4">
        <p className="text-muted-foreground text-xs leading-relaxed">
          {t(
            "Solid lines connect recorded fields. Dashed lines mark unresolved or missing evidence. A recorded call ID is checked again when opening its source.",
          )}
        </p>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap gap-2">
            <StateBadge state={correlationState(record)} />
            <StateBadge state={executionState(record)} />
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => void locate()}
            disabled={!onLocate || locating || !canLocateAuthoritySource(record)}
          >
            <ExternalLinkIcon />
            {locating ? t("Locating source") : t("Open original execution")}
          </Button>
        </div>
        {sourceError && (
          <p role="alert" className="break-words text-destructive text-xs">
            {sourceError}
          </p>
        )}
        <dl className="grid gap-x-6 gap-y-3 text-xs sm:grid-cols-2 xl:grid-cols-3">
          {facts.map(({ label, value }) => (
            <div key={label}>
              <dt className="text-muted-foreground">{label}</dt>
              <dd className="mt-1 break-words">{value}</dd>
            </div>
          ))}
        </dl>
        <section className="space-y-2 text-xs">
          <h4 className="font-medium">{t("Evidence diagnostics")}</h4>
          {advisories.length === 0 && <p>{t("No advisory rules matched this record.")}</p>}
          {advisories.map((item) => (
            <div key={item.rule} className="border-l-2 pl-3">
              <span className="font-mono">{item.rule}</span> · {t("Supporting records")}:{" "}
              {item.recordIds.map((id) => `#${id}`).join(", ")}
              <p>{t(item.message)}</p>
            </div>
          ))}
        </section>
        <details className="rounded-lg border p-3 text-xs">
          <summary className="cursor-pointer font-medium">{t("Recorded identifiers and digests")}</summary>
          <p className="my-3 text-muted-foreground leading-relaxed">
            {t(
              "These values are recorded bindings. This view does not verify their hashes or authenticate the agent, owner, or capture.",
            )}
          </p>
          <dl className="space-y-3">
            {bindings.map(({ label, value }) => (
              <div key={label}>
                <dt className="text-muted-foreground">{label}</dt>
                <dd className="mt-1 break-all font-mono">{value || t("Not recorded")}</dd>
              </div>
            ))}
          </dl>
        </details>
      </div>
    </Card>
  );
}
