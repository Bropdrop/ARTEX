"use client";

import * as React from "react";

import {
  ArrowLeftIcon,
  ArrowRightIcon,
  CircleAlertIcon,
  ExternalLinkIcon,
  GitBranchIcon,
  RefreshCwIcon,
} from "lucide-react";

import { AuthorityGraph } from "@/components/authority-graph";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { intlLocale, t } from "@/i18n";
import { api } from "@/lib/api";
import {
  type AuthorityState,
  actorState,
  authoritySourceHref,
  canLocateAuthoritySource,
  correlationState,
  decisionState,
  executionState,
  isAuthorityPageForScope,
  sourceState,
} from "@/lib/authority";
import { setVisibleInterval } from "@/lib/polling";
import type { AuthorityPage, AuthorityRecord } from "@/lib/types";
import { cn } from "@/lib/utils";

const PAGE_SIZE = 20;
const toneClasses = {
  neutral: "border-slate-200 text-slate-600 dark:border-slate-700 dark:text-slate-300",
  info: "border-blue-200 bg-blue-50/60 text-blue-700 dark:border-blue-800 dark:bg-blue-950/30 dark:text-blue-300",
  warning:
    "border-amber-200 bg-amber-50/60 text-amber-800 dark:border-amber-800 dark:bg-amber-950/30 dark:text-amber-300",
  danger: "border-rose-200 bg-rose-50/60 text-rose-700 dark:border-rose-800 dark:bg-rose-950/30 dark:text-rose-300",
};

function StateBadge({ state }: { state: AuthorityState }) {
  return (
    <Badge
      variant="outline"
      className={cn("h-auto min-h-5 whitespace-normal py-0.5 text-left", toneClasses[state.tone])}
    >
      {t(state.label)}
    </Badge>
  );
}

function timestamp(value: string | null) {
  if (!value) return t("Not recorded");
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? t("Unrecognized timestamp") : date.toLocaleString(intlLocale);
}

function RecordDetails({ record, taskId }: { record: AuthorityRecord; taskId: string }) {
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
    if (locating || !canLocateAuthoritySource(record)) return;
    setLocating(true);
    setSourceError(null);
    try {
      const source = await api.interceptExecution(record.id);
      if (!liveRef.current) return;
      const href = authoritySourceHref(record, source, taskId);
      if (!href) throw new Error(t("The execution source does not match this task."));
      // Session focus is initialized on mount. A full navigation follows the
      // existing approval source links and opens the Sessions tab reliably.
      window.location.assign(href);
    } catch (error) {
      if (liveRef.current)
        setSourceError(error instanceof Error ? error.message : t("Unable to locate the corresponding execution"));
    } finally {
      if (liveRef.current) setLocating(false);
    }
  };

  const facts = [
    { label: t("Decision source"), value: t(sourceState(record.decision_source)) },
    { label: t("Decided by"), value: t(actorState(record.decided_by)) },
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
    <Card className="min-w-0 gap-0 py-0">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b p-4">
        <div>
          <p className="text-muted-foreground text-xs">{t("Approval record #{id}", { id: record.id })}</p>
          <h3 className="mt-1 break-words font-semibold">{record.tool_name || t("Not recorded")}</h3>
        </div>
        <StateBadge state={decisionState(record.status)} />
      </div>
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
            disabled={locating || !canLocateAuthoritySource(record)}
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

function AuthorityTabContent({ taskId }: { taskId: string }) {
  const [page, setPage] = React.useState(1);
  const [data, setData] = React.useState<AuthorityPage | null>(null);
  const [selectedId, setSelectedId] = React.useState<number | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [updatedAt, setUpdatedAt] = React.useState<string | null>(null);
  const refreshRef = React.useRef<() => Promise<void>>(() => Promise.resolve());

  React.useEffect(() => {
    let disposed = false;
    let inFlight = false;
    setData(null);
    setSelectedId(null);
    setError(null);
    setUpdatedAt(null);
    const load = async () => {
      if (disposed || inFlight) return;
      inFlight = true;
      setLoading(true);
      try {
        const response = await api.authorityPage(taskId, page, PAGE_SIZE);
        if (disposed) return;
        if (!isAuthorityPageForScope(response, taskId, page, PAGE_SIZE))
          throw new Error(t("The authority response does not match this task and page."));
        setData(response);
        setSelectedId((current) =>
          response.items.some((record) => record.id === current) ? current : (response.items[0]?.id ?? null),
        );
        setError(null);
        setUpdatedAt(new Date().toISOString());
      } catch (err) {
        if (!disposed) setError(err instanceof Error ? err.message : t("Unable to load authority records"));
      } finally {
        inFlight = false;
        if (!disposed) setLoading(false);
      }
    };
    refreshRef.current = load;
    void load();
    const stopPolling = setVisibleInterval(load, 20_000);
    return () => {
      disposed = true;
      stopPolling();
    };
  }, [taskId, page]);

  const selected = data?.items.find((record) => record.id === selectedId);
  const pages = Math.max(1, Math.ceil((data?.total ?? 0) / PAGE_SIZE));
  const changePage = (next: number) => {
    setData(null);
    setSelectedId(null);
    setPage(next);
  };

  return (
    <section className="space-y-4" aria-label={t("Authority")}>
      <Card className="gap-3 p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex items-start gap-3">
            <span className="rounded-lg bg-blue-50 p-2 text-blue-600 dark:bg-blue-950 dark:text-blue-300">
              <GitBranchIcon className="size-5" />
            </span>
            <div>
              <h2 className="font-semibold">{t("Authority graph")}</h2>
              <p className="mt-1 text-muted-foreground text-xs leading-relaxed">
                {t("Explore recorded decisions, tool outcomes, and the evidence still missing.")}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="outline">{t("Read only")}</Badge>
            <Button variant="outline" size="sm" disabled={loading} onClick={() => void refreshRef.current()}>
              <RefreshCwIcon className={loading ? "animate-spin" : undefined} />
              {t("Refresh")}
            </Button>
          </div>
        </div>
        <p className="text-muted-foreground text-xs leading-relaxed">
          {t(
            "Coverage is limited to recorded interception decisions. Some actions have no interception record, and a target approval can be shared by multiple calls.",
          )}
        </p>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-t pt-3 text-xs">
          <span>
            {t("Owner grants")}: <span className="text-amber-700 dark:text-amber-300">{t("Not recorded")}</span>
          </span>
          <span>
            {t("Independent effect evidence")}:{" "}
            <span className="text-amber-700 dark:text-amber-300">{t("Not recorded")}</span>
          </span>
          <span className="ml-auto text-muted-foreground" aria-live="polite">
            {updatedAt ? t("Last refreshed: {time}", { time: timestamp(updatedAt) }) : t("No successful refresh yet")}
          </span>
        </div>
      </Card>

      {error && (
        <div
          role="alert"
          className="flex items-start gap-2 rounded-lg border border-amber-300 bg-amber-50/60 p-3 text-amber-900 text-xs dark:border-amber-800 dark:bg-amber-950/30 dark:text-amber-200"
        >
          <CircleAlertIcon className="mt-0.5 size-4 shrink-0" />
          <div>
            <p className="font-medium">
              {data ? t("Refresh failed. Displayed records may be stale.") : t("Unable to load authority records")}
            </p>
            <p className="mt-1 break-words">{error}</p>
            {!data && page > 1 && (
              <Button className="mt-2" variant="outline" size="sm" onClick={() => changePage(1)}>
                <ArrowLeftIcon />
                {t("Return to first page")}
              </Button>
            )}
          </div>
        </div>
      )}
      {!data && loading && (
        <Card className="p-8 text-center text-muted-foreground text-sm" role="status">
          {t("Loading authority records")}
        </Card>
      )}
      {data && (
        <div className="grid items-start gap-4 xl:grid-cols-[280px_minmax(0,1fr)]">
          <Card className="min-w-0 gap-0 py-0">
            <div className="border-b p-4">
              <h3 className="font-medium text-sm">{t("Recorded decisions")}</h3>
              <p className="mt-1 text-muted-foreground text-xs">
                {t("{count} interception records", { count: data.total })}
              </p>
            </div>
            {data.items.length === 0 ? (
              <div className="space-y-2 p-5 text-sm">
                <p>
                  {page === 1 ? t("No recorded interception decisions for this task.") : t("No records on this page.")}
                </p>
                <p className="text-muted-foreground text-xs leading-relaxed">
                  {t("An empty view does not establish that no actions occurred.")}
                </p>
              </div>
            ) : (
              <ul className="max-h-[560px] divide-y overflow-y-auto" aria-label={t("Recorded interception decisions")}>
                {data.items.map((record) => (
                  <li key={record.id}>
                    <button
                      type="button"
                      className={cn(
                        "w-full space-y-2 p-3.5 text-left transition-colors hover:bg-muted/60 focus-visible:outline-2 focus-visible:outline-primary focus-visible:outline-offset-[-2px]",
                        selectedId === record.id && "bg-blue-50/60 dark:bg-blue-950/20",
                      )}
                      aria-pressed={selectedId === record.id}
                      onClick={() => setSelectedId(record.id)}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="truncate font-medium text-sm">{record.tool_name || t("Not recorded")}</span>
                        <span className="text-[11px] text-muted-foreground">#{record.id}</span>
                      </div>
                      <div>
                        <StateBadge state={decisionState(record.status)} />
                      </div>
                      <p className="truncate text-muted-foreground text-xs">{record.agent_name || t("Not recorded")}</p>
                      <p className="text-[10px] text-muted-foreground">{timestamp(record.created_at)}</p>
                    </button>
                  </li>
                ))}
              </ul>
            )}
            <div className="flex items-center justify-between gap-2 border-t p-3">
              <Button
                variant="outline"
                size="icon-sm"
                aria-label={t("Previous page")}
                disabled={loading || page <= 1}
                onClick={() => changePage(page - 1)}
              >
                <ArrowLeftIcon />
              </Button>
              <span className="text-muted-foreground text-xs">
                {t("Page {page} of {pages}", { page, pages: Math.max(page, pages) })}
              </span>
              <Button
                variant="outline"
                size="icon-sm"
                aria-label={t("Next page")}
                disabled={loading || page >= pages}
                onClick={() => changePage(page + 1)}
              >
                <ArrowRightIcon />
              </Button>
            </div>
          </Card>
          {selected ? (
            <RecordDetails key={`${taskId}:${selected.id}`} record={selected} taskId={taskId} />
          ) : (
            <Card className="p-8 text-center text-muted-foreground text-sm">
              {t("Select a recorded decision to inspect its evidence graph.")}
            </Card>
          )}
        </div>
      )}
    </section>
  );
}

export function AuthorityTab({ taskId }: { taskId: string }) {
  // Task changes discard selection, stale data, and in-flight navigation state.
  return <AuthorityTabContent key={taskId} taskId={taskId} />;
}
