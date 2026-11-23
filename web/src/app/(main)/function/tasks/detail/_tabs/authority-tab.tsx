"use client";

import * as React from "react";

import { ArrowLeftIcon, ArrowRightIcon, GitBranchIcon, RefreshCwIcon } from "lucide-react";

import { AuthorityRecordBrowser } from "@/components/authority-record-browser";
import { type LocateRecord, timestamp } from "@/components/authority-record-details";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { t } from "@/i18n";
import { api, type ResolvedAuthorityFocus } from "@/lib/api";
import { authoritySourceHref, isAuthorityPageForScope } from "@/lib/authority";
import { CASEFILE_MAX_BYTES, compareCases, type LoadedCase, loadCasefile, reviewerReport } from "@/lib/casefile";
import { setVisibleInterval } from "@/lib/polling";
import type { AuthorityPage } from "@/lib/types";

const PAGE_SIZE = 20;
type Mode = "Live" | "Frozen" | "Compare";

function LiveRecords({ taskId }: { taskId: string }) {
  const [page, setPage] = React.useState(1);
  const [data, setData] = React.useState<AuthorityPage>();
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState("");
  const [updated, setUpdated] = React.useState("");
  const refresh = React.useRef<() => Promise<void>>(() => Promise.resolve());
  React.useEffect(() => {
    const controller = new AbortController();
    let pending = false;
    const load = async () => {
      if (pending || controller.signal.aborted) return;
      pending = true;
      setLoading(true);
      try {
        const result = await api.authorityPage(taskId, page, PAGE_SIZE, controller.signal);
        if (controller.signal.aborted) return;
        if (!isAuthorityPageForScope(result, taskId, page, PAGE_SIZE))
          throw new Error(t("The authority response does not match this task and page."));
        const lastPage = Math.max(1, Math.ceil(result.total / PAGE_SIZE));
        if (page > lastPage && result.items.length === 0) {
          setPage(lastPage);
          return;
        }
        setData(result);
        setError("");
        setUpdated(new Date().toISOString());
      } catch (e) {
        if (!controller.signal.aborted)
          setError(e instanceof Error ? e.message : t("Unable to load authority records"));
      } finally {
        pending = false;
        if (!controller.signal.aborted) setLoading(false);
      }
    };
    refresh.current = load;
    setData(undefined);
    setError("");
    setUpdated("");
    void load();
    const stop = setVisibleInterval(load, 20_000);
    return () => {
      controller.abort();
      stop();
    };
  }, [taskId, page]);
  const scoped = data?.page === page && data.task_id === taskId ? data : undefined;
  const records = React.useMemo(() => scoped?.items.map((row) => ({ ...row, id: String(row.id) })) ?? [], [scoped]);
  const locate: LocateRecord = async (record) => {
    const original = scoped?.items.find((row) => String(row.id) === record.id);
    if (!original) throw new Error(t("The execution source does not match this task."));
    const source = await api.interceptExecution(original.id);
    const href = authoritySourceHref(original, source, taskId);
    if (!href) throw new Error(t("The execution source does not match this task."));
    return () => window.location.assign(href);
  };
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
        <p>{updated ? t("Last refreshed: {time}", { time: timestamp(updated) }) : t("No successful refresh yet")}</p>
        <Button size="sm" variant="outline" disabled={loading} onClick={() => void refresh.current()}>
          <RefreshCwIcon />
          {t("Refresh")}
        </Button>
      </div>
      {error && (
        <Card role="alert" className="gap-1 p-3 text-sm">
          <strong>
            {scoped ? t("Refresh failed. Displayed records may be stale.") : t("Unable to load authority records")}
          </strong>
          <span>{error}</span>
          {!scoped && page > 1 && (
            <Button variant="outline" onClick={() => setPage(1)}>
              {t("Return to first page")}
            </Button>
          )}
        </Card>
      )}
      {loading && !scoped && <p role="status">{t("Loading authority records")}</p>}
      {scoped && (
        <>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-xs">{t("{count} interception records", { count: scoped.total })}</p>
            <div className="flex items-center gap-2">
              <Button
                size="icon-sm"
                variant="outline"
                aria-label={t("Previous page")}
                disabled={page <= 1 || loading}
                onClick={() => setPage(page - 1)}
              >
                <ArrowLeftIcon />
              </Button>
              <span className="text-xs">
                {t("Page {page} of {pages}", { page, pages: Math.max(1, Math.ceil(scoped.total / PAGE_SIZE)) })}
              </span>
              <Button
                size="icon-sm"
                variant="outline"
                aria-label={t("Next page")}
                disabled={page * PAGE_SIZE >= scoped.total || loading}
                onClick={() => setPage(page + 1)}
              >
                <ArrowRightIcon />
              </Button>
            </div>
          </div>
          <AuthorityRecordBrowser key={page} records={records} live onLocate={locate} />
        </>
      )}
    </div>
  );
}

function download(filename: string, data: BlobPart, type: string) {
  const url = URL.createObjectURL(new Blob([data], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 15_000);
}

function FileInput({ label, onFile }: { label: string; onFile: (file: File) => void }) {
  const id = React.useId();
  return (
    <label htmlFor={id} className="block min-w-0 space-y-1 font-medium text-sm">
      {label}
      <Input
        id={id}
        type="file"
        accept=".json,application/json"
        onChange={(e) => {
          const file = e.currentTarget.files?.[0];
          e.currentTarget.value = "";
          if (file) onFile(file);
        }}
      />
    </label>
  );
}

function CaptureSummary({ loaded }: { loaded: LoadedCase }) {
  const file = loaded.data;
  return (
    <div className="min-w-0 space-y-1 text-xs [overflow-wrap:anywhere]">
      <p className="font-medium">
        {file.synthetic && (
          <Badge variant="outline" className="mr-2">
            {t("Synthetic demonstration")}
          </Badge>
        )}
        {t("Task #{id}", { id: file.task_id })} · {t("Captured at {time}", { time: file.captured_at })}
      </p>
      <p>
        {t("Source namespace")}: {file.source_namespace ?? t("Not recorded")} · {t("Dataset incarnation")}:{" "}
        {file.dataset_incarnation ?? t("Not recorded")}
      </p>
      <p>
        {file.producer} · {file.schema} · {file.selection} · {file.coverage} ·{" "}
        {t("{count} interception records", { count: file.count })}
      </p>
      <p className="font-mono">SHA-256 {loaded.digest}</p>
    </div>
  );
}

interface Props {
  taskId: string;
  onOfflineChange?: (offline: boolean) => void;
  onSourceResolved?: (value: ResolvedAuthorityFocus) => void;
}

// Read only a bounded response, including when a server or proxy omits Content-Length.
async function freeze(taskId: string, signal: AbortSignal) {
  const response = await api.authorityCasefile(taskId, signal);
  const expected = response.headers.get("X-Casefile-SHA256");
  if (!expected || !/^[a-f0-9]{64}$/.test(expected))
    throw new Error(t("The capture response has no valid byte digest."));
  const reader = response.body?.getReader();
  if (!reader) throw new Error(t("The capture response was empty."));
  const chunks: Uint8Array<ArrayBuffer>[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > CASEFILE_MAX_BYTES) {
        await reader.cancel();
        throw new Error(t("The casefile exceeds the size limit."));
      }
      chunks.push(new Uint8Array(value));
    }
  } finally {
    reader.releaseLock();
  }
  const loaded = await loadCasefile(new Blob(chunks), expected);
  if (loaded.data.task_id !== taskId) throw new Error(t("The capture response does not match this task."));
  return loaded;
}

function Workbench({ taskId, onOfflineChange, onSourceResolved }: Props) {
  const [mode, setMode] = React.useState<Mode>(taskId ? "Live" : "Frozen");
  const [current, setCurrent] = React.useState<LoadedCase>();
  const [earlier, setEarlier] = React.useState<LoadedCase>();
  const [later, setLater] = React.useState<LoadedCase>();
  const [side, setSide] = React.useState<"earlier" | "later">("later");
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const op = React.useRef<AbortController | undefined>(undefined);
  React.useEffect(() => () => op.current?.abort(), []);
  React.useEffect(() => {
    onOfflineChange?.(mode !== "Live");
  }, [mode, onOfflineChange]);
  const changeMode = (next: Mode) => {
    op.current?.abort();
    setBusy(false);
    setError("");
    setMode(next);
  };
  const load = async (slot: "current" | "earlier" | "later", file?: File) => {
    op.current?.abort();
    const controller = new AbortController();
    op.current = controller;
    setBusy(true);
    setError("");
    try {
      const result = file ? await loadCasefile(file) : await freeze(taskId, controller.signal);
      if (controller.signal.aborted) return;
      if (slot === "current") {
        setCurrent(result);
        if (current) {
          setEarlier(current);
          setLater(result);
        } else {
          setEarlier(result);
          setLater(undefined);
        }
        setMode("Frozen");
      } else if (slot === "earlier") {
        setEarlier(result);
        setSide("earlier");
      } else {
        setLater(result);
        setSide("later");
      }
    } catch (e) {
      if (!controller.signal.aborted) {
        if (file) {
          if (slot === "earlier") setEarlier(undefined);
          else if (slot === "later") setLater(undefined);
          else setCurrent(undefined);
        }
        setError(e instanceof Error ? t(e.message) : t("Unable to read casefile"));
      }
    } finally {
      if (!controller.signal.aborted) setBusy(false);
    }
  };
  const comparison = React.useMemo(
    () => (mode === "Compare" && earlier && later ? compareCases(earlier.data, later.data) : undefined),
    [mode, earlier, later],
  );
  const selectedSide = side === "later" ? (later ?? earlier) : (earlier ?? later);
  const loaded = mode === "Compare" ? selectedSide : current;
  const file = loaded?.data;
  const captureLabel = loaded === earlier ? t("Earlier casefile") : t("Later casefile");
  const namespace = file?.source_namespace;
  const incarnation = file?.dataset_incarnation;
  const locate: LocateRecord | undefined =
    file?.task_id === taskId && namespace && incarnation && onSourceResolved
      ? async (record) => {
          const source = await api.authorityRecordedSource(taskId, record.id, {
            source_namespace: namespace,
            dataset_incarnation: incarnation,
            run_id: record.run_id,
            tool_use_id: record.tool_use_id,
            tool_name: record.tool_name,
          });
          if (
            source.task_id !== taskId ||
            ("conversation_id" in source && source.conversation_id != null) ||
            !Number.isSafeInteger(source.seq) ||
            source.seq <= 0 ||
            typeof source.session !== "string" ||
            !/^(plan|main:[0-9]+|intent:[1-9][0-9]*)$/.test(source.session)
          ) {
            throw new Error(t("The execution source does not match this task."));
          }
          return () => onSourceResolved({ id: record.id, source: { ...source, items: [], conversation_id: null } });
        }
      : undefined;
  const exportReport = () => {
    if (!loaded) return;
    try {
      const report = mode === "Compare" && earlier && later ? reviewerReport(earlier, later) : reviewerReport(loaded);
      download(`wolftrax-${loaded.data.task_id}-report.html`, report, "text/html;charset=utf-8");
    } catch (e) {
      setError(e instanceof Error ? t(e.message) : t("Unable to export report"));
    }
  };
  const filename = loaded ? `wolftrax-${loaded.data.task_id}-${loaded.digest.slice(0, 12)}.json` : "";
  const modes: Mode[] = taskId ? ["Live", "Frozen", "Compare"] : ["Frozen", "Compare"];
  return (
    <section aria-label={t("Authority")} className="min-w-0 space-y-4">
      <Card className="gap-3 p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex items-center gap-3">
            <span className="rounded-lg bg-muted p-2">
              <GitBranchIcon className="size-5" />
            </span>
            <h2 className="font-semibold">{t("Investigation Lab")}</h2>
          </div>
          <fieldset aria-label={t("Investigation mode")} className="flex flex-wrap gap-1">
            {modes.map((item) => (
              <Button
                key={item}
                size="sm"
                variant={mode === item ? "default" : "outline"}
                aria-pressed={mode === item}
                onClick={() => changeMode(item)}
              >
                {t(item)}
              </Button>
            ))}
          </fieldset>
        </div>
        <p className="text-muted-foreground text-xs">
          {t(
            "Coverage is limited to recorded interception decisions. Some actions have no interception record, and a target approval can be shared by multiple calls.",
          )}
        </p>
        <p className="text-xs">
          {t("Owner grants")}: {t("Not recorded")} · {t("Independent effect evidence")}: {t("Not recorded")}
        </p>
        {mode === "Live" && (
          <div className="flex flex-wrap items-center justify-between gap-2 border-t pt-3">
            <p className="text-xs">{t("Freeze the complete task selection while the assessment continues.")}</p>
            <Button size="sm" disabled={busy} onClick={() => void load("current")}>
              {t("Freeze task")}
            </Button>
          </div>
        )}
        {mode === "Frozen" && <FileInput label={t("Open casefile")} onFile={(f) => void load("current", f)} />}
        {mode === "Compare" && (
          <div className="grid min-w-0 gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <FileInput label={t("Open earlier casefile")} onFile={(f) => void load("earlier", f)} />
              {earlier && <CaptureSummary loaded={earlier} />}
            </div>
            <div className="space-y-2">
              <FileInput label={t("Open later casefile")} onFile={(f) => void load("later", f)} />
              {later && <CaptureSummary loaded={later} />}
            </div>
          </div>
        )}
      </Card>
      {error && (
        <p role="alert" className="break-words rounded-lg border p-3 text-destructive text-sm">
          {error}
        </p>
      )}
      {busy && (
        <p role="status" className="text-xs">
          {t("Reading casefile…")}
        </p>
      )}
      {mode === "Live" ? (
        <LiveRecords taskId={taskId} />
      ) : (
        <>
          {comparison && (
            <Card className="gap-2 p-4 text-sm">
              <h3 className="font-medium">
                {comparison.compatible ? t("Snapshot comparison") : t("Automatic comparison unavailable")}
              </h3>
              <p>{t(comparison.reason)}</p>
              {comparison.compatible && (
                <p>
                  {t("Added {added} · Absent from later snapshot {absent} · Changed {changed}", {
                    added: comparison.changes.filter((c) => c.kind === "added").length,
                    absent: comparison.changes.filter((c) => c.kind === "absent").length,
                    changed: comparison.changes.filter((c) => c.kind === "changed").length,
                  })}
                </p>
              )}
            </Card>
          )}
          {loaded && (
            <Card className="gap-3 p-4">
              {mode === "Compare" && (
                <fieldset aria-label={t("Inspect casefile")} className="flex flex-wrap gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    aria-pressed={loaded === earlier}
                    disabled={!earlier}
                    onClick={() => setSide("earlier")}
                  >
                    {t("Inspect earlier")}
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    aria-pressed={loaded === later}
                    disabled={!later}
                    onClick={() => setSide("later")}
                  >
                    {t("Inspect later")}
                  </Button>
                </fieldset>
              )}
              <h3 className="font-medium text-sm">{mode === "Compare" ? captureLabel : t("Frozen casefile")}</h3>
              {mode !== "Compare" && <CaptureSummary loaded={loaded} />}
              <p className="text-muted-foreground text-xs">
                {t(
                  "This historical database snapshot uses producer-asserted metadata. Matching hashes check bytes. Origin is unauthenticated and the security claim is unassessed.",
                )}
              </p>
              <p className="text-muted-foreground text-xs">
                {t(
                  "A recorded approval and an agent display label cannot establish target-owner authorization or authenticated identity. Tool-reported success lacks an independent receipt.",
                )}
              </p>
              <div className="flex flex-wrap gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => download(filename, loaded.bytes, "application/json")}
                >
                  {t("Download casefile")}
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => download(`${filename}.sha256`, `${loaded.digest}  ${filename}\n`, "text/plain")}
                >
                  {t("Download SHA-256")}
                </Button>
                <Button size="sm" onClick={exportReport}>
                  {t("Export reviewer report")}
                </Button>
              </div>
            </Card>
          )}
          {loaded && (
            <AuthorityRecordBrowser
              key={`${mode}:${loaded.digest}`}
              records={loaded.data.records}
              comparison={comparison}
              onLocate={locate}
            />
          )}
        </>
      )}
    </section>
  );
}

export function AuthorityTab(props: Props) {
  return <Workbench key={props.taskId} {...props} />;
}
