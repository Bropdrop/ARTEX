"use client";

import * as React from "react";

import { type LocateRecord, RecordDetails, StateBadge, timestamp } from "@/components/authority-record-details";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { t } from "@/i18n";
import { decisionState } from "@/lib/authority";
import { type CaseRecord, type Comparison, type Diagnostic, diagnostics, timeline } from "@/lib/casefile";
import { cn } from "@/lib/utils";

const textFilters = [
  ["tool_name", "Tool name"],
  ["agent_name", "Recorded agent label"],
  ["status", "Decision state"],
  ["decided_by", "Decided by"],
  ["decision_source", "Decision source"],
] as const;
const clearFilters = {
  search: "",
  tool_name: "",
  agent_name: "",
  status: "",
  decided_by: "",
  decision_source: "",
  from: "",
  until: "",
  gap: "",
};
const listSize = 25;
const changeLabels = { added: "Added to later snapshot", absent: "Absent from later snapshot", changed: "Changed" };
const eventLabels = {
  created_at: "Recorded at",
  decided_at: "Decision recorded at",
  execution_ended_at: "Tool result recorded at",
};

export function AuthorityRecordBrowser({
  records,
  live = false,
  onLocate,
  comparison,
}: {
  records: CaseRecord[];
  live?: boolean;
  onLocate?: LocateRecord;
  comparison?: Comparison;
}) {
  const prefix = React.useId();
  const [filters, setFilters] = React.useState(clearFilters);
  const [cursor, setCursor] = React.useState<{ id: string; field?: string }>();
  const [playing, setPlaying] = React.useState(false);
  const [changeFilter, setChangeFilter] = React.useState("");
  const changes = React.useMemo(() => new Map(comparison?.changes.map((change) => [change.id, change])), [comparison]);
  const findings = React.useMemo(() => diagnostics(records), [records]);
  const byId = React.useMemo(() => {
    const map = new Map<string, Diagnostic[]>();
    for (const advisory of findings)
      for (const id of advisory.recordIds) {
        const existing = map.get(id);
        if (existing) existing.push(advisory);
        else map.set(id, [advisory]);
      }
    return map;
  }, [findings]);
  const rules = React.useMemo(() => [...new Set(findings.map((d) => d.rule))].sort(), [findings]);
  const matched = React.useMemo(
    () =>
      records.filter((record) => {
        const contains = (value: string, term: string) => value.toLowerCase().includes(term.trim().toLowerCase());
        if (!textFilters.every(([key]) => contains(record[key], filters[key]))) return false;
        if (
          filters.search.trim() &&
          ![
            record.id,
            record.rule_name,
            record.tool_use_id,
            record.execution_status,
            ...textFilters.map(([key]) => record[key]),
          ].some((value) => contains(value, filters.search))
        )
          return false;
        if (changeFilter && changes.get(record.id)?.kind !== changeFilter) return false;
        if (filters.gap && !byId.get(record.id)?.some((d) => d.rule === filters.gap)) return false;
        if (!filters.from && !filters.until) return true;
        const date = record.created_at ? Date.parse(record.created_at) : NaN;
        if (!Number.isFinite(date)) return false;
        return (
          (!filters.from || date >= Date.parse(`${filters.from}T00:00:00Z`)) &&
          (!filters.until || date < Date.parse(`${filters.until}T00:00:00Z`) + 86400000)
        );
      }),
    [records, filters, byId, changeFilter, changes],
  );
  const events = React.useMemo(() => (live ? [] : timeline(matched)), [live, matched]);
  const selectedIndex = Math.max(
    0,
    matched.findIndex((row) => row.id === cursor?.id),
  );
  const selected = matched[selectedIndex];
  const firstEvent = events.findIndex((event) => event.id === selected?.id);
  const exactEvent = cursor?.field
    ? events.findIndex((event) => event.id === selected?.id && event.field === cursor.field)
    : -1;
  const eventIndex = exactEvent >= 0 ? exactEvent : Math.max(0, firstEvent);
  const event = events[eventIndex];
  const page = Math.floor(selectedIndex / listSize);
  const selectEvent = (i: number) => {
    const next = events[i];
    if (next) setCursor({ id: next.id, field: next.field });
  };
  React.useEffect(() => {
    if (!playing) return;
    const next = events[eventIndex + 1];
    if (!next) {
      setPlaying(false);
      return;
    }
    const timer = window.setTimeout(() => setCursor({ id: next.id, field: next.field }), 900);
    return () => window.clearTimeout(timer);
  }, [events, eventIndex, playing]);
  const setFilter = (key: keyof typeof clearFilters, value: string) => {
    setPlaying(false);
    setCursor(undefined);
    setFilters((old) => ({ ...old, [key]: value }));
  };
  const select = (id: string) => {
    setPlaying(false);
    setCursor({ id });
  };
  return (
    <div className="min-w-0 space-y-4">
      <Card className="gap-3 p-4">
        <label htmlFor={`${prefix}search`} className="space-y-1 font-medium text-sm">
          {t("Search records")}
          <Input
            id={`${prefix}search`}
            type="search"
            value={filters.search}
            onChange={(e) => setFilter("search", e.target.value)}
          />
        </label>
        <details>
          <summary className="w-fit cursor-pointer font-medium text-sm">{t("Filter records")}</summary>
          <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {textFilters.map(([key, label]) => (
              <label htmlFor={`${prefix}${key}`} key={key} className="space-y-1 text-xs">
                {t(label)}
                <Input id={`${prefix}${key}`} value={filters[key]} onChange={(e) => setFilter(key, e.target.value)} />
              </label>
            ))}
            <label htmlFor={`${prefix}from`} className="space-y-1 text-xs">
              {t("Recorded from (UTC)")}
              <Input
                id={`${prefix}from`}
                type="date"
                value={filters.from}
                onChange={(e) => setFilter("from", e.target.value)}
              />
            </label>
            <label htmlFor={`${prefix}until`} className="space-y-1 text-xs">
              {t("Recorded through (UTC)")}
              <Input
                id={`${prefix}until`}
                type="date"
                value={filters.until}
                onChange={(e) => setFilter("until", e.target.value)}
              />
            </label>
            <label className="space-y-1 text-xs">
              {t("Evidence gap")}
              <select
                className="block h-8 w-full rounded border bg-background px-2"
                value={filters.gap}
                onChange={(e) => setFilter("gap", e.target.value)}
              >
                <option value="">{t("All")}</option>
                {rules.map((rule) => (
                  <option key={rule} value={rule}>
                    {rule}
                  </option>
                ))}
              </select>
            </label>
            {comparison?.compatible && (
              <label className="space-y-1 text-xs">
                {t("Snapshot change")}
                <select
                  className="block h-8 w-full rounded border bg-background px-2"
                  value={changeFilter}
                  onChange={(e) => {
                    setPlaying(false);
                    setChangeFilter(e.target.value);
                    setCursor(undefined);
                  }}
                >
                  <option value="">{t("All")}</option>
                  {Object.entries(changeLabels).map(([key, label]) => (
                    <option value={key} key={key}>
                      {t(label)}
                    </option>
                  ))}
                </select>
              </label>
            )}
          </div>
        </details>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p role="status" className="text-muted-foreground text-xs">
            {live
              ? t("{matches} of {count} records on this page", { matches: matched.length, count: records.length })
              : t("{matches} of {count} records in this casefile", { matches: matched.length, count: records.length })}
          </p>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              setPlaying(false);
              setFilters(clearFilters);
              setChangeFilter("");
              setCursor(undefined);
            }}
          >
            {t("Clear filters")}
          </Button>
        </div>
      </Card>
      {!live && events.length > 0 && (
        <Card className="gap-2 p-4">
          <h3 className="font-medium text-sm">{t("Recorded timeline")}</h3>
          <p className="text-muted-foreground text-xs">
            {t(
              "Timestamps order the recorded fields. Undated entries follow dated events. Sequence alone cannot establish causation.",
            )}
          </p>
          <div className="flex items-center gap-3">
            <Button
              size="sm"
              variant="outline"
              disabled={events.length < 2}
              onClick={() => {
                if (!playing && eventIndex === events.length - 1) selectEvent(0);
                setPlaying(!playing);
              }}
            >
              {playing ? t("Pause") : t("Play")}
            </Button>
            <input
              type="range"
              className="w-full min-w-0"
              aria-label={t("Recorded event")}
              min={0}
              max={events.length - 1}
              value={eventIndex}
              aria-valuetext={event && `#${event.id} · ${t(eventLabels[event.field])} · ${timestamp(event.time)}`}
              onChange={(e) => {
                setPlaying(false);
                selectEvent(Number(e.target.value));
              }}
            />
          </div>
          {event && (
            <p className="text-xs">
              #{event.id} · {t(eventLabels[event.field])} · {timestamp(event.time)}
            </p>
          )}
        </Card>
      )}
      <div className="grid min-w-0 items-start gap-4 xl:grid-cols-[280px_minmax(0,1fr)]">
        <Card className="min-w-0 gap-0 py-0">
          <h3 className="border-b p-4 font-medium text-sm">{t("Recorded decisions")}</h3>
          {matched.length === 0 ? (
            <div className="space-y-2 p-4 text-sm">
              <p>{t("No matching recorded decisions.")}</p>
              <p className="text-muted-foreground text-xs">
                {t("An empty view does not establish that no actions occurred.")}
              </p>
            </div>
          ) : (
            <ul aria-label={t("Recorded interception decisions")} className="max-h-[560px] divide-y overflow-y-auto">
              {matched.slice(page * listSize, (page + 1) * listSize).map((row) => {
                const change = changes.get(row.id);
                return (
                  <li key={row.id}>
                    <button
                      type="button"
                      aria-pressed={row.id === selected?.id}
                      className={cn(
                        "w-full space-y-2 p-3.5 text-left hover:bg-muted/60 focus-visible:outline-2 focus-visible:outline-primary focus-visible:outline-offset-[-2px]",
                        selected?.id === row.id && "bg-blue-50/60 dark:bg-blue-950/20",
                      )}
                      onClick={() => select(row.id)}
                    >
                      <span className="flex justify-between gap-2">
                        <span className="truncate font-medium text-sm">{row.tool_name || t("Not recorded")}</span>
                        <span className="break-all text-muted-foreground text-xs">#{row.id}</span>
                      </span>
                      <StateBadge state={decisionState(row.status)} />
                      <span className="block truncate text-muted-foreground text-xs">
                        {row.agent_name || t("Not recorded")}
                      </span>
                      <span className="block text-muted-foreground text-xs">{timestamp(row.created_at)}</span>
                      {change && <span className="block font-medium text-xs">{t(changeLabels[change.kind])}</span>}
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
          {matched.length > listSize && (
            <div className="flex flex-wrap items-center justify-between gap-2 border-t p-3">
              <Button
                size="sm"
                variant="outline"
                disabled={page === 0}
                onClick={() => select(matched[(page - 1) * listSize].id)}
              >
                {t("Previous page")}
              </Button>
              <span className="text-xs">
                {page + 1} / {Math.ceil(matched.length / listSize)}
              </span>
              <Button
                size="sm"
                variant="outline"
                disabled={(page + 1) * listSize >= matched.length}
                onClick={() => select(matched[(page + 1) * listSize].id)}
              >
                {t("Next page")}
              </Button>
            </div>
          )}
        </Card>
        {selected && (
          <RecordDetails
            key={JSON.stringify([
              selected.id,
              selected.tool_use_id,
              selected.run_id,
              selected.tool_name,
              selected.correlation,
            ])}
            record={selected}
            advisories={byId.get(selected.id) ?? []}
            change={changes.get(selected.id)}
            onLocate={onLocate}
          />
        )}
      </div>
    </div>
  );
}
