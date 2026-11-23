"use client";

import * as React from "react";

import {
  Background,
  Controls,
  Handle,
  MarkerType,
  type Node,
  type NodeProps,
  Position,
  ReactFlow,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { CircleHelpIcon, FileCheck2Icon, FingerprintIcon, GitBranchIcon, TerminalIcon } from "lucide-react";

import { t } from "@/i18n";
import { type AuthorityGraphNode, actorState, authorityGraph, sourceState } from "@/lib/authority";
import type { AuthorityRecord } from "@/lib/types";
import { cn } from "@/lib/utils";

type GraphNode = Node<AuthorityGraphNode & { record: AuthorityRecord } & Record<string, unknown>, "authority">;

const colors = {
  neutral: "border-slate-300/70 dark:border-slate-600",
  info: "border-blue-300/80 dark:border-blue-700",
  warning: "border-amber-300/80 dark:border-amber-700",
  danger: "border-rose-300/80 dark:border-rose-700",
};
const iconColors = {
  neutral: "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300",
  info: "bg-blue-50 text-blue-600 dark:bg-blue-950 dark:text-blue-300",
  warning: "bg-amber-50 text-amber-700 dark:bg-amber-950 dark:text-amber-300",
  danger: "bg-rose-50 text-rose-600 dark:bg-rose-950 dark:text-rose-300",
};
const icons = {
  proposal: TerminalIcon,
  decision: GitBranchIcon,
  outcome: FileCheck2Icon,
  grant: FingerprintIcon,
  effect: CircleHelpIcon,
};

function AuthorityNode({ data }: NodeProps<GraphNode>) {
  const Icon = icons[data.kind];
  const missing = data.kind === "grant" || data.kind === "effect";
  return (
    <div
      className={cn(
        "w-[232px] rounded-xl border bg-card p-3.5 shadow-sm",
        colors[data.tone],
        missing && "border-dashed",
      )}
    >
      <Handle type="target" position={Position.Left} id="left" className="!opacity-0" />
      <Handle type="target" position={Position.Top} id="top" className="!opacity-0" />
      <Handle type="source" position={Position.Right} id="right" className="!opacity-0" />
      <Handle type="source" position={Position.Bottom} id="bottom" className="!opacity-0" />
      <div className="mb-3 flex items-center gap-2">
        <span className={cn("rounded-md p-1.5", iconColors[data.tone])}>
          <Icon className="size-4" />
        </span>
        <span className="font-medium text-muted-foreground text-xs">{t(data.title)}</span>
      </div>
      <p className="break-words font-semibold text-sm leading-snug">{data.valueIsLabel ? t(data.value) : data.value}</p>
      {data.kind === "proposal" && (
        <div className="mt-3 border-t pt-2.5">
          <p className="text-[11px] text-muted-foreground">{t(data.detail)}</p>
          <p className="mt-0.5 break-words text-xs">{data.record.agent_name || t("Not recorded")}</p>
        </div>
      )}
      {data.kind === "decision" && (
        <dl className="mt-3 space-y-1 border-t pt-2.5 text-xs">
          <div className="flex justify-between gap-2">
            <dt className="text-muted-foreground">{t("Decision source")}</dt>
            <dd>{t(sourceState(data.record.decision_source))}</dd>
          </div>
          <div className="flex justify-between gap-2">
            <dt className="text-muted-foreground">{t("Decided by")}</dt>
            <dd>{t(actorState(data.record.decided_by))}</dd>
          </div>
        </dl>
      )}
      {data.kind !== "proposal" && data.kind !== "decision" && (
        <p className="mt-2 text-[11px] text-muted-foreground leading-relaxed">{t(data.detail)}</p>
      )}
    </div>
  );
}

const nodeTypes = { authority: AuthorityNode };
const positions = {
  proposal: { x: 0, y: 198 },
  decision: { x: 284, y: 198 },
  outcome: { x: 568, y: 198 },
  grant: { x: 284, y: 0 },
  effect: { x: 568, y: 414 },
};

export function AuthorityGraph({ record }: { record: AuthorityRecord }) {
  const { nodes, edges } = React.useMemo(() => {
    const graph = authorityGraph(record);
    return {
      nodes: graph.nodes.map(
        (node): GraphNode => ({
          id: node.id,
          type: "authority",
          data: { ...node, record },
          position: positions[node.id],
        }),
      ),
      edges: graph.edges.map((edge) => {
        const vertical = edge.source === "grant" || edge.target === "effect";
        const unresolved = edge.kind === "unresolved";
        const color = unresolved ? "#b89247" : "#7188aa";
        return {
          ...edge,
          type: "smoothstep",
          sourceHandle: vertical ? "bottom" : "right",
          targetHandle: vertical ? "top" : "left",
          label: t(edge.label),
          style: { stroke: color, strokeWidth: 1.5, strokeDasharray: unresolved ? "5 5" : undefined },
          markerEnd: { type: MarkerType.ArrowClosed, color, width: 14, height: 14 },
          labelStyle: { fill: "var(--muted-foreground)", fontSize: 10 },
          labelBgStyle: { fill: "var(--card)", fillOpacity: 1 },
          labelBgPadding: [4, 4] as [number, number],
          labelBgBorderRadius: 4,
        };
      }),
    };
  }, [record]);

  return (
    <figure className="h-[430px] bg-muted/20 xl:h-[490px]" aria-label={t("Recorded decision evidence graph")}>
      <ReactFlow
        key={record.id}
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.08 }}
        minZoom={0.35}
        maxZoom={1.6}
        nodesDraggable={false}
        nodesConnectable={false}
        nodesFocusable={false}
        edgesFocusable={false}
        elementsSelectable={false}
        deleteKeyCode={null}
        preventScrolling={false}
        proOptions={{ hideAttribution: true }}
      >
        <Background gap={18} size={1} color="var(--border)" />
        <Controls showInteractive={false} />
      </ReactFlow>
    </figure>
  );
}
