import { ChevronRight, ChevronsDownUp, ChevronsUpDown, ShieldAlert } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { CodeView } from "../components/CodeView";
import { Card, SectionTitle, SEV_TEXT, astKindColor, cx } from "../components/ui";
import type { AstNode, Finding } from "../types";
import type { StageViewProps } from "./common";

interface Index {
  byId: Map<number, AstNode>;
  parent: Map<number, number>;
  depth: Map<number, number>;
}

function buildIndex(root: AstNode): Index {
  const byId = new Map<number, AstNode>();
  const parent = new Map<number, number>();
  const depth = new Map<number, number>();
  const stack: [AstNode, number, number | null][] = [[root, 0, null]];
  while (stack.length) {
    const [node, d, p] = stack.pop()!;
    byId.set(node.id, node);
    depth.set(node.id, d);
    if (p != null) parent.set(node.id, p);
    for (const c of node.children) stack.push([c, d + 1, node.id]);
  }
  return { byId, parent, depth };
}

export function AstStage({ stage, result, focus, setFocus }: StageViewProps<"ast">) {
  const d = stage.data;
  const index = useMemo(() => buildIndex(d.tree), [d.tree]);
  const findingsByNode = useMemo(() => {
    const map = new Map<number, Finding[]>();
    for (const f of result.report.findings) {
      if (f.node_id == null) continue;
      map.set(f.node_id, [...(map.get(f.node_id) ?? []), f]);
    }
    return map;
  }, [result.report.findings]);
  // Ancestors of flagged nodes, so collapsed branches still show where findings are.
  const flaggedPaths = useMemo(() => {
    const set = new Set<number>();
    for (const id of findingsByNode.keys()) {
      let cur: number | undefined = id;
      while (cur != null) {
        set.add(cur);
        cur = index.parent.get(cur);
      }
    }
    return set;
  }, [findingsByNode, index]);

  const [expanded, setExpanded] = useState<Set<number>>(() => {
    const s = new Set<number>();
    index.depth.forEach((dep, id) => dep < 3 && s.add(id));
    return s;
  });
  const [selected, setSelected] = useState<number>(focus.nodeId ?? d.tree.children[0]?.id ?? 0);
  const treeBox = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (focus.nodeId == null || !index.byId.has(focus.nodeId)) return;
    const id = focus.nodeId;
    setSelected(id);
    setExpanded((prev) => {
      const next = new Set(prev);
      let cur = index.parent.get(id);
      while (cur != null) {
        next.add(cur);
        cur = index.parent.get(cur);
      }
      return next;
    });
    setTimeout(() => {
      treeBox.current?.querySelector(`[data-node="${id}"]`)?.scrollIntoView({ block: "center", behavior: "smooth" });
    }, 50);
  }, [focus.nodeId, index]);

  const toggle = (id: number) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const select = (node: AstNode) => {
    setSelected(node.id);
    if (node.line) setFocus({ line: node.line, nodeId: node.id });
  };

  const node = index.byId.get(selected) ?? d.tree;
  const path: AstNode[] = [];
  for (let cur: number | undefined = node.id; cur != null; cur = index.parent.get(cur)) path.unshift(index.byId.get(cur)!);

  const renderNode = (n: AstNode, depth: number): JSX.Element => {
    const open = expanded.has(n.id);
    const hasKids = n.children.length > 0;
    const hits = findingsByNode.get(n.id);
    return (
      <div key={n.id}>
        <div
          data-node={n.id}
          onClick={() => select(n)}
          className={cx(
            "group flex cursor-pointer items-center gap-1.5 rounded-md py-[3px] pr-2 hover:bg-panel-2",
            selected === n.id && "bg-accent/15 ring-1 ring-accent/40",
          )}
          style={{ paddingLeft: depth * 16 + 4 }}
        >
          <button
            onClick={(e) => {
              e.stopPropagation();
              if (hasKids) toggle(n.id);
            }}
            className={cx("flex h-4 w-4 items-center justify-center text-faint", !hasKids && "invisible")}
          >
            <ChevronRight size={13} className={cx("transition-transform", open && "rotate-90")} />
          </button>
          <span className={cx("h-2 w-2 shrink-0 rounded-full", astKindColor(n.kind))} />
          {n.role && n.role !== "decls" && n.role !== "items" && (
            <span className="font-mono text-[10.5px] text-faint">{n.role}:</span>
          )}
          <span className="truncate font-mono text-[12px]">{n.label}</span>
          {hits && <ShieldAlert size={13} className={cx("shrink-0", SEV_TEXT[hits[0].severity])} />}
          {!hits && !open && flaggedPaths.has(n.id) && <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-sev-critical" title="contains findings" />}
          {n.line > 0 && <span className="ml-auto pl-2 font-mono text-[10.5px] text-faint opacity-0 group-hover:opacity-100">L{n.line}</span>}
        </div>
        {open && hasKids && n.children.map((c) => renderNode(c, depth + 1))}
      </div>
    );
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-1.5">
        {Object.entries(d.kinds).map(([kind, count]) => (
          <span key={kind} className="inline-flex items-center gap-1.5 rounded-full border border-line px-2 py-0.5 text-[11px]">
            <span className={cx("h-2 w-2 rounded-full", astKindColor(kind))} />
            {kind} <b className="font-mono">{count}</b>
          </span>
        ))}
      </div>
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)]">
        <div className="overflow-hidden rounded-xl border border-line bg-code">
          <div className="flex items-center gap-2 border-b border-line px-3 py-2 text-xs text-muted">
            <span className="font-medium">{d.node_count} nodes · depth {d.depth}</span>
            <button className="ml-auto inline-flex items-center gap-1 hover:text-fg" onClick={() => setExpanded(new Set(index.byId.keys()))}>
              <ChevronsUpDown size={13} /> Expand all
            </button>
            <button className="inline-flex items-center gap-1 hover:text-fg" onClick={() => setExpanded(new Set([d.tree.id]))}>
              <ChevronsDownUp size={13} /> Collapse
            </button>
          </div>
          <div ref={treeBox} className="max-h-[32rem] overflow-auto p-2">
            {renderNode(d.tree, 0)}
          </div>
        </div>
        <div className="space-y-3">
          <Card className="p-4">
            <div className="mb-2 flex flex-wrap items-center gap-1 text-[11px] text-faint">
              {path.map((p, i) => (
                <span key={p.id} className="inline-flex items-center gap-1">
                  {i > 0 && <ChevronRight size={10} />}
                  <button className="hover:text-accent" onClick={() => select(p)}>{p.kind}</button>
                </span>
              ))}
            </div>
            <div className="flex items-center gap-2">
              <span className={cx("h-2.5 w-2.5 rounded-full", astKindColor(node.kind))} />
              <span className="font-mono text-sm font-semibold">{node.label}</span>
            </div>
            <div className="mt-1 text-xs text-faint">
              node #{node.id} · line {node.line}:{node.col} · {node.children.length} child node(s)
            </div>
            {Object.keys(node.attrs).length > 0 && (
              <table className="mt-3 w-full text-[12px]">
                <tbody>
                  {Object.entries(node.attrs).map(([k, v]) => (
                    <tr key={k} className="border-t border-line">
                      <td className="py-1 pr-3 text-faint">{k}</td>
                      <td className="break-all py-1 font-mono">{JSON.stringify(v)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {findingsByNode.get(node.id)?.map((f) => (
              <div key={f.id} className={cx("mt-3 rounded-lg bg-panel-2 px-3 py-2 text-[12.5px]", SEV_TEXT[f.severity])}>
                <b>{f.rule_id}</b> {f.title} — <span className="text-muted">{f.message}</span>
              </div>
            ))}
          </Card>
          <div>
            <SectionTitle>Source of the selected node</SectionTitle>
            <CodeView source={result.source} focusLine={node.line || undefined} findings={result.report.findings} maxHeight="16rem" compact />
          </div>
        </div>
      </div>
    </div>
  );
}
