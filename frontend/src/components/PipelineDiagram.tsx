import type { Stage, StageId } from "../types";
import { ms } from "./ui";

type NodeState = "pending" | "running" | "done";

interface Props {
  stages: Stage[];
  revealed: number; // number of stages whose results are visible
  running: boolean; // request still in flight
  active: StageId;
  onSelect: (id: StageId) => void;
}

const W = 168;
const H = 58;
const NODES: { id: StageId; x: number; y: number; label: string; sub: string; module?: boolean }[] = [
  { id: "source", x: 12, y: 14, label: "Source Code", sub: "input" },
  { id: "lexer", x: 200, y: 14, label: "Lexer", sub: "tokens" },
  { id: "parser", x: 388, y: 14, label: "Parser", sub: "derivation" },
  { id: "ast", x: 576, y: 14, label: "AST", sub: "syntax tree" },
  { id: "semantic", x: 764, y: 14, label: "Semantic", sub: "symbol table" },
  { id: "lexical_security", x: 200, y: 124, label: "Module 1", sub: "Lexical Security", module: true },
  { id: "ast_security", x: 670, y: 124, label: "Module 2", sub: "Syntax / AST Security", module: true },
  { id: "rule_engine", x: 330, y: 234, label: "Rule Engine", sub: "correlate · merge" },
  { id: "report", x: 560, y: 234, label: "Security Report", sub: "score · findings" },
];

const EDGES: [StageId, StageId][] = [
  ["source", "lexer"],
  ["lexer", "parser"],
  ["parser", "ast"],
  ["ast", "semantic"],
  ["lexer", "lexical_security"],
  ["semantic", "ast_security"],
  ["ast", "ast_security"],
  ["lexical_security", "rule_engine"],
  ["ast_security", "rule_engine"],
  ["rule_engine", "report"],
];

const ORDER: StageId[] = ["source", "lexer", "lexical_security", "parser", "ast", "semantic", "ast_security", "rule_engine", "report"];

function anchor(id: StageId, side: "l" | "r" | "t" | "b") {
  const n = NODES.find((x) => x.id === id)!;
  return {
    l: [n.x, n.y + H / 2],
    r: [n.x + W, n.y + H / 2],
    t: [n.x + W / 2, n.y],
    b: [n.x + W / 2, n.y + H],
  }[side] as [number, number];
}

function edgePath(from: StageId, to: StageId): string {
  const a = NODES.find((n) => n.id === from)!;
  const b = NODES.find((n) => n.id === to)!;
  if (Math.abs(a.y - b.y) < 5) {
    const [x1, y1] = anchor(from, a.x < b.x ? "r" : "l");
    const [x2, y2] = anchor(to, a.x < b.x ? "l" : "r");
    return `M${x1},${y1} L${x2},${y2}`;
  }
  const [x1, y1] = anchor(from, "b");
  const [x2, y2] = anchor(to, "t");
  const my = (y1 + y2) / 2;
  return `M${x1},${y1} C${x1},${my} ${x2},${my} ${x2},${y2}`;
}

export function PipelineDiagram({ stages, revealed, running, active, onSelect }: Props) {
  const stateOf = (id: StageId): NodeState => {
    const idx = ORDER.indexOf(id);
    if (idx < revealed) return "done";
    if (idx === revealed && (running || revealed < stages.length || stages.length === 0)) return "running";
    return "pending";
  };
  const stage = (id: StageId) => stages.find((s) => s.id === id);

  const strokeFor = (id: StageId) => {
    const st = stateOf(id);
    if (st === "pending") return "var(--line)";
    if (st === "running") return "var(--accent)";
    const s = stage(id);
    if (s?.status === "warning") return "var(--sev-medium)";
    if (s?.status === "alert") return "var(--sev-critical)";
    return "var(--accent)";
  };

  return (
    <div className="overflow-x-auto">
      <svg viewBox="0 0 944 306" className="w-full min-w-[640px]" role="img" aria-label="Compiler pipeline">
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" fill="var(--faint)" />
          </marker>
          <marker id="arrow-on" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" fill="var(--accent)" />
          </marker>
        </defs>

        {EDGES.map(([from, to]) => {
          const fromDone = stateOf(from) === "done";
          const toState = stateOf(to);
          const live = fromDone && toState === "running";
          const lit = fromDone && toState === "done";
          const d = edgePath(from, to);
          return (
            <g key={`${from}-${to}`}>
              <path
                d={d}
                fill="none"
                stroke={lit || live ? "var(--accent)" : "var(--line)"}
                strokeWidth={lit || live ? 2 : 1.5}
                className={live ? "flow-dash" : undefined}
                markerEnd={lit || live ? "url(#arrow-on)" : "url(#arrow)"}
              />
            </g>
          );
        })}

        {NODES.map((n) => {
          const st = stateOf(n.id);
          const s = stage(n.id);
          const selected = active === n.id;
          return (
            <g
              key={n.id}
              onClick={() => st === "done" && onSelect(n.id)}
              style={{ cursor: st === "done" ? "pointer" : "default", opacity: st === "pending" ? 0.55 : 1 }}
            >
              {selected && <rect x={n.x - 4} y={n.y - 4} width={W + 8} height={H + 8} rx={14} fill="none" stroke="var(--accent)" strokeWidth={1.5} strokeDasharray="4 3" />}
              <rect
                x={n.x}
                y={n.y}
                width={W}
                height={H}
                rx={11}
                fill={n.module ? "color-mix(in srgb, var(--sev-critical) 8%, var(--panel))" : "var(--panel)"}
                stroke={strokeFor(n.id)}
                strokeWidth={st === "pending" ? 1.2 : 2}
              />
              {st === "running" && (
                <circle cx={n.x + W - 14} cy={n.y + 14} r={4} fill="var(--accent)">
                  <animate attributeName="opacity" values="1;0.2;1" dur="0.9s" repeatCount="indefinite" />
                </circle>
              )}
              {st === "done" && s && (
                <text x={n.x + W - 10} y={n.y + 17} textAnchor="end" fontSize="9.5" fill="var(--faint)" fontFamily="var(--font-mono)">
                  {ms(s.duration_ms)}
                </text>
              )}
              <text x={n.x + 12} y={n.y + 23} fontSize="13" fontWeight={600} fill="var(--fg)" fontFamily="var(--font-sans)">
                {n.label}
              </text>
              <text x={n.x + 12} y={n.y + 41} fontSize="10.5" fill="var(--muted)" fontFamily="var(--font-sans)">
                {st === "done" && s ? truncate(s.summary, 27) : n.sub}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

function truncate(text: string, n: number) {
  return text.length > n ? text.slice(0, n - 1) + "…" : text;
}

export { ORDER as STAGE_ORDER };
