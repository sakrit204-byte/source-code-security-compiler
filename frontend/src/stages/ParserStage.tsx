import { AlertTriangle, CheckCircle2, CornerDownRight, RotateCcw, Search, XCircle } from "lucide-react";
import { useMemo, useState } from "react";
import { Badge, Card, SectionTitle, cx } from "../components/ui";
import type { TraceEntry } from "../types";
import type { StageViewProps } from "./common";

type View = "trace" | "grammar";

const EVENT_STYLE: Record<TraceEntry["event"], string> = {
  enter: "text-fg",
  match: "text-accent",
  error: "text-sev-critical",
  recover: "text-sev-medium",
};

export function ParserStage({ stage, focus, setFocus }: StageViewProps<"parser">) {
  const d = stage.data;
  const [view, setView] = useState<View>("trace");
  const [query, setQuery] = useState("");
  const [limit, setLimit] = useState(400);

  const trace = useMemo(() => {
    const q = query.trim().toLowerCase();
    return q ? d.trace.filter((t) => t.rule.toLowerCase().includes(q) || t.token.toLowerCase() === q) : d.trace;
  }, [d.trace, query]);

  return (
    <div className="space-y-4">
      {d.errors.length > 0 ? (
        <Card className="border-sev-medium/50 p-3">
          <SectionTitle>Syntax errors and panic-mode recovery</SectionTitle>
          <ul className="space-y-2 text-sm">
            {d.errors.map((e, i) => (
              <li key={i} className="cursor-pointer" onClick={() => setFocus({ line: e.line })}>
                <div className="flex items-start gap-2">
                  <XCircle size={15} className="mt-0.5 shrink-0 text-sev-critical" />
                  <span>
                    <span className="font-mono text-xs text-faint">{e.line}:{e.col}</span> {e.message}
                  </span>
                </div>
                {e.recovery && (
                  <div className="ml-6 flex items-center gap-1.5 text-xs text-muted">
                    <RotateCcw size={12} /> {e.recovery}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </Card>
      ) : (
        <div className="flex items-center gap-2 rounded-lg bg-accent-soft/60 px-3 py-2 text-sm text-accent">
          <CheckCircle2 size={16} /> The token stream is a valid sentence of the grammar — derivation from <code>translation_unit</code> succeeded.
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <div className="flex w-fit items-center gap-1 rounded-lg bg-panel-2 p-1 text-xs font-medium">
          {(["trace", "grammar"] as View[]).map((v) => (
            <button
              key={v}
              onClick={() => setView(v)}
              className={cx("rounded-md px-3 py-1", view === v ? "bg-panel shadow-sm" : "text-muted hover:text-fg")}
            >
              {v === "trace" ? `Derivation trace (${d.trace.length})` : `Grammar (${d.grammar.length} productions)`}
            </button>
          ))}
        </div>
        {d.typedefs.length > 0 && (
          <span className="text-xs text-muted">
            typedef names learned: {d.typedefs.map((t) => <Badge key={t} className="mr-1 font-mono">{t}</Badge>)}
          </span>
        )}
      </div>

      {view === "trace" && (
        <div className="overflow-hidden rounded-xl border border-line bg-code">
          <div className="flex items-center gap-2 border-b border-line px-3 py-2">
            <Search size={14} className="text-faint" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter by production (e.g. if_statement, function_call) or exact token"
              className="w-full bg-transparent text-sm outline-none placeholder:text-faint"
            />
          </div>
          <div className="max-h-[30rem] overflow-auto py-1 font-mono text-[12px]">
            {trace.slice(0, limit).map((t, i) => (
              <div
                key={i}
                onClick={() => setFocus({ line: t.line })}
                className={cx(
                  "flex cursor-pointer items-center gap-2 whitespace-nowrap px-3 py-[1px] hover:bg-panel-2/70",
                  focus.line === t.line && "bg-accent/10",
                )}
              >
                <span className="w-12 shrink-0 text-right text-faint">{t.line}:{t.col}</span>
                <span style={{ paddingLeft: Math.min(t.depth, 40) * 12 }} className={cx("flex items-center gap-1", EVENT_STYLE[t.event])}>
                  {t.event === "enter" && <CornerDownRight size={11} className="text-faint" />}
                  {t.event === "error" && <XCircle size={11} />}
                  {t.event === "recover" && <AlertTriangle size={11} />}
                  {t.event === "match" && <CheckCircle2 size={11} />}
                  {t.rule}
                </span>
                {t.event === "enter" && <span className="text-faint">⟵ '{t.token}'</span>}
              </div>
            ))}
            {trace.length > limit && (
              <button onClick={() => setLimit(limit + 1000)} className="w-full py-2 text-xs text-accent">
                Show more ({trace.length - limit} remaining)
              </button>
            )}
            {d.trace_truncated && <div className="px-3 py-2 text-xs text-faint">Trace truncated for very large inputs.</div>}
          </div>
        </div>
      )}

      {view === "grammar" && (
        <div className="overflow-auto rounded-xl border border-line">
          <table className="w-full text-left text-[12.5px]">
            <thead className="bg-panel-2 text-faint">
              <tr>
                <th className="px-3 py-2 font-medium">Non-terminal</th>
                <th className="px-3 py-2 font-medium">Production (EBNF)</th>
                <th className="px-3 py-2 text-right font-medium">Applied</th>
              </tr>
            </thead>
            <tbody>
              {d.grammar.map((g) => (
                <tr key={g.lhs} className={cx("border-t border-line align-top", !g.uses && "opacity-50")}>
                  <td className="whitespace-nowrap px-3 py-2 font-mono font-medium text-violet-600 dark:text-violet-300">{g.lhs}</td>
                  <td className="px-3 py-2 font-mono text-[11.5px] text-muted">::= {g.rhs}</td>
                  <td className="px-3 py-2 text-right font-mono">{g.uses || "–"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
