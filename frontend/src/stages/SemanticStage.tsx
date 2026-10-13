import { AlertTriangle, Info, Radio, XCircle } from "lucide-react";
import { Badge, Card, Empty, SectionTitle, cx } from "../components/ui";
import type { ScopeInfo, SymbolInfo } from "../types";
import type { StageViewProps } from "./common";

const KIND_TONE: Record<string, string> = {
  function: "text-orange-600 dark:text-orange-300",
  parameter: "text-teal-700 dark:text-teal-300",
  variable: "text-sky-700 dark:text-sky-300",
  typedef: "text-violet-600 dark:text-violet-300",
  enum_constant: "text-emerald-700 dark:text-emerald-300",
  record: "text-fuchsia-700 dark:text-fuchsia-300",
};

function dims(s: SymbolInfo) {
  return s.array_dims.map((d) => `[${d ?? ""}]`).join("");
}

function ScopeBox({ scope, onLine, depth = 0 }: { scope: ScopeInfo; onLine: (line: number) => void; depth?: number }) {
  return (
    <div className={cx("rounded-xl border border-line", depth === 0 ? "bg-panel" : "bg-panel-2/40")}>
      <div className="flex items-center gap-2 border-b border-line px-3 py-1.5 text-xs">
        <span className="font-mono font-semibold">#{scope.id}</span>
        <span className="font-medium">{scope.name}</span>
        <Badge>{scope.kind}</Badge>
        <span className="ml-auto text-faint">line {scope.line}</span>
      </div>
      {scope.symbols.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[12px]">
            <tbody>
              {scope.symbols.map((s) => (
                <tr key={`${s.name}-${s.line}`} className="cursor-pointer border-t border-line first:border-t-0 hover:bg-panel-2" onClick={() => onLine(s.line)}>
                  <td className="whitespace-nowrap px-3 py-1 font-mono font-medium">
                    {s.name}
                    {dims(s)}
                  </td>
                  <td className={cx("px-2 py-1", KIND_TONE[s.kind])}>{s.kind.replace("_", " ")}</td>
                  <td className="px-2 py-1 font-mono text-muted">{s.type}</td>
                  <td className="whitespace-nowrap px-2 py-1 text-faint">L{s.line}</td>
                  <td className="whitespace-nowrap px-2 py-1 text-faint">{s.uses} use{s.uses === 1 ? "" : "s"}</td>
                  <td className="px-3 py-1 text-right">
                    {s.tainted && (
                      <Badge tone="danger" title={s.taint_reason}>
                        <Radio size={10} /> input
                      </Badge>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {scope.children.length > 0 && (
        <div className="space-y-2 p-2">
          {scope.children.map((c) => (
            <ScopeBox key={c.id} scope={c} onLine={onLine} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

export function SemanticStage({ stage, setFocus }: StageViewProps<"semantic">) {
  const d = stage.data;
  const onLine = (line: number) => setFocus({ line });
  const externals = Object.entries(d.external_functions).sort((a, b) => b[1] - a[1]);
  return (
    <div className="space-y-5">
      <div className="grid gap-4 lg:grid-cols-2">
        <div>
          <SectionTitle>Input-derived symbols (taint sources)</SectionTitle>
          {d.tainted.length ? (
            <div className="space-y-1.5">
              {d.tainted.map((s) => (
                <div
                  key={`${s.name}-${s.line}`}
                  onClick={() => onLine(s.line)}
                  className="cursor-pointer rounded-lg border border-sev-critical/30 bg-sev-critical/5 px-3 py-2 text-[12.5px]"
                >
                  <span className="font-mono font-semibold">{s.name}</span>
                  <span className="text-faint"> ({s.scope})</span> — <span className="text-muted">{s.taint_reason}</span>
                </div>
              ))}
            </div>
          ) : (
            <Empty>No variable receives external input.</Empty>
          )}
        </div>
        <div>
          <SectionTitle>Semantic diagnostics</SectionTitle>
          {d.diagnostics.length ? (
            <ul className="max-h-60 space-y-1 overflow-auto">
              {d.diagnostics.map((g, i) => (
                <li key={i} onClick={() => onLine(g.line)} className="flex cursor-pointer items-start gap-2 rounded px-1 text-[12.5px] hover:bg-panel-2">
                  {g.severity === "error" ? (
                    <XCircle size={14} className="mt-0.5 shrink-0 text-sev-critical" />
                  ) : g.severity === "warning" ? (
                    <AlertTriangle size={14} className="mt-0.5 shrink-0 text-sev-medium" />
                  ) : (
                    <Info size={14} className="mt-0.5 shrink-0 text-sev-low" />
                  )}
                  <span>
                    <span className="font-mono text-faint">L{g.line}</span> {g.message}
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <Empty>No semantic diagnostics.</Empty>
          )}
        </div>
      </div>

      {externals.length > 0 && (
        <Card className="p-3">
          <SectionTitle>External (library) functions called — not declared in this file</SectionTitle>
          <div className="flex flex-wrap gap-1.5">
            {externals.map(([name, count]) => (
              <Badge key={name} className="font-mono">
                {name}() <span className="text-faint">×{count}</span>
              </Badge>
            ))}
          </div>
        </Card>
      )}

      <div>
        <SectionTitle>Symbol table — nested scopes ({d.symbols.length} symbols)</SectionTitle>
        <ScopeBox scope={d.scopes} onLine={onLine} />
      </div>
    </div>
  );
}
