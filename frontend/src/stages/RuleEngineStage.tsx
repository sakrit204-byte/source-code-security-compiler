import { ArrowRight, Link2 } from "lucide-react";
import { Badge, Card, Empty, SectionTitle, SEV_BG, SEVERITIES, cx, ms } from "../components/ui";
import type { StageViewProps } from "./common";

export function RuleEngineStage({ stage, setFocus }: StageViewProps<"rule_engine">) {
  const d = stage.data;
  const maxTime = Math.max(...d.rules.map((r) => r.duration_ms), 0.001);
  const total = SEVERITIES.reduce((n, s) => n + d.severity_counts[s], 0);
  return (
    <div className="space-y-5">
      <Card className="p-4">
        <SectionTitle>Merge pipeline</SectionTitle>
        <div className="flex flex-wrap items-center gap-3 text-sm">
          <Flow value={d.raw_counts.lexical} label="lexical findings" tone="lexical" />
          <span className="text-faint">+</span>
          <Flow value={d.raw_counts.ast} label="AST findings" tone="ast" />
          <ArrowRight className="text-faint" size={16} />
          <Flow value={d.correlations.length} label="correlated pairs" tone="accent" />
          <ArrowRight className="text-faint" size={16} />
          <Flow value={d.merged_count} label="unique findings" tone="neutral" />
        </div>
        {total > 0 && (
          <div className="mt-4">
            <div className="flex h-2.5 overflow-hidden rounded-full bg-panel-2">
              {SEVERITIES.map((s) =>
                d.severity_counts[s] ? (
                  <div key={s} className={SEV_BG[s]} style={{ width: `${(d.severity_counts[s] / total) * 100}%` }} title={`${s}: ${d.severity_counts[s]}`} />
                ) : null,
              )}
            </div>
            <div className="mt-2 flex flex-wrap gap-3 text-[11px] text-muted">
              {SEVERITIES.map((s) => (
                <span key={s} className="inline-flex items-center gap-1">
                  <span className={cx("h-2 w-2 rounded-full", SEV_BG[s])} /> {s} {d.severity_counts[s]}
                </span>
              ))}
            </div>
          </div>
        )}
      </Card>

      <div>
        <SectionTitle>Cross-module correlation</SectionTitle>
        {d.correlations.length ? (
          <div className="space-y-1.5">
            {d.correlations.map((c) => (
              <div
                key={`${c.lexical}-${c.ast}`}
                onClick={() => setFocus({ line: c.line })}
                className="flex cursor-pointer flex-wrap items-center gap-2 rounded-lg border border-line px-3 py-2 text-[12.5px] hover:bg-panel-2"
              >
                <Badge tone="lexical">{c.lexical}</Badge>
                <Link2 size={13} className="text-accent" />
                <Badge tone="ast">{c.ast}</Badge>
                <span className="font-mono text-faint">L{c.line}</span>
                <span className="font-mono">{c.subject}</span>
                <span className="text-muted">— {c.reason}</span>
              </div>
            ))}
          </div>
        ) : (
          <Empty>No lexical finding was confirmed by an AST finding.</Empty>
        )}
      </div>

      <div>
        <SectionTitle>Rule execution profile</SectionTitle>
        <div className="overflow-auto rounded-xl border border-line">
          <table className="w-full text-left text-[12px]">
            <thead className="bg-panel-2 text-faint">
              <tr>
                <th className="px-3 py-2 font-medium">Rule</th>
                <th className="px-3 py-2 font-medium">Module</th>
                <th className="px-3 py-2 text-right font-medium">Examined</th>
                <th className="px-3 py-2 text-right font-medium">Hits</th>
                <th className="w-1/3 px-3 py-2 font-medium">Time</th>
              </tr>
            </thead>
            <tbody>
              {d.rules.map((r) => (
                <tr key={r.id} className="border-t border-line">
                  <td className="px-3 py-1.5">
                    <span className="font-mono text-faint">{r.id}</span> {r.name}
                  </td>
                  <td className="px-3 py-1.5">
                    <Badge tone={r.level === "lexical" ? "lexical" : "ast"}>{r.level === "lexical" ? "Module 1" : "Module 2"}</Badge>
                  </td>
                  <td className="px-3 py-1.5 text-right font-mono text-muted">{r.examined}</td>
                  <td className={cx("px-3 py-1.5 text-right font-mono font-semibold", r.hits ? "text-sev-critical" : "text-faint")}>{r.hits}</td>
                  <td className="px-3 py-1.5">
                    <div className="flex items-center gap-2">
                      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-panel-2">
                        <div className="h-full rounded-full bg-accent" style={{ width: `${Math.max(2, (r.duration_ms / maxTime) * 100)}%` }} />
                      </div>
                      <span className="w-16 text-right font-mono text-faint">{ms(r.duration_ms)}</span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function Flow({ value, label, tone }: { value: number; label: string; tone: "lexical" | "ast" | "accent" | "neutral" }) {
  return (
    <div className="flex items-baseline gap-1.5">
      <Badge tone={tone} className="font-mono text-sm">{value}</Badge>
      <span className="text-xs text-muted">{label}</span>
    </div>
  );
}
