import { CheckCircle2 } from "lucide-react";
import { FindingCard } from "../components/FindingCard";
import { Badge, Empty, SectionTitle, SeverityBadge, cx, ms } from "../components/ui";
import type { Finding, RuleRun } from "../types";
import type { StageViewProps } from "./common";

export function RulesTable({ rules, unit }: { rules: RuleRun[]; unit: string }) {
  return (
    <div className="overflow-auto rounded-xl border border-line">
      <table className="w-full text-left text-[12.5px]">
        <thead className="bg-panel-2 text-faint">
          <tr>
            <th className="px-3 py-2 font-medium">Rule</th>
            <th className="hidden px-3 py-2 font-medium md:table-cell">Matching logic</th>
            <th className="px-3 py-2 text-right font-medium">Examined</th>
            <th className="px-3 py-2 text-right font-medium">Hits</th>
            <th className="px-3 py-2 text-right font-medium">Time</th>
          </tr>
        </thead>
        <tbody>
          {rules.map((r) => (
            <tr key={r.id} className={cx("border-t border-line align-top", r.hits > 0 && "bg-sev-critical/[0.04]")}>
              <td className="px-3 py-2">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs text-faint">{r.id}</span>
                  <span className="font-medium">{r.name}</span>
                </div>
                <div className="mt-1 flex flex-wrap items-center gap-1">
                  <SeverityBadge severity={r.severity} />
                  <span className="text-[11px] text-faint">{r.cwe} · {r.category}</span>
                </div>
                {r.error && <div className="mt-1 text-xs text-sev-critical">rule error: {r.error}</div>}
              </td>
              <td className="hidden max-w-md px-3 py-2 font-mono text-[11px] text-muted md:table-cell">{r.detects}</td>
              <td className="px-3 py-2 text-right font-mono text-muted" title={`${unit} inspected`}>{r.examined}</td>
              <td className={cx("px-3 py-2 text-right font-mono font-semibold", r.hits ? "text-sev-critical" : "text-faint")}>{r.hits}</td>
              <td className="whitespace-nowrap px-3 py-2 text-right font-mono text-faint">{ms(r.duration_ms)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function FindingList({
  findings,
  goTo,
  emptyText,
}: {
  findings: Finding[];
  goTo: StageViewProps["goTo"];
  emptyText: string;
}) {
  if (!findings.length)
    return (
      <Empty>
        <CheckCircle2 className="mx-auto mb-2 text-accent" /> {emptyText}
      </Empty>
    );
  return (
    <div className="space-y-2">
      {findings.map((f) => (
        <FindingCard
          key={f.id}
          finding={f}
          onShowLine={(line) => goTo("source", { line })}
          onShowNode={(nodeId) => goTo("ast", { nodeId, line: f.line })}
        />
      ))}
    </div>
  );
}

export function LexicalSecurityStage({ stage, goTo }: StageViewProps<"lexical_security">) {
  const { rules, findings } = stage.data;
  return (
    <div className="space-y-5">
      <div>
        <SectionTitle right={<Badge tone="lexical">Module 1 · token level</Badge>}>Findings ({findings.length})</SectionTitle>
        <FindingList findings={findings} goTo={goTo} emptyText="No token-level patterns matched." />
      </div>
      <div>
        <SectionTitle>Token rules executed</SectionTitle>
        <RulesTable rules={rules} unit="tokens" />
      </div>
    </div>
  );
}

export function AstSecurityStage({ stage, goTo }: StageViewProps<"ast_security">) {
  const { rules, findings } = stage.data;
  return (
    <div className="space-y-5">
      <div>
        <SectionTitle right={<Badge tone="ast">Module 2 · structure aware</Badge>}>Findings ({findings.length})</SectionTitle>
        <FindingList findings={findings} goTo={goTo} emptyText="No structural security patterns matched." />
      </div>
      <div>
        <SectionTitle>AST rules executed</SectionTitle>
        <RulesTable rules={rules} unit="AST nodes / calls" />
      </div>
    </div>
  );
}
