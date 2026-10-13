import { Download, FileCode2, FileJson, FileText } from "lucide-react";
import { useMemo, useState } from "react";
import { api } from "../api";
import { CodeView } from "../components/CodeView";
import { GradeRing } from "../components/GradeRing";
import { Badge, Card, SectionTitle, SEV_BG, SEVERITIES, cx } from "../components/ui";
import type { Severity } from "../types";
import type { StageViewProps } from "./common";
import { FindingList } from "./SecurityStage";

type ModuleFilter = "all" | "lexical" | "ast" | "both";

export function ReportStage({ stage, result, focus, setFocus, goTo }: StageViewProps<"report">) {
  const r = stage.data;
  const [sevs, setSevs] = useState<Set<Severity>>(new Set(SEVERITIES));
  const [mod, setMod] = useState<ModuleFilter>("all");
  const [exporting, setExporting] = useState<string | null>(null);

  const findings = useMemo(
    () =>
      r.findings.filter((f) => {
        if (!sevs.has(f.severity)) return false;
        if (mod === "both") return f.detected_by.length > 1;
        if (mod === "lexical") return f.detected_by.length === 1 && f.detected_by[0] === "lexical";
        if (mod === "ast") return f.detected_by.length === 1 && f.detected_by[0] === "ast";
        return true;
      }),
    [r.findings, sevs, mod],
  );

  const toggleSev = (s: Severity) =>
    setSevs((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next.size ? next : new Set(SEVERITIES);
    });

  const doExport = async (format: "html" | "json" | "text") => {
    setExporting(format);
    try {
      await api.export(result.source, result.meta.filename, format);
    } finally {
      setExporting(null);
    }
  };

  const maxCat = Math.max(1, ...Object.values(r.by_category));

  return (
    <div className="space-y-5">
      <Card className="flex flex-col gap-5 p-5 sm:flex-row sm:items-center">
        <GradeRing grade={r.grade} score={r.score} size={96} />
        <div className="min-w-0 flex-1">
          <div className="text-lg font-semibold">{r.risk}</div>
          <div className="text-sm text-muted">
            {r.total} finding{r.total === 1 ? "" : "s"} in {r.meta.filename} · {r.affected_lines.length} affected line(s)
          </div>
          <div className="mt-3 flex flex-wrap gap-1.5">
            {SEVERITIES.map((s) => (
              <button
                key={s}
                onClick={() => toggleSev(s)}
                className={cx(
                  "inline-flex items-center gap-1.5 rounded-full border border-line px-2.5 py-1 text-xs capitalize transition",
                  !sevs.has(s) && "opacity-40",
                )}
              >
                <span className={cx("h-2 w-2 rounded-full", SEV_BG[s])} /> {s} <b className="font-mono">{r.severity_counts[s]}</b>
              </button>
            ))}
          </div>
          <p className="mt-2 font-mono text-[11px] text-faint">{r.scoring}</p>
        </div>
        <div className="flex shrink-0 flex-row gap-2 sm:flex-col">
          {([
            ["html", "HTML report", FileCode2],
            ["json", "JSON", FileJson],
            ["text", "Plain text", FileText],
          ] as const).map(([fmt, label, Icon]) => (
            <button
              key={fmt}
              onClick={() => doExport(fmt)}
              disabled={exporting !== null}
              className="inline-flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-xs hover:bg-panel-2 disabled:opacity-50"
            >
              {exporting === fmt ? <Download size={13} className="animate-bounce" /> : <Icon size={13} />} {label}
            </button>
          ))}
        </div>
      </Card>

      <div className="grid gap-4 md:grid-cols-3">
        <Card className="p-4">
          <SectionTitle>Detected by</SectionTitle>
          <div className="space-y-2 text-sm">
            <Row label="Both modules (correlated)" value={r.by_module.both} tone="accent" />
            <Row label="AST analysis only" value={r.by_module.ast_only} tone="ast" />
            <Row label="Lexical analysis only" value={r.by_module.lexical_only} tone="lexical" />
          </div>
        </Card>
        <Card className="p-4 md:col-span-2">
          <SectionTitle>By category</SectionTitle>
          <div className="space-y-1.5">
            {Object.entries(r.by_category).map(([cat, n]) => (
              <div key={cat} className="flex items-center gap-2 text-[12.5px]">
                <span className="w-40 shrink-0 truncate text-muted">{cat}</span>
                <div className="h-2 flex-1 overflow-hidden rounded-full bg-panel-2">
                  <div className="h-full rounded-full bg-accent" style={{ width: `${(n / maxCat) * 100}%` }} />
                </div>
                <span className="w-6 text-right font-mono">{n}</span>
              </div>
            ))}
            {!r.total && <div className="text-sm text-faint">Nothing to categorise.</div>}
          </div>
        </Card>
      </div>

      <div>
        <SectionTitle
          right={
            <div className="flex gap-1 rounded-lg bg-panel-2 p-0.5 text-[11px]">
              {(["all", "both", "ast", "lexical"] as ModuleFilter[]).map((m) => (
                <button
                  key={m}
                  onClick={() => setMod(m)}
                  className={cx("rounded-md px-2 py-0.5 capitalize", mod === m ? "bg-panel shadow-sm" : "text-muted")}
                >
                  {m === "both" ? "correlated" : m}
                </button>
              ))}
            </div>
          }
        >
          Findings ({findings.length}/{r.total})
        </SectionTitle>
        <FindingList findings={findings} goTo={goTo} emptyText="No findings match the current filters." />
      </div>

      <div>
        <SectionTitle>Annotated source</SectionTitle>
        <CodeView source={result.source} findings={r.findings} focusLine={focus.line} onLineClick={(line) => setFocus({ line })} />
      </div>
    </div>
  );
}

function Row({ label, value, tone }: { label: string; value: number; tone: "accent" | "ast" | "lexical" }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="text-muted">{label}</span>
      <Badge tone={tone} className="font-mono">{value}</Badge>
    </div>
  );
}
