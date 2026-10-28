import {
  AlertTriangle,
  BookOpen,
  CheckCircle2,
  ChevronDown,
  CircleDashed,
  Copy,
  FileCode2,
  Loader2,
  PencilLine,
  RefreshCw,
  ShieldCheck,
  ShieldAlert,
} from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { api } from "../api";
import type { LanguageChoice } from "../languages";
import { AstStage } from "../stages/AstStage";
import { LexerStage } from "../stages/LexerStage";
import { ParserStage } from "../stages/ParserStage";
import { ReportStage } from "../stages/ReportStage";
import { RuleEngineStage } from "../stages/RuleEngineStage";
import { AstSecurityStage, LexicalSecurityStage } from "../stages/SecurityStage";
import { SemanticStage } from "../stages/SemanticStage";
import { SourceStage } from "../stages/SourceStage";
import type { StageViewProps } from "../stages/common";
import type { Focus, Report, ScanResult, Stage, StageId, Turn } from "../types";
import { GradeRing } from "./GradeRing";
import { PipelineDiagram, STAGE_ORDER } from "./PipelineDiagram";
import { Badge, LogConsole, SEV_BG, SEV_TEXT, SEVERITIES, cx, ms } from "./ui";

const STEP_MS = 320;

const VIEWS: Record<StageId, (p: StageViewProps<any>) => JSX.Element> = {
  source: SourceStage,
  lexer: LexerStage,
  lexical_security: LexicalSecurityStage,
  parser: ParserStage,
  ast: AstStage,
  semantic: SemanticStage,
  ast_security: AstSecurityStage,
  rule_engine: RuleEngineStage,
  report: ReportStage,
};

const SHORT: Record<StageId, string> = {
  source: "Source",
  lexer: "Lexer",
  lexical_security: "Module 1",
  parser: "Parser",
  ast: "AST",
  semantic: "Semantic",
  ast_security: "Module 2",
  rule_engine: "Rule engine",
  report: "Report",
};

interface Props {
  turn: Turn;
  onAnimationDone: () => void;
  onEdit: (code: string, filename: string, language: LanguageChoice) => void;
  onRetry: () => void;
}

export function AssistantMessage({ turn, onAnimationDone, onEdit, onRetry }: Props) {
  const result = turn.result;
  const total = result?.stages.length ?? STAGE_ORDER.length;
  const [revealed, setRevealed] = useState(() => (result && !turn.animate ? total : 0));
  const [active, setActive] = useState<StageId>(result && !turn.animate ? "report" : "source");
  const [focus, setFocus] = useState<Focus>({});
  const done = !!result && revealed >= total;

  useEffect(() => {
    if (!result) return;
    if (!turn.animate) {
      setRevealed(total);
      return;
    }
    let n = 0;
    const timer = setInterval(() => {
      n += 1;
      setRevealed(n);
      setActive(STAGE_ORDER[Math.min(n, total) - 1]);
      if (n >= total) {
        clearInterval(timer);
        setActive("report");
        onAnimationDone();
      }
    }, STEP_MS);
    return () => clearInterval(timer);
  }, [result]);

  const goTo = (stage: StageId, f?: Focus) => {
    setActive(stage);
    if (f) setFocus(f);
  };

  return (
    <div className="flex gap-3 sm:gap-4">
      <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-line bg-panel">
        <ShieldCheck size={17} className="text-accent" />
      </div>
      <div className="min-w-0 flex-1 space-y-4">
        {turn.error ? (
          <ErrorBlock message={turn.error} onRetry={onRetry} />
        ) : (
          <>
            <Intro turn={turn} result={result} done={done} />
            <Steps stages={result?.stages ?? []} revealed={revealed} running={!result} done={done} active={active} onSelect={(id) => goTo(id)} />
            <div className="rounded-2xl border border-line bg-panel p-3">
              <PipelineDiagram
                stages={result?.stages ?? []}
                revealed={revealed}
                running={!result}
                active={active}
                onSelect={(id) => goTo(id)}
              />
            </div>
            {done && result && (
              <>
                <Summary report={result.report} onOpen={(line) => goTo("report", { line })} />
                <Inspector result={result} active={active} setActive={setActive} focus={focus} setFocus={setFocus} goTo={goTo} />
                <Actions turn={turn} result={result} onEdit={onEdit} />
              </>
            )}
          </>
        )}
      </div>
    </div>
  );
}

const METHOD_TEXT: Record<string, string> = {
  extension: "recognised from the file extension",
  content: "auto-detected from the code",
  default: "assumed by default",
};

function Intro({ turn, result, done }: { turn: Turn; result?: ScanResult; done: boolean }) {
  if (!result)
    return (
      <p className="flex items-center gap-2 text-[15px] text-muted">
        <Loader2 size={16} className="animate-spin text-accent" />
        Compiling <code className="rounded bg-panel-2 px-1.5 py-0.5 text-[13px]">{turn.filename || "your code"}</code> through the analysis pipeline…
      </p>
    );
  return (
    <p className="text-[15px] leading-relaxed">
      {done ? "I ran " : "Running "}
      <code className="rounded bg-panel-2 px-1.5 py-0.5 text-[13px]">{result.meta.filename}</code>
      {" "}({result.meta.lines} lines of <b>{result.meta.language}</b>
      {result.meta.detection.method === "user" ? ", as you selected" : `, ${METHOD_TEXT[result.meta.detection.method]}`}) through all {result.stages.length} stages of the compiler front end and both security
      modules{done ? <> in <b>{ms(result.meta.duration_ms)}</b>. Here is what happened at each step.</> : "…"}
    </p>
  );
}

function Steps({
  stages,
  revealed,
  running,
  done,
  active,
  onSelect,
}: {
  stages: Stage[];
  revealed: number;
  running: boolean;
  done: boolean;
  active: StageId;
  onSelect: (id: StageId) => void;
}) {
  const [open, setOpen] = useState(true);
  useEffect(() => {
    if (done) setOpen(false);
  }, [done]);
  const totalMs = stages.reduce((n, s) => n + s.duration_ms, 0);
  return (
    <div className="rounded-xl border border-line">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-muted hover:text-fg">
        {done ? <CheckCircle2 size={15} className="text-accent" /> : <Loader2 size={15} className="animate-spin text-accent" />}
        {done ? `Completed ${stages.length} stages · ${ms(totalMs)} of compute` : "Working through the pipeline…"}
        <ChevronDown size={15} className={cx("ml-auto transition-transform", open && "rotate-180")} />
      </button>
      {open && (
        <ol className="space-y-0.5 border-t border-line px-3 py-2">
          {STAGE_ORDER.map((id, i) => {
            const s = stages.find((x) => x.id === id);
            const state = i < revealed ? "done" : i === revealed && (running || !done) ? "running" : "pending";
            return (
              <li
                key={id}
                onClick={() => state === "done" && onSelect(id)}
                className={cx(
                  "flex items-center gap-2.5 rounded-md px-1.5 py-1 text-[13px]",
                  state === "done" && "cursor-pointer hover:bg-panel-2",
                  state === "pending" && "opacity-45",
                  active === id && done && "bg-panel-2",
                )}
              >
                {state === "done" ? (
                  s?.status === "alert" ? (
                    <ShieldAlert size={15} className="shrink-0 text-sev-critical" />
                  ) : s?.status === "warning" ? (
                    <AlertTriangle size={15} className="shrink-0 text-sev-medium" />
                  ) : (
                    <CheckCircle2 size={15} className="shrink-0 text-accent" />
                  )
                ) : state === "running" ? (
                  <Loader2 size={15} className="shrink-0 animate-spin text-accent" />
                ) : (
                  <CircleDashed size={15} className="shrink-0 text-faint" />
                )}
                <span className="w-44 shrink-0 truncate font-medium">{s?.title ?? SHORT[id]}</span>
                <span className="hidden truncate text-muted sm:inline">{state === "done" ? s?.summary : ""}</span>
                {state === "done" && s && <span className="ml-auto shrink-0 font-mono text-[11px] text-faint">{ms(s.duration_ms)}</span>}
              </li>
            );
          })}
        </ol>
      )}
    </div>
  );
}

export function summarise(report: Report): string {
  if (!report.total) return "No security findings were produced by the rule set. That does not prove the code is safe, but none of the known patterns matched.";
  const parts = SEVERITIES.filter((s) => report.severity_counts[s]).map((s) => `${report.severity_counts[s]} ${s}`);
  const top = report.findings[0];
  return `Found ${report.total} issue${report.total === 1 ? "" : "s"} (${parts.join(", ")}). Score ${report.score}/100, grade ${report.grade} — ${report.risk.toLowerCase()}. The most serious: ${top.title.toLowerCase()} on line ${top.line} (${top.cwe}).`;
}

function Summary({ report, onOpen }: { report: Report; onOpen: (line: number) => void }) {
  const top = report.findings.slice(0, 4);
  return (
    <div className="animate-fade-up flex flex-col gap-4 rounded-2xl border border-line bg-panel p-4 sm:flex-row">
      <GradeRing grade={report.grade} score={report.score} />
      <div className="min-w-0 flex-1">
        <p className="text-[15px] leading-relaxed">{summarise(report)}</p>
        {top.length > 0 && (
          <ul className="mt-3 space-y-1.5">
            {top.map((f) => (
              <li key={f.id}>
                <button onClick={() => onOpen(f.line)} className="flex w-full items-center gap-2 rounded-md text-left text-[13px] hover:bg-panel-2">
                  <span className={cx("h-2 w-2 shrink-0 rounded-full", SEV_BG[f.severity])} />
                  <span className={cx("w-16 shrink-0 font-semibold capitalize", SEV_TEXT[f.severity])}>{f.severity}</span>
                  <span className="truncate">{f.title}</span>
                  <span className="ml-auto shrink-0 font-mono text-[11px] text-faint">L{f.line} · {f.rule_id}</span>
                </button>
              </li>
            ))}
            {report.total > top.length && (
              <li className="text-xs text-faint">+ {report.total - top.length} more in the report tab below</li>
            )}
          </ul>
        )}
      </div>
    </div>
  );
}

function Inspector({
  result,
  active,
  setActive,
  focus,
  setFocus,
  goTo,
}: {
  result: ScanResult;
  active: StageId;
  setActive: (id: StageId) => void;
  focus: Focus;
  setFocus: (f: Focus) => void;
  goTo: (id: StageId, f?: Focus) => void;
}) {
  const stage = result.stages.find((s) => s.id === active)!;
  const View = VIEWS[active];
  const [explainOpen, setExplainOpen] = useState(true);
  return (
    <div className="animate-fade-up overflow-hidden rounded-2xl border border-line bg-panel">
      <div className="flex gap-1 overflow-x-auto border-b border-line bg-panel-2/50 px-2 pt-2">
        {STAGE_ORDER.map((id, i) => {
          const s = result.stages.find((x) => x.id === id);
          return (
            <button
              key={id}
              onClick={() => setActive(id)}
              className={cx(
                "flex shrink-0 items-center gap-1.5 rounded-t-lg border border-b-0 px-3 py-2 text-[12.5px] font-medium",
                active === id ? "border-line bg-panel text-fg" : "border-transparent text-muted hover:text-fg",
              )}
            >
              <span className="font-mono text-[10px] text-faint">{i + 1}</span>
              {SHORT[id]}
              {s?.status === "alert" && <span className="h-1.5 w-1.5 rounded-full bg-sev-critical" />}
              {s?.status === "warning" && <span className="h-1.5 w-1.5 rounded-full bg-sev-medium" />}
            </button>
          );
        })}
      </div>
      <div className="space-y-4 p-4">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="text-base font-semibold">{stage.title}</h3>
          <Badge tone={stage.module === "Module 1" ? "lexical" : stage.module === "Module 2" ? "ast" : "neutral"}>{stage.module}</Badge>
          <Badge tone={stage.status === "ok" ? "accent" : stage.status === "warning" ? "warn" : "danger"}>{stage.status}</Badge>
          <span className="ml-auto font-mono text-xs text-faint">{ms(stage.duration_ms)}</span>
        </div>
        <div className="rounded-xl bg-accent-soft/50 px-4 py-3 text-[13.5px] leading-relaxed">
          <button onClick={() => setExplainOpen(!explainOpen)} className="flex w-full items-center gap-2 text-left font-medium text-accent">
            <BookOpen size={15} /> How this stage works
            <ChevronDown size={14} className={cx("ml-auto transition-transform", explainOpen && "rotate-180")} />
          </button>
          {explainOpen && <p className="mt-1.5 text-fg/90">{stage.explain}</p>}
        </div>
        <LogConsole lines={stage.log} />
        <View stage={stage} result={result} focus={focus} setFocus={setFocus} goTo={goTo} />
      </div>
    </div>
  );
}

function Actions({ turn, result, onEdit }: { turn: Turn; result: ScanResult; onEdit: Props["onEdit"] }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(summarise(result.report));
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  };
  return (
    <div className="flex flex-wrap gap-2">
      <Chip onClick={() => onEdit(turn.code, turn.filename, turn.language ?? "auto")} icon={<PencilLine size={13} />}>Edit &amp; re-scan</Chip>
      <Chip onClick={() => api.export(result.source, result.meta.filename, "html", result.meta.language_id)} icon={<FileCode2 size={13} />}>Export HTML report</Chip>
      <Chip onClick={copy} icon={<Copy size={13} />}>{copied ? "Copied" : "Copy summary"}</Chip>
    </div>
  );
}

function Chip({ children, onClick, icon }: { children: ReactNode; onClick: () => void; icon: ReactNode }) {
  return (
    <button onClick={onClick} className="inline-flex items-center gap-1.5 rounded-full border border-line px-3 py-1.5 text-xs text-muted hover:bg-panel-2 hover:text-fg">
      {icon}
      {children}
    </button>
  );
}

function ErrorBlock({ message, onRetry }: { message: string; onRetry: () => void }) {
  const offline = /fetch|network|Failed/i.test(message);
  return (
    <div className="rounded-xl border border-sev-critical/40 bg-sev-critical/5 p-4 text-sm">
      <div className="flex items-center gap-2 font-semibold text-sev-critical">
        <AlertTriangle size={16} /> The scan could not be completed
      </div>
      <p className="mt-1 text-muted">{offline ? "The analysis server is not reachable. Start it with: python backend/app.py" : message}</p>
      <button onClick={onRetry} className="mt-3 inline-flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-xs hover:bg-panel-2">
        <RefreshCw size={13} /> Retry
      </button>
    </div>
  );
}
