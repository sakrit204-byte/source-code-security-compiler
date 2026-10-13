import { Terminal } from "lucide-react";
import { useState, type ReactNode } from "react";
import type { Severity } from "../types";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEV_TEXT: Record<Severity, string> = {
  critical: "text-sev-critical",
  high: "text-sev-high",
  medium: "text-sev-medium",
  low: "text-sev-low",
  info: "text-sev-info",
};

export const SEV_BG: Record<Severity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

export const SEV_BORDER: Record<Severity, string> = {
  critical: "border-sev-critical",
  high: "border-sev-high",
  medium: "border-sev-medium",
  low: "border-sev-low",
  info: "border-sev-info",
};

export function cx(...parts: (string | false | null | undefined)[]) {
  return parts.filter(Boolean).join(" ");
}

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-white",
        SEV_BG[severity],
        className,
      )}
    >
      {severity}
    </span>
  );
}

export function Badge({
  children,
  tone = "neutral",
  className,
  title,
}: {
  children: ReactNode;
  tone?: "neutral" | "accent" | "lexical" | "ast" | "warn" | "danger";
  className?: string;
  title?: string;
}) {
  const tones = {
    neutral: "border-line text-muted",
    accent: "border-accent/40 bg-accent-soft text-accent",
    lexical: "border-violet-400/40 bg-violet-500/10 text-violet-600 dark:text-violet-300",
    ast: "border-sky-400/40 bg-sky-500/10 text-sky-700 dark:text-sky-300",
    warn: "border-amber-400/50 bg-amber-500/10 text-amber-700 dark:text-amber-300",
    danger: "border-sev-critical/40 bg-sev-critical/10 text-sev-critical",
  };
  return (
    <span
      title={title}
      className={cx("inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium", tones[tone], className)}
    >
      {children}
    </span>
  );
}

export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cx("rounded-xl border border-line bg-panel", className)}>{children}</div>;
}

export function SectionTitle({ children, right }: { children: ReactNode; right?: ReactNode }) {
  return (
    <div className="mb-2 flex items-center justify-between gap-2">
      <h4 className="text-xs font-semibold uppercase tracking-wider text-faint">{children}</h4>
      {right}
    </div>
  );
}

export function Stat({ label, value, hint }: { label: string; value: ReactNode; hint?: string }) {
  return (
    <div className="rounded-lg border border-line bg-panel-2/60 px-3 py-2" title={hint}>
      <div className="text-[11px] text-faint">{label}</div>
      <div className="font-mono text-base font-semibold">{value}</div>
    </div>
  );
}

export function LogConsole({ lines, title = "Under the hood" }: { lines: string[]; title?: string }) {
  const [open, setOpen] = useState(true);
  return (
    <div className="overflow-hidden rounded-xl border border-line bg-code">
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-2 border-b border-line px-3 py-2 text-left text-xs font-medium text-muted hover:text-fg"
      >
        <Terminal size={14} /> {title}
        <span className="ml-auto text-faint">{open ? "hide" : `show ${lines.length} lines`}</span>
      </button>
      {open && (
        <pre className="max-h-64 overflow-auto px-3 py-2 font-mono text-[12px] leading-relaxed text-muted">
          {lines.map((l, i) => (
            <div key={i} className="whitespace-pre-wrap">
              <span className="select-none text-accent">›</span> {l}
            </div>
          ))}
        </pre>
      )}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="rounded-lg border border-dashed border-line px-4 py-6 text-center text-sm text-faint">{children}</div>;
}

export const TOKEN_COLORS: Record<string, string> = {
  KEYWORD: "text-violet-600 dark:text-violet-300",
  IDENTIFIER: "text-sky-700 dark:text-sky-300",
  INT_LITERAL: "text-amber-700 dark:text-amber-300",
  FLOAT_LITERAL: "text-amber-700 dark:text-amber-300",
  STRING_LITERAL: "text-emerald-700 dark:text-emerald-300",
  CHAR_LITERAL: "text-teal-700 dark:text-teal-300",
  OPERATOR: "text-pink-600 dark:text-pink-300",
  DELIMITER: "text-zinc-500 dark:text-zinc-400",
  PREPROCESSOR: "text-fuchsia-700 dark:text-fuchsia-300",
  COMMENT: "text-zinc-400 italic dark:text-zinc-500",
  ERROR: "text-sev-critical underline decoration-wavy",
};

export const TOKEN_BG: Record<string, string> = {
  KEYWORD: "bg-violet-500/10 border-violet-500/30",
  IDENTIFIER: "bg-sky-500/10 border-sky-500/30",
  INT_LITERAL: "bg-amber-500/10 border-amber-500/30",
  FLOAT_LITERAL: "bg-amber-500/10 border-amber-500/30",
  STRING_LITERAL: "bg-emerald-500/10 border-emerald-500/30",
  CHAR_LITERAL: "bg-teal-500/10 border-teal-500/30",
  OPERATOR: "bg-pink-500/10 border-pink-500/30",
  DELIMITER: "bg-zinc-500/10 border-zinc-500/30",
  PREPROCESSOR: "bg-fuchsia-500/10 border-fuchsia-500/30",
  COMMENT: "bg-zinc-500/5 border-zinc-500/20",
  ERROR: "bg-red-500/15 border-red-500/40",
};

const DECL = new Set(["FunctionDef", "FunctionDecl", "VarDecl", "Param", "DeclStmt", "TypedefDecl", "RecordDecl", "EnumDecl", "Enumerator"]);
const STMT = new Set(["Compound", "If", "While", "DoWhile", "For", "Switch", "Case", "Default", "Label", "Goto", "Return", "Break", "Continue", "ExprStmt", "EmptyStmt"]);
const LIT = new Set(["IntLiteral", "FloatLiteral", "CharLiteral", "StringLiteral"]);

export function astKindColor(kind: string): string {
  if (kind === "TranslationUnit") return "bg-zinc-500";
  if (DECL.has(kind)) return "bg-violet-500";
  if (STMT.has(kind)) return "bg-blue-500";
  if (kind === "Call") return "bg-orange-500";
  if (kind === "Identifier") return "bg-sky-500";
  if (LIT.has(kind)) return "bg-emerald-500";
  return "bg-pink-500";
}

export function ms(value: number) {
  return value < 1 ? `${(value * 1000).toFixed(0)} µs` : `${value.toFixed(value < 10 ? 2 : 1)} ms`;
}
