import { ChevronDown, Code2, ExternalLink, GitBranch, Lightbulb, Link2, ScanSearch } from "lucide-react";
import { useState } from "react";
import type { Finding } from "../types";
import { Badge, SEV_BORDER, SeverityBadge, cx } from "./ui";

interface Props {
  finding: Finding;
  onShowLine?: (line: number) => void;
  onShowNode?: (nodeId: number) => void;
  defaultOpen?: boolean;
}

export function FindingCard({ finding: f, onShowLine, onShowNode, defaultOpen = false }: Props) {
  const [open, setOpen] = useState(defaultOpen);
  const cweNum = f.cwe.replace(/^CWE-/, "");
  return (
    <div className={cx("animate-fade-up overflow-hidden rounded-xl border border-l-4 border-line bg-panel", SEV_BORDER[f.severity])}>
      <button onClick={() => setOpen(!open)} className="flex w-full items-start gap-3 px-4 py-3 text-left">
        <div className="mt-0.5 shrink-0">
          <SeverityBadge severity={f.severity} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span className="font-semibold">{f.title}</span>
            <span className="font-mono text-xs text-faint">
              {f.rule_id} · line {f.line}:{f.col}
            </span>
          </div>
          <p className={cx("mt-1 text-sm text-muted", !open && "line-clamp-2")}>{f.message}</p>
        </div>
        <div className="flex shrink-0 items-center gap-1.5">
          {f.detected_by.map((d) => (
            <Badge key={d} tone={d === "lexical" ? "lexical" : "ast"}>
              {d === "lexical" ? "Lexical" : "AST"}
            </Badge>
          ))}
          <ChevronDown size={16} className={cx("text-faint transition-transform", open && "rotate-180")} />
        </div>
      </button>
      {open && (
        <div className="space-y-3 border-t border-line px-4 py-3 text-sm">
          {f.snippet && (
            <pre className="overflow-x-auto rounded-lg bg-code px-3 py-2 font-mono text-[12.5px]">
              <span className="select-none pr-3 text-faint">{f.line}</span>
              {f.snippet}
            </pre>
          )}
          <div className="flex gap-2 rounded-lg bg-accent-soft/60 px-3 py-2 text-[13px]">
            <Lightbulb size={16} className="mt-0.5 shrink-0 text-accent" />
            <div>
              <span className="font-semibold text-accent">Recommendation: </span>
              {f.recommendation}
            </div>
          </div>
          {f.evidence && (
            <div className="flex gap-2 text-[12px] text-muted">
              <ScanSearch size={14} className="mt-0.5 shrink-0" />
              <div>
                <span className="font-medium">How it was detected: </span>
                <code className="break-all font-mono text-[11.5px]">{f.evidence}</code>
              </div>
            </div>
          )}
          <div className="flex flex-wrap items-center gap-2">
            <Badge>{f.category}</Badge>
            <Badge title="Confidence of this finding">confidence: {f.confidence}</Badge>
            {f.correlated.length > 0 && (
              <Badge tone="accent" title="Confirmed by the other analysis module">
                <Link2 size={11} /> correlated with {f.correlated.join(", ")}
              </Badge>
            )}
            <a
              href={`https://cwe.mitre.org/data/definitions/${cweNum}.html`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-xs text-accent hover:underline"
            >
              {f.cwe} <ExternalLink size={11} />
            </a>
            <div className="ml-auto flex gap-1.5">
              {onShowLine && (
                <button
                  onClick={() => onShowLine(f.line)}
                  className="inline-flex items-center gap-1 rounded-md border border-line px-2 py-1 text-xs hover:bg-panel-2"
                >
                  <Code2 size={12} /> Show in source
                </button>
              )}
              {onShowNode && f.node_id != null && (
                <button
                  onClick={() => onShowNode(f.node_id!)}
                  className="inline-flex items-center gap-1 rounded-md border border-line px-2 py-1 text-xs hover:bg-panel-2"
                >
                  <GitBranch size={12} /> Show AST node
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
