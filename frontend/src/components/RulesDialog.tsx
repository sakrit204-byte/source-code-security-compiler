import { X } from "lucide-react";
import { useEffect, useState } from "react";
import { api } from "../api";
import type { RuleMeta } from "../types";
import { Badge, SeverityBadge } from "./ui";

export function RulesDialog({ onClose }: { onClose: () => void }) {
  const [rules, setRules] = useState<RuleMeta[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.rules().then(setRules, (e) => setError(String(e)));
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const groups: [string, RuleMeta[]][] = rules
    ? [
        ["Module 1 — Lexical Security Analyzer", rules.filter((r) => r.level === "lexical")],
        ["Module 2 — Syntax / AST Security Analyzer", rules.filter((r) => r.level === "ast")],
      ]
    : [];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-3" onClick={onClose}>
      <div
        className="flex max-h-[88vh] w-full max-w-3xl flex-col overflow-hidden rounded-2xl border border-line bg-bg shadow-2xl"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-label="Rule catalog"
      >
        <div className="flex items-center border-b border-line px-5 py-3">
          <h2 className="font-semibold">Security rule catalog</h2>
          <span className="ml-2 text-xs text-faint">{rules ? `${rules.length} rules` : ""}</span>
          <button onClick={onClose} className="ml-auto rounded-md p-1 text-muted hover:bg-panel-2" aria-label="Close">
            <X size={18} />
          </button>
        </div>
        <div className="space-y-6 overflow-y-auto px-5 py-4">
          {error && <p className="text-sm text-sev-critical">{error}</p>}
          {!rules && !error && <p className="text-sm text-faint">Loading…</p>}
          {groups.map(([title, list]) => (
            <section key={title}>
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-faint">{title}</h3>
              <div className="space-y-2">
                {list.map((r) => (
                  <div key={r.id} className="rounded-xl border border-line bg-panel p-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-xs text-faint">{r.id}</span>
                      <span className="font-medium">{r.name}</span>
                      <SeverityBadge severity={r.severity} />
                      <Badge>{r.cwe}</Badge>
                      <Badge>{r.category}</Badge>
                    </div>
                    <p className="mt-1.5 text-[13px] text-muted">{r.description}</p>
                    <p className="mt-1 font-mono text-[11px] text-faint">{r.detects}</p>
                  </div>
                ))}
              </div>
            </section>
          ))}
        </div>
      </div>
    </div>
  );
}
