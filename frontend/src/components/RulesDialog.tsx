import { X } from "lucide-react";
import { useEffect, useState } from "react";
import { api } from "../api";
import { LANGUAGES, type LanguageId } from "../languages";
import type { RuleMeta } from "../types";
import { Badge, cx, LanguagePill, SeverityBadge } from "./ui";

export function RulesDialog({ onClose }: { onClose: () => void }) {
  const [rules, setRules] = useState<RuleMeta[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [language, setLanguage] = useState<LanguageId | "all">("all");

  useEffect(() => {
    api.rules().then(setRules, (e) => setError(String(e)));
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const shown = (rules ?? []).filter((r) => language === "all" || r.languages.includes(language));
  const groups: [string, RuleMeta[]][] = rules
    ? [
        ["Module 1 — Lexical Security Analyzer", shown.filter((r) => r.level === "lexical")],
        ["Module 2 — Syntax / AST Security Analyzer", shown.filter((r) => r.level === "ast")],
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
          <span className="ml-2 text-xs text-faint">{rules ? `${shown.length} of ${rules.length} rules` : ""}</span>
          <button onClick={onClose} className="ml-auto rounded-md p-1 text-muted hover:bg-panel-2" aria-label="Close">
            <X size={18} />
          </button>
        </div>
        <div className="flex gap-1 border-b border-line px-5 py-2">
          {(["all", ...LANGUAGES.map((l) => l.id)] as const).map((id) => (
            <button
              key={id}
              onClick={() => setLanguage(id)}
              className={cx(
                "rounded-full px-3 py-1 text-xs",
                language === id ? "bg-fg text-bg" : "text-muted hover:bg-panel-2 hover:text-fg",
              )}
            >
              {id === "all" ? "All languages" : LANGUAGES.find((l) => l.id === id)!.name}
            </button>
          ))}
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
                      <span className="ml-auto flex gap-1">
                        {r.languages.map((l) => (
                          <LanguagePill key={l} language={l} />
                        ))}
                      </span>
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
