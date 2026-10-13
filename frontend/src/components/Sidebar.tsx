import { BookMarked, FlaskConical, Moon, PanelLeftClose, Plus, ShieldCheck, Sun, Trash2 } from "lucide-react";
import type { Conversation, Sample } from "../types";
import { cx } from "./ui";

interface Props {
  conversations: Conversation[];
  activeId: string | null;
  samples: Sample[];
  theme: "light" | "dark";
  onNew: () => void;
  onSelect: (id: string) => void;
  onDelete: (id: string) => void;
  onClear: () => void;
  onSample: (s: Sample) => void;
  onRules: () => void;
  onToggleTheme: () => void;
  onClose: () => void;
}

const GRADE_TONE: Record<string, string> = {
  A: "bg-accent/15 text-accent",
  B: "bg-sev-low/15 text-sev-low",
  C: "bg-sev-medium/15 text-sev-medium",
  D: "bg-sev-high/15 text-sev-high",
  F: "bg-sev-critical/15 text-sev-critical",
};

function groupLabel(ts: number) {
  const day = 86_400_000;
  const diff = Date.now() - ts;
  if (diff < day && new Date(ts).getDate() === new Date().getDate()) return "Today";
  if (diff < 2 * day) return "Yesterday";
  if (diff < 7 * day) return "Previous 7 days";
  return "Older";
}

export function Sidebar(p: Props) {
  const groups = new Map<string, Conversation[]>();
  for (const c of p.conversations) {
    const g = groupLabel(c.updatedAt);
    groups.set(g, [...(groups.get(g) ?? []), c]);
  }

  return (
    <aside className="flex h-full w-72 flex-col bg-sidebar">
      <div className="flex items-center gap-2 px-3 pb-2 pt-3">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-accent text-white">
          <ShieldCheck size={18} />
        </div>
        <div className="min-w-0 leading-tight">
          <div className="text-sm font-semibold">SecScan Compiler</div>
          <div className="text-[11px] text-faint">C source security analysis</div>
        </div>
        <button onClick={p.onClose} className="ml-auto rounded-md p-1.5 text-muted hover:bg-panel-2 md:hidden" aria-label="Close sidebar">
          <PanelLeftClose size={18} />
        </button>
      </div>

      <div className="px-2">
        <button
          onClick={p.onNew}
          className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium hover:bg-panel-2"
        >
          <Plus size={16} /> New scan
        </button>
        <button onClick={p.onRules} className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-sm hover:bg-panel-2">
          <BookMarked size={16} /> Rule catalog
        </button>
      </div>

      <div className="mt-2 flex-1 overflow-y-auto px-2 pb-2">
        <div className="px-3 pb-1 pt-3 text-[11px] font-semibold uppercase tracking-wider text-faint">Sample programs</div>
        {p.samples.map((s) => (
          <button
            key={s.id}
            onClick={() => p.onSample(s)}
            title={s.description}
            className="flex w-full items-center gap-2 truncate rounded-lg px-3 py-1.5 text-left text-[13px] text-muted hover:bg-panel-2 hover:text-fg"
          >
            <FlaskConical size={14} className="shrink-0" />
            <span className="truncate">{s.title}</span>
          </button>
        ))}

        {[...groups.entries()].map(([label, convs]) => (
          <div key={label}>
            <div className="px-3 pb-1 pt-4 text-[11px] font-semibold uppercase tracking-wider text-faint">{label}</div>
            {convs.map((c) => (
              <div
                key={c.id}
                className={cx(
                  "group flex items-center gap-2 rounded-lg px-3 py-1.5 text-[13px]",
                  c.id === p.activeId ? "bg-panel-2 text-fg" : "text-muted hover:bg-panel-2/70 hover:text-fg",
                )}
              >
                <button onClick={() => p.onSelect(c.id)} className="flex min-w-0 flex-1 items-center gap-2 text-left">
                  {c.grade && (
                    <span className={cx("flex h-5 w-5 shrink-0 items-center justify-center rounded text-[10px] font-bold", GRADE_TONE[c.grade])}>
                      {c.grade}
                    </span>
                  )}
                  <span className="truncate">{c.title}</span>
                  {c.turns.length > 1 && <span className="shrink-0 text-[10px] text-faint">×{c.turns.length}</span>}
                </button>
                <button
                  onClick={() => p.onDelete(c.id)}
                  className="shrink-0 rounded p-0.5 text-faint opacity-0 hover:text-sev-critical group-hover:opacity-100"
                  aria-label="Delete scan"
                >
                  <Trash2 size={13} />
                </button>
              </div>
            ))}
          </div>
        ))}
      </div>

      <div className="flex items-center gap-1 border-t border-line px-2 py-2">
        <button onClick={p.onToggleTheme} className="flex items-center gap-2 rounded-lg px-3 py-2 text-[13px] text-muted hover:bg-panel-2 hover:text-fg">
          {p.theme === "dark" ? <Sun size={15} /> : <Moon size={15} />}
          {p.theme === "dark" ? "Light mode" : "Dark mode"}
        </button>
        {p.conversations.length > 0 && (
          <button onClick={p.onClear} className="ml-auto rounded-lg px-3 py-2 text-[12px] text-faint hover:bg-panel-2 hover:text-sev-critical">
            Clear history
          </button>
        )}
      </div>
    </aside>
  );
}
