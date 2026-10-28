import { PanelLeftOpen, SquarePen } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { api } from "./api";
import { AssistantMessage } from "./components/AssistantMessage";
import { Composer, type ComposerHandle } from "./components/Composer";
import { EmptyState } from "./components/EmptyState";
import { RulesDialog } from "./components/RulesDialog";
import { Sidebar } from "./components/Sidebar";
import { UserMessage } from "./components/UserMessage";
import { cx } from "./components/ui";
import { useConversations, useTheme } from "./store";
import type { Sample } from "./types";

export default function App() {
  const store = useConversations();
  const { theme, toggle } = useTheme();
  const [samples, setSamples] = useState<Sample[]>([]);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [rulesOpen, setRulesOpen] = useState(false);
  const composer = useRef<ComposerHandle>(null);
  const thread = useRef<HTMLDivElement>(null);
  const turnCount = store.active?.turns.length ?? 0;

  useEffect(() => {
    api.samples().then(setSamples, () => setSamples([]));
  }, []);

  // When a new turn is added, bring the user's message to the top of the viewport.
  useEffect(() => {
    if (!turnCount || !thread.current) return;
    const last = thread.current.querySelector<HTMLElement>(`[data-turn="${turnCount - 1}"]`);
    last?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [turnCount, store.activeId]);

  const newScan = () => {
    store.select(null);
    setSidebarOpen(false);
  };

  const runSample = (s: Sample) => {
    setSidebarOpen(false);
    store.submit(s.code, s.filename, "auto", { fresh: true });
  };

  return (
    <div className="flex h-full overflow-hidden">
      {/* Sidebar: static on desktop, drawer on mobile */}
      <div
        className={cx(
          "fixed inset-y-0 left-0 z-40 border-r border-line transition-transform md:static md:translate-x-0",
          sidebarOpen ? "translate-x-0" : "-translate-x-full",
        )}
      >
        <Sidebar
          conversations={store.conversations}
          activeId={store.activeId}
          samples={samples}
          theme={theme}
          onNew={newScan}
          onSelect={(id) => {
            store.select(id);
            setSidebarOpen(false);
          }}
          onDelete={store.remove}
          onClear={store.clearAll}
          onSample={runSample}
          onRules={() => setRulesOpen(true)}
          onToggleTheme={toggle}
          onClose={() => setSidebarOpen(false)}
        />
      </div>
      {sidebarOpen && <div className="fixed inset-0 z-30 bg-black/40 md:hidden" onClick={() => setSidebarOpen(false)} />}

      <main className="flex min-w-0 flex-1 flex-col bg-bg">
        <header className="flex h-12 shrink-0 items-center gap-2 px-3">
          <button onClick={() => setSidebarOpen(true)} className="rounded-md p-1.5 text-muted hover:bg-panel-2 md:hidden" aria-label="Open sidebar">
            <PanelLeftOpen size={19} />
          </button>
          <div className="min-w-0 truncate text-[15px] font-medium">{store.active?.title ?? "SecScan Compiler"}</div>
          <button onClick={newScan} className="ml-auto rounded-md p-1.5 text-muted hover:bg-panel-2" title="New scan">
            <SquarePen size={18} />
          </button>
        </header>

        <div ref={thread} className="flex-1 overflow-y-auto">
          {!store.active ? (
            <EmptyState samples={samples} onSample={runSample} />
          ) : (
            <div className="mx-auto w-full max-w-5xl space-y-8 px-3 py-6 sm:px-6">
              {store.active.turns.map((turn, i) => (
                <div key={turn.id} data-turn={i} className="scroll-mt-4 space-y-6">
                  <UserMessage turn={turn} />
                  <AssistantMessage
                    key={`${turn.id}-${turn.result ? "r" : "p"}`}
                    turn={turn}
                    onAnimationDone={() => store.finishAnimation(store.active!.id, turn.id)}
                    onEdit={(code, filename, language) => composer.current?.load(code, filename, language)}
                    onRetry={() => store.retry(turn.id)}
                  />
                </div>
              ))}
              <div className="h-4" />
            </div>
          )}
        </div>

        <Composer ref={composer} busy={store.busy} onSubmit={(code, filename, language) => store.submit(code, filename, language)} />
      </main>

      {rulesOpen && <RulesDialog onClose={() => setRulesOpen(false)} />}
    </div>
  );
}
