import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./api";
import { isLanguageChoice, type LanguageChoice } from "./languages";
import type { Conversation, Turn } from "./types";

const STORAGE_KEY = "secscan.conversations.v1";
const MAX_CONVERSATIONS = 40;

const uid = () => Math.random().toString(36).slice(2, 10) + Date.now().toString(36);

/** Results are large and cheap to recompute, so only code + metadata is persisted. */
function persist(conversations: Conversation[]) {
  const slim = conversations.slice(0, MAX_CONVERSATIONS).map((c) => ({
    ...c,
    turns: c.turns.map(({ id, code, filename, language, createdAt }) => ({ id, code, filename, language, createdAt })),
  }));
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(slim));
  } catch {
    /* storage unavailable or full: history simply isn't kept */
  }
}

function load(): Conversation[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as Conversation[]) : [];
  } catch {
    return [];
  }
}

function titleFor(code: string, filename: string): string {
  if (filename) return filename;
  const cls = code.match(/\b(?:class|interface|enum|record|struct)\s+([A-Za-z_]\w*)\s*[:{<]|\bclass\s+([A-Za-z_]\w*)/);
  if (cls) return `${cls[1] ?? cls[2]} scan`;
  const fn = code.match(/\b(?:int|void|char|static|unsigned|long|float|double)\s+\**\s*([A-Za-z_]\w*)\s*\(/);
  return fn ? `${fn[1]}() scan` : "Untitled scan";
}

export function useConversations() {
  const [conversations, setConversations] = useState<Conversation[]>(load);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const rehydrating = useRef(new Set<string>());

  useEffect(() => persist(conversations), [conversations]);

  const patchTurn = useCallback((convId: string, turnId: string, patch: Partial<Turn>) => {
    setConversations((prev) =>
      prev.map((c) => {
        if (c.id !== convId) return c;
        const turns = c.turns.map((t) => (t.id === turnId ? { ...t, ...patch } : t));
        const last = turns[turns.length - 1];
        return { ...c, turns, grade: last?.result?.report.grade ?? c.grade };
      }),
    );
  }, []);

  const runTurn = useCallback(
    async (convId: string, turn: Turn) => {
      try {
        const result = await api.scan(turn.code, turn.filename, turn.language ?? "auto");
        patchTurn(convId, turn.id, { result, error: undefined });
      } catch (err) {
        patchTurn(convId, turn.id, { error: err instanceof Error ? err.message : String(err) });
      }
    },
    [patchTurn],
  );

  const submit = useCallback(
    async (code: string, filename: string, language: LanguageChoice = "auto", opts: { fresh?: boolean } = {}) => {
      const turn: Turn = { id: uid(), code, filename, language, createdAt: Date.now(), animate: true };
      let convId = opts.fresh ? null : activeId;
      if (!convId) {
        convId = uid();
        const conv: Conversation = {
          id: convId,
          title: titleFor(code, filename),
          createdAt: Date.now(),
          updatedAt: Date.now(),
          turns: [turn],
        };
        setConversations((prev) => [conv, ...prev]);
        setActiveId(convId);
      } else {
        const id = convId;
        setConversations((prev) => {
          const target = prev.find((c) => c.id === id);
          if (!target) return prev;
          const updated = { ...target, turns: [...target.turns, turn], updatedAt: Date.now() };
          return [updated, ...prev.filter((c) => c.id !== id)];
        });
      }
      setBusy(true);
      await runTurn(convId, turn);
      setBusy(false);
    },
    [activeId, runTurn],
  );

  /** Re-run scans for a conversation restored from storage (results are not persisted). */
  const select = useCallback(
    (id: string | null) => {
      setActiveId(id);
      if (!id || rehydrating.current.has(id)) return;
      const conv = conversations.find((c) => c.id === id);
      if (!conv) return;
      const missing = conv.turns.filter((t) => !t.result && !t.error);
      if (!missing.length) return;
      rehydrating.current.add(id);
      Promise.all(missing.map((t) => runTurn(id, t))).finally(() => rehydrating.current.delete(id));
    },
    [conversations, runTurn],
  );

  const remove = useCallback(
    (id: string) => {
      setConversations((prev) => prev.filter((c) => c.id !== id));
      if (activeId === id) setActiveId(null);
    },
    [activeId],
  );

  const clearAll = useCallback(() => {
    setConversations([]);
    setActiveId(null);
  }, []);

  const retry = useCallback(
    async (turnId: string) => {
      const conv = conversations.find((c) => c.id === activeId);
      const turn = conv?.turns.find((t) => t.id === turnId);
      if (!conv || !turn) return;
      patchTurn(conv.id, turnId, { error: undefined, result: undefined, animate: true });
      setBusy(true);
      await runTurn(conv.id, turn);
      setBusy(false);
    },
    [conversations, activeId, patchTurn, runTurn],
  );

  const finishAnimation = useCallback(
    (convId: string, turnId: string) => patchTurn(convId, turnId, { animate: false }),
    [patchTurn],
  );

  const active = conversations.find((c) => c.id === activeId) ?? null;
  return { conversations, active, activeId, busy, submit, select, remove, clearAll, retry, finishAnimation };
}

/** The composer's language choice survives reloads. */
export function useLanguageChoice() {
  const [language, setLanguage] = useState<LanguageChoice>(() => {
    try {
      const saved = localStorage.getItem("secscan.language");
      return isLanguageChoice(saved) ? saved : "auto";
    } catch {
      return "auto";
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem("secscan.language", language);
    } catch {
      /* ignore */
    }
  }, [language]);
  return [language, setLanguage] as const;
}

export function useTheme() {
  const [theme, setTheme] = useState<"light" | "dark">(() => {
    try {
      const saved = localStorage.getItem("secscan.theme");
      if (saved === "light" || saved === "dark") return saved;
    } catch {
      /* ignore */
    }
    return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
  });
  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
    try {
      localStorage.setItem("secscan.theme", theme);
    } catch {
      /* ignore */
    }
  }, [theme]);
  return { theme, toggle: () => setTheme((t) => (t === "dark" ? "light" : "dark")) };
}
