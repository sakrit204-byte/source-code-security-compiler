import { ArrowRight, EyeOff, Filter } from "lucide-react";
import { useMemo, useState } from "react";
import { Badge, Card, Empty, SectionTitle, TOKEN_BG, TOKEN_COLORS, cx } from "../components/ui";
import type { Token } from "../types";
import type { StageViewProps } from "./common";

type View = "stream" | "table" | "patterns";
const TRIVIA = new Set(["COMMENT", "PREPROCESSOR"]);

export function LexerStage({ stage, focus, setFocus }: StageViewProps<"lexer">) {
  const d = stage.data;
  const [view, setView] = useState<View>("stream");
  const [filter, setFilter] = useState<string | null>(null);
  const [selected, setSelected] = useState<Token | null>(
    () => d.tokens.find((t) => t.index === focus.tokenIndex) ?? d.tokens.find((t) => !TRIVIA.has(t.type)) ?? null,
  );
  const [limit, setLimit] = useState(300);

  const visible = useMemo(() => (filter ? d.tokens.filter((t) => t.type === filter) : d.tokens), [d.tokens, filter]);
  const byLine = useMemo(() => {
    const map = new Map<number, Token[]>();
    for (const t of visible) map.set(t.line, [...(map.get(t.line) ?? []), t]);
    return [...map.entries()].sort((a, b) => a[0] - b[0]);
  }, [visible]);

  const pick = (t: Token) => {
    setSelected(t);
    setFocus({ line: t.line, tokenIndex: t.index });
  };

  return (
    <div className="space-y-4">
      <div>
        <SectionTitle right={filter && <button className="text-xs text-accent" onClick={() => setFilter(null)}>clear filter</button>}>
          Token classes
        </SectionTitle>
        <div className="flex flex-wrap gap-1.5">
          {Object.entries(d.stats)
            .sort((a, b) => b[1] - a[1])
            .map(([type, count]) => (
              <button
                key={type}
                onClick={() => setFilter(filter === type ? null : type)}
                className={cx(
                  "rounded-full border px-2.5 py-1 font-mono text-[11px] transition",
                  TOKEN_BG[type],
                  TOKEN_COLORS[type],
                  filter && filter !== type && "opacity-40",
                )}
              >
                {type} <b>{count}</b>
              </button>
            ))}
        </div>
        <p className="mt-2 text-xs text-faint">
          {d.parser_stream_count} tokens are passed to the parser; comments and preprocessor directives stay with the lexical security analyser.
        </p>
      </div>

      {d.errors.length > 0 && (
        <Card className="border-sev-medium/50 p-3">
          <SectionTitle>Lexical errors (recovered)</SectionTitle>
          <ul className="space-y-1 text-sm">
            {d.errors.map((e, i) => (
              <li key={i} className="cursor-pointer font-mono text-[12px] text-sev-medium" onClick={() => setFocus({ line: e.line })}>
                {e.line}:{e.col} — {e.message}
              </li>
            ))}
          </ul>
        </Card>
      )}

      <div className="flex items-center gap-1 rounded-lg bg-panel-2 p-1 text-xs font-medium w-fit">
        {(["stream", "table", "patterns"] as View[]).map((v) => (
          <button
            key={v}
            onClick={() => setView(v)}
            className={cx("rounded-md px-3 py-1 capitalize", view === v ? "bg-panel shadow-sm" : "text-muted hover:text-fg")}
          >
            {v === "stream" ? "Token stream" : v === "table" ? "Token table" : "Patterns"}
          </button>
        ))}
        {filter && (
          <span className="ml-2 inline-flex items-center gap-1 text-faint">
            <Filter size={12} /> {filter}
          </span>
        )}
      </div>

      {view === "stream" && (
        <div className="grid gap-4 lg:grid-cols-[1fr_300px]">
          <div className="max-h-[30rem] overflow-auto rounded-xl border border-line bg-code p-2 font-mono text-[12px]">
            {byLine.length === 0 && <Empty>No tokens of this class.</Empty>}
            {byLine.map(([line, toks]) => (
              <div key={line} className={cx("flex gap-2 rounded px-1 py-0.5", focus.line === line && "bg-accent/10")}>
                <span className="w-8 shrink-0 select-none pt-0.5 text-right text-faint">{line}</span>
                <div className="flex flex-wrap gap-1">
                  {toks.map((t) => (
                    <button
                      key={t.index}
                      onClick={() => pick(t)}
                      title={`${t.type} @ ${t.line}:${t.col}`}
                      className={cx(
                        "max-w-[22rem] truncate rounded border px-1.5 py-0.5 text-left",
                        TOKEN_BG[t.type],
                        TOKEN_COLORS[t.type],
                        selected?.index === t.index && "ring-2 ring-accent",
                        TRIVIA.has(t.type) && "opacity-70",
                      )}
                    >
                      {t.lexeme}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
          <TokenDetail token={selected} />
        </div>
      )}

      {view === "table" && (
        <div className="overflow-auto rounded-xl border border-line">
          <table className="w-full text-left text-[12px]">
            <thead className="sticky top-0 bg-panel-2 text-faint">
              <tr>
                {["#", "Pos", "Type", "Lexeme", "Value", "Decision"].map((h) => (
                  <th key={h} className="px-3 py-2 font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="font-mono">
              {visible.slice(0, limit).map((t) => (
                <tr
                  key={t.index}
                  onClick={() => pick(t)}
                  className={cx("cursor-pointer border-t border-line hover:bg-panel-2/60", selected?.index === t.index && "bg-accent/10")}
                >
                  <td className="px-3 py-1.5 text-faint">{t.index}</td>
                  <td className="px-3 py-1.5 text-faint">{t.line}:{t.col}</td>
                  <td className={cx("px-3 py-1.5", TOKEN_COLORS[t.type])}>{t.type}</td>
                  <td className="max-w-[16rem] truncate px-3 py-1.5">{t.lexeme}</td>
                  <td className="max-w-[10rem] truncate px-3 py-1.5 text-muted">{formatValue(t.value)}</td>
                  <td className="max-w-[20rem] truncate px-3 py-1.5 font-sans text-muted">{t.notes[0] ?? ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {visible.length > limit && (
            <button onClick={() => setLimit(limit + 500)} className="w-full border-t border-line py-2 text-xs text-accent">
              Show more ({visible.length - limit} remaining)
            </button>
          )}
        </div>
      )}

      {view === "patterns" && (
        <div className="overflow-hidden rounded-xl border border-line">
          <table className="w-full text-left text-[12.5px]">
            <tbody>
              {Object.entries(d.patterns).map(([name, pattern]) => (
                <tr key={name} className="border-t border-line first:border-t-0">
                  <td className="w-40 px-3 py-2 font-medium">{name.replace("_", " ")}</td>
                  <td className="px-3 py-2 font-mono text-muted">{pattern}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {Object.keys(d.macro_constants).length > 0 && (
            <div className="border-t border-line px-3 py-2 text-xs text-muted">
              Integer macros recorded for constant folding:{" "}
              {Object.entries(d.macro_constants).map(([k, v]) => (
                <Badge key={k} className="mr-1 font-mono">{k}={v}</Badge>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function TokenDetail({ token }: { token: Token | null }) {
  if (!token) return <Empty>Select a token to see how the lexer recognised it.</Empty>;
  const trivia = TRIVIA.has(token.type);
  return (
    <Card className="h-fit p-4 text-sm lg:sticky lg:top-2">
      <div className="mb-3 flex items-center justify-between">
        <span className={cx("rounded border px-2 py-0.5 font-mono text-xs", TOKEN_BG[token.type], TOKEN_COLORS[token.type])}>{token.type}</span>
        <span className="font-mono text-xs text-faint">#{token.index} · {token.line}:{token.col}</span>
      </div>
      <div className="mb-3 break-all rounded-lg bg-code px-3 py-2 font-mono text-[13px]">{token.lexeme}</div>
      <dl className="space-y-2 text-[12.5px]">
        <div>
          <dt className="text-faint">Matched pattern</dt>
          <dd className="break-all font-mono text-[11.5px]">{token.pattern}</dd>
        </div>
        {token.value != null && token.value !== "" && (
          <div>
            <dt className="text-faint">Semantic value</dt>
            <dd className="break-all font-mono text-[11.5px]">{formatValue(token.value)}</dd>
          </div>
        )}
        {token.notes.length > 0 && (
          <div>
            <dt className="text-faint">Scanner decisions</dt>
            <dd>
              <ul className="list-inside list-disc text-muted">
                {token.notes.map((n, i) => <li key={i}>{n}</li>)}
              </ul>
            </dd>
          </div>
        )}
      </dl>
      <div className="mt-3 flex items-center gap-1.5 border-t border-line pt-3 text-xs text-muted">
        {trivia ? (
          <><EyeOff size={13} /> Not sent to the parser (trivia); scanned by Module 1</>
        ) : token.type === "ERROR" ? (
          <><EyeOff size={13} /> Discarded after reporting a lexical error</>
        ) : (
          <><ArrowRight size={13} /> Sent to the parser and to Module 1</>
        )}
      </div>
    </Card>
  );
}

function formatValue(v: unknown): string {
  if (v == null) return "";
  if (typeof v === "string") return JSON.stringify(v);
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}
