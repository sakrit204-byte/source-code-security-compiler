import { useEffect, useMemo, useRef } from "react";
import type { Finding, Severity } from "../types";
import { SEV_BG, SEVERITIES, cx } from "./ui";

interface Props {
  source: string;
  findings?: Finding[];
  focusLine?: number;
  onLineClick?: (line: number) => void;
  maxHeight?: string;
  compact?: boolean;
}

/** Line-numbered source listing with a severity gutter and an optional focused line. */
export function CodeView({ source, findings = [], focusLine, onLineClick, maxHeight = "28rem", compact }: Props) {
  const lines = useMemo(() => source.split("\n"), [source]);
  const byLine = useMemo(() => {
    const map = new Map<number, Finding[]>();
    for (const f of findings) map.set(f.line, [...(map.get(f.line) ?? []), f]);
    return map;
  }, [findings]);
  const container = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!focusLine || !container.current) return;
    const el = container.current.querySelector<HTMLElement>(`[data-line="${focusLine}"]`);
    if (el) {
      const box = container.current;
      box.scrollTo({ top: el.offsetTop - box.clientHeight / 2 + el.clientHeight, behavior: "smooth" });
    }
  }, [focusLine]);

  const worst = (fs: Finding[]): Severity =>
    SEVERITIES.find((s) => fs.some((f) => f.severity === s)) ?? "info";

  return (
    <div
      ref={container}
      className="relative overflow-auto rounded-xl border border-line bg-code font-mono text-[12.5px] leading-[1.6]"
      style={{ maxHeight }}
    >
      <table className="w-full border-collapse">
        <tbody>
          {lines.map((text, i) => {
            const n = i + 1;
            const hits = byLine.get(n);
            const focused = focusLine === n;
            return (
              <tr
                key={n}
                data-line={n}
                onClick={() => onLineClick?.(n)}
                className={cx(
                  onLineClick && "cursor-pointer",
                  focused ? "line-flash bg-accent/15" : hits ? "bg-sev-critical/[0.06]" : "hover:bg-panel-2/70",
                )}
                title={hits?.map((f) => `${f.rule_id} ${f.title}: ${f.message}`).join("\n")}
              >
                <td className="sticky left-0 w-1 bg-code p-0">
                  {hits && <div className={cx("h-full min-h-[20px] w-1", SEV_BG[worst(hits)])} />}
                </td>
                <td className={cx("select-none pr-3 text-right align-top text-faint", compact ? "w-8 pl-2" : "w-12 pl-3")}>{n}</td>
                <td className="whitespace-pre pr-4 align-top">
                  {text || " "}
                  {hits && !compact && (
                    <span className="ml-3 inline-flex gap-1 align-middle">
                      {hits.map((f) => (
                        <span
                          key={f.id}
                          className={cx("rounded px-1 font-sans text-[10px] font-semibold text-white", SEV_BG[f.severity])}
                        >
                          {f.rule_id}
                        </span>
                      ))}
                    </span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
