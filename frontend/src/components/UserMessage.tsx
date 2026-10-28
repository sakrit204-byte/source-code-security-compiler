import { ChevronDown, FileCode2 } from "lucide-react";
import { useState } from "react";
import type { Turn } from "../types";
import { cx, LanguagePill } from "./ui";

const PREVIEW_LINES = 12;

export function UserMessage({ turn }: { turn: Turn }) {
  const [open, setOpen] = useState(false);
  const lines = turn.code.split("\n");
  const long = lines.length > PREVIEW_LINES;
  const shown = open || !long ? lines : lines.slice(0, PREVIEW_LINES);
  return (
    <div className="flex justify-end">
      <div className="w-full max-w-[min(42rem,92%)] overflow-hidden rounded-3xl rounded-tr-md bg-panel-2">
        <div className="flex items-center gap-2 px-4 pt-3 text-xs text-muted">
          <FileCode2 size={14} />
          <span className="font-medium">{turn.result?.meta.filename ?? (turn.filename || "pasted code")}</span>
          <LanguagePill language={turn.result?.meta.language_id ?? (turn.language !== "auto" ? turn.language : undefined)} />
          {turn.language === "auto" && turn.result && <span className="text-faint">auto</span>}
          <span className="text-faint">· {lines.length} lines · {new Date(turn.createdAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
        </div>
        <pre className={cx("overflow-x-auto px-4 py-2 font-mono text-[12.5px] leading-[1.55]", long && !open && "mask-b")}>
          {shown.join("\n")}
        </pre>
        {long && (
          <button
            onClick={() => setOpen(!open)}
            className="flex w-full items-center justify-center gap-1 border-t border-line/60 py-1.5 text-xs text-muted hover:text-fg"
          >
            {open ? "Show less" : `Show all ${lines.length} lines`}
            <ChevronDown size={13} className={cx("transition-transform", open && "rotate-180")} />
          </button>
        )}
      </div>
    </div>
  );
}
