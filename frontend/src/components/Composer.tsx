import { ArrowUp, FileCode2, Loader2, Paperclip, X } from "lucide-react";
import { forwardRef, useEffect, useImperativeHandle, useRef, useState } from "react";
import { cx } from "./ui";

export interface ComposerHandle {
  load: (code: string, filename: string) => void;
}

interface Props {
  busy: boolean;
  onSubmit: (code: string, filename: string) => void;
}

const MAX_BYTES = 400_000;

export const Composer = forwardRef<ComposerHandle, Props>(function Composer({ busy, onSubmit }, ref) {
  const [code, setCode] = useState("");
  const [filename, setFilename] = useState("input.c");
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const area = useRef<HTMLTextAreaElement>(null);
  const file = useRef<HTMLInputElement>(null);

  useImperativeHandle(ref, () => ({
    load(nextCode, nextName) {
      setCode(nextCode);
      setFilename(nextName || "input.c");
      setError(null);
      requestAnimationFrame(() => area.current?.focus());
    },
  }));

  useEffect(() => {
    const el = area.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${Math.min(el.scrollHeight, window.innerHeight * 0.45)}px`;
  }, [code]);

  const submit = () => {
    if (busy || !code.trim()) return;
    onSubmit(code, filename.trim() || "input.c");
    setCode("");
    setFilename("input.c");
  };

  const readFile = (f: File) => {
    if (f.size > MAX_BYTES) {
      setError(`${f.name} is larger than ${MAX_BYTES / 1000} KB.`);
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      setCode(String(reader.result ?? ""));
      setFilename(f.name);
      setError(null);
    };
    reader.readAsText(f);
  };

  return (
    <div className="mx-auto w-full max-w-4xl px-3 pb-3 sm:px-4">
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          const f = e.dataTransfer.files[0];
          if (f) readFile(f);
        }}
        className={cx(
          "rounded-3xl border bg-panel shadow-[0_4px_24px_rgba(0,0,0,0.06)] transition dark:shadow-none",
          dragging ? "border-accent ring-2 ring-accent/30" : "border-line",
        )}
      >
        <textarea
          ref={area}
          value={code}
          onChange={(e) => setCode(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
              e.preventDefault();
              submit();
            }
            if (e.key === "Tab") {
              e.preventDefault();
              const el = e.currentTarget;
              const { selectionStart: s, selectionEnd: t } = el;
              setCode(code.slice(0, s) + "    " + code.slice(t));
              requestAnimationFrame(() => el.setSelectionRange(s + 4, s + 4));
            }
          }}
          placeholder="Paste C source code here, drop a .c file, or pick a sample…"
          spellCheck={false}
          rows={3}
          className="block max-h-[45vh] w-full resize-none bg-transparent px-5 pt-4 font-mono text-[13px] leading-relaxed outline-none placeholder:font-sans placeholder:text-faint"
        />
        <div className="flex items-center gap-2 px-3 pb-3 pt-1">
          <input ref={file} type="file" accept=".c,.h,.txt" className="hidden" onChange={(e) => e.target.files?.[0] && readFile(e.target.files[0])} />
          <button
            onClick={() => file.current?.click()}
            className="flex h-9 w-9 items-center justify-center rounded-full text-muted hover:bg-panel-2 hover:text-fg"
            title="Attach a .c file"
          >
            <Paperclip size={17} />
          </button>
          <label className="flex min-w-0 items-center gap-1.5 rounded-full border border-line px-3 py-1.5 text-xs text-muted">
            <FileCode2 size={13} />
            <input
              value={filename}
              onChange={(e) => setFilename(e.target.value)}
              className="w-28 min-w-0 bg-transparent outline-none sm:w-40"
              aria-label="File name"
            />
          </label>
          {code && (
            <button onClick={() => setCode("")} className="hidden items-center gap-1 text-xs text-faint hover:text-fg sm:inline-flex">
              <X size={12} /> clear
            </button>
          )}
          <span className="ml-auto hidden text-[11px] text-faint sm:inline">
            {code ? `${code.split("\n").length} lines · ` : ""}Ctrl + Enter to analyze
          </span>
          <button
            onClick={submit}
            disabled={busy || !code.trim()}
            className="ml-auto flex h-9 w-9 items-center justify-center rounded-full bg-fg text-bg transition disabled:opacity-25 sm:ml-0"
            title="Analyze"
          >
            {busy ? <Loader2 size={17} className="animate-spin" /> : <ArrowUp size={18} />}
          </button>
        </div>
      </div>
      {error && <p className="mt-1.5 text-center text-xs text-sev-critical">{error}</p>}
      <p className="mt-2 text-center text-[11px] text-faint">
        Rule-based static analysis — findings can include false positives and miss issues outside the rule set.
      </p>
    </div>
  );
});
