import { ArrowUp, ChevronDown, FileCode2, Languages, Loader2, Paperclip, Sparkles, X } from "lucide-react";
import { forwardRef, useEffect, useImperativeHandle, useRef, useState } from "react";
import { api } from "../api";
import { FILE_ACCEPT, LANGUAGE_CHOICES, languageInfo, type LanguageChoice } from "../languages";
import { useLanguageChoice } from "../store";
import type { Detection } from "../types";
import { cx, LanguagePill } from "./ui";

export interface ComposerHandle {
  load: (code: string, filename: string, language?: LanguageChoice) => void;
}

interface Props {
  busy: boolean;
  onSubmit: (code: string, filename: string, language: LanguageChoice) => void;
}

const MAX_BYTES = 400_000;
const DETECT_DELAY_MS = 350;

/** Ask the backend which language the text looks like, debounced while the user types or pastes. */
function useDetection(code: string, filename: string) {
  const [detection, setDetection] = useState<Detection | null>(null);
  const [pending, setPending] = useState(false);
  useEffect(() => {
    if (!code.trim()) {
      setDetection(null);
      setPending(false);
      return;
    }
    setPending(true);
    const ctrl = new AbortController();
    const timer = setTimeout(() => {
      api
        .detect(code, filename, ctrl.signal)
        .then((d) => setDetection(d))
        .catch(() => {
          /* aborted or offline: keep the previous guess */
        })
        .finally(() => !ctrl.signal.aborted && setPending(false));
    }, DETECT_DELAY_MS);
    return () => {
      clearTimeout(timer);
      ctrl.abort();
    };
  }, [code, filename]);
  return { detection, pending };
}

export const Composer = forwardRef<ComposerHandle, Props>(function Composer({ busy, onSubmit }, ref) {
  const [code, setCode] = useState("");
  const [filename, setFilename] = useState("");
  const [language, setLanguage] = useLanguageChoice();
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const area = useRef<HTMLTextAreaElement>(null);
  const file = useRef<HTMLInputElement>(null);
  const { detection, pending } = useDetection(code, filename.trim());

  useImperativeHandle(ref, () => ({
    load(nextCode, nextName, nextLanguage) {
      setCode(nextCode);
      setFilename(nextName);
      if (nextLanguage) setLanguage(nextLanguage);
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

  const effective = language === "auto" ? detection?.language : language;
  const placeholderName = languageInfo(effective)?.defaultFile ?? "file name";

  const submit = () => {
    if (busy || !code.trim()) return;
    onSubmit(code, filename.trim(), language);
    setCode("");
    setFilename("");
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
          placeholder="Paste C, C++ or Java source code here, drop a file, or pick a sample…"
          spellCheck={false}
          rows={3}
          className="block max-h-[45vh] w-full resize-none bg-transparent px-5 pt-4 font-mono text-[13px] leading-relaxed outline-none placeholder:font-sans placeholder:text-faint"
        />
        <div className="flex flex-wrap items-center gap-2 px-3 pb-3 pt-1">
          <input
            ref={file}
            type="file"
            accept={FILE_ACCEPT}
            className="hidden"
            onChange={(e) => {
              if (e.target.files?.[0]) readFile(e.target.files[0]);
              e.target.value = "";
            }}
          />
          <button
            onClick={() => file.current?.click()}
            className="flex h-9 w-9 items-center justify-center rounded-full text-muted hover:bg-panel-2 hover:text-fg"
            title="Attach a source file (.c, .cpp, .h, .java …)"
          >
            <Paperclip size={17} />
          </button>

          <label
            className="relative flex items-center gap-1.5 rounded-full border border-line py-1.5 pl-3 pr-7 text-xs text-muted hover:bg-panel-2"
            title="Source language"
          >
            <Languages size={13} />
            <select
              value={language}
              onChange={(e) => setLanguage(e.target.value as LanguageChoice)}
              className="cursor-pointer appearance-none bg-transparent font-medium text-fg outline-none"
              aria-label="Source language"
            >
              {LANGUAGE_CHOICES.map((c) => (
                <option key={c.id} value={c.id} className="bg-panel text-fg">
                  {c.label}
                </option>
              ))}
            </select>
            <ChevronDown size={12} className="pointer-events-none absolute right-2.5" />
          </label>

          <DetectionHint language={language} detection={detection} pending={pending} hasCode={!!code.trim()} onAdopt={setLanguage} />

          <label className="flex min-w-0 items-center gap-1.5 rounded-full border border-line px-3 py-1.5 text-xs text-muted">
            <FileCode2 size={13} />
            <input
              value={filename}
              onChange={(e) => setFilename(e.target.value)}
              placeholder={placeholderName}
              className="w-24 min-w-0 bg-transparent outline-none placeholder:text-faint sm:w-32"
              aria-label="File name (optional)"
            />
          </label>
          {code && (
            <button onClick={() => setCode("")} className="hidden items-center gap-1 text-xs text-faint hover:text-fg sm:inline-flex">
              <X size={12} /> clear
            </button>
          )}
          <span className="ml-auto hidden text-[11px] text-faint lg:inline">
            {code ? `${code.split("\n").length} lines · ` : ""}Ctrl + Enter to analyze
          </span>
          <button
            onClick={submit}
            disabled={busy || !code.trim()}
            className="ml-auto flex h-9 w-9 items-center justify-center rounded-full bg-fg text-bg transition disabled:opacity-25 lg:ml-0"
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

function DetectionHint({
  language,
  detection,
  pending,
  hasCode,
  onAdopt,
}: {
  language: LanguageChoice;
  detection: Detection | null;
  pending: boolean;
  hasCode: boolean;
  onAdopt: (language: LanguageChoice) => void;
}) {
  if (!hasCode) return null;
  if (!detection)
    return pending ? (
      <span className="inline-flex items-center gap-1 text-[11px] text-faint">
        <Loader2 size={11} className="animate-spin" /> detecting…
      </span>
    ) : null;

  const tooltip = `${detection.method === "extension" ? "From the file extension" : "Evidence"}: ${
    detection.signals.join(", ") || "none"
  }`;
  if (language === "auto")
    return (
      <span className={cx("inline-flex items-center gap-1.5 text-[11px] text-muted transition", pending && "opacity-60")} title={tooltip}>
        <Sparkles size={12} className="text-accent" />
        <span className="hidden sm:inline">Detected</span>
        <LanguagePill language={detection.language} />
        <span className="text-faint">{Math.round(detection.confidence * 100)}%</span>
      </span>
    );

  const disagrees = detection.language !== language && detection.method !== "default" && detection.confidence >= 0.7;
  if (!disagrees) return null;
  return (
    <button
      onClick={() => onAdopt(detection.language)}
      className="inline-flex items-center gap-1.5 rounded-full bg-sev-medium/10 px-2.5 py-1 text-[11px] text-sev-medium hover:bg-sev-medium/20"
      title={tooltip}
    >
      Looks like {detection.name} — switch
    </button>
  );
}
