import { CodeView } from "../components/CodeView";
import { Card, LanguagePill, SectionTitle, Stat, cx } from "../components/ui";
import { LANGUAGES } from "../languages";
import type { Detection } from "../types";
import type { StageViewProps } from "./common";

const METHOD_LABEL: Record<Detection["method"], string> = {
  user: "Chosen by the user",
  extension: "File extension",
  content: "Detected from the code",
  default: "Default (no distinctive signals)",
};

export function SourceStage({ stage, result, focus, setFocus }: StageViewProps<"source">) {
  const d = stage.data;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Stat label="Lines" value={d.lines} />
        <Stat label="Non-blank lines" value={d.non_blank_lines} />
        <Stat label="Characters" value={d.characters} />
        <Stat label="SHA-256" value={d.sha256.slice(0, 10) + "…"} hint={d.sha256} />
      </div>
      {d.detection && <LanguageDetection detection={d.detection} />}
      <div>
        <SectionTitle>Annotated source — flagged lines carry the final report's findings</SectionTitle>
        <CodeView
          source={result.source}
          findings={result.report.findings}
          focusLine={focus.line}
          onLineClick={(line) => setFocus({ line })}
          maxHeight="32rem"
        />
      </div>
    </div>
  );
}

function LanguageDetection({ detection }: { detection: Detection }) {
  const max = Math.max(1, ...Object.values(detection.scores));
  return (
    <Card>
      <SectionTitle>Language selection — chooses the scanner, grammar, taint profile and rule set</SectionTitle>
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <LanguagePill language={detection.language} className="text-xs" />
        <span className="font-medium">{detection.name}</span>
        <span className="text-muted">· {METHOD_LABEL[detection.method]}</span>
        <span className="text-faint">· confidence {Math.round(detection.confidence * 100)}%</span>
      </div>
      {detection.signals.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {detection.signals.map((s) => (
            <span key={s} className="rounded-md border border-line bg-panel-2 px-1.5 py-0.5 text-[11px] text-muted">
              {s}
            </span>
          ))}
        </div>
      )}
      <div className="mt-3 space-y-1.5">
        {LANGUAGES.map((l) => {
          const value = detection.scores[l.id] ?? 0;
          return (
            <div key={l.id} className="flex items-center gap-2 text-xs">
              <span className="w-10 text-muted">{l.name}</span>
              <div className="h-2 flex-1 overflow-hidden rounded-full bg-panel-2">
                <div
                  className={cx("h-full rounded-full", l.id === detection.language ? "bg-accent" : "bg-faint/50")}
                  style={{ width: `${(value / max) * 100}%` }}
                />
              </div>
              <span className="w-10 text-right font-mono text-faint">{value}</span>
            </div>
          );
        })}
      </div>
      <p className="mt-2 text-[11px] text-faint">
        Weighted lexical signals (keywords, headers, library calls) counted outside comments and strings. C++ only wins on
        C++-specific evidence because most C is also valid C++.
      </p>
    </Card>
  );
}
