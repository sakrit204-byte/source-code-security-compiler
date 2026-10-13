import { CodeView } from "../components/CodeView";
import { SectionTitle, Stat } from "../components/ui";
import type { StageViewProps } from "./common";

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
