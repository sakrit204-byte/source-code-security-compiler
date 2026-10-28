import { ArrowRight, Binary, Braces, FileSearch, GitBranch, ListTree, Scale, ShieldAlert, ShieldCheck, Table2 } from "lucide-react";
import { LANGUAGES } from "../languages";
import type { Sample } from "../types";
import { LanguagePill } from "./ui";

const STEPS = [
  { icon: FileSearch, title: "Source", text: "read & position-tag" },
  { icon: Binary, title: "Lexer", text: "characters → tokens" },
  { icon: ShieldAlert, title: "Module 1", text: "token-level rules" },
  { icon: Braces, title: "Parser", text: "grammar derivation" },
  { icon: GitBranch, title: "AST", text: "program structure" },
  { icon: Table2, title: "Semantic", text: "scopes & symbols" },
  { icon: ListTree, title: "Module 2", text: "AST-level rules" },
  { icon: Scale, title: "Rule engine", text: "correlate & merge" },
  { icon: ShieldCheck, title: "Report", text: "score & fixes" },
];

/** Two samples per language, so every front end is one click away. */
function pickSamples(samples: Sample[]): Sample[] {
  return LANGUAGES.flatMap((l) => samples.filter((s) => s.language === l.id).slice(0, 2));
}

export function EmptyState({ samples, onSample }: { samples: Sample[]; onSample: (s: Sample) => void }) {
  return (
    <div className="mx-auto flex w-full max-w-4xl flex-col items-center px-4 pb-8 pt-[8vh] text-center">
      <h1 className="text-2xl font-semibold sm:text-3xl">What code should I analyze?</h1>
      <p className="mt-2 max-w-xl text-sm text-muted">
        Paste a C, C++ or Java program below — the language is detected automatically, or pick it yourself. The code is
        compiled through a hand-written lexer, parser and semantic analyser for that language, then checked by two
        security modules. Every stage and its inner workings are shown step by step.
      </p>
      <div className="mt-3 flex items-center gap-1.5 text-xs text-faint">
        Supported:
        {LANGUAGES.map((l) => (
          <LanguagePill key={l.id} language={l.id} />
        ))}
      </div>

      <div className="mt-8 flex w-full flex-wrap items-center justify-center gap-1.5">
        {STEPS.map((s, i) => (
          <div key={s.title} className="flex items-center gap-1.5">
            <div className="flex items-center gap-2 rounded-xl border border-line bg-panel px-2.5 py-1.5 text-left">
              <s.icon size={15} className="text-accent" />
              <div className="leading-tight">
                <div className="text-[12px] font-medium">{s.title}</div>
                <div className="text-[10.5px] text-faint">{s.text}</div>
              </div>
            </div>
            {i < STEPS.length - 1 && <ArrowRight size={12} className="text-faint" />}
          </div>
        ))}
      </div>

      <div className="mt-10 grid w-full gap-2 sm:grid-cols-2">
        {pickSamples(samples).map((s) => (
          <button
            key={s.id}
            onClick={() => onSample(s)}
            className="group rounded-2xl border border-line bg-panel px-4 py-3 text-left transition hover:bg-panel-2"
          >
            <div className="flex items-center gap-2 text-sm font-medium">
              <LanguagePill language={s.language} />
              {s.title}
              <ArrowRight size={14} className="ml-auto text-faint opacity-0 transition group-hover:opacity-100" />
            </div>
            <div className="mt-0.5 line-clamp-1 text-xs text-muted">{s.description || s.filename}</div>
          </button>
        ))}
      </div>
    </div>
  );
}
