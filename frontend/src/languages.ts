export type LanguageId = "c" | "cpp" | "java";
export type LanguageChoice = "auto" | LanguageId;

export interface LanguageInfo {
  id: LanguageId;
  name: string;
  defaultFile: string;
  /** Tailwind classes for the small language pill. */
  tone: string;
}

export const LANGUAGES: LanguageInfo[] = [
  { id: "c", name: "C", defaultFile: "input.c", tone: "bg-sky-500/12 text-sky-700 dark:text-sky-300" },
  { id: "cpp", name: "C++", defaultFile: "input.cpp", tone: "bg-indigo-500/12 text-indigo-700 dark:text-indigo-300" },
  { id: "java", name: "Java", defaultFile: "Input.java", tone: "bg-orange-500/12 text-orange-700 dark:text-orange-300" },
];

export const LANGUAGE_CHOICES: { id: LanguageChoice; label: string }[] = [
  { id: "auto", label: "Auto-detect" },
  ...LANGUAGES.map((l) => ({ id: l.id, label: l.name })),
];

export const FILE_ACCEPT = ".c,.h,.cpp,.cc,.cxx,.hpp,.hh,.hxx,.java,.txt";

export function languageInfo(id: string | undefined): LanguageInfo | undefined {
  return LANGUAGES.find((l) => l.id === id);
}

export function isLanguageChoice(value: unknown): value is LanguageChoice {
  return value === "auto" || LANGUAGES.some((l) => l.id === value);
}
