import type { LanguageChoice, LanguageId } from "./languages";

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type StageStatus = "ok" | "warning" | "alert" | "error";
export type StageId =
  | "source"
  | "lexer"
  | "lexical_security"
  | "parser"
  | "ast"
  | "semantic"
  | "ast_security"
  | "rule_engine"
  | "report";

export interface Token {
  index: number;
  type: string;
  lexeme: string;
  line: number;
  col: number;
  end_line: number;
  end_col: number;
  value: unknown;
  pattern: string;
  notes: string[];
}

export interface Finding {
  id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  level: "lexical" | "ast";
  category: string;
  cwe: string;
  line: number;
  col: number;
  message: string;
  recommendation: string;
  evidence: string;
  subject: string;
  snippet: string;
  confidence: string;
  node_id: number | null;
  token_index: number | null;
  detected_by: string[];
  correlated: string[];
}

export interface RuleMeta {
  id: string;
  name: string;
  level: "lexical" | "ast";
  severity: Severity;
  category: string;
  cwe: string;
  description: string;
  recommendation: string;
  detects: string;
  languages: LanguageId[];
}

export interface Detection {
  language: LanguageId;
  name: string;
  confidence: number;
  method: "user" | "extension" | "content" | "default";
  signals: string[];
  scores: Record<LanguageId, number>;
}

export interface RuleRun extends RuleMeta {
  examined: number;
  hits: number;
  duration_ms: number;
  lines: number[];
  error: string;
}

export interface AstNode {
  id: number;
  kind: string;
  label: string;
  line: number;
  col: number;
  role?: string;
  attrs: Record<string, unknown>;
  children: AstNode[];
}

export interface TraceEntry {
  depth: number;
  rule: string;
  token: string;
  line: number;
  col: number;
  event: "enter" | "match" | "error" | "recover";
}

export interface SymbolInfo {
  name: string;
  kind: string;
  type: string;
  scope: string;
  line: number;
  col: number;
  node_id: number;
  array_dims: (number | null)[];
  pointer_depth: number;
  is_const: boolean;
  storage: string;
  uses: number;
  tainted: boolean;
  taint_reason: string;
  literal_init: string | null;
}

export interface ScopeInfo {
  id: number;
  name: string;
  kind: string;
  line: number;
  symbols: SymbolInfo[];
  children: ScopeInfo[];
}

export interface Diagnostic {
  severity: "error" | "warning" | "info";
  message: string;
  line: number;
  col: number;
  recovery?: string;
}

export interface Report {
  meta: Record<string, unknown> & { filename: string; lines: number; tokens: number; ast_nodes: number };
  score: number;
  grade: string;
  risk: string;
  total: number;
  severity_counts: Record<Severity, number>;
  by_category: Record<string, number>;
  by_cwe: Record<string, number>;
  by_module: { lexical_only: number; ast_only: number; both: number };
  affected_lines: number[];
  findings: Finding[];
  scoring: string;
}

export interface StageData {
  source: {
    filename: string;
    lines: number;
    non_blank_lines: number;
    characters: number;
    sha256: string;
    language: LanguageId;
    language_name: string;
    detection: Detection;
  };
  lexer: {
    tokens: Token[];
    stats: Record<string, number>;
    errors: Diagnostic[];
    parser_stream_count: number;
    patterns: Record<string, string>;
    macro_constants: Record<string, number>;
  };
  lexical_security: { rules: RuleRun[]; findings: Finding[] };
  parser: {
    trace: TraceEntry[];
    trace_truncated: boolean;
    errors: Diagnostic[];
    grammar: { lhs: string; rhs: string; uses: number }[];
    production_counts: Record<string, number>;
    typedefs: string[];
    constants: Record<string, number>;
  };
  ast: { tree: AstNode; node_count: number; depth: number; kinds: Record<string, number>; functions: string[]; classes: string[] };
  semantic: {
    scopes: ScopeInfo;
    symbols: SymbolInfo[];
    diagnostics: Diagnostic[];
    external_functions: Record<string, number>;
    tainted: SymbolInfo[];
  };
  ast_security: { rules: RuleRun[]; findings: Finding[] };
  rule_engine: {
    rules: RuleRun[];
    correlations: { lexical: string; ast: string; line: number; subject: string; reason: string }[];
    raw_counts: { lexical: number; ast: number };
    merged_count: number;
    severity_counts: Record<Severity, number>;
  };
  report: Report;
}

export interface Stage<K extends StageId = StageId> {
  id: K;
  title: string;
  module: string;
  explain: string;
  duration_ms: number;
  status: StageStatus;
  summary: string;
  log: string[];
  data: StageData[K];
}

export interface ScanResult {
  meta: {
    filename: string;
    lines: number;
    tokens: number;
    ast_nodes: number;
    duration_ms: number;
    generated_at: string;
    version: string;
    language: string;
    language_id: LanguageId;
    detection: Detection;
  };
  source: string;
  stages: Stage[];
  report: Report;
}

export interface Sample {
  id: string;
  filename: string;
  title: string;
  description: string;
  code: string;
  language: LanguageId;
}

export interface Turn {
  id: string;
  code: string;
  filename: string;
  /** What the user asked for; the resolved language is in result.meta. */
  language?: LanguageChoice;
  createdAt: number;
  result?: ScanResult;
  error?: string;
  animate?: boolean;
}

export interface Conversation {
  id: string;
  title: string;
  createdAt: number;
  updatedAt: number;
  turns: Turn[];
  grade?: string;
}

/** Shared "focus" so findings, tokens and AST nodes can point at the same source location. */
export interface Focus {
  line?: number;
  nodeId?: number | null;
  tokenIndex?: number | null;
}
