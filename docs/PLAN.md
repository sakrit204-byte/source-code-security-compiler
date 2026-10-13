# Compiler-Based Source Code Security Scanner — Implementation Plan

## Goal
A lightweight, explainable static security scanner for C source code built on a
hand-written compiler front end (lexer → parser → AST → semantic analysis), with
two analysis modules feeding a common rule engine and report generator. A
chat-style web UI shows every compiler stage and its internal working.

## Architecture

```
Source Code ─► Lexer ─► Tokens ─► Parser ─► AST ─► Semantic Analysis
                          │                   │            │
                          ▼                   ▼            ▼
              Module 1: Lexical        Module 2: Syntax / AST
              Security Analyzer        Security Analyzer
                          │                   │
                          └───► Security Rule Engine ◄─┘
                                        │
                                        ▼
                                Security Report
```

## Backend (`backend/secscan`)

| File | Stage | Responsibility |
|------|-------|----------------|
| `tokens.py` | — | Token types, `Token` record, keyword / operator tables |
| `lexer.py` | Lexical analysis | Hand-written scanner, maximal munch, positions, per-token trace, lexical errors |
| `ast_nodes.py` | — | AST node classes, JSON serialisation, node ids |
| `parser.py` | Syntax analysis | Recursive-descent parser for a C subset, production trace, panic-mode recovery |
| `semantic.py` | Semantic analysis | Scoped symbol table, types, array sizes, usage counts, input-source tagging |
| `rules/base.py` | Rule engine | `Rule`, `RuleMeta`, `Finding`, severity model |
| `rules/lexical_rules.py` | Module 1 | Token-level security rules |
| `rules/ast_rules.py` | Module 2 | Structure-aware security rules |
| `engine.py` | Rule engine | Runs rules, per-rule statistics, lexical↔AST correlation |
| `report.py` | Report generator | Merge, score, grade, JSON / HTML / text export |
| `pipeline.py` | Orchestrator | Runs every stage, records timings, logs and outputs |
| `__main__.py` | CLI | `python -m secscan file.c [--format text|json|html]` |

`backend/app.py` — FastAPI: `POST /api/scan`, `GET /api/rules`, `GET /api/samples`, serves built UI.

## Security rules

Module 1 (lexical): LEX001 hard-coded credential · LEX002 secret-like literal ·
LEX003 dangerous function name · LEX004 suspicious identifier · LEX005 sensitive
comment · LEX006 hard-coded network address / insecure URL.

Module 2 (AST): AST001 unsafe string/buffer function · AST002 format string ·
AST003 command injection · AST004 unbounded input · AST005 hard-coded credential
comparison/assignment · AST006 insecure randomness · AST007 unchecked allocation /
size overflow · AST008 constant out-of-bounds index · AST009 off-by-one loop ·
AST010 use-after-free / double free · AST011 assignment in condition ·
AST012 insecure temp file · AST013 copy size exceeds destination · AST014 unchecked
numeric conversion.

## Frontend (`frontend/`, React + Vite + TS + Tailwind)
- Chat layout: sidebar (new scan, history, samples), thread, composer.
- Assistant reply = animated pipeline diagram + stage inspector:
  Source · Tokens · Lexical findings · Parser trace · AST tree · Symbol table ·
  AST findings · Rule engine · Report (export JSON/HTML).
- Click-through linking: findings / AST nodes / tokens highlight source lines.

## Quality
- pytest suite for lexer, parser, semantic analysis and every rule.
- Sample programs in `samples/`.

## Scope / limitations
Rule-based and intraprocedural; flow-insensitive input tagging; no full
preprocessor (directives are tokenised, not expanded); false positives and
negatives are possible.
