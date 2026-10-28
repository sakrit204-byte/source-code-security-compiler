# SecScan Compiler — Compiler-Based Source Code Security Scanner

A lightweight, explainable static security scanner for **C, C++ and Java** built on hand-written compiler
front ends (lexer → parser → AST → semantic analysis) — one per language, sharing a common AST, rule engine
and report. Two analysis modules, a **Lexical Security Analyzer** and a
**Syntax/AST Security Analyzer**, feed a common **Security Rule Engine** and **Report Generator**.
A chat-style web UI shows every compiler stage and its inner workings.

```
Source ─► Lexer ─► Tokens ─► Parser ─► AST ─► Semantic analysis
             │                          │            │
             ▼                          ▼            ▼
   Module 1: Lexical            Module 2: Syntax / AST
   Security Analyzer            Security Analyzer
             └──────► Security Rule Engine ◄──────┘
                              │
                              ▼
                       Security Report
```

## Quick start

Requirements: Python 3.10+, Node 18+.

```bash
# 1. backend dependencies
pip install -r backend/requirements.txt

# 2. build the UI (one time)
cd frontend && npm install && npm run build && cd ..

# 3. run — UI and API on http://127.0.0.1:8000
python backend/app.py
```

On Windows you can simply run `run.bat`.

**UI development:** run `python backend/app.py` and `npm run dev` in `frontend/`
(Vite on http://localhost:5173 proxies `/api` to the backend).

**Command line:**

```bash
cd backend
python -m secscan ../samples/c/01_buffer_overflow.c                 # text report
python -m secscan ../samples/c/03_command_injection.c --format stages
python -m secscan file.c --format html -o report.html
python -m secscan file.c --fail-on high                           # exit code 2 for CI
```

**Tests:** `cd backend && python -m pytest`

## Using the UI

1. Paste C code into the composer, drop a `.c` file onto it, or click a sample. Press **Ctrl+Enter**.
2. The answer animates through the nine stages, with the pipeline diagram lighting up as each one finishes.
3. You get a summary (grade, score and the most serious findings), then the **stage inspector**:

| Tab | What you see |
|-----|--------------|
| Source | annotated listing with a severity gutter |
| Lexer | token classes, colour-coded token stream, token table, the pattern each lexeme matched and the scanner's decisions (keyword lookup, maximal munch, escapes) |
| Module 1 | token-level rule hits and the rules that ran (tokens examined, hits, time) |
| Parser | full derivation trace (every production entered), syntax errors with panic-mode recovery, the EBNF grammar with usage counts |
| AST | interactive tree, node attributes, path, flagged nodes, linked source |
| Semantic | nested scopes and symbol tables, input-derived (tainted) variables with reasons, diagnostics |
| Module 2 | structural rule hits with the matched AST pattern as evidence |
| Rule engine | lexical ↔ AST correlation, merge pipeline, per-rule profile |
| Report | filters, categories, export (HTML / JSON / text) |

Each tab explains how the stage works and shows its internal log under **Under the hood**.
Scans are kept in the sidebar history like chat conversations. Use **Edit & re-scan** to iterate on code.

## Languages

| Language | Front end | Extras |
|---|---|---|
| C | `lexer.py`, `parser.py` | preprocessor tokens, integer macros for constant folding |
| C++ | `langs/lexer.py`, `langs/cpp_parser.py` | classes, templates, namespaces, `new`/`delete`, lambdas, range-for, C++ casts, raw strings |
| Java | `langs/lexer.py`, `langs/java_parser.py` | classes/records/enums, generics, annotations, lambdas, try-with-resources, switch expressions, text blocks |

The UI has a language selector (**Auto-detect**, C, C++, Java). In auto mode the language is taken from the
file extension, or detected from weighted signals in the code (`langs/detect.py`); the composer shows the
detected language live while you type or paste, and the Source stage explains the decision.
CLI: `python -m secscan FILE --language auto|c|cpp|java`. API: `POST /api/scan` with `"language"`, and
`POST /api/detect`.

Rules declare the languages they apply to. Shared rules (credentials, injection, SQL injection, swallowed
exceptions …) run everywhere; C/C++ memory-safety rules run for C and C++; `CPP001`–`CPP005`
(new/delete mismatch, unbounded `cin >>`, unsafe casts, predictable `<random>` seeds, leaked `new`) and
`JAVA001`–`JAVA012` (command injection, deserialization, weak crypto, insecure randomness, path traversal,
XSS, XXE, disabled TLS validation, information exposure, open redirect, unsafe reflection, insecure cookies)
are language-specific.

## Security rules

| ID | Module | Rule | CWE |
|----|--------|------|-----|
| LEX001 | Lexical | Hard-coded credential (identifier / `#define`) | 798 |
| LEX002 | Lexical | Secret-like literal (AWS/GitHub/JWT/PEM, URL credentials, entropy) | 798 |
| LEX003 | Lexical | Dangerous function referenced | 676 / 242 / 120 / 78 |
| LEX004 | Lexical | Suspicious identifier (backdoor, bypass, debug_mode …) | 912 |
| LEX005 | Lexical | Security-relevant / secret-leaking comment | 615 / 546 |
| LEX006 | Lexical | Plain-HTTP URL or hard-coded IP | 319 / 547 |
| AST001 | AST | Unsafe buffer operation (proves overflow using declared sizes) | 120 / 787 / 242 |
| AST002 | AST | Format string vulnerability, format/argument mismatch, `%n` | 134 / 685 |
| AST003 | AST | OS command injection | 78 |
| AST004 | AST | Unbounded `%s`, size argument larger than buffer | 120 / 787 |
| AST005 | AST | Hard-coded credential in comparisons / initialisation | 798 |
| AST006 | AST | Insecure randomness, predictable seed | 338 / 337 |
| AST007 | AST | Unchecked allocation, size overflow, realloc leak, tainted size | 690 / 190 / 401 / 789 |
| AST008 | AST | Constant out-of-bounds index | 787 / 125 |
| AST009 | AST | Off-by-one / over-long loop bound | 193 / 787 |
| AST010 | AST | Use after free / double free | 416 / 415 |
| AST011 | AST | Assignment used as condition (authorization bypass) | 481 |
| AST012 | AST | Insecure temp file, access→open TOCTOU | 377 / 367 |
| AST013 | AST | Copy size exceeds destination, missing NUL | 120 / 787 / 170 |
| AST014 | AST | Unchecked numeric conversion | 190 / 20 |
| AST015 | AST | World-writable permissions, `umask(0)` | 732 |
| AST016 | AST | Weak cryptographic algorithm | 327 |

Severity is raised when an argument is **input-derived**. The semantic pass tags variables that receive data
from `argv`, `gets`, `fgets`, `scanf`, `read`, `recv`, `getenv` … and propagates the tag through assignments
and copy functions.

## Project layout

```
backend/
  app.py                 FastAPI server (API + built UI)
  secscan/
    tokens.py            token types, keyword/operator tables
    lexer.py             hand-written scanner
    ast_nodes.py         AST node classes
    parser.py            recursive-descent parser + grammar
    semantic.py          symbol table, scopes, input tagging (per-language taint profiles)
    langs/               C++ and Java scanners and parsers, language detection, taint profiles
    rules/base.py        rule interface, finding model, helpers
    rules/lexical_rules.py   Module 1
    rules/ast_rules.py       Module 2 (C / C++, some shared)
    rules/common_rules.py    Module 2, all languages
    rules/cpp_rules.py       Module 2, C++
    rules/java_rules.py      Module 2, Java
    engine.py            rule engine + correlation
    report.py            scoring, text/HTML reports
    pipeline.py          stage orchestration
    __main__.py          CLI
  tests/                 pytest suite
frontend/                React + Vite + Tailwind UI
samples/c, cpp, java     example programs (vulnerable and secure)
docs/PLAN.md             implementation plan
```

## Scope and limitations

- Targets a substantial subset of C, C++ and Java (C++ templates are parsed but not instantiated;
  Java types from libraries are known only by name).
- C: preprocessor directives are tokenised, and integer `#define`s are used
  for constant folding, but macros are not expanded and headers are not read.
- Analysis is rule-based and intraprocedural. Input tagging is flow-insensitive, and use-after-free uses a
  lexical approximation of dominance.
- False positives and false negatives are possible. Interprocedural data flow, full taint tracking,
  symbolic execution, ML and binary analysis are out of scope.
