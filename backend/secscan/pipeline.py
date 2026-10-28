"""Pipeline orchestrator: runs every compiler / analysis stage in order and
records its output, timing and internal log for display."""

from __future__ import annotations

import hashlib
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Callable, Optional

from . import ast_nodes as A
from .engine import RuleEngine
from .langs import LANGUAGE_IDS, front_end
from .langs.detect import Detection, detect_language
from .parser import BUILTIN_TYPEDEFS
from .report import build_report
from .rules.base import SEVERITIES, AstContext, LexicalContext
from .semantic import analyze
from .tokens import TokenType

VERSION = "1.1.0"
MAX_SOURCE_BYTES = 400_000

STAGE_INFO = {
    "source": ("Source Input", "Front end",
               "The raw program text is read and normalised (line endings), and every character keeps its "
               "line/column position so later diagnostics can point back to the exact place in the source."),
    "lexer": ("Lexical Analysis", "Front end",
              "The scanner groups characters into lexemes and classifies them as tokens (keywords, identifiers, "
              "literals, operators, delimiters). At each position it picks the automaton matching the first "
              "character and consumes the longest valid lexeme (maximal munch). Identifiers are checked against "
              "the keyword table. Comments and preprocessor directives are kept for security analysis but "
              "removed from the parser's stream. Each language has its own keyword and operator tables "
              "(C++ adds ::, raw strings and digit separators; Java adds annotations, text blocks and >>>)."),
    "lexical_security": ("Lexical Security Analyzer", "Module 1",
                         "Token-level rules scan the complete token stream, including comments and directives, for "
                         "hard-coded credentials, secret-looking literals, dangerous function names, suspicious "
                         "identifiers and plaintext endpoints. These rules are fast but know nothing about program "
                         "structure, so their confidence is lower."),
    "parser": ("Syntax Analysis", "Front end",
               "A recursive-descent parser checks the token stream against a context-free grammar for the selected "
               "language (C, C++ or Java). Each non-terminal is one procedure; binary operators use precedence climbing. The trace lists every "
               "production entered. On a syntax error the parser reports it and recovers in panic mode by skipping "
               "to a synchronising token (';' or '}')."),
    "ast": ("Abstract Syntax Tree", "Front end",
            "The parser builds an AST, which keeps the program's structure (functions, statements, expressions) "
            "and drops purely syntactic tokens such as parentheses and semicolons. Each node gets a pre-order id "
            "and a parent link so rules can navigate the tree."),
    "semantic": ("Semantic Analysis", "Front end",
                 "A tree walk builds a scoped symbol table (global → function → block), resolves every identifier "
                 "to its declaration, records types and array sizes, and flags undeclared or unused names. A "
                 "flow-insensitive pass then tags variables that may hold external input (argv, gets, scanf, "
                 "recv in C; cin and getline in C++; request.getParameter, readLine and args in Java) and "
                 "propagates the tag through assignments, copies and string building."),
    "ast_security": ("Syntax / AST Security Analyzer", "Module 2",
                     "Structure-aware rules match patterns on AST nodes such as calls and their arguments, "
                     "assignments, conditions and loops. They use the symbol table for buffer sizes and the "
                     "input tags for severity. Shared rules run for every language and language-specific "
                     "rules are added (C/C++ memory safety, C++ new/delete and streams, Java injection, "
                     "deserialisation and crypto APIs). This separates a real gets() call from a mention in a comment and "
                     "can prove overflows such as strcpy of a 25-byte literal into char[10]."),
    "rule_engine": ("Security Rule Engine", "Rule engine",
                    "Every rule implements one interface (id, severity, CWE, explanation, recommendation). The "
                    "engine runs each rule, times it, and isolates failures. It then correlates the two modules: a "
                    "lexical finding confirmed by an AST finding on the same line and subject is merged into a "
                    "single high-confidence finding."),
    "report": ("Security Report", "Report generator",
               "Merged findings are ranked by severity and turned into a report with source location, "
               "explanation, recommendation and CWE reference, plus an overall score and grade. It can be "
               "exported as JSON, HTML or plain text."),
}


class StageRecorder:
    def __init__(self) -> None:
        self.stages: list[dict] = []

    def run(self, stage_id: str, fn: Callable[[], tuple[dict, list[str], str, str]]):
        title, module, explain = STAGE_INFO[stage_id]
        start = time.perf_counter()
        data, log, summary, status = fn()
        self.stages.append({
            "id": stage_id, "title": title, "module": module, "explain": explain,
            "duration_ms": round((time.perf_counter() - start) * 1000, 3),
            "status": status, "summary": summary, "log": log, "data": data,
        })


def resolve_language(source: str, filename: str, language: str = "auto") -> Detection:
    """The user's explicit choice wins; otherwise the language is detected from the extension or content."""
    detected = detect_language(source, filename)
    if language in LANGUAGE_IDS:
        fe = front_end(language)
        agrees = "agrees" if detected.language == language else f"content suggests {detected.name}"
        return Detection(language, fe.name, 1.0, "user", [f"selected by the user ({agrees})"], detected.scores)
    return detected


def run_pipeline(source: str, filename: str = "input.c", disabled_rules: Optional[list[str]] = None,
                 language: str = "auto", named: bool = True) -> dict:
    """named=False: the file name was invented for pasted code, so its extension is not evidence."""
    if len(source.encode("utf-8", "replace")) > MAX_SOURCE_BYTES:
        raise ValueError(f"source is larger than {MAX_SOURCE_BYTES // 1000} KB")
    t0 = time.perf_counter()
    rec = StageRecorder()
    normalised = source.replace("\r\n", "\n").replace("\r", "\n")
    detection = resolve_language(normalised, filename if named else "", language)
    lang = detection.language
    fe = front_end(lang)
    engine = RuleEngine(disabled_rules, lang)
    lines = normalised.split("\n")
    state: dict = {}

    # 1. Source ---------------------------------------------------------------
    def stage_source():
        digest = hashlib.sha256(normalised.encode("utf-8", "replace")).hexdigest()
        non_blank = sum(1 for ln in lines if ln.strip())
        data = {"filename": filename, "lines": len(lines), "non_blank_lines": non_blank,
                "characters": len(normalised), "sha256": digest, "language": lang, "language_name": fe.name,
                "detection": detection.to_dict()}
        how = {"user": "chosen by the user", "extension": "from the file extension",
               "content": "detected from the code", "default": "default (no distinctive signals)"}[detection.method]
        log = [f"Read '{filename}': {len(normalised)} characters, {len(lines)} lines ({non_blank} non-blank)",
               "Normalised line endings to LF", f"SHA-256 {digest[:16]}…",
               f"Language: {fe.name} — {how}, confidence {round(detection.confidence * 100)}%"]
        if detection.signals:
            log.append("Evidence: " + "; ".join(detection.signals))
        log.append("Signal scores: " + ", ".join(f"{k}={v}" for k, v in detection.scores.items()))
        return data, log, f"{fe.name} · {len(lines)} lines · {len(normalised)} chars", "ok"

    rec.run("source", stage_source)

    # 2. Lexer ----------------------------------------------------------------
    def stage_lexer():
        lex = fe.tokenize(normalised)
        state["lex"] = lex
        constants: dict[str, int] = {}
        for tok in lex.tokens:
            if tok.type == TokenType.PREPROCESSOR and isinstance(tok.value, dict) and tok.value.get("macro"):
                repl = tok.value.get("replacement", "").strip("() ")
                try:
                    constants[tok.value["macro"]] = int(repl, 0)
                except ValueError:
                    pass
        state["macro_constants"] = constants
        stats = lex.stats()
        data = {
            "tokens": [t.to_dict() for t in lex.tokens if t.type != TokenType.EOF],
            "stats": stats,
            "errors": [e.to_dict() for e in lex.errors],
            "parser_stream_count": len(lex.parser_tokens) - 1,
            "patterns": fe.patterns,
            "macro_constants": constants,
        }
        log = list(lex.log)
        if constants:
            log.append("Integer macros recorded for constant folding: "
                       + ", ".join(f"{k}={v}" for k, v in constants.items()))
        total = sum(stats.values())
        status = "warning" if lex.errors else "ok"
        return data, log, f"{total} tokens · {len(stats)} token classes" + (
            f" · {len(lex.errors)} error(s)" if lex.errors else ""), status

    rec.run("lexer", stage_lexer)

    # 3. Module 1 — lexical security ------------------------------------------
    def stage_lexical_security():
        findings, runs = engine.run_lexical(LexicalContext(state["lex"], lines, lang))
        state["lex_findings"], state["lex_runs"] = findings, runs
        log = [f"{r.rule.meta.id} {r.rule.meta.name}: examined {r.rule.examined} token(s) → {len(r.findings)} hit(s)"
               for r in runs]
        return {"rules": runs, "findings": findings}, log, f"{len(findings)} finding(s) from {len(runs)} token rules", \
            "alert" if findings else "ok"

    rec.run("lexical_security", stage_lexical_security)

    # 4. Parser ---------------------------------------------------------------
    def stage_parser():
        result = fe.parse(state["lex"].parser_tokens, state["macro_constants"])
        state["parse"] = result
        log = [f"Parsing {len(state['lex'].parser_tokens) - 1} tokens with the {fe.name} recursive-descent parser",
               f"Entered {sum(result.production_counts.values())} productions "
               f"({len(result.production_counts)} distinct non-terminals)"]
        user_typedefs = sorted(result.typedef_names - BUILTIN_TYPEDEFS) if lang != "java" else []
        if user_typedefs:
            log.append(("Typedef names" if lang == "c" else "Type names (typedefs, classes, templates)")
                       + " learned while parsing: " + ", ".join(user_typedefs[:40]))
        for err in result.errors:
            log.append(f"[{err.line}:{err.col}] syntax error: {err.message} → {err.recovery}")
        if not result.errors:
            log.append("Input accepted: the token stream derives from translation_unit")
        data = {
            "trace": result.trace, "trace_truncated": result.trace_truncated,
            "errors": [e.to_dict() for e in result.errors],
            "grammar": [{"lhs": lhs, "rhs": rhs, "uses": result.production_counts.get(lhs, 0)}
                        for lhs, rhs in fe.grammar],
            "production_counts": result.production_counts,
            "typedefs": user_typedefs,
            "constants": result.constants,
        }
        status = "warning" if result.errors else "ok"
        return data, log, f"{len(result.trace)} derivation steps" + (
            f" · {len(result.errors)} syntax error(s) recovered" if result.errors else " · accepted"), status

    rec.run("parser", stage_parser)

    # 5. AST ------------------------------------------------------------------
    def stage_ast():
        ast = state["parse"].ast
        nodes = list(ast.walk())
        kinds = Counter(n.kind for n in nodes)
        functions = [n.name for n in nodes if isinstance(n, A.FunctionDef)]
        classes = [n.name for n in nodes if isinstance(n, A.ClassDecl)]
        depth = A.tree_depth(ast)
        log = [f"Built AST with {len(nodes)} nodes, maximum depth {depth}",
               f"Top-level declarations: {len(ast.decls)}; functions: {', '.join(functions) or 'none'}",
               *([f"Classes / types: {', '.join(classes)}"] if classes else []),
               "Most frequent node kinds: " + ", ".join(f"{k}×{v}" for k, v in kinds.most_common(6))]
        data = {"tree": ast.to_dict(), "node_count": len(nodes), "depth": depth, "kinds": dict(kinds.most_common()),
                "functions": functions, "classes": classes}
        return data, log, f"{len(nodes)} nodes · depth {depth} · {len(functions)} function(s)", "ok"

    rec.run("ast", stage_ast)

    # 6. Semantic analysis ----------------------------------------------------
    def stage_semantic():
        sem = analyze(state["parse"].ast, fe.profile)
        state["sem"] = sem
        tainted = [s.to_dict() for s in sem.symbols if s.tainted]
        data = {"scopes": sem.global_scope.to_dict(), "symbols": [s.to_dict() for s in sem.symbols],
                "diagnostics": [d.to_dict() for d in sem.diagnostics], "external_functions": sem.external_functions,
                "tainted": tainted}
        warnings = sum(1 for d in sem.diagnostics if d.severity != "info")
        return data, sem.log, (f"{len(sem.symbols)} symbols · {len(tainted)} input-derived · "
                               f"{len(sem.diagnostics)} diagnostic(s)"), "warning" if warnings else "ok"

    rec.run("semantic", stage_semantic)

    # 7. Module 2 — AST security ----------------------------------------------
    def stage_ast_security():
        consts = {**state["parse"].constants}
        ctx = AstContext(state["parse"], state["sem"], lines, consts, lang)
        findings, runs = engine.run_ast(ctx)
        state["ast_findings"], state["ast_runs"] = findings, runs
        log = [f"{r.rule.meta.id} {r.rule.meta.name}: examined {r.rule.examined} node(s) → {len(r.findings)} hit(s)"
               + (f" [rule error: {r.error}]" if r.error else "") for r in runs]
        return {"rules": runs, "findings": findings}, log, \
            f"{len(findings)} finding(s) from {len(runs)} structural rules", "alert" if findings else "ok"

    rec.run("ast_security", stage_ast_security)

    # 8. Rule engine ----------------------------------------------------------
    def stage_engine():
        lex_f, ast_f = state["lex_findings"], state["ast_findings"]
        links = engine.correlate(lex_f, ast_f)
        merged = engine.merge(lex_f, ast_f)
        state["merged"] = merged
        runs = state["lex_runs"] + state["ast_runs"]
        log = [f"Executed {len(runs)} rules ({len(state['lex_runs'])} lexical, {len(state['ast_runs'])} AST)",
               f"Raw findings: {len(lex_f)} lexical + {len(ast_f)} AST = {len(lex_f) + len(ast_f)}"]
        log += [f"Correlated {l['lexical']} ↔ {l['ast']} on line {l['line']} ('{l['subject']}'): {l['reason']}"
                for l in links]
        log.append(f"After correlation: {len(merged)} unique finding(s)")
        errors = [r for r in runs if r.error]
        data = {"rules": [r.to_dict() for r in runs], "correlations": links,
                "raw_counts": {"lexical": len(lex_f), "ast": len(ast_f)}, "merged_count": len(merged),
                "severity_counts": {s: sum(1 for f in merged if f.severity == s) for s in SEVERITIES}}
        return data, log, f"{len(runs)} rules · {len(links)} correlation(s) · {len(merged)} unique", \
            "warning" if errors else "ok"

    rec.run("rule_engine", stage_engine)

    # 9. Report ---------------------------------------------------------------
    meta = {
        "filename": filename, "lines": len(lines), "tokens": sum(state["lex"].stats().values()),
        "ast_nodes": rec.stages[4]["data"]["node_count"], "language": fe.name, "language_id": lang,
        "detection": detection.to_dict(),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "version": VERSION,
    }

    def stage_report():
        report = build_report(state["merged"], meta)
        state["report"] = report
        log = [f"Score {report['score']}/100 → grade {report['grade']} ({report['risk']})", report["scoring"],
               "Severity counts: " + ", ".join(f"{k}={v}" for k, v in report["severity_counts"].items())]
        status = "alert" if report["total"] else "ok"
        return report, log, f"Grade {report['grade']} · {report['total']} finding(s)", status

    rec.run("report", stage_report)

    # Findings are serialised last so correlation results appear in every stage.
    for stage in rec.stages:
        if stage["id"] in ("lexical_security", "ast_security"):
            stage["data"] = {"rules": [r.to_dict() for r in stage["data"]["rules"]],
                             "findings": [f.to_dict() for f in stage["data"]["findings"]]}

    meta["duration_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    return {"meta": meta, "source": normalised, "stages": rec.stages, "report": state["report"]}
