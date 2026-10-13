"""Security Rule Engine: runs rules through one interface and correlates findings."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Iterable, Optional

from .rules.ast_rules import AST_RULES
from .rules.base import SEVERITY_RANK, Finding, Rule
from .rules.lexical_rules import LEXICAL_RULES


@dataclass
class RuleRun:
    rule: Rule
    findings: list[Finding] = field(default_factory=list)
    duration_ms: float = 0.0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            **self.rule.meta.to_dict(),
            "examined": self.rule.examined,
            "hits": len(self.findings),
            "duration_ms": round(self.duration_ms, 3),
            "lines": sorted({f.line for f in self.findings}),
            "error": self.error,
        }


def all_rule_classes() -> list[type[Rule]]:
    return [*LEXICAL_RULES, *AST_RULES]


def rule_catalog() -> list[dict]:
    return [cls.meta.to_dict() for cls in all_rule_classes()]


class RuleEngine:
    def __init__(self, disabled: Optional[Iterable[str]] = None):
        self.disabled = set(disabled or ())

    def run(self, rule_classes: list[type[Rule]], ctx, prefix: str) -> tuple[list[Finding], list[RuleRun]]:
        runs: list[RuleRun] = []
        findings: list[Finding] = []
        for cls in rule_classes:
            if cls.meta.id in self.disabled:
                continue
            rule = cls()
            run = RuleRun(rule)
            start = time.perf_counter()
            try:
                run.findings = list(rule.check(ctx))
            except Exception as exc:  # a faulty rule must never break the whole scan
                run.error = f"{type(exc).__name__}: {exc}"
            run.duration_ms = (time.perf_counter() - start) * 1000
            runs.append(run)
            findings.extend(run.findings)
        findings.sort(key=lambda f: (f.line, f.col, -SEVERITY_RANK[f.severity]))
        for i, f in enumerate(findings, 1):
            f.id = f"{prefix}{i}"
            f.detected_by = [f.level]
        return findings, runs

    def run_lexical(self, ctx) -> tuple[list[Finding], list[RuleRun]]:
        return self.run(LEXICAL_RULES, ctx, "L")

    def run_ast(self, ctx) -> tuple[list[Finding], list[RuleRun]]:
        return self.run(AST_RULES, ctx, "A")

    @staticmethod
    def correlate(lexical: list[Finding], ast: list[Finding]) -> list[dict]:
        """Link token-level and structure-level findings that describe the same issue.

        A lexical finding is confirmed when an AST finding sits on the same line and
        concerns the same subject (function or identifier), or when both are
        credential findings on the same line.
        """
        links: list[dict] = []
        for lf in lexical:
            for af in ast:
                if af.line != lf.line:
                    continue
                same_subject = lf.subject and af.subject and lf.subject == af.subject
                both_credentials = lf.category == "Credentials" and af.category == "Credentials"
                if same_subject or both_credentials:
                    lf.correlated.append(af.id)
                    af.correlated.append(lf.id)
                    if "lexical" not in af.detected_by:
                        af.detected_by.insert(0, "lexical")
                    # The AST rule refines the generic "dangerous name" verdict, so it wins there; any other
                    # lexical evidence (e.g. a matched key format) may raise the severity.
                    if lf.rule_id != "LEX003" and SEVERITY_RANK[lf.severity] > SEVERITY_RANK[af.severity]:
                        af.severity = lf.severity
                    links.append({"lexical": lf.id, "ast": af.id, "line": lf.line, "subject": lf.subject or af.subject,
                                  "reason": "same subject on the same line" if same_subject else
                                  "credential findings on the same line"})
                    break
        return links

    @staticmethod
    def merge(lexical: list[Finding], ast: list[Finding]) -> list[Finding]:
        """Final report list: AST findings (structure-aware, higher confidence) plus
        lexical findings that no AST rule confirmed."""
        merged = list(ast)
        for f in ast:
            if "lexical" in f.detected_by:
                f.confidence = "high"
        merged.extend(f for f in lexical if not f.correlated)
        merged.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.line, f.col))
        return merged
