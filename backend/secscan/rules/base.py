"""Common interface for security rules and the findings they produce."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

from .. import ast_nodes as A
from ..lexer import LexResult
from ..parser import ParseResult
from ..semantic import SemanticResult
from ..tokens import Token

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: rank for rank, name in enumerate(reversed(SEVERITIES))}  # info=0 … critical=4

CREDENTIAL_NAME = re.compile(
    r"(?i)(passw(or)?d|passwd|pwd|passphrase|secret|api_?key|apikey|auth_?(key|token)|"
    r"access_?(key|token)|private_?key|priv_?key|credential|token|session_?key|db_?pass|admin_?pass)"
)


def is_credential_name(name: str) -> bool:
    return bool(name) and CREDENTIAL_NAME.search(name) is not None


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values())


def looks_like_secret_value(value: str) -> bool:
    """Heuristic: is a literal plausibly a real credential rather than UI text?"""
    if not value or len(value) < 3:
        return False
    if "%" in value or value.endswith(":") or value.endswith(": ") or "\n" in value:
        return False
    if len(value.split()) > 3:
        return False
    return True


@dataclass
class RuleMeta:
    id: str
    name: str
    level: str  # "lexical" (Module 1) or "ast" (Module 2)
    severity: str  # default severity
    category: str
    cwe: str
    description: str
    recommendation: str
    detects: str = ""  # how the rule matches, shown in the UI
    languages: tuple = ("c", "cpp")  # source languages the rule applies to

    def to_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "level": self.level, "severity": self.severity,
            "category": self.category, "cwe": self.cwe, "description": self.description,
            "recommendation": self.recommendation, "detects": self.detects,
            "languages": list(self.languages),
        }


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    level: str
    category: str
    cwe: str
    line: int
    col: int
    message: str
    recommendation: str
    evidence: str = ""
    subject: str = ""
    snippet: str = ""
    confidence: str = "high"
    node_id: Optional[int] = None
    token_index: Optional[int] = None
    id: str = ""
    detected_by: list[str] = field(default_factory=list)
    correlated: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "rule_id": self.rule_id, "title": self.title, "severity": self.severity,
            "level": self.level, "category": self.category, "cwe": self.cwe, "line": self.line,
            "col": self.col, "message": self.message, "recommendation": self.recommendation,
            "evidence": self.evidence, "subject": self.subject, "snippet": self.snippet,
            "confidence": self.confidence, "node_id": self.node_id, "token_index": self.token_index,
            "detected_by": self.detected_by or [self.level], "correlated": self.correlated,
        }


@dataclass
class LexicalContext:
    lex: LexResult
    lines: list[str]
    language: str = "c"

    @property
    def tokens(self) -> list[Token]:
        return self.lex.tokens


@dataclass
class AstContext:
    parse: ParseResult
    sem: SemanticResult
    lines: list[str]
    constants: dict[str, int]
    language: str = "c"

    @property
    def ast(self) -> A.TranslationUnit:
        return self.parse.ast

    def calls(self) -> Iterable[A.Call]:
        for node in self.ast.walk():
            if isinstance(node, A.Call):
                yield node

    def enclosing_function(self, node: A.Node) -> Optional[A.FunctionDef]:
        for anc in node.ancestors():
            if isinstance(anc, A.FunctionDef):
                return anc
        return None

    def const_eval(self, node: Optional[A.Node]) -> Optional[int]:
        """Constant-fold integer expressions, including macros, enums and sizeof(array)."""
        if node is None:
            return None
        if isinstance(node, (A.IntLiteral, A.CharLiteral)):
            return node.value
        if isinstance(node, A.KeywordLiteral):
            return {"true": 1, "false": 0, "null": 0, "nullptr": 0}.get(node.value)
        if isinstance(node, A.Identifier):
            if node.name in self.constants:
                return self.constants[node.name]
            sym = self.sem.resolved.get(node.id)
            if sym is not None and sym.kind == "enum_constant":
                return self.constants.get(sym.name)
            return None
        if isinstance(node, A.Cast):
            return self.const_eval(node.expr)
        if isinstance(node, A.SizeOf):
            if node.expr is not None:
                sym = self.sem.symbol_for(node.expr)
                if sym is not None and sym.array_dims and isinstance(node.expr, A.Identifier) \
                        and sym.kind == "variable" and sym.array_size is not None:
                    elem = 1 if "char" in sym.type else None
                    return sym.array_size * elem if elem else None
                return None
            return {"char": 1, "unsigned char": 1, "signed char": 1, "short": 2, "int": 4,
                    "long": 8, "long long": 8, "float": 4, "double": 8}.get(node.type)
        if isinstance(node, A.UnaryOp) and node.op == "-" and not node.postfix:
            value = self.const_eval(node.operand)
            return -value if value is not None else None
        if isinstance(node, A.BinaryOp):
            left, right = self.const_eval(node.left), self.const_eval(node.right)
            if left is None or right is None:
                return None
            try:
                ops = {"+": lambda: left + right, "-": lambda: left - right, "*": lambda: left * right,
                       "/": lambda: left // right if right else None,
                       "%": lambda: left % right if right else None,
                       "<<": lambda: left << right if 0 <= right < 64 else None, ">>": lambda: left >> right}
                fn = ops.get(node.op)
                return fn() if fn else None
            except (ValueError, OverflowError):
                return None
        return None

    def buffer_size(self, node: Optional[A.Node]) -> Optional[int]:
        """Size in elements of a fixed-size local/global array referenced by the expression."""
        if not isinstance(node, (A.Identifier, A.Cast)):
            return None
        sym = self.sem.symbol_for(node)
        if sym is None or sym.kind != "variable" or not sym.array_dims:
            return None
        return sym.array_size


def describe(node: Optional[A.Node], ctx: Optional[AstContext] = None, depth: int = 0) -> str:
    """Compact textual rendering of an AST pattern, used as finding evidence."""
    if node is None:
        return "∅"
    if depth > 3:
        return "…"
    if isinstance(node, A.Identifier):
        extra = ""
        if ctx is not None:
            sym = ctx.sem.resolved.get(node.id)
            if sym is not None:
                dims = "".join(f"[{d if d is not None else ''}]" for d in sym.array_dims)
                extra = f" : {sym.type}{dims}"
                if sym.tainted:
                    extra += " ⚑input"
        return f"Identifier('{node.name}'{extra})"
    if isinstance(node, A.StringLiteral):
        shown = node.value if len(node.value) <= 24 else node.value[:21] + "…"
        return f"StringLiteral({shown!r}, len={len(node.value)})"
    if isinstance(node, (A.IntLiteral, A.FloatLiteral, A.CharLiteral)):
        return f"{node.kind}({node.raw})"
    if isinstance(node, A.Call):
        args = ", ".join(describe(a, ctx, depth + 1) for a in node.args)
        return f"Call({A.callee_path(node.callee) or describe(node.callee, ctx, depth + 1)}, [{args}])"
    if isinstance(node, A.New):
        args = ", ".join(describe(a, ctx, depth + 1) for a in node.args)
        size = f"[{describe(node.array_size, ctx, depth + 1)}]" if node.is_array else ""
        return f"New({node.type}{size}, [{args}])"
    if isinstance(node, A.Delete):
        return f"Delete{'[]' if node.is_array else ''}({describe(node.operand, ctx, depth + 1)})"
    if isinstance(node, A.KeywordLiteral):
        return f"Literal({node.value})"
    if isinstance(node, A.Lambda):
        return f"Lambda({', '.join(p.name for p in node.params)})"
    if isinstance(node, A.BinaryOp):
        return f"BinaryOp('{node.op}', {describe(node.left, ctx, depth + 1)}, {describe(node.right, ctx, depth + 1)})"
    if isinstance(node, A.Assignment):
        return f"Assignment('{node.op}', {describe(node.target, ctx, depth + 1)}, {describe(node.value, ctx, depth + 1)})"
    if isinstance(node, A.Index):
        return f"Index({describe(node.array, ctx, depth + 1)}, {describe(node.index, ctx, depth + 1)})"
    if isinstance(node, A.UnaryOp):
        return f"UnaryOp('{node.op}', {describe(node.operand, ctx, depth + 1)})"
    if isinstance(node, A.Cast):
        return f"Cast({node.type}, {describe(node.expr, ctx, depth + 1)})"
    if isinstance(node, A.Member):
        return f"Member({describe(node.obj, ctx, depth + 1)}, {'->' if node.arrow else '.'}{node.field_name})"
    if isinstance(node, A.SizeOf):
        return f"SizeOf({node.type or describe(node.expr, ctx, depth + 1)})"
    return node.kind


class Rule:
    meta: RuleMeta

    def __init__(self) -> None:
        self.examined = 0

    def check(self, ctx) -> Iterable[Finding]:  # pragma: no cover - interface
        raise NotImplementedError

    def finding(self, ctx, line: int, col: int, message: str, *, severity: Optional[str] = None,
                evidence: str = "", subject: str = "", node: Optional[A.Node] = None,
                token: Optional[Token] = None, confidence: str = "high", cwe: Optional[str] = None,
                recommendation: Optional[str] = None, title: Optional[str] = None) -> Finding:
        snippet = ctx.lines[line - 1].strip() if 0 < line <= len(ctx.lines) else ""
        return Finding(
            rule_id=self.meta.id, title=title or self.meta.name, severity=severity or self.meta.severity,
            level=self.meta.level, category=self.meta.category, cwe=cwe or self.meta.cwe, line=line, col=col,
            message=message, recommendation=recommendation or self.meta.recommendation, evidence=evidence,
            subject=subject, snippet=snippet, confidence=confidence,
            node_id=node.id if node is not None else None,
            token_index=token.index if token is not None else None,
        )


# Shared knowledge base of risky C library functions.
DANGEROUS_FUNCTIONS: dict[str, dict] = {
    "gets": {"severity": "critical", "cwe": "CWE-242", "why": "reads an unbounded line into a fixed buffer and was removed in C11",
             "use": "fgets(buf, sizeof buf, stdin)"},
    "strcpy": {"severity": "high", "cwe": "CWE-120", "why": "copies without checking the destination size",
               "use": "strncpy/strlcpy or snprintf(dst, sizeof dst, \"%s\", src)"},
    "strcat": {"severity": "high", "cwe": "CWE-120", "why": "appends without checking the remaining space",
               "use": "strncat/strlcat with the remaining buffer size"},
    "sprintf": {"severity": "high", "cwe": "CWE-120", "why": "formats into a buffer without a size limit",
                "use": "snprintf(buf, sizeof buf, ...)"},
    "vsprintf": {"severity": "high", "cwe": "CWE-120", "why": "formats into a buffer without a size limit",
                 "use": "vsnprintf"},
    "wcscpy": {"severity": "high", "cwe": "CWE-120", "why": "wide-string copy without bounds", "use": "wcsncpy / wcslcpy"},
    "wcscat": {"severity": "high", "cwe": "CWE-120", "why": "wide-string append without bounds", "use": "wcsncat"},
    "stpcpy": {"severity": "high", "cwe": "CWE-120", "why": "copies without bounds", "use": "stpncpy"},
    "scanf": {"severity": "medium", "cwe": "CWE-120", "why": "'%s' conversions without a width overflow buffers",
              "use": "a field width (\"%31s\") or fgets + sscanf"},
    "fscanf": {"severity": "medium", "cwe": "CWE-120", "why": "'%s' conversions without a width overflow buffers",
               "use": "a field width or fgets + sscanf"},
    "sscanf": {"severity": "low", "cwe": "CWE-120", "why": "'%s' conversions without a width overflow buffers",
               "use": "a field width on every %s"},
    "system": {"severity": "high", "cwe": "CWE-78", "why": "runs a command through the shell",
               "use": "execve() with a fixed program path and argument vector"},
    "popen": {"severity": "high", "cwe": "CWE-78", "why": "runs a command through the shell",
              "use": "pipe()+fork()+execve() with fixed arguments"},
    "execl": {"severity": "medium", "cwe": "CWE-78", "why": "executes an external program", "use": "a fixed absolute program path"},
    "execlp": {"severity": "medium", "cwe": "CWE-78", "why": "searches PATH for the program", "use": "execv with an absolute path"},
    "execvp": {"severity": "medium", "cwe": "CWE-78", "why": "searches PATH for the program", "use": "execv with an absolute path"},
    "execv": {"severity": "medium", "cwe": "CWE-78", "why": "executes an external program", "use": "a fixed absolute program path"},
    "execve": {"severity": "low", "cwe": "CWE-78", "why": "executes an external program", "use": "validated, fixed arguments"},
    "mktemp": {"severity": "medium", "cwe": "CWE-377", "why": "creates predictable temp names (race condition)", "use": "mkstemp()"},
    "tmpnam": {"severity": "medium", "cwe": "CWE-377", "why": "creates predictable temp names (race condition)", "use": "mkstemp() or tmpfile()"},
    "tempnam": {"severity": "medium", "cwe": "CWE-377", "why": "creates predictable temp names (race condition)", "use": "mkstemp()"},
    "rand": {"severity": "low", "cwe": "CWE-338", "why": "is a predictable pseudo-random generator", "use": "getrandom()/arc4random() or a CSPRNG"},
    "random": {"severity": "low", "cwe": "CWE-338", "why": "is a predictable pseudo-random generator", "use": "getrandom()/arc4random()"},
    "atoi": {"severity": "low", "cwe": "CWE-190", "why": "cannot report conversion errors or overflow", "use": "strtol() with errno and end-pointer checks"},
    "atol": {"severity": "low", "cwe": "CWE-190", "why": "cannot report conversion errors or overflow", "use": "strtol()"},
    "atof": {"severity": "low", "cwe": "CWE-20", "why": "cannot report conversion errors", "use": "strtod()"},
    "alloca": {"severity": "medium", "cwe": "CWE-770", "why": "allocates on the stack without failure reporting", "use": "malloc() with a size check"},
    "getwd": {"severity": "medium", "cwe": "CWE-120", "why": "has no buffer size argument", "use": "getcwd(buf, sizeof buf)"},
    "strtok": {"severity": "low", "cwe": "CWE-676", "why": "keeps hidden global state and is not re-entrant", "use": "strtok_r()"},
}

# Risky Java APIs, matched by name at token level (Module 1).
JAVA_DANGEROUS: dict[str, dict] = {
    "exec": {"severity": "high", "cwe": "CWE-78", "why": "runs an operating-system command (Runtime.exec)",
             "use": "ProcessBuilder with a fixed program and an argument list (no shell)"},
    "ProcessBuilder": {"severity": "medium", "cwe": "CWE-78", "why": "starts an external process",
                       "use": "a fixed program path and validated, allow-listed arguments"},
    "readObject": {"severity": "high", "cwe": "CWE-502", "why": "deserialises bytes into live objects",
                   "use": "a data format such as JSON, or an ObjectInputFilter allow-list"},
    "ObjectInputStream": {"severity": "medium", "cwe": "CWE-502", "why": "is the entry point of Java deserialisation",
                          "use": "a data-only format, or ObjectInputFilter with an allow-list"},
    "XMLDecoder": {"severity": "high", "cwe": "CWE-502", "why": "can instantiate arbitrary classes from XML",
                   "use": "a schema-validated data binding such as JAXB"},
    "Random": {"severity": "low", "cwe": "CWE-330", "why": "(java.util.Random) is a predictable generator",
               "use": "java.security.SecureRandom"},
    "printStackTrace": {"severity": "low", "cwe": "CWE-209", "why": "writes internal stack traces to the output",
                        "use": "a logger with a generic error message to the user"},
    "DESKeySpec": {"severity": "medium", "cwe": "CWE-327", "why": "builds a key for the broken DES cipher",
                   "use": "AES-GCM keys (KeyGenerator.getInstance(\"AES\"))"},
}


def dangerous_for(language: str) -> dict[str, dict]:
    return JAVA_DANGEROUS if language == "java" else DANGEROUS_FUNCTIONS
