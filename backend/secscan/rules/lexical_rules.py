"""Module 1 — Lexical Security Analyzer.

These rules look only at the token stream (including comments and
preprocessor directives, which the parser never sees). They are fast and
language-structure agnostic, at the cost of lower confidence than AST rules.
"""

from __future__ import annotations

import re
from typing import Iterable

from ..tokens import Token, TokenType
from .base import (DANGEROUS_FUNCTIONS, Finding, LexicalContext, Rule, RuleMeta, is_credential_name,
                   looks_like_secret_value, shannon_entropy)


class HardcodedCredentialRule(Rule):
    meta = RuleMeta(
        id="LEX001", name="Hard-coded credential", level="lexical", severity="high",
        category="Credentials", cwe="CWE-798",
        description="A credential-like identifier is assigned a string literal directly in the source.",
        recommendation="Load secrets at runtime from a protected configuration store or environment, "
                       "never commit them to source code.",
        detects="IDENTIFIER~/pass|secret|key|token/  ('[' … ']')?  '='  STRING_LITERAL   — or —   #define NAME \"…\"",
    )

    def check(self, ctx: LexicalContext) -> Iterable[Finding]:
        toks = ctx.tokens
        for i, tok in enumerate(toks):
            if tok.type == TokenType.PREPROCESSOR:
                self.examined += 1
                value = tok.value or {}
                macro, repl = value.get("macro", ""), value.get("replacement", "")
                if macro and is_credential_name(macro) and repl.startswith('"') and len(repl) > 2:
                    literal = repl.strip('"')
                    if looks_like_secret_value(literal):
                        yield self.finding(ctx, tok.line, tok.col,
                                           f"Macro '{macro}' expands to the hard-coded secret \"{mask(literal)}\".",
                                           evidence=f"PREPROCESSOR(#define {macro} {repl[:3]}…)", subject=macro,
                                           token=tok, confidence="medium")
                continue
            if tok.type != TokenType.IDENTIFIER or not is_credential_name(tok.lexeme):
                continue
            self.examined += 1
            j = i + 1
            if j < len(toks) and toks[j].is_op("["):  # skip array declarator: password[] / password[32]
                depth = 0
                while j < len(toks):
                    if toks[j].is_op("["):
                        depth += 1
                    elif toks[j].is_op("]"):
                        depth -= 1
                        if depth == 0:
                            j += 1
                            break
                    j += 1
            if j + 1 < len(toks) and toks[j].is_op("=") and toks[j + 1].type == TokenType.STRING_LITERAL:
                literal = toks[j + 1].value or ""
                if looks_like_secret_value(literal):
                    seq = " ".join(t.lexeme for t in toks[i:j + 2])
                    yield self.finding(
                        ctx, tok.line, tok.col,
                        f"Identifier '{tok.lexeme}' is initialised with the literal \"{mask(literal)}\". "
                        "Anyone with access to the source or binary (e.g. via `strings`) can recover it.",
                        evidence=f"tokens: {seq[:80]}", subject=tok.lexeme, token=tok, confidence="medium")


SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id", "critical"),
    (re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "PEM private key", "critical"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"), "GitHub token", "critical"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token", "high"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+"), "JSON Web Token", "high"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]{16,}"), "bearer token", "high"),
    (re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:[^/\s@]+@"), "URL with embedded credentials", "high"),
    (re.compile(r"(?i)(password|passwd|pwd)\s*=\s*[^;\s]{3,}"), "connection string password", "high"),
]


DEFINE_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')


def string_values(ctx: LexicalContext) -> Iterable[tuple[Token, str]]:
    """String literal values, including quoted strings inside #define bodies."""
    for tok in ctx.tokens:
        if tok.type == TokenType.STRING_LITERAL:
            yield tok, tok.value or ""
        elif tok.type == TokenType.PREPROCESSOR and isinstance(tok.value, dict) and tok.value.get("directive") == "define":
            for m in DEFINE_STRING.finditer(tok.value.get("replacement", "")):
                yield tok, m.group(1)


class SecretLiteralRule(Rule):
    meta = RuleMeta(
        id="LEX002", name="Secret-like string literal", level="lexical", severity="medium",
        category="Credentials", cwe="CWE-798",
        description="A string literal matches a known secret format or has the high entropy typical of keys.",
        recommendation="Remove the secret from source control, rotate it, and inject it at runtime.",
        detects="STRING_LITERAL value matched against key/token regexes and Shannon entropy ≥ 4.0 bits/char",
    )

    def check(self, ctx: LexicalContext) -> Iterable[Finding]:
        for tok, value in string_values(ctx):
            self.examined += 1
            for pattern, label, severity in SECRET_PATTERNS:
                if pattern.search(value):
                    yield self.finding(ctx, tok.line, tok.col,
                                       f"String literal looks like a {label}: \"{mask(value)}\".",
                                       severity=severity, evidence=f"regex /{pattern.pattern[:48]}/ matched",
                                       subject=label, token=tok, confidence="high")
                    break
            else:
                entropy = shannon_entropy(value)
                classes = sum(bool(re.search(p, value)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"))
                if len(value) >= 20 and " " not in value and entropy >= 4.0 and classes >= 3:
                    yield self.finding(ctx, tok.line, tok.col,
                                       f"High-entropy literal ({entropy:.2f} bits/char, {len(value)} chars) "
                                       f"may be an embedded key: \"{mask(value)}\".",
                                       evidence=f"entropy={entropy:.2f}, char classes={classes}",
                                       subject="high-entropy string", token=tok, confidence="low")


class DangerousFunctionNameRule(Rule):
    meta = RuleMeta(
        id="LEX003", name="Dangerous function referenced", level="lexical", severity="high",
        category="Unsafe API", cwe="CWE-676",
        description="An identifier token names a C library function that is known to be unsafe.",
        recommendation="Replace the function with its bounded or safer alternative.",
        detects="IDENTIFIER ∈ unsafe-function list (gets, strcpy, sprintf, system, …)",
    )

    def check(self, ctx: LexicalContext) -> Iterable[Finding]:
        toks = ctx.tokens
        for i, tok in enumerate(toks):
            if tok.type != TokenType.IDENTIFIER:
                continue
            self.examined += 1
            info = DANGEROUS_FUNCTIONS.get(tok.lexeme)
            if info is None:
                continue
            nxt = toks[i + 1] if i + 1 < len(toks) else None
            is_call = nxt is not None and nxt.is_op("(")
            yield self.finding(
                ctx, tok.line, tok.col,
                f"'{tok.lexeme}' {info['why']}." + ("" if is_call else " (referenced without a direct call)"),
                severity=info["severity"], cwe=info["cwe"],
                recommendation=f"Use {info['use']} instead of {tok.lexeme}().",
                evidence=f"IDENTIFIER('{tok.lexeme}') followed by {repr(nxt.lexeme) if nxt else 'EOF'}",
                subject=tok.lexeme, token=tok, confidence="medium",
            )


SUSPICIOUS_IDENT = re.compile(
    r"(?i)(backdoor|bypass|skip_?auth|no_?auth|disable_?(auth|security|ssl|tls|check|verify)|"
    r"debug_?(mode|login|pass|user)|master_?(key|pass(word)?)|god_?mode|hidden_?(user|admin|cmd|command)|"
    r"magic_?(key|pass(word)?|number)|secret_?(cmd|command|login)|test_?pass(word)?|insecure|"
    r"no_?verify|allow_?all|root_?shell|admin_?override)"
)


class SuspiciousIdentifierRule(Rule):
    meta = RuleMeta(
        id="LEX004", name="Suspicious identifier", level="lexical", severity="medium",
        category="Hidden functionality", cwe="CWE-912",
        description="Identifier names suggest backdoors, debug bypasses or disabled security checks.",
        recommendation="Review the code path; remove debug/bypass logic from production builds.",
        detects="IDENTIFIER ~ /backdoor|bypass|skip_auth|debug_mode|master_key|god_mode|…/",
    )

    def check(self, ctx: LexicalContext) -> Iterable[Finding]:
        seen: dict[str, Token] = {}
        counts: dict[str, int] = {}
        for tok in ctx.tokens:
            if tok.type != TokenType.IDENTIFIER:
                continue
            self.examined += 1
            if SUSPICIOUS_IDENT.search(tok.lexeme):
                counts[tok.lexeme] = counts.get(tok.lexeme, 0) + 1
                seen.setdefault(tok.lexeme, tok)
        for name, tok in seen.items():
            match = SUSPICIOUS_IDENT.search(name)
            yield self.finding(ctx, tok.line, tok.col,
                               f"Identifier '{name}' (matched '{match.group(0)}') appears {counts[name]} time(s); "
                               "such names often mark hidden or debug-only access paths.",
                               evidence=f"IDENTIFIER('{name}') ~ /{match.group(0)}/", subject=name, token=tok,
                               confidence="low")


SECURITY_WORDS = re.compile(
    r"(?i)(password|passwd|credential|secret|auth|login|security|insecure|vuln|overflow|injection|bypass|"
    r"hard-?coded|crypto|encrypt|validate|sanitiz|unsafe|backdoor|exploit|privilege|root)"
)
MARKERS = re.compile(r"\b(TODO|FIXME|HACK|XXX|BUG)\b")
LEAK_IN_COMMENT = re.compile(r"(?i)(password|passwd|pwd|secret|api[_ ]?key|token)\s*(is|=|:)\s*\S{3,}")


class SensitiveCommentRule(Rule):
    meta = RuleMeta(
        id="LEX005", name="Security-relevant comment", level="lexical", severity="low",
        category="Information exposure", cwe="CWE-615",
        description="Comments reveal unfinished security work or contain sensitive values.",
        recommendation="Resolve the noted issue and strip sensitive information from comments.",
        detects="COMMENT ~ /TODO|FIXME|HACK/ ∧ security keyword   — or —   COMMENT ~ /password\\s*[:=]\\s*\\S+/",
    )

    def check(self, ctx: LexicalContext) -> Iterable[Finding]:
        for tok in ctx.tokens:
            if tok.type != TokenType.COMMENT:
                continue
            self.examined += 1
            text = str(tok.value or "")
            leak = LEAK_IN_COMMENT.search(text)
            if leak:
                yield self.finding(ctx, tok.line, tok.col,
                                   f"Comment appears to disclose a secret ('{leak.group(0)[:40]}').",
                                   severity="medium", evidence=f"COMMENT ~ /{leak.group(1)} …/",
                                   subject="secret in comment", token=tok)
                continue
            marker, word = MARKERS.search(text), SECURITY_WORDS.search(text)
            if marker and word:
                yield self.finding(ctx, tok.line, tok.col,
                                   f"{marker.group(0)} note mentions '{word.group(0)}': "
                                   f"\"{text[:70]}{'…' if len(text) > 70 else ''}\"",
                                   evidence=f"COMMENT contains {marker.group(0)} + '{word.group(0)}'",
                                   subject=marker.group(0), token=tok, confidence="medium",
                                   cwe="CWE-546")


IPV4 = re.compile(r"\b((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)\b")
HTTP_URL = re.compile(r"\bhttp://[^\s\"']+", re.I)


class NetworkLiteralRule(Rule):
    meta = RuleMeta(
        id="LEX006", name="Hard-coded network endpoint", level="lexical", severity="low",
        category="Configuration", cwe="CWE-319",
        description="A string literal hard-codes an IP address or a plaintext http:// URL.",
        recommendation="Use HTTPS/TLS and move endpoints into configuration.",
        detects="STRING_LITERAL ~ /http:\\/\\// or IPv4 dotted quad (loopback/any excluded)",
    )

    def check(self, ctx: LexicalContext) -> Iterable[Finding]:
        for tok, value in string_values(ctx):
            self.examined += 1
            url = HTTP_URL.search(value)
            if url and not re.match(r"(?i)http://(localhost|127\.0\.0\.1)", url.group(0)):
                yield self.finding(ctx, tok.line, tok.col,
                                   f"Plaintext URL '{url.group(0)[:60]}' sends data without encryption.",
                                   evidence="STRING_LITERAL ~ /http:\\/\\//", subject=url.group(0)[:60], token=tok)
                continue
            ip = IPV4.search(value)
            if ip and ip.group(0) not in ("127.0.0.1", "0.0.0.0", "255.255.255.255"):
                yield self.finding(ctx, tok.line, tok.col,
                                   f"Hard-coded IP address {ip.group(0)} ties the program to a fixed host.",
                                   severity="info", cwe="CWE-547", evidence="STRING_LITERAL ~ IPv4",
                                   subject=ip.group(0), token=tok, confidence="medium")


def mask(secret: str) -> str:
    if len(secret) <= 4:
        return secret[0] + "*" * (len(secret) - 1) if secret else ""
    return secret[:2] + "*" * min(len(secret) - 4, 12) + secret[-2:]


LEXICAL_RULES = [
    HardcodedCredentialRule, SecretLiteralRule, DangerousFunctionNameRule,
    SuspiciousIdentifierRule, SensitiveCommentRule, NetworkLiteralRule,
]
