"""Module 2 — Syntax / AST Security Analyzer.

These rules match structural patterns in the AST (calls, arguments,
assignments, conditions, loops) and consult the semantic symbol table for
buffer sizes and input-derived data. Knowing the structure lets them separate
a real call from a mere mention and judge the actual arguments.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional

from .. import ast_nodes as A
from .base import (DANGEROUS_FUNCTIONS, AstContext, Finding, Rule, RuleMeta, describe, is_credential_name,
                   looks_like_secret_value, shannon_entropy)
from .lexical_rules import mask


def call_args(call: A.Call, index: int) -> Optional[A.Node]:
    return call.args[index] if index < len(call.args) else None


def strip_casts(node: Optional[A.Node]) -> Optional[A.Node]:
    while isinstance(node, A.Cast):
        node = node.expr
    return node


def is_null(node: Optional[A.Node]) -> bool:
    node = strip_casts(node)
    return (isinstance(node, A.Identifier) and node.name == "NULL") or \
        (isinstance(node, A.IntLiteral) and node.value == 0)


# --------------------------------------------------------------------- AST001
class UnsafeBufferFunctionRule(Rule):
    meta = RuleMeta(
        id="AST001", name="Unsafe buffer operation", level="ast", severity="high",
        category="Buffer overflow", cwe="CWE-120",
        description="Call to a string/buffer function that performs no bounds checking.",
        recommendation="Use a bounded alternative and pass the destination size explicitly.",
        detects="Call(callee ∈ {gets, strcpy, strcat, sprintf, vsprintf, …}) + destination size from symbol table",
    )
    TARGETS = {"gets", "strcpy", "strcat", "sprintf", "vsprintf", "wcscpy", "wcscat", "stpcpy"}

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for call in ctx.calls():
            self.examined += 1
            name = call.func_name
            if name not in self.TARGETS:
                continue
            info = DANGEROUS_FUNCTIONS[name]
            dest = call_args(call, 0)
            dest_size = ctx.buffer_size(dest)
            size_txt = f" (destination '{A.root_identifier(dest)}' holds {dest_size} bytes)" if dest_size else ""
            rec = f"Replace {name}() with {info['use']}."
            evidence = describe(call, ctx)
            if name == "gets":
                yield self.finding(ctx, call.line, call.col,
                                   f"gets() {info['why']}{size_txt}. Any input line longer than the buffer "
                                   "overwrites adjacent stack memory.",
                                   severity="critical", cwe="CWE-242", evidence=evidence, subject=name,
                                   node=call, recommendation=rec)
                continue
            src = call_args(call, 1)
            severity, msg, confidence = "high", f"{name}() {info['why']}{size_txt}.", "high"
            tainted, why = ctx.sem.is_tainted(src) if name in ("strcpy", "strcat", "wcscpy", "wcscat", "stpcpy") \
                else (False, "")
            if name in ("sprintf", "vsprintf"):
                for arg in call.args[2:]:
                    tainted, why = ctx.sem.is_tainted(arg)
                    if tainted:
                        break
            literal = A.literal_string(src)
            if name in ("strcpy", "stpcpy") and literal is not None and dest_size is not None:
                need = len(literal) + 1
                if need > dest_size:
                    severity = "critical"
                    msg = (f"Definite overflow: {name}() copies {need} bytes (\"{literal[:20]}\" + NUL) into "
                           f"'{A.root_identifier(dest)}', which holds only {dest_size} bytes.")
                    cwe = "CWE-787"
                    yield self.finding(ctx, call.line, call.col, msg, severity=severity, cwe=cwe, evidence=evidence,
                                       subject=name, node=call, recommendation=rec)
                    continue
                severity, confidence = "low", "medium"
                msg = (f"{name}() copies a {need}-byte literal into a {dest_size}-byte buffer: safe today, "
                       "but it breaks silently if either side changes.")
            elif tainted:
                severity = "critical"
                msg = f"{name}() writes input-derived data ({why}) into a fixed buffer without a length check{size_txt}."
            elif name in ("strcpy", "strcat"):
                src_size = ctx.buffer_size(src)
                if src_size is not None and dest_size is not None and src_size > dest_size:
                    msg = (f"Source buffer '{A.root_identifier(src)}' ({src_size} bytes) is larger than the "
                           f"destination '{A.root_identifier(dest)}' ({dest_size} bytes).")
            yield self.finding(ctx, call.line, call.col, msg, severity=severity, evidence=evidence, subject=name,
                               node=call, confidence=confidence, recommendation=rec, cwe=info["cwe"])


# --------------------------------------------------------------------- AST002
FORMAT_INDEX = {"printf": 0, "vprintf": 0, "wprintf": 0, "fprintf": 1, "vfprintf": 1, "dprintf": 1,
                "sprintf": 1, "vsprintf": 1, "snprintf": 2, "vsnprintf": 2, "syslog": 1, "err": 1,
                "errx": 1, "warn": 0, "warnx": 0, "fwprintf": 1}
CONVERSION = re.compile(r"%(?:%|[-+ #0]*(\*|\d+)?(?:\.(\*|\d+))?(?:hh|h|ll|l|j|z|t|L)?([diouxXeEfFgGaAcspn]))")


def count_conversions(fmt: str) -> tuple[int, bool]:
    """Number of arguments a printf-style format consumes, and whether it uses %n."""
    count, uses_n = 0, False
    for m in CONVERSION.finditer(fmt):
        if m.group(0) == "%%":
            continue
        count += 1 + (m.group(1) == "*") + (m.group(2) == "*")
        uses_n |= m.group(3) == "n"
    return count, uses_n


class FormatStringRule(Rule):
    meta = RuleMeta(
        id="AST002", name="Format string vulnerability", level="ast", severity="high",
        category="Format string", cwe="CWE-134",
        description="A printf-family function receives a non-literal format string, or the format and "
                    "argument list do not agree.",
        recommendation="Always use a constant format string, e.g. printf(\"%s\", msg).",
        detects="Call(printf-family, args[fmt_index] ≠ StringLiteral)  ·  count(%conversions) ≠ count(args)",
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for call in ctx.calls():
            self.examined += 1
            idx = FORMAT_INDEX.get(call.func_name)
            if idx is None:
                continue
            fmt_node = call_args(call, idx)
            if fmt_node is None:
                continue
            fmt = A.literal_string(fmt_node)
            if fmt is None:
                sym = ctx.sem.symbol_for(fmt_node)
                if sym is not None and sym.is_const and sym.literal_init is not None:
                    continue  # const char *fmt = "..." — effectively a literal
                tainted, why = ctx.sem.is_tainted(fmt_node)
                if call.func_name.startswith("v") and not tainted:
                    continue  # v*printf wrappers legitimately forward a format parameter
                severity = "critical" if tainted else "high"
                detail = f" The format comes from input ({why})." if tainted else ""
                yield self.finding(
                    ctx, call.line, call.col,
                    f"{call.func_name}() uses a non-constant format string.{detail} Directives such as %x or %n "
                    "in that data can read or write arbitrary memory.",
                    severity=severity, evidence=describe(call, ctx), subject=call.func_name, node=call,
                    recommendation=f"Call {call.func_name}(… \"%s\", value) instead of passing the data as the format.")
                continue
            expected, uses_n = count_conversions(fmt)
            supplied = len(call.args) - idx - 1
            if call.func_name.startswith("v"):
                continue
            if uses_n:
                yield self.finding(ctx, call.line, call.col,
                                   f"Format string uses %n, which writes to memory and is a classic exploitation primitive.",
                                   severity="medium", evidence=f"format {fmt[:40]!r} contains %n", subject="%n",
                                   node=call, recommendation="Remove %n; compute lengths with the return value.")
            if expected != supplied:
                yield self.finding(
                    ctx, call.line, call.col,
                    f"{call.func_name}() format expects {expected} argument(s) but {supplied} supplied — "
                    + ("missing arguments make it read garbage from the stack." if expected > supplied
                       else "extra arguments are ignored."),
                    severity="medium" if expected > supplied else "low", cwe="CWE-685",
                    title="Format/argument count mismatch", evidence=f"conversions={expected}, args={supplied}",
                    subject=call.func_name, node=call,
                    recommendation="Make every conversion specifier match exactly one argument.")


# --------------------------------------------------------------------- AST003
COMMAND_FUNCS = {"system": 0, "popen": 0, "_popen": 0, "_wsystem": 0, "WinExec": 0, "execl": 0,
                 "execlp": 0, "execle": 0, "execv": 0, "execvp": 0, "execve": 0, "execvpe": 0}


class CommandInjectionRule(Rule):
    meta = RuleMeta(
        id="AST003", name="OS command injection", level="ast", severity="high",
        category="Injection", cwe="CWE-78",
        description="A command execution function receives a command built at runtime.",
        recommendation="Avoid the shell; call execve() with a fixed program path and validated arguments, "
                       "or strictly allow-list user input.",
        detects="Call(callee ∈ {system, popen, exec*}, args[0] ≠ StringLiteral) + input tagging",
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for call in ctx.calls():
            self.examined += 1
            idx = COMMAND_FUNCS.get(call.func_name)
            if idx is None:
                continue
            cmd = call_args(call, idx)
            shell = call.func_name in ("system", "popen", "_popen", "_wsystem", "WinExec")
            literal = A.literal_string(cmd)
            if literal is not None:
                if shell:
                    yield self.finding(ctx, call.line, call.col,
                                       f"{call.func_name}(\"{literal[:40]}\") starts a shell with a fixed command; "
                                       "it still depends on PATH and the environment.",
                                       severity="low", evidence=describe(call, ctx), subject=call.func_name,
                                       node=call, confidence="medium")
                continue
            tainted, why = False, ""
            for arg in call.args[idx:]:
                tainted, why = ctx.sem.is_tainted(arg)
                if tainted:
                    break
            if tainted:
                severity = "critical"
                impact = ("Shell metacharacters such as ';', '|' or '$( )' let an attacker run arbitrary commands."
                          if shell else "An attacker can choose which program is executed and with what arguments.")
                msg = f"{call.func_name}() executes a command containing input-derived data ({why}). {impact}"
            else:
                severity = "high" if shell else "medium"
                msg = f"{call.func_name}() executes a command assembled at runtime; verify that no part is attacker-controlled."
            yield self.finding(ctx, call.line, call.col, msg, severity=severity, evidence=describe(call, ctx),
                               subject=call.func_name, node=call)


# --------------------------------------------------------------------- AST004
SCANF_FMT = {"scanf": 0, "fscanf": 1, "sscanf": 1, "vscanf": 0}
UNBOUNDED_SCAN = re.compile(r"%(?!\d)(\*?)(l?)(s|\[)")
SIZED_READERS = {"fgets": (0, 1), "read": (1, 2), "recv": (1, 2), "fread": (0, 2), "getline": None,
                 "memset": (0, 2), "snprintf": (0, 1), "vsnprintf": (0, 1)}


class UnboundedInputRule(Rule):
    meta = RuleMeta(
        id="AST004", name="Unbounded or oversized input read", level="ast", severity="high",
        category="Input handling", cwe="CWE-120",
        description="Input is read with no length limit, or with a limit larger than the destination buffer.",
        recommendation="Give every %s a field width and pass sizeof(buffer) as the size argument.",
        detects="Call(scanf-family, fmt contains %s without width)  ·  Call(fgets/read/recv, size > sizeof(dest))",
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for call in ctx.calls():
            self.examined += 1
            name = call.func_name
            if name in SCANF_FMT:
                fmt = A.literal_string(call_args(call, SCANF_FMT[name]))
                if fmt is None:
                    continue
                for m in UNBOUNDED_SCAN.finditer(fmt):
                    if m.group(1) == "*":
                        continue  # assignment suppressed
                    yield self.finding(
                        ctx, call.line, call.col,
                        f"{name}() reads '%{m.group(2)}{m.group(3)}' with no field width; input longer than the "
                        "destination buffer overflows it.",
                        evidence=f"format {fmt[:40]!r} — conversion '{m.group(0)}' has no width",
                        subject=name, node=call,
                        recommendation='Specify a width one less than the buffer size, e.g. "%31s" for char[32].')
                    break
                continue
            spec = SIZED_READERS.get(name)
            if not spec:
                continue
            dest_i, size_i = spec
            dest, size_node = call_args(call, dest_i), call_args(call, size_i)
            dest_size, size = ctx.buffer_size(dest), ctx.const_eval(size_node)
            if dest_size is None or size is None or size <= dest_size:
                continue
            title = "Size argument exceeds buffer" if name in ("memset", "snprintf", "vsnprintf") else None
            yield self.finding(
                ctx, call.line, call.col,
                f"{name}() is told it may write {size} bytes into '{A.root_identifier(dest)}', which holds only "
                f"{dest_size} bytes.",
                cwe="CWE-787", evidence=describe(call, ctx), subject=name, node=call, title=title,
                recommendation=f"Pass sizeof({A.root_identifier(dest)}) as the size argument.")


# --------------------------------------------------------------------- AST005
COMPARE_FUNCS = {"strcmp", "strncmp", "strcasecmp", "strncasecmp", "memcmp", "_stricmp", "stricmp", "wcscmp"}


class HardcodedCredentialAstRule(Rule):
    meta = RuleMeta(
        id="AST005", name="Hard-coded credential in logic", level="ast", severity="high",
        category="Credentials", cwe="CWE-798",
        description="A credential is compared against, or initialised from, a string literal.",
        recommendation="Verify secrets against a salted hash stored outside the code (e.g. bcrypt/argon2), "
                       "and compare in constant time.",
        detects="Call(strcmp-family, credential-like Identifier, StringLiteral) · VarDecl/Assignment(credential-like, StringLiteral)",
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for node in ctx.ast.walk():
            self.examined += 1
            if isinstance(node, A.Call) and node.func_name in COMPARE_FUNCS and len(node.args) >= 2:
                a, b = node.args[0], node.args[1]
                for var, lit in ((a, b), (b, a)):
                    literal = A.literal_string(lit)
                    name = A.root_identifier(var) or (var.field_name if isinstance(var, A.Member) else "")
                    if isinstance(var, A.Member):
                        name = var.field_name
                    if literal is None or not looks_like_secret_value(literal):
                        continue
                    in_condition = any(isinstance(anc, (A.If, A.While, A.Conditional, A.Return)) for anc in node.ancestors())
                    if is_credential_name(name) or (in_condition and shannon_entropy(literal) >= 3.0 and len(literal) >= 8):
                        yield self.finding(
                            ctx, node.line, node.col,
                            f"'{name}' is checked against the hard-coded value \"{mask(literal)}\" with "
                            f"{node.func_name}(); the secret is embedded in the binary and the comparison leaks timing.",
                            evidence=describe(node, ctx), subject=name, node=node)
                        break
            elif isinstance(node, A.VarDecl) and is_credential_name(node.name):
                literal = A.literal_string(node.init)
                if literal is not None and looks_like_secret_value(literal):
                    yield self.finding(ctx, node.line, node.col,
                                       f"Variable '{node.name}' is initialised with the hard-coded secret "
                                       f"\"{mask(literal)}\".",
                                       evidence=f"VarDecl({node.type} {node.name}, init={describe(node.init, ctx)})",
                                       subject=node.name, node=node)
            elif isinstance(node, A.Assignment) and node.op == "=":
                name = A.root_identifier(node.target) or (node.target.field_name if isinstance(node.target, A.Member) else "")
                if isinstance(node.target, A.Member):
                    name = node.target.field_name
                literal = A.literal_string(node.value)
                if is_credential_name(name) and literal is not None and looks_like_secret_value(literal):
                    yield self.finding(ctx, node.line, node.col,
                                       f"'{name}' is assigned the hard-coded secret \"{mask(literal)}\".",
                                       evidence=describe(node, ctx), subject=name, node=node)
            elif isinstance(node, A.BinaryOp) and node.op in ("==", "!="):
                for var, lit in ((node.left, node.right), (node.right, node.left)):
                    name = A.root_identifier(var) or ""
                    if isinstance(lit, A.IntLiteral) and is_credential_name(name) and abs(lit.value) >= 100:
                        yield self.finding(ctx, node.line, node.col,
                                           f"'{name}' is compared with the hard-coded numeric secret {lit.raw}.",
                                           severity="medium", evidence=describe(node, ctx), subject=name, node=node)
                        break


# --------------------------------------------------------------------- AST006
WEAK_RNG = {"rand", "random", "drand48", "lrand48", "mrand48", "rand_r"}
SECURITY_NAME = re.compile(r"(?i)(token|key|session|nonce|salt|otp|pass|secret|iv|seed|uuid|auth|cookie|pin)")


class InsecureRandomRule(Rule):
    meta = RuleMeta(
        id="AST006", name="Insecure randomness", level="ast", severity="medium",
        category="Cryptography", cwe="CWE-338",
        description="A non-cryptographic PRNG (or a predictable seed) is used.",
        recommendation="Use a CSPRNG such as getrandom(), arc4random_buf() or /dev/urandom for security values.",
        detects="Call(rand/random/…)  ·  Call(srand, args=[Call(time) | constant])",
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for call in ctx.calls():
            self.examined += 1
            if call.func_name in WEAK_RNG:
                target = self.assigned_name(call)
                if target and SECURITY_NAME.search(target):
                    yield self.finding(ctx, call.line, call.col,
                                       f"{call.func_name}() output feeds the security-sensitive value '{target}'; "
                                       "its sequence is predictable once a few outputs or the seed are known.",
                                       severity="high", evidence=describe(call, ctx), subject=call.func_name, node=call)
                else:
                    yield self.finding(ctx, call.line, call.col,
                                       f"{call.func_name}() is not cryptographically secure; do not use it for "
                                       "tokens, keys or anything an attacker must not guess.",
                                       severity="low", evidence=describe(call, ctx), subject=call.func_name, node=call,
                                       confidence="medium")
            elif call.func_name in ("srand", "srandom", "srand48") and call.args:
                seed = strip_casts(call.args[0])
                if isinstance(seed, A.Call) and seed.func_name in ("time", "clock", "getpid"):
                    yield self.finding(ctx, call.line, call.col,
                                       f"PRNG seeded with {seed.func_name}(), which an attacker can guess within a "
                                       "small window.", cwe="CWE-337", title="Predictable PRNG seed",
                                       evidence=describe(call, ctx), subject=call.func_name, node=call)
                elif ctx.const_eval(seed) is not None:
                    yield self.finding(ctx, call.line, call.col,
                                       "PRNG seeded with a constant: every run produces the same sequence.",
                                       cwe="CWE-336", title="Constant PRNG seed", evidence=describe(call, ctx),
                                       subject=call.func_name, node=call)

    @staticmethod
    def assigned_name(call: A.Call) -> str:
        for anc in call.ancestors():
            if isinstance(anc, A.Assignment):
                return A.root_identifier(anc.target) or (anc.target.field_name if isinstance(anc.target, A.Member) else "")
            if isinstance(anc, A.VarDecl):
                return anc.name
            if isinstance(anc, A.Node) and isinstance(anc, A.STATEMENT_KINDS):
                return ""
        return ""


# --------------------------------------------------------------------- AST007
ALLOC_FUNCS = {"malloc", "calloc", "realloc", "strdup", "strndup", "aligned_alloc"}


class AllocationRule(Rule):
    meta = RuleMeta(
        id="AST007", name="Unsafe memory allocation", level="ast", severity="medium",
        category="Memory management", cwe="CWE-690",
        description="Allocation results are used without a NULL check, sizes may overflow, "
                    "or realloc() can leak the original block.",
        recommendation="Check every allocation against NULL, use calloc() for n*size, and assign realloc() "
                       "to a temporary pointer.",
        detects="x = malloc(…) with no (x == NULL | !x | if (x)) in the function · malloc(a * b) · p = realloc(p, …)",
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for call in ctx.calls():
            self.examined += 1
            if call.func_name not in ALLOC_FUNCS:
                continue
            func = ctx.enclosing_function(call)
            target_node, target_sym = self.target_of(call, ctx)
            size_arg = call_args(call, 1 if call.func_name == "realloc" else 0)
            size = strip_casts(size_arg)
            if call.func_name in ("malloc", "realloc") and isinstance(size, A.BinaryOp) and size.op == "*" \
                    and ctx.const_eval(size) is None:
                yield self.finding(ctx, call.line, call.col,
                                   f"Size computed as a multiplication inside {call.func_name}(); if it wraps "
                                   "around, a too-small block is allocated and later writes overflow it.",
                                   cwe="CWE-190", title="Allocation size may overflow", evidence=describe(call, ctx),
                                   subject=call.func_name, node=call,
                                   recommendation="Use calloc(n, size) or check n <= SIZE_MAX / size first.")
            tainted, why = ctx.sem.is_tainted(size_arg)
            if tainted:
                yield self.finding(ctx, call.line, call.col,
                                   f"Allocation size is input-derived ({why}); an attacker controls how much memory is requested.",
                                   cwe="CWE-789", title="Uncontrolled allocation size", evidence=describe(call, ctx),
                                   subject=call.func_name, node=call,
                                   recommendation="Validate the requested size against an upper bound.")
            if call.func_name == "realloc" and target_sym is not None and \
                    A.root_identifier(call_args(call, 0)) == target_sym.name:
                yield self.finding(ctx, call.line, call.col,
                                   f"'{target_sym.name} = realloc({target_sym.name}, …)' loses the original pointer "
                                   "when realloc() fails, leaking memory.",
                                   severity="low", cwe="CWE-401", title="realloc() may leak memory",
                                   evidence=describe(call.parent, ctx), subject="realloc", node=call,
                                   recommendation="Assign to a temporary, check it, then replace the original pointer.")
            if target_sym is None or func is None:
                continue
            if not self.null_checked(func, target_sym, ctx):
                yield self.finding(ctx, call.line, call.col,
                                   f"Result of {call.func_name}() stored in '{target_sym.name}' is never compared "
                                   f"with NULL in {func.name}(); a failed allocation leads to a NULL dereference.",
                                   evidence=describe(target_node, ctx) if target_node else describe(call, ctx),
                                   subject=target_sym.name, node=call, confidence="medium")

    @staticmethod
    def target_of(call: A.Call, ctx: AstContext):
        parent = call.parent
        while isinstance(parent, A.Cast):
            parent = parent.parent
        if isinstance(parent, A.Assignment) and parent.op == "=":
            return parent, ctx.sem.symbol_for(parent.target)
        if isinstance(parent, A.VarDecl):
            for sym in ctx.sem.symbols:
                if sym.node_id == parent.id:
                    return parent, sym
        return None, None

    @staticmethod
    def null_checked(func: A.FunctionDef, sym, ctx: AstContext) -> bool:
        def refers(node: Optional[A.Node]) -> bool:
            node = strip_casts(node)
            return isinstance(node, A.Identifier) and ctx.sem.resolved.get(node.id) is sym

        for node in func.walk():
            if isinstance(node, A.BinaryOp) and node.op in ("==", "!="):
                if (refers(node.left) and is_null(node.right)) or (refers(node.right) and is_null(node.left)):
                    return True
            if isinstance(node, A.UnaryOp) and node.op == "!" and refers(node.operand):
                return True
            if isinstance(node, (A.If, A.While, A.Conditional)) and refers(node.cond):
                return True
            if isinstance(node, A.BinaryOp) and node.op in ("&&", "||") and (refers(node.left) or refers(node.right)):
                return True
            if isinstance(node, A.Call) and node.func_name == "assert" and node.args and refers(node.args[0]):
                return True
        return False


# --------------------------------------------------------------------- AST008
class ConstantIndexOutOfBoundsRule(Rule):
    meta = RuleMeta(
        id="AST008", name="Out-of-bounds array index", level="ast", severity="high",
        category="Buffer overflow", cwe="CWE-787",
        description="A constant index lies outside the declared bounds of a fixed-size array.",
        recommendation="Valid indices for T a[N] are 0 … N-1; fix the index or the declared size.",
        detects="Index(Identifier(a : T[N]), k) where const_eval(k) ∉ [0, N)",
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for node in ctx.ast.walk():
            if not isinstance(node, A.Index):
                continue
            self.examined += 1
            if not isinstance(node.array, A.Identifier):
                continue
            size = ctx.buffer_size(node.array)
            index = ctx.const_eval(node.index)
            if size is None or index is None or 0 <= index < size:
                continue
            is_write = isinstance(node.parent, A.Assignment) and node.parent.target is node
            yield self.finding(
                ctx, node.line, node.col,
                f"{'Write to' if is_write else 'Read of'} {node.array.name}[{index}] but '{node.array.name}' has "
                f"{size} elements (valid indices 0…{size - 1}).",
                cwe="CWE-787" if is_write else "CWE-125", evidence=describe(node, ctx), subject=node.array.name,
                node=node, title="Out-of-bounds write" if is_write else "Out-of-bounds read")


# --------------------------------------------------------------------- AST009
class OffByOneLoopRule(Rule):
    meta = RuleMeta(
        id="AST009", name="Loop bound exceeds array size", level="ast", severity="high",
        category="Buffer overflow", cwe="CWE-193",
        description="A loop indexes an array with a counter whose bound reaches past the end of the array.",
        recommendation="Use 'i < N' (not 'i <= N') and derive N from the array, e.g. sizeof a / sizeof a[0].",
        detects="For(cond=BinaryOp('<=' | '<', i, C), body ∋ Index(a : T[N], i)) where C ≥ N (or C+1 > N for '<=')",
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for loop in ctx.ast.walk():
            if not isinstance(loop, (A.For, A.While)):
                continue
            self.examined += 1
            cond = loop.cond
            if not isinstance(cond, A.BinaryOp) or cond.op not in ("<", "<=") or not isinstance(cond.left, A.Identifier):
                continue
            bound = ctx.const_eval(cond.right)
            if bound is None:
                continue
            last = bound if cond.op == "<=" else bound - 1
            counter = cond.left.name
            reported: set[str] = set()
            for node in loop.body.walk() if loop.body else []:
                if not (isinstance(node, A.Index) and isinstance(node.array, A.Identifier)
                        and isinstance(node.index, A.Identifier) and node.index.name == counter):
                    continue
                size = ctx.buffer_size(node.array)
                if size is None or last < size or node.array.name in reported:
                    continue
                reported.add(node.array.name)
                off_by_one = cond.op == "<=" and bound == size
                yield self.finding(
                    ctx, loop.line, loop.col,
                    (f"Off-by-one: loop runs while {counter} <= {bound}, so {node.array.name}[{bound}] is accessed "
                     f"but '{node.array.name}' has only {size} elements.") if off_by_one else
                    (f"Loop counter '{counter}' reaches {last}, past the end of '{node.array.name}' "
                     f"({size} elements)."),
                    cwe="CWE-193" if off_by_one else "CWE-787", evidence=f"{describe(cond, ctx)} ⟶ {describe(node, ctx)}",
                    subject=node.array.name, node=node,
                    title="Off-by-one loop bound" if off_by_one else "Loop bound exceeds array size")


# --------------------------------------------------------------------- AST010
class UseAfterFreeRule(Rule):
    meta = RuleMeta(
        id="AST010", name="Use after free / double free", level="ast", severity="high",
        category="Memory management", cwe="CWE-416",
        description="A pointer is used or freed again after free() in the same block, without being reassigned.",
        recommendation="Set the pointer to NULL right after free() and do not touch it again.",
        detects="Within one function, in source order: Call(free, p) … use(p) with no 'p = …' in between "
                "(free must dominate the use lexically)",
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for func in ctx.ast.walk():
            if not isinstance(func, A.FunctionDef) or func.body is None:
                continue
            self.examined += 1
            events = []  # (line, col, order, kind, sym, node, block)
            order = 0
            for node in func.body.walk():
                order += 1
                if isinstance(node, A.Call) and node.func_name == "free" and node.args:
                    sym = ctx.sem.symbol_for(node.args[0])
                    if sym is not None and isinstance(strip_casts(node.args[0]), A.Identifier):
                        events.append((node.line, node.col, order, "free", sym, node))
                elif isinstance(node, A.Assignment):
                    sym = ctx.sem.symbol_for(node.target) if isinstance(node.target, A.Identifier) else None
                    if sym is not None:
                        events.append((node.line, node.col, order, "assign", sym, node))
                elif isinstance(node, A.Identifier):
                    sym = ctx.sem.resolved.get(node.id)
                    if sym is None or self.is_free_arg(node) or self.is_assign_target(node) or self.in_sizeof(node):
                        continue
                    events.append((node.line, node.col, order, "use", sym, node))
            freed: dict[int, A.Call] = {}
            reported: set[int] = set()
            for _, _, _, kind, sym, node in sorted(events, key=lambda e: (e[0], e[1], e[2])):
                key = id(sym)
                if kind == "assign":
                    if self.dominates(freed.get(key), node):
                        freed.pop(key, None)
                    continue
                if kind == "free":
                    prev = freed.get(key)
                    if prev is not None and self.dominates(prev, node) and key not in reported:
                        reported.add(key)
                        yield self.finding(ctx, node.line, node.col,
                                           f"'{sym.name}' is freed again (first freed on line {prev.line}); double "
                                           "free corrupts the allocator and is often exploitable.",
                                           cwe="CWE-415", title="Double free", evidence=describe(node, ctx),
                                           subject=sym.name, node=node)
                    else:
                        freed[key] = node
                    continue
                prev = freed.get(key)
                if prev is not None and self.dominates(prev, node) and key not in reported:
                    reported.add(key)
                    yield self.finding(ctx, node.line, node.col,
                                       f"'{sym.name}' is used after being freed on line {prev.line}; the memory may "
                                       "already belong to another allocation.",
                                       title="Use after free", evidence=f"free({sym.name}) @L{prev.line} ⟶ "
                                       f"{describe(node.parent, ctx)} @L{node.line}", subject=sym.name, node=node)

    @staticmethod
    def is_free_arg(node: A.Identifier) -> bool:
        parent = node.parent
        while isinstance(parent, A.Cast):
            parent = parent.parent
        return isinstance(parent, A.Call) and parent.func_name == "free"

    @staticmethod
    def is_assign_target(node: A.Identifier) -> bool:
        return isinstance(node.parent, A.Assignment) and node.parent.target is node and node.parent.op == "="

    @staticmethod
    def in_sizeof(node: A.Node) -> bool:
        return any(isinstance(a, A.SizeOf) for a in node.ancestors())

    @staticmethod
    def dominates(free_call: Optional[A.Node], later: A.Node) -> bool:
        """Lexical approximation: the block containing free() must enclose the later node,
        and free() must not be followed by a jump in that block."""
        if free_call is None:
            return False
        stmt = free_call
        while stmt.parent is not None and not isinstance(stmt.parent, A.Compound):
            stmt = stmt.parent
            if isinstance(stmt, (A.If, A.While, A.For, A.DoWhile, A.Switch)):
                return False  # free() is conditional (inside if/loop header-level statement)
        block = stmt.parent
        if block is None:
            return False
        if not any(anc is block for anc in later.ancestors()):
            return False
        idx = block.items.index(stmt) if stmt in block.items else -1
        for item in block.items[idx + 1:]:
            if isinstance(item, (A.Return, A.Break, A.Continue, A.Goto)):
                return False
            if any(anc is item for anc in later.ancestors()) or item is later:
                break
        return True


# --------------------------------------------------------------------- AST011
AUTH_NAME = re.compile(r"(?i)(admin|auth|logged|valid|granted|access|root|priv|allow|perm|is_|verified|trusted)")


class AssignmentInConditionRule(Rule):
    meta = RuleMeta(
        id="AST011", name="Assignment used as condition", level="ast", severity="medium",
        category="Logic error", cwe="CWE-481",
        description="A condition contains '=' where '==' was probably intended; the branch outcome is fixed.",
        recommendation="Use '==' for comparison; if the assignment is intended, compare its result explicitly.",
        detects="If/While/For(cond = Assignment('='))",
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for node in ctx.ast.walk():
            if not isinstance(node, (A.If, A.While, A.DoWhile, A.For)):
                continue
            self.examined += 1
            cond = node.cond
            if not isinstance(cond, A.Assignment) or cond.op != "=":
                continue
            name = A.root_identifier(cond.target) or ""
            value = strip_casts(cond.value)
            if isinstance(value, A.Call):
                yield self.finding(ctx, cond.line, cond.col,
                                   f"Condition assigns the result of {value.func_name or 'a call'}() to '{name}'. "
                                   "This is a common idiom but easy to misread; compare explicitly.",
                                   severity="info", evidence=describe(cond, ctx), subject=name, node=cond,
                                   confidence="low")
                continue
            constant = ctx.const_eval(value)
            critical = AUTH_NAME.search(name) is not None
            outcome = ""
            if constant is not None:
                outcome = f" The condition is always {'true' if constant else 'false'}."
            yield self.finding(
                ctx, cond.line, cond.col,
                (f"'{name} = …' inside a condition overwrites the security flag '{name}' instead of testing it — "
                 f"a classic authorization bypass.{outcome}") if critical else
                f"Assignment '{name} = …' used as a condition; '==' was probably intended.{outcome}",
                severity="high" if critical else "medium", evidence=describe(cond, ctx), subject=name, node=cond,
                title="Authorization check overwritten" if critical else None)


# --------------------------------------------------------------------- AST012
class InsecureTempFileRule(Rule):
    meta = RuleMeta(
        id="AST012", name="Race-prone file handling", level="ast", severity="medium",
        category="Race condition", cwe="CWE-377",
        description="Predictable temporary file names, or a check-then-use (access → open) sequence on a path.",
        recommendation="Use mkstemp()/tmpfile(); open the file first and then check it with fstat().",
        detects="Call(tmpnam | tempnam | mktemp)  ·  Call(access, p) followed by Call(open | fopen, p)",
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for func in ctx.ast.walk():
            if not isinstance(func, A.FunctionDef):
                continue
            checked: dict[str, A.Call] = {}
            for call in (n for n in func.walk() if isinstance(n, A.Call)):
                self.examined += 1
                name = call.func_name
                if name in ("tmpnam", "tempnam", "mktemp"):
                    yield self.finding(ctx, call.line, call.col,
                                       f"{name}() returns a predictable name; another process can create that "
                                       "file first (symlink attack) between name generation and open().",
                                       evidence=describe(call, ctx), subject=name, node=call)
                elif name in ("access", "stat", "lstat") and call.args:
                    checked[self.key(call.args[0])] = call
                elif name in ("open", "fopen", "creat", "freopen", "chmod", "chown", "unlink") and call.args:
                    prev = checked.get(self.key(call.args[0]))
                    if prev is not None and prev.line <= call.line:
                        yield self.finding(ctx, call.line, call.col,
                                           f"Path checked with {prev.func_name}() on line {prev.line} and then used "
                                           f"by {name}(); the file can be swapped in between (TOCTOU).",
                                           cwe="CWE-367", title="Time-of-check / time-of-use race",
                                           evidence=f"{describe(prev, ctx)} ⟶ {describe(call, ctx)}",
                                           subject=name, node=call)

    @staticmethod
    def key(node: A.Node) -> str:
        literal = A.literal_string(node)
        return f"lit:{literal}" if literal is not None else f"id:{A.root_identifier(node)}"


# --------------------------------------------------------------------- AST013
COPY_FUNCS = {"memcpy": (0, 2), "memmove": (0, 2), "strncpy": (0, 2), "strncat": (0, 2), "wmemcpy": (0, 2)}


class CopySizeRule(Rule):
    meta = RuleMeta(
        id="AST013", name="Copy size exceeds destination", level="ast", severity="high",
        category="Buffer overflow", cwe="CWE-120",
        description="A bounded copy is given a length larger than the destination, or strncpy() may leave "
                    "the result unterminated.",
        recommendation="Pass sizeof(dest) (minus one for strings) and terminate the string explicitly.",
        detects="Call(memcpy | strncpy | …, dest : T[N], _, n) where const_eval(n) > N",
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for call in ctx.calls():
            self.examined += 1
            spec = COPY_FUNCS.get(call.func_name)
            if spec is None:
                continue
            dest, size_node = call_args(call, spec[0]), call_args(call, spec[1])
            dest_size, size = ctx.buffer_size(dest), ctx.const_eval(size_node)
            if dest_size is None:
                continue
            tainted, why = ctx.sem.is_tainted(size_node)
            if size is not None and size > dest_size:
                yield self.finding(ctx, call.line, call.col,
                                   f"{call.func_name}() copies {size} bytes into '{A.root_identifier(dest)}' "
                                   f"({dest_size} bytes): {size - dest_size} byte(s) overflow.",
                                   cwe="CWE-787", evidence=describe(call, ctx), subject=call.func_name, node=call)
            elif size is None and tainted:
                yield self.finding(ctx, call.line, call.col,
                                   f"{call.func_name}() copy length is input-derived ({why}) and is not "
                                   f"bounded by the {dest_size}-byte destination.",
                                   severity="critical", evidence=describe(call, ctx), subject=call.func_name, node=call)
            elif call.func_name == "strncpy" and size == dest_size:
                yield self.finding(ctx, call.line, call.col,
                                   f"strncpy() with n == sizeof(dest) leaves '{A.root_identifier(dest)}' without a "
                                   "terminating NUL when the source is long enough.",
                                   severity="low", cwe="CWE-170", title="Possible missing NUL terminator",
                                   evidence=describe(call, ctx), subject="strncpy", node=call,
                                   recommendation="Copy sizeof(dest) - 1 bytes and set dest[sizeof dest - 1] = '\\0'.")


# --------------------------------------------------------------------- AST014
class UncheckedConversionRule(Rule):
    meta = RuleMeta(
        id="AST014", name="Unchecked numeric conversion", level="ast", severity="low",
        category="Input validation", cwe="CWE-190",
        description="String-to-number conversion without error detection, especially on input data.",
        recommendation="Use strtol()/strtoul() and check errno, the end pointer and the value range.",
        detects="Call(atoi | atol | atoll | atof, arg) — severity raised when arg is input-derived",
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for call in ctx.calls():
            self.examined += 1
            if call.func_name not in ("atoi", "atol", "atoll", "atof"):
                continue
            tainted, why = ctx.sem.is_tainted(call_args(call, 0))
            yield self.finding(
                ctx, call.line, call.col,
                f"{call.func_name}() converts " + (f"input-derived text ({why}) " if tainted else "text ")
                + "without detecting invalid digits or overflow; the result may be negative or wrapped.",
                severity="medium" if tainted else "low", evidence=describe(call, ctx),
                subject=call.func_name, node=call, cwe="CWE-20" if tainted else "CWE-190")


# --------------------------------------------------------------------- AST015
class InsecurePermissionRule(Rule):
    meta = RuleMeta(
        id="AST015", name="Insecure file permissions", level="ast", severity="medium",
        category="Access control", cwe="CWE-732",
        description="Files are created or changed to be world-writable, or the umask is cleared.",
        recommendation="Grant the minimum mode needed (e.g. 0600 / 0644) and never clear the umask.",
        detects="Call(chmod | fchmod | open | mkdir, mode) with mode & 0o002  ·  Call(umask, 0)",
    )
    MODE_INDEX = {"chmod": 1, "fchmod": 1, "mkdir": 1, "open": 2, "creat": 1, "fchmodat": 2}

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for call in ctx.calls():
            self.examined += 1
            if call.func_name == "umask" and call.args and ctx.const_eval(call.args[0]) == 0:
                yield self.finding(ctx, call.line, call.col,
                                   "umask(0) makes every file created afterwards world-readable and writable.",
                                   evidence=describe(call, ctx), subject="umask", node=call)
                continue
            idx = self.MODE_INDEX.get(call.func_name)
            if idx is None:
                continue
            mode = ctx.const_eval(call_args(call, idx))
            if mode is not None and mode & 0o002:
                yield self.finding(ctx, call.line, call.col,
                                   f"{call.func_name}() uses mode {oct(mode)}, which lets any local user modify the file.",
                                   evidence=describe(call, ctx), subject=call.func_name, node=call)


# --------------------------------------------------------------------- AST016
WEAK_CRYPTO = {
    "MD5": "MD5", "MD5_Init": "MD5", "MD5_Update": "MD5", "MD4": "MD4", "SHA1": "SHA-1", "SHA1_Init": "SHA-1",
    "DES_ecb_encrypt": "DES", "DES_set_key": "DES", "DES_cbc_encrypt": "DES", "RC4": "RC4", "RC4_set_key": "RC4",
    "EVP_md5": "MD5", "EVP_sha1": "SHA-1", "EVP_des_cbc": "DES", "EVP_des_ecb": "DES", "EVP_rc4": "RC4",
    "EVP_aes_128_ecb": "AES-ECB", "EVP_aes_256_ecb": "AES-ECB", "crypt": "DES-based crypt()",
}


class WeakCryptoRule(Rule):
    meta = RuleMeta(
        id="AST016", name="Weak cryptographic algorithm", level="ast", severity="medium",
        category="Cryptography", cwe="CWE-327",
        description="A broken or obsolete cryptographic primitive is called.",
        recommendation="Use SHA-256/SHA-3 for hashing, Argon2/bcrypt for passwords and AES-GCM/ChaCha20-Poly1305 for encryption.",
        detects="Call(callee ∈ {MD5*, SHA1*, DES_*, RC4*, EVP_*_ecb, crypt})",
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for call in ctx.calls():
            self.examined += 1
            algo = WEAK_CRYPTO.get(call.func_name)
            if algo:
                yield self.finding(ctx, call.line, call.col,
                                   f"{call.func_name}() relies on {algo}, which is considered broken for security use.",
                                   evidence=describe(call, ctx), subject=call.func_name, node=call)


AST_RULES = [
    UnsafeBufferFunctionRule, FormatStringRule, CommandInjectionRule, UnboundedInputRule,
    HardcodedCredentialAstRule, InsecureRandomRule, AllocationRule, ConstantIndexOutOfBoundsRule,
    OffByOneLoopRule, UseAfterFreeRule, AssignmentInConditionRule, InsecureTempFileRule, CopySizeRule,
    UncheckedConversionRule, InsecurePermissionRule, WeakCryptoRule,
]
