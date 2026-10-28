"""Module 2 rules for C++.

All C rules also run on C++ code; these add checks for C++-only constructs:
new/delete, iostream extraction, C++ casts and <random> engines.
"""

from __future__ import annotations

from typing import Iterable, Optional

from .. import ast_nodes as A
from .base import AstContext, Finding, Rule, RuleMeta, describe
from .java_rules import simple_type

CPP = ("cpp",)
MALLOC_FAMILY = {"malloc", "calloc", "realloc", "strdup", "strndup"}
RELEASE_FOR = {"new": "delete", "new[]": "delete[]", "malloc": "free"}


def strip_casts(node: Optional[A.Node]) -> Optional[A.Node]:
    while isinstance(node, A.Cast):
        node = node.expr
    return node


def storage_key(node: Optional[A.Node], ctx: AstContext) -> Optional[tuple]:
    """Identify the variable / field a pointer lives in: p, this->p and p_ inside a method are the same field."""
    node = strip_casts(node)
    if isinstance(node, A.Member) and isinstance(node.obj, A.KeywordLiteral) and node.obj.value == "this":
        return ("field", node.field_name)
    if isinstance(node, A.Identifier):
        sym = ctx.sem.resolved.get(node.id)
        if sym is None:
            return None
        return ("field", sym.name) if sym.kind == "field" else ("sym", sym.node_id, sym.name)
    return None


def alloc_kind(node: Optional[A.Node]) -> str:
    node = strip_casts(node)
    if isinstance(node, A.New):
        return "new[]" if node.is_array else "new"
    if isinstance(node, A.Call) and node.func_name in MALLOC_FAMILY:
        return "malloc"
    return ""


# --------------------------------------------------------------------- CPP001
class AllocMismatchRule(Rule):
    meta = RuleMeta(
        id="CPP001", name="Mismatched allocation / release", level="ast", severity="high",
        category="Memory management", cwe="CWE-762",
        description="Memory is released with a function that does not match how it was allocated "
                    "(new[] → delete, new → delete[], malloc → delete, new → free). This is undefined "
                    "behaviour and corrupts the heap.",
        recommendation="Pair new/delete, new[]/delete[] and malloc/free — or better, use std::vector, "
                       "std::string and std::unique_ptr so no manual release is needed.",
        detects="p = New(T[n]) | New(T) | Call(malloc) … then Delete(p) | Delete[](p) | Call(free, p) of the "
                "wrong kind (variables and class fields tracked across methods)",
        languages=CPP,
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        allocated: dict[tuple, dict[str, int]] = {}  # key -> {kind: first line}
        for node in ctx.ast.walk():
            if isinstance(node, A.VarDecl) and node.init is not None:
                kind = alloc_kind(node.init)
                sym = next((s for s in ctx.sem.symbols if s.node_id == node.id), None) if kind else None
                if sym is None:
                    continue
                key = ("field", sym.name) if sym.kind == "field" else ("sym", sym.node_id, sym.name)
                if kind and key:
                    allocated.setdefault(key, {}).setdefault(kind, node.line)
            elif isinstance(node, A.Assignment) and node.op == "=":
                kind = alloc_kind(node.value)
                key = storage_key(node.target, ctx)
                if kind and key:
                    allocated.setdefault(key, {}).setdefault(kind, node.line)
        if not allocated:
            return
        for node in ctx.ast.walk():
            if isinstance(node, A.Delete):
                release, target = ("delete[]" if node.is_array else "delete"), node.operand
            elif isinstance(node, A.Call) and node.func_name == "free" and node.args:
                release, target = "free", node.args[0]
            else:
                continue
            self.examined += 1
            key = storage_key(target, ctx)
            kinds = allocated.get(key) if key else None
            if not kinds or any(RELEASE_FOR[k] == release for k in kinds):
                continue
            kind, line = next(iter(kinds.items()))
            name = key[-1]
            yield self.finding(ctx, node.line, node.col,
                               f"'{name}' was allocated with {kind} (line {line}) but is released with {release}; "
                               f"it must be released with {RELEASE_FOR[kind]}. Mixing them is undefined behaviour "
                               "(wrong destructor count or a corrupted heap).",
                               evidence=f"{kind} @L{line} ⟶ {describe(node, ctx)} @L{node.line}", subject=name,
                               node=node, title=f"{kind} released with {release}")


# --------------------------------------------------------------------- CPP002
class StreamOverflowRule(Rule):
    meta = RuleMeta(
        id="CPP002", name="Unbounded stream read into array", level="ast", severity="high",
        category="Buffer overflow", cwe="CWE-120",
        description="'cin >> buf' into a char array has no length limit (before C++20), and getline/read with "
                    "a count larger than the buffer writes past its end.",
        recommendation="Read into std::string (std::getline(std::cin, s)), or limit the width with "
                       "cin >> std::setw(sizeof buf) >> buf; pass sizeof buf to cin.getline().",
        detects="BinaryOp('>>', stream, Identifier(char[N])) without setw · Call(stream.getline|get|read, buf, n > N)",
        languages=CPP,
    )

    def is_stream(self, node: Optional[A.Node], ctx: AstContext) -> bool:
        node = strip_casts(node)
        if isinstance(node, A.Identifier):
            if node.name in ctx.sem.profile.stream_sources:
                return True
            sym = ctx.sem.resolved.get(node.id)
            return sym is not None and any(t in sym.type for t in ctx.sem.profile.stream_types)
        return False

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for node in ctx.ast.walk():
            if isinstance(node, A.BinaryOp) and node.op == ">>" and not (
                    isinstance(node.parent, A.BinaryOp) and node.parent.op == ">>"):
                chain: list[A.Node] = []
                cur: Optional[A.Node] = node
                while isinstance(cur, A.BinaryOp) and cur.op == ">>":
                    chain.append(cur.right)
                    cur = cur.left
                if not self.is_stream(cur, ctx):
                    continue
                chain.reverse()
                stream = A.callee_path(cur)
                for i, target in enumerate(chain):
                    self.examined += 1
                    sym = ctx.sem.symbol_for(target)
                    if sym is None or not sym.array_dims or "char" not in sym.type or \
                            not isinstance(strip_casts(target), A.Identifier):
                        continue
                    prev = chain[i - 1] if i else None
                    if isinstance(prev, A.Call) and prev.func_name in ("setw", "std::setw"):
                        continue
                    size = sym.array_size
                    yield self.finding(ctx, target.line, target.col,
                                       f"'{stream} >> {sym.name}' reads a whitespace-delimited word of any length "
                                       f"into char[{size if size is not None else ''}]; a longer input overflows "
                                       "the stack buffer.", evidence=f"BinaryOp('>>', {stream}, "
                                       f"{describe(target, ctx)})", subject=sym.name, node=target)
            elif isinstance(node, A.Call) and isinstance(node.callee, A.Member) and \
                    node.callee.field_name in ("getline", "get", "read") and len(node.args) >= 2 and \
                    self.is_stream(node.callee.obj, ctx):
                self.examined += 1
                size = ctx.buffer_size(node.args[0])
                count = ctx.const_eval(node.args[1])
                if size is not None and count is not None and count > size:
                    yield self.finding(ctx, node.line, node.col,
                                       f"{A.callee_path(node.callee)}() may store {count} characters into "
                                       f"'{A.root_identifier(node.args[0])}', which holds only {size}.",
                                       evidence=describe(node, ctx), subject=node.callee.field_name, node=node)


# --------------------------------------------------------------------- CPP003
class UnsafeCastRule(Rule):
    meta = RuleMeta(
        id="CPP003", name="Unsafe type cast", level="ast", severity="low",
        category="Type safety", cwe="CWE-704",
        description="reinterpret_cast reinterprets memory as an unrelated type and const_cast removes "
                    "const-ness; both bypass the type system and easily cause undefined behaviour.",
        recommendation="Prefer static_cast, std::bit_cast or std::memcpy for byte views; never write through a "
                       "pointer obtained by casting away const.",
        detects="Cast(reinterpret_cast<T> | const_cast<T>, expr)",
        languages=CPP,
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for node in ctx.ast.walk():
            if not isinstance(node, A.Cast):
                continue
            self.examined += 1
            op = node.type.split("<", 1)[0]
            if op not in ("reinterpret_cast", "const_cast"):
                continue
            if op == "const_cast":
                on_string = any(isinstance(n, A.Call) and n.method in ("c_str", "data") for n in node.expr.walk()) \
                    or isinstance(node.expr, A.StringLiteral)
                msg = ("const_cast removes const from " + ("read-only string storage; writing through the result "
                                                           "is undefined behaviour." if on_string else
                                                           "an object; writing through it is undefined behaviour "
                                                           "if the object really is const."))
                severity = "medium" if on_string else "low"
            else:
                msg = f"{node.type} reinterprets the bits of {describe(node.expr, ctx, 2)}; aliasing and " \
                      "alignment rules are not checked."
                severity = "low"
            yield self.finding(ctx, node.line, node.col, msg, severity=severity, evidence=describe(node, ctx),
                               subject=op, node=node)


# --------------------------------------------------------------------- CPP004
ENGINES = {"mt19937", "mt19937_64", "minstd_rand", "minstd_rand0", "default_random_engine", "ranlux24",
           "ranlux48", "knuth_b"}


class PredictableEngineRule(Rule):
    meta = RuleMeta(
        id="CPP004", name="Predictable random engine", level="ast", severity="medium",
        category="Cryptography", cwe="CWE-338",
        description="A <random> engine such as std::mt19937 is seeded with the time, a constant or the default "
                    "seed. Its output can be predicted, and Mersenne Twister is never safe for secrets.",
        recommendation="Use the OS CSPRNG (getrandom(), /dev/urandom, BCryptGenRandom or a crypto library) for "
                       "tokens and keys; seed simulations with std::random_device.",
        detects="VarDecl(std::mt19937 | default_random_engine …, init = ∅ | constant | time(…)) · "
                "Call(engine.seed, constant | time)",
        languages=CPP,
    )

    @staticmethod
    def seed_problem(seed: Optional[A.Node], ctx: AstContext) -> str:
        if seed is None:
            return "the fixed default seed (5489 for mt19937)"
        if any(isinstance(n, A.Call) and n.func_name in ("time", "clock") for n in seed.walk()):
            return "the current time, which an attacker can guess to the second"
        if ctx.const_eval(seed) is not None:
            return f"the constant {describe(seed, ctx, 2)}"
        return ""

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for node in ctx.ast.walk():
            seed, name, where = None, "", None
            if isinstance(node, A.VarDecl) and simple_type(node.base_type or node.type).split("::")[-1] in ENGINES \
                    and not node.pointer_depth:
                self.examined += 1
                init = node.init
                if isinstance(init, A.Call) and isinstance(init.callee, A.Identifier):
                    seed = init.args[0] if init.args else None
                elif isinstance(init, A.InitList):
                    seed = init.items[0] if init.items else None
                elif init is not None:
                    continue
                name, where = node.name, node
            elif isinstance(node, A.Call) and node.method == "seed" and isinstance(node.callee, A.Member):
                sym = ctx.sem.symbol_for(node.callee.obj)
                if sym is None or simple_type(sym.type).split("::")[-1] not in ENGINES or not node.args:
                    continue
                self.examined += 1
                seed, name, where = node.args[0], sym.name, node
            else:
                continue
            problem = self.seed_problem(seed, ctx)
            if not problem:
                continue
            yield self.finding(ctx, where.line, where.col,
                               f"Random engine '{name}' is seeded with {problem}; every value it produces can be "
                               "reproduced by an attacker.", evidence=describe(where.init if isinstance(where, A.VarDecl)
                                                                               else where, ctx),
                               subject=name, node=where)


# --------------------------------------------------------------------- CPP005
OWNERS = {"unique_ptr", "shared_ptr", "make_unique", "make_shared", "reset", "auto_ptr"}


class RawNewLeakRule(Rule):
    meta = RuleMeta(
        id="CPP005", name="Leaked raw allocation", level="ast", severity="low",
        category="Memory management", cwe="CWE-401",
        description="A local pointer receives memory from 'new' but is never deleted, returned, stored or "
                    "handed to an owner, so the memory leaks (repeated leaks allow denial of service).",
        recommendation="Use std::unique_ptr / std::make_unique or a container instead of raw new.",
        detects="VarDecl(T* p = New(…)) in a function with no Delete(p), Return(p), p passed to a call, or p "
                "stored elsewhere",
        languages=CPP,
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for func in ctx.ast.walk():
            if not isinstance(func, A.FunctionDef) or func.body is None:
                continue
            for decl in func.body.walk():
                if not isinstance(decl, A.VarDecl) or not isinstance(strip_casts(decl.init), A.New):
                    continue
                self.examined += 1
                sym = next((s for s in ctx.sem.symbols if s.node_id == decl.id), None)
                if sym is None or not self.leaks(func, sym, ctx):
                    continue
                yield self.finding(ctx, decl.line, decl.col,
                                   f"'{decl.name}' owns memory from {describe(decl.init, ctx, 2)} but {func.name}() "
                                   "never deletes it, returns it or passes ownership on; it leaks on every call.",
                                   evidence=f"VarDecl({decl.name} = {describe(decl.init, ctx, 2)}) — no release "
                                   f"in {func.name}()", subject=decl.name, node=decl)

    @staticmethod
    def leaks(func: A.FunctionDef, sym, ctx: AstContext) -> bool:
        for node in func.body.walk():
            if not isinstance(node, A.Identifier) or ctx.sem.resolved.get(node.id) is not sym:
                continue
            parent = node.parent
            while isinstance(parent, A.Cast):
                parent = parent.parent
            if isinstance(parent, (A.Delete, A.Return, A.InitList, A.Lambda)):
                return False
            if isinstance(parent, A.Call) and node in parent.args:
                return False  # handed to a function / container / smart pointer
            if isinstance(parent, A.Assignment) and parent.value is node:
                return False  # stored somewhere else
            if isinstance(parent, A.VarDecl) and parent.init is node:
                return False
            if isinstance(parent, A.Member) and parent.field_name in OWNERS:
                return False
        return True


CPP_RULES = [AllocMismatchRule, StreamOverflowRule, UnsafeCastRule, PredictableEngineRule, RawNewLeakRule]
