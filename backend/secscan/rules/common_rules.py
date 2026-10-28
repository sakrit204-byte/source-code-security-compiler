"""Module 2 rules shared by several languages (C, C++, Java).

They work on the language-neutral AST nodes (Call, BinaryOp, Catch, Return …)
and use the same semantic information (symbol table, input tagging) as the
C rules.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional

from .. import ast_nodes as A
from .base import AstContext, Finding, Rule, RuleMeta, describe

SQL_WORDS = re.compile(r"(?i)\b(select|insert|update|delete|where|from|values|into|drop|union|order\s+by)\b")


def node_index(ctx: AstContext) -> dict[int, A.Node]:
    cache = getattr(ctx, "_node_index", None)
    if cache is None:
        cache = {n.id: n for n in ctx.ast.walk()}
        setattr(ctx, "_node_index", cache)
    return cache


def is_constant(node: Optional[A.Node]) -> bool:
    return node is None or isinstance(node, (A.StringLiteral, A.IntLiteral, A.FloatLiteral, A.CharLiteral,
                                             A.KeywordLiteral))


def literal_text(node: Optional[A.Node]) -> str:
    """All string-literal text inside an expression (used to recognise SQL / shell fragments)."""
    if node is None:
        return ""
    return " ".join(n.value for n in node.walk() if isinstance(n, A.StringLiteral))


def built_at_runtime(expr: Optional[A.Node], ctx: AstContext, depth: int = 0) -> str:
    """Explain how a string is assembled from non-constant parts, or '' if it is constant / unknown."""
    if expr is None or depth > 3:
        return ""
    while isinstance(expr, A.Cast):
        expr = expr.expr
    if isinstance(expr, A.BinaryOp) and expr.op == "+":
        parts = [expr.left, expr.right]
        dynamic = [p for p in parts if not is_constant(p) and not built_is_constant(p)]
        if dynamic:
            return f"string concatenation with {describe(dynamic[0], ctx, 2)}"
        return ""
    if isinstance(expr, A.Call):
        method = expr.method
        if method in ("format", "formatted") and any(not is_constant(a) for a in expr.args[1 if method == "format"
                                                                                           else 0:]):
            return f"{A.callee_path(expr.callee)}() with runtime arguments"
        if method in ("c_str", "data", "toString", "str") and isinstance(expr.callee, A.Member):
            return built_at_runtime(expr.callee.obj, ctx, depth + 1)
        if method == "concat" and expr.args and not is_constant(expr.args[0]):
            return "String.concat() with a runtime value"
        return ""
    if isinstance(expr, A.Identifier):
        sym = ctx.sem.resolved.get(expr.id)
        if sym is None:
            return ""
        index = node_index(ctx)
        decl = index.get(sym.node_id)
        if isinstance(decl, A.VarDecl) and decl.init is not None:
            how = built_at_runtime(decl.init, ctx, depth + 1)
            if how:
                return f"'{sym.name}' built by {how} (line {decl.line})"
        for node in index.values():
            if isinstance(node, A.Assignment) and ctx.sem.symbol_for(node.target) is sym:
                if node.op == "+=" and not is_constant(node.value):
                    return f"'{sym.name}' extended with '+=' a runtime value (line {node.line})"
                how = built_at_runtime(node.value, ctx, depth + 1)
                if how:
                    return f"'{sym.name}' assigned {how} (line {node.line})"
            elif isinstance(node, A.Call) and node.func_name in ("sprintf", "snprintf", "strcat", "strncat",
                                                                 "strcpy", "strncpy") and node.args:
                if ctx.sem.symbol_for(node.args[0]) is sym:
                    start = 2 if node.func_name == "sprintf" else 3 if node.func_name == "snprintf" else 1
                    if any(not is_constant(a) for a in node.args[start:]):
                        return f"'{sym.name}' filled by {node.func_name}() with runtime values (line {node.line})"
            elif isinstance(node, A.Call) and isinstance(node.callee, A.Member) and \
                    node.callee.field_name in ("append", "insert", "push_back") and \
                    ctx.sem.symbol_for(node.callee.obj) is sym and any(not is_constant(a) for a in node.args):
                return f"'{sym.name}' extended with .{node.callee.field_name}() (line {node.line})"
    return ""


def built_is_constant(node: A.Node) -> bool:
    return isinstance(node, A.BinaryOp) and node.op == "+" and is_constant(node.left) and is_constant(node.right)


# --------------------------------------------------------------------- AST017
SQL_FUNCTIONS = {  # C / C++ client libraries: function -> index of the SQL argument
    "sqlite3_exec": 1, "sqlite3_prepare": 1, "sqlite3_prepare_v2": 1, "sqlite3_prepare_v3": 1,
    "mysql_query": 1, "mysql_real_query": 1, "PQexec": 1, "PQsendQuery": 1, "PQprepare": 2,
    "SQLExecDirect": 1, "SQLPrepare": 1,
}
SQL_METHODS = {  # obj.method(sql, …)
    "java": {"executeQuery", "executeUpdate", "execute", "executeLargeUpdate", "addBatch", "prepareStatement",
             "prepareCall", "createQuery", "createNativeQuery", "createSQLQuery", "queryForObject",
             "queryForList", "queryForMap", "queryForRowSet", "batchUpdate"},
    "cpp": {"exec", "exec0", "exec1", "execute", "prepare", "query"},
    "c": set(),
}
GENERIC_SQL_METHODS = {"execute", "exec", "query", "prepare", "addBatch"}


class SqlInjectionRule(Rule):
    meta = RuleMeta(
        id="AST017", name="SQL injection", level="ast", severity="high",
        category="Injection", cwe="CWE-89",
        description="A SQL statement passed to the database API is assembled from runtime values instead of "
                    "using bound parameters.",
        recommendation="Use parameterised queries (PreparedStatement with '?' placeholders, sqlite3_bind_*, "
                       "PQexecParams) and never concatenate input into SQL text.",
        detects="Call(sqlite3_exec | mysql_query | stmt.executeQuery | …, sql) where sql = BinaryOp('+') / "
                "String.format / sprintf-built buffer, or is input-derived",
        languages=("c", "cpp", "java"),
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        methods = SQL_METHODS.get(ctx.language, set())
        for call in ctx.calls():
            self.examined += 1
            if call.func_name in SQL_FUNCTIONS:
                idx, name = SQL_FUNCTIONS[call.func_name], call.func_name
            elif isinstance(call.callee, A.Member) and call.callee.field_name in methods:
                idx, name = 0, call.callee.field_name
            else:
                continue
            if idx >= len(call.args):
                continue
            sql = call.args[idx]
            if A.literal_string(sql) is not None:
                continue
            how = built_at_runtime(sql, ctx)
            tainted, why = ctx.sem.is_tainted(sql)
            if not how and not tainted:
                continue
            text = literal_text(sql)
            if name in GENERIC_SQL_METHODS and not SQL_WORDS.search(text) and not tainted:
                continue  # e.g. executor.execute(task): not SQL
            if tainted:
                severity, msg = "critical", (f"{name}() runs SQL that contains input-derived data ({why}). An "
                                             "attacker can change the query, e.g. ' OR '1'='1 to bypass a filter "
                                             "or ; DROP TABLE to destroy data.")
            else:
                severity, msg = "high", (f"{name}() runs SQL assembled at runtime ({how}). If any part comes from "
                                         "a user, the query structure can be changed.")
            yield self.finding(ctx, call.line, call.col, msg, severity=severity, evidence=describe(call, ctx),
                               subject=name, node=call)


# --------------------------------------------------------------------- AST018
CATCH_ALL = {"Exception", "Throwable", "RuntimeException", "Error", "std::exception", "exception"}


class SwallowedExceptionRule(Rule):
    meta = RuleMeta(
        id="AST018", name="Swallowed exception", level="ast", severity="low",
        category="Error handling", cwe="CWE-390",
        description="An exception handler has an empty body, so failures (including failed security checks) "
                    "pass silently.",
        recommendation="Handle the error: log it, fail closed, or rethrow. Catch the most specific type possible.",
        detects="Catch(param, body = Block{ }) — catch-all handlers (catch (...) / Exception / Throwable) rank higher",
        languages=("cpp", "java"),
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for node in ctx.ast.walk():
            if not isinstance(node, A.Catch):
                continue
            self.examined += 1
            if node.body is None or node.body.items:
                continue
            caught = "..." if node.param is None else node.param.type.replace("const ", "").rstrip("&* ")
            catch_all = node.param is None or caught in CATCH_ALL or caught.split("::")[-1] in CATCH_ALL
            yield self.finding(
                ctx, node.line, node.col,
                f"catch ({caught}) has an empty body: " + ("every error, including unexpected ones, is silently "
                                                         "discarded." if catch_all else
                                                         "the failure is ignored and execution continues."),
                severity="medium" if catch_all else "low", cwe="CWE-396" if catch_all else "CWE-390",
                evidence=f"Catch({caught}) → Block{{ }} (0 statements)", subject=caught, node=node,
                title="Catch-all exception swallowed" if catch_all else None)


# --------------------------------------------------------------------- AST019
class ReturnLocalAddressRule(Rule):
    meta = RuleMeta(
        id="AST019", name="Return of stack address", level="ast", severity="high",
        category="Memory management", cwe="CWE-562",
        description="A function returns a pointer or reference to one of its own local variables, which no "
                    "longer exists after the function returns.",
        recommendation="Return by value, use a static/heap buffer owned by the caller, or let the caller pass "
                       "the destination buffer in.",
        detects="FunctionDef(return type T* | T&) ∋ Return(&local | local_array | local [for T&])",
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for func in ctx.ast.walk():
            if not isinstance(func, A.FunctionDef) or func.body is None:
                continue
            ret = func.return_type.replace(" ", "")
            returns_ref = ret.endswith("&") and not ret.endswith("&&")
            if "*" not in ret and not returns_ref:
                continue
            self.examined += 1
            for node in func.body.walk():
                if not isinstance(node, A.Return) or node.value is None:
                    continue
                if any(isinstance(a, A.Lambda) for a in node.ancestors() if a is not func):
                    continue
                value = node.value
                while isinstance(value, A.Cast):
                    value = value.expr
                target, how = None, ""
                if isinstance(value, A.UnaryOp) and value.op == "&" and isinstance(value.operand, A.Identifier):
                    target, how = value.operand, "the address of"
                elif isinstance(value, A.Identifier):
                    target = value
                if target is None:
                    continue
                sym = ctx.sem.resolved.get(target.id)
                if sym is None or sym.kind != "variable" or "static" in sym.storage:
                    continue
                if ctx.sem.function_of.get(sym.node_id) is not func:
                    continue
                if not how:
                    if sym.array_dims and "*" in ret:
                        how = "the local array"
                    elif returns_ref and "&" not in sym.type and not sym.pointer_depth:
                        how = "a reference to"
                    else:
                        continue
                yield self.finding(
                    ctx, node.line, node.col,
                    f"{func.name}() returns {how} '{sym.name}', a local variable declared on line {sym.line}. Its "
                    "stack memory is reused as soon as the function returns, so the caller reads garbage or "
                    "attacker-influenced data.",
                    evidence=f"Return({describe(node.value, ctx)}) in {func.name}() : {func.return_type}",
                    subject=sym.name, node=node)


COMMON_RULES = [SqlInjectionRule, SwallowedExceptionRule, ReturnLocalAddressRule]
