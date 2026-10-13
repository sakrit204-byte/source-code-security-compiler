"""Semantic analysis: scoped symbol table, name resolution and input tagging.

The analyser walks the AST once, opening a scope for the translation unit,
every function and every block. Each identifier use is resolved against the
innermost enclosing scope. A light, flow-insensitive pass then tags variables
that may hold externally controlled data (user input), which the AST security
rules use to raise the severity of a finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from . import ast_nodes as A

KNOWN_GLOBALS = {
    "NULL", "stdin", "stdout", "stderr", "errno", "EOF", "true", "false", "EXIT_SUCCESS",
    "EXIT_FAILURE", "BUFSIZ", "SIZE_MAX", "INT_MAX", "INT_MIN", "UINT_MAX", "CHAR_BIT",
    "RAND_MAX", "PATH_MAX", "SEEK_SET", "SEEK_END", "SEEK_CUR", "O_RDONLY", "O_WRONLY",
    "O_RDWR", "O_CREAT", "AF_INET", "SOCK_STREAM", "INADDR_ANY", "LOG_ERR", "LOG_INFO",
    "LOG_WARNING", "__FILE__", "__LINE__", "__func__",
}

# Functions that write external input into one of their arguments (by index).
INPUT_WRITERS = {
    "gets": [0], "fgets": [0], "read": [1], "recv": [1], "recvfrom": [1], "fread": [0],
    "getline": [0], "getdelim": [0], "gets_s": [0], "fgetws": [0],
}
# scanf-family: every argument after the format is written with input.
SCANF_FORMAT_INDEX = {"scanf": 0, "fscanf": 1, "sscanf": 1, "vscanf": 0, "wscanf": 0}
# Functions whose return value is externally controlled.
INPUT_RETURNS = {"getenv", "secure_getenv", "getchar", "fgetc", "getc", "readline"}
# Copy-like functions: data flows from source argument(s) into the first argument.
PROPAGATORS = {"strcpy", "strncpy", "strcat", "strncat", "memcpy", "memmove", "sprintf",
               "snprintf", "vsprintf", "vsnprintf", "strlcpy", "strlcat", "wcscpy", "wcscat"}


@dataclass
class Symbol:
    name: str
    kind: str  # variable | parameter | function | typedef | enum_constant | record
    type: str
    scope: str
    line: int
    col: int
    node_id: int
    pointer_depth: int = 0
    array_dims: list = field(default_factory=list)
    is_const: bool = False
    storage: str = ""
    uses: int = 0
    tainted: bool = False
    taint_reason: str = ""
    literal_init: Optional[str] = None
    allocated_by: str = ""

    @property
    def array_size(self) -> Optional[int]:
        return self.array_dims[0] if self.array_dims else None

    def to_dict(self) -> dict:
        return {
            "name": self.name, "kind": self.kind, "type": self.type, "scope": self.scope,
            "line": self.line, "col": self.col, "node_id": self.node_id,
            "array_dims": self.array_dims, "pointer_depth": self.pointer_depth,
            "is_const": self.is_const, "storage": self.storage, "uses": self.uses,
            "tainted": self.tainted, "taint_reason": self.taint_reason,
            "literal_init": self.literal_init,
        }


@dataclass
class Scope:
    id: int
    name: str
    kind: str
    line: int
    parent: Optional["Scope"] = None
    symbols: dict[str, Symbol] = field(default_factory=dict)
    children: list["Scope"] = field(default_factory=list)

    def lookup(self, name: str) -> Optional[Symbol]:
        scope: Optional[Scope] = self
        while scope is not None:
            if name in scope.symbols:
                return scope.symbols[name]
            scope = scope.parent
        return None

    def to_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "kind": self.kind, "line": self.line,
            "symbols": [s.to_dict() for s in self.symbols.values()],
            "children": [c.to_dict() for c in self.children],
        }


@dataclass
class Diagnostic:
    severity: str  # error | warning | info
    message: str
    line: int
    col: int

    def to_dict(self) -> dict:
        return {"severity": self.severity, "message": self.message, "line": self.line, "col": self.col}


@dataclass
class SemanticResult:
    global_scope: Scope
    symbols: list[Symbol]
    resolved: dict[int, Symbol]  # Identifier node id -> Symbol
    node_scope: dict[int, Scope]  # Identifier node id -> scope it was used in
    diagnostics: list[Diagnostic]
    external_functions: dict[str, int]
    function_of: dict[int, A.FunctionDef]  # node id -> enclosing function
    log: list[str]

    def symbol_for(self, node: Optional[A.Node]) -> Optional[Symbol]:
        name_node = node
        while name_node is not None and not isinstance(name_node, A.Identifier):
            if isinstance(name_node, A.Index):
                name_node = name_node.array
            elif isinstance(name_node, A.Member):
                name_node = name_node.obj
            elif isinstance(name_node, A.UnaryOp) and name_node.op in ("&", "*"):
                name_node = name_node.operand
            elif isinstance(name_node, A.Cast):
                name_node = name_node.expr
            else:
                return None
        return self.resolved.get(name_node.id) if name_node is not None else None

    def is_tainted(self, node: Optional[A.Node]) -> tuple[bool, str]:
        """Does the expression reference input-derived data?"""
        if node is None:
            return False, ""
        for sub in node.walk():
            if isinstance(sub, A.Identifier):
                sym = self.resolved.get(sub.id)
                if sym is not None and sym.tainted:
                    return True, f"'{sym.name}' {sym.taint_reason}"
            if isinstance(sub, A.Call) and sub.func_name in INPUT_RETURNS:
                return True, f"value comes directly from {sub.func_name}()"
        return False, ""


class SemanticAnalyzer:
    def __init__(self) -> None:
        self.scope_count = 0
        self.global_scope = self.new_scope("global", "global", 1, None)
        self.scope = self.global_scope
        self.symbols: list[Symbol] = []
        self.resolved: dict[int, Symbol] = {}
        self.node_scope: dict[int, Scope] = {}
        self.diagnostics: list[Diagnostic] = []
        self.external: dict[str, int] = {}
        self.function_of: dict[int, A.FunctionDef] = {}
        self.current_function: Optional[A.FunctionDef] = None
        self.log: list[str] = []

    def new_scope(self, name: str, kind: str, line: int, parent: Optional[Scope]) -> Scope:
        scope = Scope(self.scope_count, name, kind, line, parent)
        self.scope_count += 1
        if parent:
            parent.children.append(scope)
        return scope

    def push(self, name: str, kind: str, line: int) -> None:
        self.scope = self.new_scope(name, kind, line, self.scope)

    def pop(self) -> None:
        for sym in self.scope.symbols.values():
            if sym.kind == "variable" and sym.uses == 0 and self.scope is not self.global_scope:
                self.diagnostics.append(Diagnostic("info", f"variable '{sym.name}' is declared but never used",
                                                   sym.line, sym.col))
        assert self.scope.parent is not None
        self.scope = self.scope.parent

    def declare(self, sym: Symbol) -> Symbol:
        existing = self.scope.symbols.get(sym.name)
        if existing is not None:
            if existing.kind == "function" and sym.kind == "function":
                return existing  # prototype followed by definition
            self.diagnostics.append(Diagnostic(
                "warning", f"redeclaration of '{sym.name}' (first declared on line {existing.line})",
                sym.line, sym.col))
        elif self.scope.parent is not None and self.scope.parent.lookup(sym.name) is not None \
                and sym.kind in ("variable", "parameter"):
            outer = self.scope.parent.lookup(sym.name)
            self.diagnostics.append(Diagnostic(
                "info", f"'{sym.name}' shadows a declaration from line {outer.line}", sym.line, sym.col))
        self.scope.symbols[sym.name] = sym
        self.symbols.append(sym)
        return sym

    # ------------------------------------------------------------------ walk
    def analyze(self, unit: A.TranslationUnit) -> SemanticResult:
        self.log.append("Opened scope #0 'global'")
        for decl in unit.decls:
            self.visit(decl)
        self.tag_inputs(unit)
        tainted = [s.name for s in self.symbols if s.tainted]
        self.log.append(f"Declared {len(self.symbols)} symbols in {self.scope_count} scopes")
        self.log.append(f"Resolved {len(self.resolved)} identifier references")
        if self.external:
            self.log.append("External (library) functions: " + ", ".join(sorted(self.external)))
        self.log.append("Input-derived symbols: " + (", ".join(tainted) if tainted else "none"))
        return SemanticResult(self.global_scope, self.symbols, self.resolved, self.node_scope,
                              self.diagnostics, self.external, self.function_of, self.log)

    def visit(self, node: Optional[A.Node]) -> None:
        if node is None:
            return
        if self.current_function is not None:
            self.function_of[node.id] = self.current_function
        method = getattr(self, f"visit_{node.kind}", None)
        if method:
            method(node)
        else:
            for child in node.children():
                self.visit(child)

    def visit_FunctionDef(self, node: A.FunctionDef) -> None:
        self.declare(Symbol(node.name, "function", node.return_type, self.scope.name, node.line, node.col,
                            node.id, storage=node.storage))
        self.push(node.name, "function", node.line)
        self.log.append(f"Opened scope #{self.scope.id} for function '{node.name}'")
        self.current_function = node
        self.function_of[node.id] = node
        for p in node.params:
            self.function_of[p.id] = node
            if p.name:
                sym = self.declare(Symbol(p.name, "parameter", p.type, self.scope.name, p.line, p.col, p.id,
                                          pointer_depth=p.pointer_depth, array_dims=list(p.array_dims)))
                if p.name == "argv" or (node.name == "main" and p.pointer_depth >= 2):
                    sym.tainted, sym.taint_reason = True, "holds command-line arguments"
        if node.body is not None:
            self.function_of[node.body.id] = node
            for item in node.body.items:  # body shares the function scope
                self.visit(item)
        self.pop()
        self.current_function = None

    def visit_FunctionDecl(self, node: A.FunctionDecl) -> None:
        self.declare(Symbol(node.name, "function", node.return_type, self.scope.name, node.line, node.col, node.id))

    def visit_Compound(self, node: A.Compound) -> None:
        self.push(f"block@{node.line}", "block", node.line)
        for item in node.items:
            self.visit(item)
        self.pop()

    def visit_For(self, node: A.For) -> None:
        self.push(f"for@{node.line}", "block", node.line)
        for child in node.children():
            self.visit(child)
        self.pop()

    def visit_VarDecl(self, node: A.VarDecl) -> None:
        if node.init is not None:
            self.visit(node.init)  # initializer is evaluated before the name is in scope
        sym = Symbol(node.name, "variable", node.type, self.scope.name, node.line, node.col, node.id,
                     pointer_depth=node.pointer_depth, array_dims=list(node.array_dims),
                     is_const=node.is_const, storage=node.storage)
        literal = A.literal_string(node.init)
        if literal is not None:
            sym.literal_init = literal
            if node.array_dims and node.array_dims[0] is None:
                sym.array_dims = [len(literal) + 1] + node.array_dims[1:]
        if isinstance(node.init, A.InitList) and node.array_dims and node.array_dims[0] is None:
            sym.array_dims = [len(node.init.items)] + node.array_dims[1:]
        self.declare(sym)

    def visit_TypedefDecl(self, node: A.TypedefDecl) -> None:
        self.declare(Symbol(node.name, "typedef", node.type, self.scope.name, node.line, node.col, node.id))

    def visit_RecordDecl(self, node: A.RecordDecl) -> None:
        if node.name:
            self.scope.symbols.setdefault(f"{node.tag} {node.name}", Symbol(
                f"{node.tag} {node.name}", "record", node.tag, self.scope.name, node.line, node.col, node.id))
        # Members live in their own namespace; they are not declared as variables.

    def visit_EnumDecl(self, node: A.EnumDecl) -> None:
        for item in node.items:
            self.declare(Symbol(item.name, "enum_constant", f"enum {node.name}".strip(), self.scope.name,
                                item.line, item.col, item.id))

    def visit_Member(self, node: A.Member) -> None:
        self.visit(node.obj)

    def visit_Call(self, node: A.Call) -> None:
        if isinstance(node.callee, A.Identifier):
            sym = self.scope.lookup(node.callee.name)
            if sym is None:
                self.external[node.callee.name] = self.external.get(node.callee.name, 0) + 1
                if self.current_function is not None:
                    self.function_of[node.callee.id] = self.current_function
            else:
                sym.uses += 1
                self.resolved[node.callee.id] = sym
        else:
            self.visit(node.callee)
        for arg in node.args:
            self.visit(arg)

    def visit_Identifier(self, node: A.Identifier) -> None:
        self.node_scope[node.id] = self.scope
        sym = self.scope.lookup(node.name)
        if sym is None:
            if node.name not in KNOWN_GLOBALS and not node.name.isupper():
                self.diagnostics.append(Diagnostic("warning", f"use of undeclared identifier '{node.name}'",
                                                   node.line, node.col))
            return
        sym.uses += 1
        self.resolved[node.id] = sym

    # --------------------------------------------------------- input tagging
    def tag_inputs(self, unit: A.TranslationUnit) -> None:
        """Flow-insensitive propagation of 'input-derived' tags to a fixed point."""

        def taint(target: Optional[A.Node], reason: str) -> bool:
            sym = self.symbol_from(target)
            if sym is not None and not sym.tainted and sym.kind in ("variable", "parameter"):
                sym.tainted, sym.taint_reason = True, reason
                self.log.append(f"Tagged '{sym.name}' as input-derived: {reason}")
                return True
            return False

        def tainted_expr(expr: Optional[A.Node]) -> Optional[str]:
            if expr is None:
                return None
            for sub in expr.walk():
                if isinstance(sub, A.Identifier):
                    sym = self.resolved.get(sub.id)
                    if sym is not None and sym.tainted:
                        return f"'{sym.name}'"
                if isinstance(sub, A.Call) and sub.func_name in INPUT_RETURNS:
                    return f"{sub.func_name}()"
            return None

        nodes = list(unit.walk())
        changed, rounds = True, 0
        while changed and rounds < 10:
            changed, rounds = False, rounds + 1
            for node in nodes:
                if isinstance(node, A.Call):
                    name = node.func_name
                    if name in INPUT_WRITERS:
                        for i in INPUT_WRITERS[name]:
                            if i < len(node.args):
                                changed |= taint(node.args[i], f"receives input from {name}() on line {node.line}")
                    elif name in SCANF_FORMAT_INDEX:
                        for arg in node.args[SCANF_FORMAT_INDEX[name] + 1:]:
                            changed |= taint(arg, f"receives input from {name}() on line {node.line}")
                    elif name in PROPAGATORS and len(node.args) >= 2:
                        src = next((s for s in map(tainted_expr, node.args[1:]) if s), None)
                        if src:
                            changed |= taint(node.args[0], f"copied from input-derived {src} via {name}() on line {node.line}")
                elif isinstance(node, A.Assignment):
                    src = tainted_expr(node.value)
                    if src:
                        changed |= taint(node.target, f"assigned from input-derived {src} on line {node.line}")
                elif isinstance(node, A.VarDecl) and node.init is not None:
                    src = tainted_expr(node.init)
                    if src:
                        sym = self.symbol_by_decl(node)
                        if sym and not sym.tainted:
                            sym.tainted = True
                            sym.taint_reason = f"initialised from input-derived {src} on line {node.line}"
                            self.log.append(f"Tagged '{sym.name}' as input-derived: {sym.taint_reason}")
                            changed = True
        self.log.append(f"Input tagging reached a fixed point after {rounds} pass(es)")

    def symbol_from(self, node: Optional[A.Node]) -> Optional[Symbol]:
        while node is not None and not isinstance(node, A.Identifier):
            if isinstance(node, A.Index):
                node = node.array
            elif isinstance(node, A.Member):
                node = node.obj
            elif isinstance(node, A.UnaryOp) and node.op in ("&", "*"):
                node = node.operand
            elif isinstance(node, A.Cast):
                node = node.expr
            else:
                return None
        return self.resolved.get(node.id) if node is not None else None

    def symbol_by_decl(self, node: A.VarDecl) -> Optional[Symbol]:
        for sym in self.symbols:
            if sym.node_id == node.id:
                return sym
        return None


def analyze(unit: A.TranslationUnit) -> SemanticResult:
    return SemanticAnalyzer().analyze(unit)
