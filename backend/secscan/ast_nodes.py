"""Abstract Syntax Tree node definitions.

Every node records its source position. Child nodes are discovered
automatically from dataclass fields, which keeps traversal and JSON
serialisation generic for all node kinds.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from typing import Iterator, Optional


@dataclass(eq=False, kw_only=True)
class Node:
    line: int = 0
    col: int = 0
    id: int = field(default=-1, repr=False)
    parent: Optional["Node"] = field(default=None, repr=False)

    _SKIP = ("line", "col", "id", "parent")

    @property
    def kind(self) -> str:
        return type(self).__name__

    def label(self) -> str:
        return self.kind

    def child_items(self) -> Iterator[tuple[str, "Node"]]:
        for f in fields(self):
            if f.name in Node._SKIP:
                continue
            value = getattr(self, f.name)
            if isinstance(value, Node):
                yield f.name, value
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, Node):
                        yield f.name, item

    def children(self) -> list["Node"]:
        return [child for _, child in self.child_items()]

    def attrs(self) -> dict:
        out = {}
        for f in fields(self):
            if f.name in Node._SKIP:
                continue
            value = getattr(self, f.name)
            if isinstance(value, Node) or (isinstance(value, list) and any(isinstance(v, Node) for v in value)):
                continue
            if isinstance(value, list) and not value:
                continue
            if value is None or value == "":
                continue
            out[f.name] = value
        return out

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "label": self.label(),
            "line": self.line,
            "col": self.col,
            "attrs": self.attrs(),
            "children": [dict(child.to_dict(), role=role) for role, child in self.child_items()],
        }

    def walk(self) -> Iterator["Node"]:
        """Pre-order traversal."""
        stack: list[Node] = [self]
        while stack:
            node = stack.pop()
            yield node
            stack.extend(reversed(node.children()))

    def ancestors(self) -> Iterator["Node"]:
        node = self.parent
        while node is not None:
            yield node
            node = node.parent


# ----------------------------------------------------------------- top level
@dataclass(eq=False, kw_only=True)
class TranslationUnit(Node):
    decls: list[Node] = field(default_factory=list)


@dataclass(eq=False, kw_only=True)
class Param(Node):
    name: str = ""
    type: str = ""
    pointer_depth: int = 0
    array_dims: list = field(default_factory=list)

    def label(self) -> str:
        return f"Param {self.type} {self.name}".rstrip()


@dataclass(eq=False, kw_only=True)
class FunctionDef(Node):
    name: str = ""
    return_type: str = ""
    storage: str = ""
    params: list[Param] = field(default_factory=list)
    variadic: bool = False
    body: Optional[Node] = None

    def label(self) -> str:
        return f"FunctionDef {self.name}()"


@dataclass(eq=False, kw_only=True)
class FunctionDecl(Node):
    name: str = ""
    return_type: str = ""
    params: list[Param] = field(default_factory=list)
    variadic: bool = False

    def label(self) -> str:
        return f"FunctionDecl {self.name}()"


@dataclass(eq=False, kw_only=True)
class VarDecl(Node):
    name: str = ""
    type: str = ""
    base_type: str = ""
    pointer_depth: int = 0
    array_dims: list = field(default_factory=list)  # ints or None (unknown size)
    storage: str = ""
    is_const: bool = False
    init: Optional[Node] = None

    def label(self) -> str:
        dims = "".join(f"[{'' if d is None else d}]" for d in self.array_dims)
        return f"VarDecl {self.type} {self.name}{dims}"


@dataclass(eq=False, kw_only=True)
class DeclStmt(Node):
    decls: list[Node] = field(default_factory=list)


@dataclass(eq=False, kw_only=True)
class TypedefDecl(Node):
    name: str = ""
    type: str = ""

    def label(self) -> str:
        return f"Typedef {self.name} = {self.type}"


@dataclass(eq=False, kw_only=True)
class RecordDecl(Node):
    tag: str = "struct"
    name: str = ""
    members: list[Node] = field(default_factory=list)

    def label(self) -> str:
        return f"{self.tag.capitalize()} {self.name or '<anonymous>'}"


@dataclass(eq=False, kw_only=True)
class Enumerator(Node):
    name: str = ""
    value: Optional[Node] = None

    def label(self) -> str:
        return f"Enumerator {self.name}"


@dataclass(eq=False, kw_only=True)
class EnumDecl(Node):
    name: str = ""
    items: list[Enumerator] = field(default_factory=list)

    def label(self) -> str:
        return f"Enum {self.name or '<anonymous>'}"


# ---------------------------------------------------------------- statements
@dataclass(eq=False, kw_only=True)
class Compound(Node):
    items: list[Node] = field(default_factory=list)

    def label(self) -> str:
        return "Block { }"


@dataclass(eq=False, kw_only=True)
class If(Node):
    cond: Optional[Node] = None
    then: Optional[Node] = None
    otherwise: Optional[Node] = None


@dataclass(eq=False, kw_only=True)
class While(Node):
    cond: Optional[Node] = None
    body: Optional[Node] = None


@dataclass(eq=False, kw_only=True)
class DoWhile(Node):
    body: Optional[Node] = None
    cond: Optional[Node] = None


@dataclass(eq=False, kw_only=True)
class For(Node):
    init: Optional[Node] = None
    cond: Optional[Node] = None
    step: Optional[Node] = None
    body: Optional[Node] = None


@dataclass(eq=False, kw_only=True)
class Switch(Node):
    cond: Optional[Node] = None
    body: Optional[Node] = None


@dataclass(eq=False, kw_only=True)
class Case(Node):
    value: Optional[Node] = None
    body: Optional[Node] = None


@dataclass(eq=False, kw_only=True)
class Default(Node):
    body: Optional[Node] = None


@dataclass(eq=False, kw_only=True)
class Label(Node):
    name: str = ""
    body: Optional[Node] = None

    def label(self) -> str:
        return f"Label {self.name}:"


@dataclass(eq=False, kw_only=True)
class Goto(Node):
    target: str = ""

    def label(self) -> str:
        return f"Goto {self.target}"


@dataclass(eq=False, kw_only=True)
class Return(Node):
    value: Optional[Node] = None


@dataclass(eq=False, kw_only=True)
class Break(Node):
    pass


@dataclass(eq=False, kw_only=True)
class Continue(Node):
    pass


@dataclass(eq=False, kw_only=True)
class ExprStmt(Node):
    expr: Optional[Node] = None


@dataclass(eq=False, kw_only=True)
class EmptyStmt(Node):
    pass


# --------------------------------------------------------------- expressions
@dataclass(eq=False, kw_only=True)
class Identifier(Node):
    name: str = ""

    def label(self) -> str:
        return f"Identifier {self.name}"


@dataclass(eq=False, kw_only=True)
class IntLiteral(Node):
    value: int = 0
    raw: str = ""

    def label(self) -> str:
        return f"IntLiteral {self.raw}"


@dataclass(eq=False, kw_only=True)
class FloatLiteral(Node):
    value: float = 0.0
    raw: str = ""

    def label(self) -> str:
        return f"FloatLiteral {self.raw}"


@dataclass(eq=False, kw_only=True)
class CharLiteral(Node):
    value: int = 0
    raw: str = ""

    def label(self) -> str:
        return f"CharLiteral {self.raw}"


@dataclass(eq=False, kw_only=True)
class StringLiteral(Node):
    value: str = ""
    raw: str = ""

    def label(self) -> str:
        text = self.raw if len(self.raw) <= 40 else self.raw[:37] + '..."'
        return f"StringLiteral {text}"


@dataclass(eq=False, kw_only=True)
class BinaryOp(Node):
    op: str = ""
    left: Optional[Node] = None
    right: Optional[Node] = None

    def label(self) -> str:
        return f"BinaryOp '{self.op}'"


@dataclass(eq=False, kw_only=True)
class Assignment(Node):
    op: str = "="
    target: Optional[Node] = None
    value: Optional[Node] = None

    def label(self) -> str:
        return f"Assignment '{self.op}'"


@dataclass(eq=False, kw_only=True)
class UnaryOp(Node):
    op: str = ""
    postfix: bool = False
    operand: Optional[Node] = None

    def label(self) -> str:
        return f"UnaryOp '{self.op}'{' (postfix)' if self.postfix else ''}"


@dataclass(eq=False, kw_only=True)
class Conditional(Node):
    cond: Optional[Node] = None
    then: Optional[Node] = None
    otherwise: Optional[Node] = None

    def label(self) -> str:
        return "Conditional ?:"


@dataclass(eq=False, kw_only=True)
class Call(Node):
    callee: Optional[Node] = None
    args: list[Node] = field(default_factory=list)

    @property
    def func_name(self) -> str:
        """Plain function name; C++ 'std::' / '::' qualification is dropped so C rules match std::strcpy."""
        if not isinstance(self.callee, Identifier):
            return ""
        name = self.callee.name
        for prefix in ("::", "std::"):
            if name.startswith(prefix):
                name = name[len(prefix):]
        return name

    @property
    def method(self) -> str:
        """Name of the called function or method: 'exec' for both exec(x) and cp.exec(x)."""
        if isinstance(self.callee, Member):
            return self.callee.field_name
        return self.func_name

    def label(self) -> str:
        return f"Call {callee_path(self.callee) or '<expr>'}()"


@dataclass(eq=False, kw_only=True)
class Index(Node):
    array: Optional[Node] = None
    index: Optional[Node] = None

    def label(self) -> str:
        return "Index [ ]"


@dataclass(eq=False, kw_only=True)
class Member(Node):
    obj: Optional[Node] = None
    field_name: str = ""
    arrow: bool = False

    def label(self) -> str:
        return f"Member {'->' if self.arrow else '.'}{self.field_name}"


@dataclass(eq=False, kw_only=True)
class Cast(Node):
    type: str = ""
    expr: Optional[Node] = None

    def label(self) -> str:
        return f"Cast ({self.type})"


@dataclass(eq=False, kw_only=True)
class SizeOf(Node):
    type: str = ""
    expr: Optional[Node] = None

    def label(self) -> str:
        return f"SizeOf({self.type})" if self.type else "SizeOf"


@dataclass(eq=False, kw_only=True)
class InitList(Node):
    items: list[Node] = field(default_factory=list)

    def label(self) -> str:
        return f"InitList {{{len(self.items)} items}}"


@dataclass(eq=False, kw_only=True)
class Designated(Node):
    designator: str = ""
    value: Optional[Node] = None

    def label(self) -> str:
        return f"Designated {self.designator}"


@dataclass(eq=False, kw_only=True)
class Comma(Node):
    exprs: list[Node] = field(default_factory=list)


# ------------------------------------------------------ C++ / Java constructs
@dataclass(eq=False, kw_only=True)
class ClassDecl(Node):
    """class / interface / enum / record, C++ struct with methods, or C++ namespace."""
    tag: str = "class"
    name: str = ""
    bases: list = field(default_factory=list)
    modifiers: str = ""
    members: list[Node] = field(default_factory=list)

    def label(self) -> str:
        ext = f" : {', '.join(self.bases)}" if self.bases else ""
        return f"{self.tag.capitalize()} {self.name or '<anonymous>'}{ext}"


@dataclass(eq=False, kw_only=True)
class ImportDecl(Node):
    """import / package / using directive."""
    tag: str = "import"
    module: str = ""
    names: list = field(default_factory=list)

    def label(self) -> str:
        return f"{self.tag.capitalize()} {self.module}"


@dataclass(eq=False, kw_only=True)
class Lambda(Node):
    """Lambda expression (Java / C++)."""
    params: list[Param] = field(default_factory=list)
    captures: str = ""
    body: Optional[Node] = None

    def label(self) -> str:
        return f"Lambda ({', '.join(p.name for p in self.params)})"


@dataclass(eq=False, kw_only=True)
class New(Node):
    type: str = ""
    args: list[Node] = field(default_factory=list)
    array_size: Optional[Node] = None
    is_array: bool = False
    init: Optional[Node] = None  # array initializer or anonymous class body

    def label(self) -> str:
        return f"New {self.type}{'[]' if self.is_array else '()'}"


@dataclass(eq=False, kw_only=True)
class Delete(Node):
    is_array: bool = False
    operand: Optional[Node] = None

    def label(self) -> str:
        return "Delete[]" if self.is_array else "Delete"


@dataclass(eq=False, kw_only=True)
class Try(Node):
    resources: list[Node] = field(default_factory=list)
    body: Optional[Node] = None
    handlers: list[Node] = field(default_factory=list)
    final: Optional[Node] = None


@dataclass(eq=False, kw_only=True)
class Catch(Node):
    param: Optional[Param] = None
    body: Optional[Node] = None

    def label(self) -> str:
        if self.param is None:
            return "Catch (...)"
        return f"Catch ({' '.join(x for x in (self.param.type, self.param.name) if x)})"


@dataclass(eq=False, kw_only=True)
class Throw(Node):
    value: Optional[Node] = None


@dataclass(eq=False, kw_only=True)
class ForEach(Node):
    """Enhanced / range-based for: for (T x : xs)."""
    decl: Optional[Node] = None
    iterable: Optional[Node] = None
    body: Optional[Node] = None

    def label(self) -> str:
        name = getattr(self.decl, "name", "") or "…"
        return f"ForEach {name} : …"


@dataclass(eq=False, kw_only=True)
class ArrayLiteral(Node):
    items: list[Node] = field(default_factory=list)

    def label(self) -> str:
        return f"ArrayLiteral [{len(self.items)}]"


@dataclass(eq=False, kw_only=True)
class KeywordLiteral(Node):
    """true / false / null / this / super / nullptr."""
    value: str = ""

    def label(self) -> str:
        return f"Literal {self.value}"


STATEMENT_KINDS = (
    Compound, If, While, DoWhile, For, Switch, Case, Default, Label, Goto, Return,
    Break, Continue, ExprStmt, EmptyStmt, DeclStmt, Try, Throw, ForEach,
)


def link_tree(root: Node) -> int:
    """Assign pre-order ids and parent pointers. Returns the node count."""
    count = 0
    stack: list[tuple[Node, Optional[Node]]] = [(root, None)]
    while stack:
        node, parent = stack.pop()
        node.id = count
        node.parent = parent
        count += 1
        for child in reversed(node.children()):
            stack.append((child, node))
    return count


def tree_depth(root: Node) -> int:
    best = 0
    stack = [(root, 1)]
    while stack:
        node, depth = stack.pop()
        best = max(best, depth)
        stack.extend((c, depth + 1) for c in node.children())
    return best


def literal_string(node: Optional[Node]) -> Optional[str]:
    """Return the value of a string literal (through casts), else None."""
    while isinstance(node, Cast):
        node = node.expr
    return node.value if isinstance(node, StringLiteral) else None


def root_identifier(node: Optional[Node]) -> Optional[str]:
    """Name of the base variable in expressions like buf, &buf, buf[i], s.f, *p."""
    while node is not None:
        if isinstance(node, Identifier):
            return node.name
        if isinstance(node, (Index,)):
            node = node.array
        elif isinstance(node, Member):
            node = node.obj
        elif isinstance(node, UnaryOp) and node.op in ("&", "*"):
            node = node.operand
        elif isinstance(node, Cast):
            node = node.expr
        else:
            return None
    return None


def callee_path(node: Optional[Node], limit: int = 5) -> str:
    """Dotted rendering of a callee, e.g. 'Runtime.getRuntime().exec'."""
    if node is None or limit < 0:
        return ""
    if isinstance(node, Identifier):
        return node.name
    if isinstance(node, KeywordLiteral):
        return node.value
    if isinstance(node, Member):
        base = callee_path(node.obj, limit - 1)
        sep = "->" if node.arrow else "."
        return f"{base}{sep}{node.field_name}" if base else node.field_name
    if isinstance(node, Call):
        base = callee_path(node.callee, limit - 1)
        return f"{base}()" if base else ""
    if isinstance(node, New):
        return f"new {node.type}()"
    if isinstance(node, Index):
        base = callee_path(node.array, limit - 1)
        return f"{base}[]" if base else ""
    return ""


def member_path(node: Optional[Node]) -> str:
    """Dotted path of a plain member chain (request.session.id -> 'request.session.id'); '' for anything else."""
    parts: list[str] = []
    while isinstance(node, (Member, Index)):
        if isinstance(node, Member):
            parts.append(node.field_name)
            node = node.obj
        else:
            node = node.array
    if isinstance(node, Identifier):
        parts.append(node.name)
    elif isinstance(node, KeywordLiteral):
        parts.append(node.value)
    else:
        return ""
    return ".".join(reversed(parts))
