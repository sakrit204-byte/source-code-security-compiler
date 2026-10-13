"""Recursive-descent parser for a practical subset of C.

Each grammar non-terminal is implemented by one ``parse_*`` method. Binary
expressions use precedence climbing driven by the ``BINARY_PRECEDENCE`` table.
Every production the parser enters is recorded in a trace so the derivation
can be inspected, and syntax errors are handled with panic-mode recovery
(skip to a synchronising token such as ';' or '}' and continue).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from . import ast_nodes as A
from .tokens import Token, TokenType

GRAMMAR = [
    ("translation_unit", "external_declaration*"),
    ("external_declaration", "function_definition | declaration"),
    ("function_definition", "decl_specifiers declarator compound_statement"),
    ("declaration", "decl_specifiers init_declarator (',' init_declarator)* ';'"),
    ("decl_specifiers", "(storage_class | type_qualifier | type_specifier)+"),
    ("type_specifier", "void | char | short | int | long | float | double | signed | unsigned | struct_or_union_specifier | enum_specifier | TYPEDEF_NAME"),
    ("struct_or_union_specifier", "(struct | union) IDENTIFIER? ('{' declaration* '}')?"),
    ("enum_specifier", "enum IDENTIFIER? ('{' enumerator (',' enumerator)* ','? '}')?"),
    ("init_declarator", "declarator ('=' initializer)?"),
    ("declarator", "'*'* (IDENTIFIER | '(' declarator ')') ('[' constant_expr? ']' | '(' parameter_list ')')*"),
    ("parameter_list", "parameter_declaration (',' parameter_declaration)* (',' '...')? | void"),
    ("initializer", "assignment_expression | '{' initializer_list ','? '}'"),
    ("compound_statement", "'{' (declaration | statement)* '}'"),
    ("statement", "compound | if | while | do_while | for | switch | case | default | return | break | continue | goto | labeled | expression_statement"),
    ("labeled_statement", "case constant_expr ':' statement | default ':' statement | IDENTIFIER ':' statement"),
    ("if_statement", "if '(' expression ')' statement (else statement)?"),
    ("while_statement", "while '(' expression ')' statement"),
    ("do_while_statement", "do statement while '(' expression ')' ';'"),
    ("for_statement", "for '(' (declaration | expression? ';') expression? ';' expression? ')' statement"),
    ("switch_statement", "switch '(' expression ')' statement"),
    ("jump_statement", "return expression? ';' | break ';' | continue ';' | goto IDENTIFIER ';'"),
    ("expression_statement", "expression? ';'"),
    ("expression", "assignment_expression (',' assignment_expression)*"),
    ("assignment_expression", "conditional_expression (assign_op assignment_expression)?"),
    ("conditional_expression", "binary_expression ('?' expression ':' conditional_expression)?"),
    ("binary_expression", "cast_expression (binary_op cast_expression)*   — precedence climbing"),
    ("cast_expression", "'(' type_name ')' cast_expression | unary_expression"),
    ("type_name", "decl_specifiers abstract_declarator?"),
    ("unary_expression", "('++' | '--' | '&' | '*' | '+' | '-' | '~' | '!') cast_expression | sizeof unary_expression | sizeof '(' type_name ')' | postfix_expression"),
    ("postfix_expression", "primary ('[' expression ']' | '(' arguments? ')' | '.' IDENTIFIER | '->' IDENTIFIER | '++' | '--')*"),
    ("function_call", "postfix_expression '(' (assignment_expression (',' assignment_expression)*)? ')'"),
    ("primary_expression", "IDENTIFIER | constant | STRING_LITERAL+ | '(' expression ')'"),
]

BINARY_PRECEDENCE = {
    "||": 1, "&&": 2, "|": 3, "^": 4, "&": 5,
    "==": 6, "!=": 6,
    "<": 7, ">": 7, "<=": 7, ">=": 7,
    "<<": 8, ">>": 8,
    "+": 9, "-": 9,
    "*": 10, "/": 10, "%": 10,
}
ASSIGN_OPS = {"=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>="}
UNARY_OPS = {"++", "--", "&", "*", "+", "-", "~", "!"}

TYPE_KEYWORDS = {"void", "char", "short", "int", "long", "float", "double", "signed",
                 "unsigned", "_Bool", "_Complex"}
QUALIFIERS = {"const", "volatile", "restrict"}
STORAGE = {"static", "extern", "auto", "register", "typedef", "inline", "_Noreturn", "_Thread_local"}

BUILTIN_TYPEDEFS = {
    "size_t", "ssize_t", "FILE", "bool", "ptrdiff_t", "wchar_t", "off_t", "pid_t", "time_t",
    "clock_t", "va_list", "socklen_t", "uid_t", "gid_t", "mode_t", "intptr_t", "uintptr_t",
    "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "DIR", "jmp_buf", "sig_atomic_t", "fd_set", "pthread_t", "pthread_mutex_t", "BYTE", "DWORD",
    "WORD", "BOOL", "HANDLE", "LPSTR", "LPCSTR",
}

TRACE_LIMIT = 6000


class ParseError(Exception):
    def __init__(self, message: str, token: Token):
        super().__init__(message)
        self.message = message
        self.token = token


@dataclass
class SyntaxErrorInfo:
    message: str
    line: int
    col: int
    recovery: str = ""

    def to_dict(self) -> dict:
        return {"message": self.message, "line": self.line, "col": self.col, "recovery": self.recovery}


@dataclass
class ParseResult:
    ast: A.TranslationUnit
    errors: list[SyntaxErrorInfo] = field(default_factory=list)
    trace: list[dict] = field(default_factory=list)
    production_counts: dict[str, int] = field(default_factory=dict)
    typedef_names: set[str] = field(default_factory=set)
    trace_truncated: bool = False
    constants: dict[str, int] = field(default_factory=dict)


@dataclass
class Declarator:
    name: str = ""
    pointer_depth: int = 0
    array_dims: list = field(default_factory=list)
    params: Optional[list[A.Param]] = None
    variadic: bool = False
    func_pointer: bool = False
    token: Optional[Token] = None


def production(name: str) -> Callable:
    """Decorator that records entry into a grammar production in the trace."""

    def wrap(fn: Callable) -> Callable:
        def inner(self: "Parser", *args, **kwargs):
            self.enter(name)
            try:
                return fn(self, *args, **kwargs)
            finally:
                self.depth -= 1

        inner.__name__ = fn.__name__
        return inner

    return wrap


class Parser:
    def __init__(self, tokens: list[Token], constants: Optional[dict[str, int]] = None):
        self.tokens = tokens
        self.constants: dict[str, int] = dict(constants or {})
        self.pos = 0
        self.errors: list[SyntaxErrorInfo] = []
        self.trace: list[dict] = []
        self.counts: dict[str, int] = {}
        self.depth = 0
        self.typedefs = set(BUILTIN_TYPEDEFS)
        self.truncated = False

    # ---------------------------------------------------------------- tracing
    def enter(self, rule: str) -> None:
        self.counts[rule] = self.counts.get(rule, 0) + 1
        tok = self.cur
        if len(self.trace) < TRACE_LIMIT:
            self.trace.append({"depth": self.depth, "rule": rule, "token": tok.lexeme or "EOF",
                               "line": tok.line, "col": tok.col, "event": "enter"})
        else:
            self.truncated = True
        self.depth += 1

    def count(self, rule: str) -> None:
        """Count a production without tracing it (used for very frequent expression rules)."""
        self.counts[rule] = self.counts.get(rule, 0) + 1

    def note(self, event: str, message: str, tok: Optional[Token] = None) -> None:
        tok = tok or self.cur
        if len(self.trace) < TRACE_LIMIT:
            self.trace.append({"depth": self.depth, "rule": message, "token": tok.lexeme or "EOF",
                               "line": tok.line, "col": tok.col, "event": event})

    # ---------------------------------------------------------- token helpers
    @property
    def cur(self) -> Token:
        return self.tokens[self.pos]

    def peek(self, offset: int = 1) -> Token:
        i = min(self.pos + offset, len(self.tokens) - 1)
        return self.tokens[i]

    def at_end(self) -> bool:
        return self.cur.type == TokenType.EOF

    def advance(self) -> Token:
        tok = self.cur
        if not self.at_end():
            self.pos += 1
        return tok

    def check(self, *lexemes: str) -> bool:
        return self.cur.type in (TokenType.OPERATOR, TokenType.DELIMITER) and self.cur.lexeme in lexemes

    def check_kw(self, *words: str) -> bool:
        return self.cur.type == TokenType.KEYWORD and self.cur.lexeme in words

    def accept(self, *lexemes: str) -> Optional[Token]:
        if self.check(*lexemes):
            return self.advance()
        return None

    def expect(self, lexeme: str, context: str = "") -> Token:
        if self.check(lexeme):
            return self.advance()
        where = f" {context}" if context else ""
        found = self.cur.lexeme or "end of input"
        raise ParseError(f"expected '{lexeme}'{where} but found '{found}'", self.cur)

    def expect_ident(self, context: str = "") -> Token:
        if self.cur.type == TokenType.IDENTIFIER:
            return self.advance()
        found = self.cur.lexeme or "end of input"
        raise ParseError(f"expected identifier{' ' + context if context else ''} but found '{found}'", self.cur)

    def pos_of(self, tok: Token) -> dict:
        return {"line": tok.line, "col": tok.col}

    # ------------------------------------------------------------- recovery
    def record_error(self, err: ParseError, recovery: str) -> None:
        self.errors.append(SyntaxErrorInfo(err.message, err.token.line, err.token.col, recovery))
        self.note("error", f"syntax error: {err.message}", err.token)

    def sync_statement(self) -> str:
        start = self.cur
        while not self.at_end():
            if self.check(";"):
                self.advance()
                break
            if self.check("}"):
                break
            if self.check("{"):
                self.skip_balanced()
                break
            self.advance()
        msg = f"panic mode: skipped from {start.line}:{start.col} to {self.cur.line}:{self.cur.col}"
        self.note("recover", msg)
        return msg

    def skip_balanced(self) -> None:
        depth = 0
        while not self.at_end():
            if self.check("{"):
                depth += 1
            elif self.check("}"):
                depth -= 1
                if depth <= 0:
                    self.advance()
                    return
            self.advance()

    def sync_top_level(self) -> str:
        start = self.cur
        while not self.at_end():
            if self.check(";"):
                self.advance()
                break
            if self.check("{"):
                self.skip_balanced()
                break
            self.advance()
        msg = f"panic mode: skipped external declaration from {start.line}:{start.col}"
        self.note("recover", msg)
        return msg

    # ----------------------------------------------------------- top level
    def parse(self) -> ParseResult:
        unit = self.parse_translation_unit()
        return ParseResult(unit, self.errors, self.trace, self.counts, self.typedefs, self.truncated,
                           self.constants)

    @production("translation_unit")
    def parse_translation_unit(self) -> A.TranslationUnit:
        unit = A.TranslationUnit(line=1, col=1)
        while not self.at_end():
            before = self.pos
            try:
                unit.decls.extend(self.parse_external_declaration())
            except ParseError as err:
                self.pos = max(self.pos, before)
                self.record_error(err, "")
                self.errors[-1].recovery = self.sync_top_level()
            if self.pos == before:  # guarantee progress
                self.advance()
        return unit

    def starts_declaration(self) -> bool:
        tok = self.cur
        if tok.type == TokenType.KEYWORD:
            return tok.lexeme in TYPE_KEYWORDS | QUALIFIERS | STORAGE | {"struct", "union", "enum"}
        if tok.type == TokenType.IDENTIFIER and tok.lexeme in self.typedefs:
            nxt = self.peek()
            return nxt.type == TokenType.IDENTIFIER or nxt.is_op("*") or nxt.is_kw(*QUALIFIERS)
        return False

    @production("external_declaration")
    def parse_external_declaration(self) -> list[A.Node]:
        if self.accept(";"):
            return []
        start = self.cur
        spec = self.parse_decl_specifiers()
        if self.check(";"):  # e.g. "struct point { ... };"
            self.advance()
            return spec["records"]
        decl = self.parse_declarator()
        if decl.params is not None and not decl.func_pointer and self.check("{"):
            return spec["records"] + [self.parse_function_definition(spec, decl, start)]
        return spec["records"] + self.finish_declaration(spec, decl, start, top_level=True)

    @production("function_definition")
    def parse_function_definition(self, spec: dict, decl: Declarator, start: Token) -> A.FunctionDef:
        ret = spec["type"] + (" " + "*" * decl.pointer_depth if decl.pointer_depth else "")
        self.note("match", f"function '{decl.name}' returns {ret.strip()}", decl.token)
        body = self.parse_compound()
        return A.FunctionDef(name=decl.name, return_type=ret.strip(), storage=spec["storage"],
                             params=decl.params or [], variadic=decl.variadic, body=body,
                             line=start.line, col=start.col)

    def finish_declaration(self, spec: dict, first: Declarator, start: Token, top_level: bool) -> list[A.Node]:
        self.enter("declaration")
        try:
            out: list[A.Node] = []
            decl = first
            while True:
                out.append(self.build_declaration(spec, decl, top_level))
                if not self.accept(","):
                    break
                decl = self.parse_declarator()
            self.expect(";", "after declaration")
            return out
        finally:
            self.depth -= 1

    def build_declaration(self, spec: dict, decl: Declarator, top_level: bool) -> A.Node:
        tok = decl.token or self.cur
        self.count("init_declarator")
        if spec["storage"] == "typedef":
            self.typedefs.add(decl.name)
            self.note("match", f"typedef name '{decl.name}' added to the typedef table", tok)
            ptr = " " + "*" * decl.pointer_depth if decl.pointer_depth else ""
            return A.TypedefDecl(name=decl.name, type=(spec["type"] + ptr).strip(), line=tok.line, col=tok.col)
        if decl.params is not None and not decl.func_pointer:
            ptr = " " + "*" * decl.pointer_depth if decl.pointer_depth else ""
            return A.FunctionDecl(name=decl.name, return_type=(spec["type"] + ptr).strip(),
                                  params=decl.params, variadic=decl.variadic, line=tok.line, col=tok.col)
        init = None
        if self.accept("="):
            init = self.parse_initializer()
        type_str = spec["type"] + (" " + "*" * decl.pointer_depth if decl.pointer_depth else "")
        if decl.func_pointer:
            type_str = spec["type"] + " (*)()"
        return A.VarDecl(name=decl.name, type=type_str.strip(), base_type=spec["type"],
                         pointer_depth=decl.pointer_depth + (1 if decl.func_pointer else 0),
                         array_dims=decl.array_dims, storage=spec["storage"], is_const=spec["const"],
                         init=init, line=tok.line, col=tok.col)

    # ------------------------------------------------------------ specifiers
    @production("decl_specifiers")
    def parse_decl_specifiers(self) -> dict:
        words: list[str] = []
        storage = ""
        const = False
        records: list[A.Node] = []
        have_type = False
        while True:
            tok = self.cur
            if tok.type == TokenType.KEYWORD and tok.lexeme in STORAGE:
                if tok.lexeme in ("typedef", "static", "extern"):
                    storage = tok.lexeme
                self.advance()
            elif tok.type == TokenType.KEYWORD and tok.lexeme in QUALIFIERS:
                const = const or tok.lexeme == "const"
                words.append(tok.lexeme) if tok.lexeme == "const" else None
                self.advance()
            elif tok.type == TokenType.KEYWORD and tok.lexeme in TYPE_KEYWORDS:
                self.count("type_specifier")
                words.append(tok.lexeme)
                have_type = True
                self.advance()
            elif tok.type == TokenType.KEYWORD and tok.lexeme in ("struct", "union"):
                name, record = self.parse_record_specifier()
                words.append(f"{tok.lexeme} {name}".strip())
                if record:
                    records.append(record)
                have_type = True
            elif tok.type == TokenType.KEYWORD and tok.lexeme == "enum":
                name, enum = self.parse_enum_specifier()
                words.append(f"enum {name}".strip())
                if enum:
                    records.append(enum)
                have_type = True
            elif tok.type == TokenType.IDENTIFIER and tok.lexeme in self.typedefs and not have_type:
                self.count("type_specifier")
                words.append(tok.lexeme)
                have_type = True
                self.advance()
            else:
                break
        if not have_type:
            if not words and not storage:
                raise ParseError(f"expected a declaration but found '{self.cur.lexeme or 'end of input'}'", self.cur)
            words.append("int")  # implicit int (pre-C99 style)
        return {"type": " ".join(words), "storage": storage, "const": const, "records": records}

    @production("struct_or_union_specifier")
    def parse_record_specifier(self) -> tuple[str, Optional[A.Node]]:
        kw = self.advance()
        name = self.advance().lexeme if self.cur.type == TokenType.IDENTIFIER else ""
        if not self.check("{"):
            return name, None
        self.advance()
        record = A.RecordDecl(tag=kw.lexeme, name=name, line=kw.line, col=kw.col)
        while not self.check("}") and not self.at_end():
            try:
                spec = self.parse_decl_specifiers()
                record.members.extend(spec["records"])
                if self.accept(";"):
                    continue
                while True:
                    d = self.parse_declarator()
                    if self.accept(":"):  # bit-field width
                        self.parse_conditional()
                    record.members.append(self.build_declaration({**spec, "storage": ""}, d, False))
                    if not self.accept(","):
                        break
                self.expect(";", "after struct member")
            except ParseError as err:
                self.record_error(err, "")
                self.errors[-1].recovery = self.sync_statement()
        self.expect("}", "to close struct body")
        return name, record

    @production("enum_specifier")
    def parse_enum_specifier(self) -> tuple[str, Optional[A.Node]]:
        kw = self.advance()
        name = self.advance().lexeme if self.cur.type == TokenType.IDENTIFIER else ""
        if not self.accept("{"):
            return name, None
        enum = A.EnumDecl(name=name, line=kw.line, col=kw.col)
        next_value: Optional[int] = 0
        while not self.check("}") and not self.at_end():
            tok = self.expect_ident("in enum")
            value = self.parse_conditional() if self.accept("=") else None
            if value is not None:
                next_value = self.const_value(value)
            if next_value is not None:
                self.constants[tok.lexeme] = next_value
                next_value += 1
            enum.items.append(A.Enumerator(name=tok.lexeme, value=value, line=tok.line, col=tok.col))
            if not self.accept(","):
                break
        self.expect("}", "to close enum")
        return name, enum

    # ------------------------------------------------------------ declarators
    @production("declarator")
    def parse_declarator(self, abstract: bool = False) -> Declarator:
        d = Declarator()
        while self.accept("*"):
            d.pointer_depth += 1
            while self.check_kw(*QUALIFIERS):
                self.advance()
        if self.check("(") and (self.peek().is_op("*") or self.peek().is_op("(")):
            # Parenthesised declarator, e.g. function pointer: (*handler)(int)
            self.advance()
            inner = self.parse_declarator(abstract)
            self.expect(")", "after parenthesised declarator")
            d.name, d.token = inner.name, inner.token
            d.func_pointer = inner.pointer_depth > 0
            d.pointer_depth += max(inner.pointer_depth - 1, 0)
            d.array_dims = inner.array_dims
        elif self.cur.type == TokenType.IDENTIFIER:
            d.token = self.advance()
            d.name = d.token.lexeme
        elif not abstract:
            found = self.cur.lexeme or "end of input"
            raise ParseError(f"expected identifier in declarator but found '{found}'", self.cur)
        while True:
            if self.accept("["):
                if self.check("]"):
                    d.array_dims.append(None)
                else:
                    size_expr = self.parse_assignment()
                    d.array_dims.append(self.const_value(size_expr))
                self.expect("]", "to close array size")
            elif self.check("("):
                params, variadic = self.parse_parameter_list()
                if d.params is None:
                    d.params, d.variadic = params, variadic
            else:
                break
        return d

    def const_value(self, node: A.Node) -> Optional[int]:
        """Fold simple constant expressions (used for array sizes)."""
        if isinstance(node, A.IntLiteral):
            return node.value
        if isinstance(node, A.CharLiteral):
            return node.value
        if isinstance(node, A.Identifier):
            return self.constants.get(node.name)
        if isinstance(node, A.BinaryOp):
            left, right = self.const_value(node.left), self.const_value(node.right)
            if left is None or right is None:
                return None
            try:
                return {"+": left + right, "-": left - right, "*": left * right,
                        "/": left // right if right else None, "<<": left << right,
                        "%": left % right if right else None}.get(node.op)
            except (ValueError, OverflowError):
                return None
        return None

    @production("parameter_list")
    def parse_parameter_list(self) -> tuple[list[A.Param], bool]:
        self.expect("(")
        params: list[A.Param] = []
        variadic = False
        if self.check_kw("void") and self.peek().is_op(")"):
            self.advance()
        while not self.check(")") and not self.at_end():
            if self.accept("..."):
                variadic = True
                break
            tok = self.cur
            spec = self.parse_decl_specifiers()
            d = self.parse_declarator(abstract=True)
            depth = d.pointer_depth + (1 if d.func_pointer else 0)
            type_str = spec["type"] + (" " + "*" * depth if depth else "")
            params.append(A.Param(name=d.name, type=type_str.strip(), pointer_depth=depth,
                                  array_dims=d.array_dims, line=(d.token or tok).line, col=(d.token or tok).col))
            if not self.accept(","):
                break
        self.expect(")", "to close parameter list")
        return params, variadic

    @production("type_name")
    def parse_type_name(self) -> str:
        spec = self.parse_decl_specifiers()
        d = self.parse_declarator(abstract=True)
        stars = d.pointer_depth + (1 if d.func_pointer else 0)
        dims = "".join(f"[{'' if x is None else x}]" for x in d.array_dims)
        return (spec["type"] + (" " + "*" * stars if stars else "") + dims).strip()

    @production("initializer")
    def parse_initializer(self) -> A.Node:
        if self.check("{"):
            open_tok = self.advance()
            lst = A.InitList(line=open_tok.line, col=open_tok.col)
            while not self.check("}") and not self.at_end():
                if self.check(".") and self.peek().type == TokenType.IDENTIFIER:
                    dot = self.advance()
                    name = self.advance().lexeme
                    self.expect("=", "after designator")
                    lst.items.append(A.Designated(designator=f".{name}", value=self.parse_initializer(),
                                                  line=dot.line, col=dot.col))
                elif self.check("["):
                    br = self.advance()
                    idx = self.parse_conditional()
                    self.expect("]")
                    self.expect("=", "after designator")
                    lst.items.append(A.Designated(designator=f"[{self.const_value(idx)}]",
                                                  value=self.parse_initializer(), line=br.line, col=br.col))
                else:
                    lst.items.append(self.parse_initializer())
                if not self.accept(","):
                    break
            self.expect("}", "to close initializer list")
            return lst
        return self.parse_assignment()

    # ------------------------------------------------------------- statements
    @production("compound_statement")
    def parse_compound(self) -> A.Compound:
        open_tok = self.expect("{", "to open block")
        block = A.Compound(line=open_tok.line, col=open_tok.col)
        while not self.check("}") and not self.at_end():
            before = self.pos
            try:
                block.items.append(self.parse_block_item())
            except ParseError as err:
                self.record_error(err, "")
                self.errors[-1].recovery = self.sync_statement()
            if self.pos == before:
                self.advance()
        self.expect("}", "to close block")
        return block

    def parse_block_item(self) -> A.Node:
        if self.starts_declaration():
            return self.parse_local_declaration()
        return self.parse_statement()

    def parse_local_declaration(self) -> A.Node:
        start = self.cur
        spec = self.parse_decl_specifiers()
        if self.accept(";"):
            return A.DeclStmt(decls=spec["records"], line=start.line, col=start.col)
        decl = self.parse_declarator()
        decls = spec["records"] + self.finish_declaration(spec, decl, start, top_level=False)
        return A.DeclStmt(decls=decls, line=start.line, col=start.col)

    @production("statement")
    def parse_statement(self) -> A.Node:
        tok = self.cur
        if self.check("{"):
            return self.parse_compound()
        if self.check(";"):
            self.advance()
            return A.EmptyStmt(line=tok.line, col=tok.col)
        if tok.type == TokenType.KEYWORD:
            handler = {
                "if": self.parse_if, "while": self.parse_while, "do": self.parse_do_while,
                "for": self.parse_for, "switch": self.parse_switch, "return": self.parse_return,
                "break": self.parse_jump, "continue": self.parse_jump, "goto": self.parse_jump,
                "case": self.parse_case, "default": self.parse_default,
            }.get(tok.lexeme)
            if handler:
                return handler()
        if tok.type == TokenType.IDENTIFIER and self.peek().is_op(":"):
            self.advance()
            self.advance()
            body = self.parse_statement() if not self.check("}") else A.EmptyStmt(line=tok.line, col=tok.col)
            return A.Label(name=tok.lexeme, body=body, line=tok.line, col=tok.col)
        return self.parse_expression_statement()

    @production("expression_statement")
    def parse_expression_statement(self) -> A.Node:
        tok = self.cur
        expr = self.parse_expression()
        self.expect(";", "after expression")
        return A.ExprStmt(expr=expr, line=tok.line, col=tok.col)

    def paren_condition(self, what: str) -> A.Node:
        self.expect("(", f"after '{what}'")
        cond = self.parse_expression()
        self.expect(")", f"to close '{what}' condition")
        return cond

    @production("if_statement")
    def parse_if(self) -> A.Node:
        tok = self.advance()
        cond = self.paren_condition("if")
        then = self.parse_statement()
        otherwise = None
        if self.check_kw("else"):
            self.advance()
            otherwise = self.parse_statement()
        return A.If(cond=cond, then=then, otherwise=otherwise, line=tok.line, col=tok.col)

    @production("while_statement")
    def parse_while(self) -> A.Node:
        tok = self.advance()
        cond = self.paren_condition("while")
        return A.While(cond=cond, body=self.parse_statement(), line=tok.line, col=tok.col)

    @production("do_while_statement")
    def parse_do_while(self) -> A.Node:
        tok = self.advance()
        body = self.parse_statement()
        if not self.check_kw("while"):
            raise ParseError(f"expected 'while' after do-body but found '{self.cur.lexeme}'", self.cur)
        self.advance()
        cond = self.paren_condition("while")
        self.expect(";", "after do-while")
        return A.DoWhile(body=body, cond=cond, line=tok.line, col=tok.col)

    @production("for_statement")
    def parse_for(self) -> A.Node:
        tok = self.advance()
        self.expect("(", "after 'for'")
        init = None
        if self.starts_declaration():
            init = self.parse_local_declaration()
        else:
            if not self.check(";"):
                init = self.parse_expression()
            self.expect(";", "in for header")
        cond = None if self.check(";") else self.parse_expression()
        self.expect(";", "in for header")
        step = None if self.check(")") else self.parse_expression()
        self.expect(")", "to close for header")
        body = self.parse_statement()
        return A.For(init=init, cond=cond, step=step, body=body, line=tok.line, col=tok.col)

    @production("switch_statement")
    def parse_switch(self) -> A.Node:
        tok = self.advance()
        cond = self.paren_condition("switch")
        return A.Switch(cond=cond, body=self.parse_statement(), line=tok.line, col=tok.col)

    @production("labeled_statement")
    def parse_case(self) -> A.Node:
        tok = self.advance()
        value = self.parse_conditional()
        self.expect(":", "after case value")
        body = None if self.check("}") or self.check_kw("case", "default") else self.parse_statement()
        return A.Case(value=value, body=body, line=tok.line, col=tok.col)

    @production("labeled_statement")
    def parse_default(self) -> A.Node:
        tok = self.advance()
        self.expect(":", "after 'default'")
        body = None if self.check("}") or self.check_kw("case", "default") else self.parse_statement()
        return A.Default(body=body, line=tok.line, col=tok.col)

    @production("jump_statement")
    def parse_return(self) -> A.Node:
        tok = self.advance()
        value = None if self.check(";") else self.parse_expression()
        self.expect(";", "after return")
        return A.Return(value=value, line=tok.line, col=tok.col)

    @production("jump_statement")
    def parse_jump(self) -> A.Node:
        tok = self.advance()
        if tok.lexeme == "goto":
            target = self.expect_ident("after goto").lexeme
            self.expect(";", "after goto")
            return A.Goto(target=target, line=tok.line, col=tok.col)
        self.expect(";", f"after '{tok.lexeme}'")
        return (A.Break if tok.lexeme == "break" else A.Continue)(line=tok.line, col=tok.col)

    # ------------------------------------------------------------ expressions
    @production("expression")
    def parse_expression(self) -> A.Node:
        first = self.parse_assignment()
        if not self.check(","):
            return first
        comma = A.Comma(exprs=[first], line=first.line, col=first.col)
        while self.accept(","):
            comma.exprs.append(self.parse_assignment())
        return comma

    def parse_assignment(self) -> A.Node:
        left = self.parse_conditional()
        if self.cur.type == TokenType.OPERATOR and self.cur.lexeme in ASSIGN_OPS:
            op = self.advance()
            self.enter("assignment_expression")
            try:
                value = self.parse_assignment()
            finally:
                self.depth -= 1
            if not isinstance(left, (A.Identifier, A.Index, A.Member, A.UnaryOp, A.Cast)):
                self.errors.append(SyntaxErrorInfo(f"left side of '{op.lexeme}' is not assignable",
                                                   op.line, op.col, "continued (semantic error)"))
            return A.Assignment(op=op.lexeme, target=left, value=value, line=left.line, col=left.col)
        return left

    def parse_conditional(self) -> A.Node:
        cond = self.parse_binary(1)
        if self.accept("?"):
            self.enter("conditional_expression")
            try:
                then = self.parse_expression()
                self.expect(":", "in conditional expression")
                otherwise = self.parse_conditional()
            finally:
                self.depth -= 1
            return A.Conditional(cond=cond, then=then, otherwise=otherwise, line=cond.line, col=cond.col)
        return cond

    def parse_binary(self, min_prec: int) -> A.Node:
        left = self.parse_cast()
        while True:
            tok = self.cur
            prec = BINARY_PRECEDENCE.get(tok.lexeme) if tok.type == TokenType.OPERATOR else None
            if prec is None or prec < min_prec:
                return left
            self.advance()
            self.count("binary_expression")
            right = self.parse_binary(prec + 1)  # all binary operators are left-associative
            left = A.BinaryOp(op=tok.lexeme, left=left, right=right, line=left.line, col=left.col)

    def is_type_start(self, tok: Token) -> bool:
        if tok.type == TokenType.KEYWORD:
            return tok.lexeme in TYPE_KEYWORDS | QUALIFIERS | {"struct", "union", "enum"}
        return tok.type == TokenType.IDENTIFIER and tok.lexeme in self.typedefs

    def parse_cast(self) -> A.Node:
        if self.check("(") and self.is_type_start(self.peek()):
            open_tok = self.advance()
            self.enter("cast_expression")
            try:
                type_name = self.parse_type_name()
                self.expect(")", "to close cast")
                if self.check("{"):  # compound literal
                    init = self.parse_initializer()
                    return A.Cast(type=type_name, expr=init, line=open_tok.line, col=open_tok.col)
                expr = self.parse_cast()
            finally:
                self.depth -= 1
            return A.Cast(type=type_name, expr=expr, line=open_tok.line, col=open_tok.col)
        return self.parse_unary()

    def parse_unary(self) -> A.Node:
        tok = self.cur
        if tok.type == TokenType.OPERATOR and tok.lexeme in UNARY_OPS:
            self.advance()
            self.enter("unary_expression")
            try:
                operand = self.parse_unary() if tok.lexeme in ("++", "--") else self.parse_cast()
            finally:
                self.depth -= 1
            return A.UnaryOp(op=tok.lexeme, operand=operand, line=tok.line, col=tok.col)
        if self.check_kw("sizeof"):
            self.advance()
            self.count("unary_expression")
            if self.check("(") and self.is_type_start(self.peek()):
                self.advance()
                type_name = self.parse_type_name()
                self.expect(")", "to close sizeof")
                return A.SizeOf(type=type_name, line=tok.line, col=tok.col)
            return A.SizeOf(expr=self.parse_unary(), line=tok.line, col=tok.col)
        return self.parse_postfix()

    def parse_postfix(self) -> A.Node:
        node = self.parse_primary()
        while True:
            tok = self.cur
            if tok.lexeme in ("[", "(", ".", "->", "++", "--"):
                self.count("postfix_expression")
            if self.accept("["):
                index = self.parse_expression()
                self.expect("]", "to close subscript")
                node = A.Index(array=node, index=index, line=node.line, col=node.col)
            elif self.check("("):
                node = self.parse_call(node)
            elif self.accept(".", "->"):
                name = self.expect_ident("after member access").lexeme
                node = A.Member(obj=node, field_name=name, arrow=tok.lexeme == "->", line=node.line, col=node.col)
            elif tok.type == TokenType.OPERATOR and tok.lexeme in ("++", "--"):
                self.advance()
                node = A.UnaryOp(op=tok.lexeme, postfix=True, operand=node, line=node.line, col=node.col)
            else:
                return node

    @production("function_call")
    def parse_call(self, callee: A.Node) -> A.Node:
        self.advance()
        call = A.Call(callee=callee, line=callee.line, col=callee.col)
        if isinstance(callee, A.Identifier):
            self.note("match", f"call to '{callee.name}'")
        while not self.check(")") and not self.at_end():
            call.args.append(self.parse_assignment())
            if not self.accept(","):
                break
        self.expect(")", "to close argument list")
        return call

    def parse_primary(self) -> A.Node:
        self.count("primary_expression")
        tok = self.cur
        if tok.type == TokenType.IDENTIFIER:
            self.advance()
            return A.Identifier(name=tok.lexeme, line=tok.line, col=tok.col)
        if tok.type == TokenType.INT_LITERAL:
            self.advance()
            return A.IntLiteral(value=tok.value if tok.value is not None else 0, raw=tok.lexeme,
                                line=tok.line, col=tok.col)
        if tok.type == TokenType.FLOAT_LITERAL:
            self.advance()
            return A.FloatLiteral(value=tok.value or 0.0, raw=tok.lexeme, line=tok.line, col=tok.col)
        if tok.type == TokenType.CHAR_LITERAL:
            self.advance()
            return A.CharLiteral(value=tok.value or 0, raw=tok.lexeme, line=tok.line, col=tok.col)
        if tok.type == TokenType.STRING_LITERAL:
            value, raws = "", []
            while self.cur.type == TokenType.STRING_LITERAL:  # adjacent literal concatenation
                value += self.cur.value or ""
                raws.append(self.advance().lexeme)
            if len(raws) > 1:
                self.note("match", f"concatenated {len(raws)} adjacent string literals", tok)
            return A.StringLiteral(value=value, raw=" ".join(raws), line=tok.line, col=tok.col)
        if self.accept("("):
            expr = self.parse_expression()
            self.expect(")", "to close parenthesis")
            return expr
        found = tok.lexeme or "end of input"
        raise ParseError(f"expected an expression but found '{found}'", tok)


def parse(tokens: list[Token], constants: Optional[dict[str, int]] = None) -> ParseResult:
    result = Parser(tokens, constants).parse()
    A.link_tree(result.ast)
    return result
