"""Recursive-descent parser for C++ (C++17 subset).

The C++ parser extends the C parser, so every C construct is handled by the
same productions. On top of that it adds classes with access specifiers and
member functions, namespaces, using-declarations, templates (headers are
skipped, template arguments are kept as text), references, qualified names
(std::string), new / delete, lambdas, C++ casts, try / catch / throw and
range-based for.

C++ declarations are ambiguous without full type information. The parser keeps
a table of known type names (classes it has seen, typedefs, using-aliases and
common standard-library types) and uses bounded lookahead: a (qualified) name
followed by an identifier starts a declaration.
"""

from __future__ import annotations

from typing import Optional

from .. import ast_nodes as A
from ..parser import (BINARY_PRECEDENCE, BUILTIN_TYPEDEFS, GRAMMAR as C_GRAMMAR, QUALIFIERS, STORAGE,
                      TYPE_KEYWORDS, Declarator, ParseError, Parser, production)
from ..tokens import Token, TokenType
from .common import SharedSyntax, join_lexemes

GRAMMAR = [
    ("translation_unit", "declaration_seq"),
    ("external_declaration", "function_definition | declaration | class_specifier ';' | namespace_definition | using_declaration | template_declaration | linkage_specification"),
    ("namespace_definition", "inline? namespace qualified_id? '{' declaration* '}'"),
    ("using_declaration", "using namespace qualified_id ';' | using qualified_id ';' | using IDENTIFIER '=' type_id ';'"),
    ("template_declaration", "template '<' template_parameter_list '>' declaration"),
    ("class_specifier", "(class | struct | union) qualified_id? final? (':' base_specifier (',' base_specifier)*)? '{' member_specification* '}'"),
    ("member_specification", "access_specifier ':' | member_declaration | constructor_definition | friend_declaration | using_declaration"),
    ("constructor_definition", "explicit? '~'? IDENTIFIER '(' parameter_list ')' (':' mem_initializer (',' mem_initializer)*)? (compound_statement | '=' (default | delete) ';')"),
    *[(lhs, rhs) for lhs, rhs in C_GRAMMAR if lhs not in ("translation_unit", "external_declaration")],
    ("qualified_id", "'::'? IDENTIFIER template_arguments? ('::' ('~'? IDENTIFIER | operator OP) template_arguments?)*"),
    ("declarator_cpp", "('*' cv* | '&' | '&&')* (qualified_id | '[' IDENTIFIER (',' IDENTIFIER)* ']') ('[' expr? ']' | parameters_and_qualifiers | '(' arguments ')')*"),
    ("range_based_for", "for '(' decl_specifiers declarator ':' expression ')' statement"),
    ("try_statement", "try compound_statement handler+"),
    ("catch_clause", "catch '(' (exception_declaration | '...') ')' compound_statement"),
    ("throw_statement", "throw assignment_expression? ';'"),
    ("new_expression", "'::'? new ('(' placement ')')? type_id ('[' expression ']')* ('(' arguments? ')' | braced_init_list)?"),
    ("delete_expression", "'::'? delete ('[' ']')? cast_expression"),
    ("lambda_expression", "'[' capture_list? ']' ('(' parameter_list ')')? mutable? ('->' type_id)? compound_statement"),
    ("cpp_cast", "(static_cast | dynamic_cast | reinterpret_cast | const_cast) '<' type_id '>' '(' expression ')'"),
]

STD_TYPES = {
    "string", "wstring", "string_view", "vector", "map", "unordered_map", "multimap", "set", "unordered_set",
    "list", "deque", "array", "queue", "stack", "priority_queue", "pair", "tuple", "optional", "variant",
    "unique_ptr", "shared_ptr", "weak_ptr", "function", "thread", "mutex", "lock_guard", "unique_lock",
    "atomic", "ostream", "istream", "iostream", "ifstream", "ofstream", "fstream", "stringstream",
    "ostringstream", "istringstream", "streambuf", "exception", "runtime_error", "logic_error",
    "invalid_argument", "out_of_range", "bad_alloc", "size_type", "iterator", "const_iterator",
    "mt19937", "mt19937_64", "default_random_engine", "random_device", "minstd_rand",
    "uniform_int_distribution", "uniform_real_distribution", "byte", "nullptr_t", "chrono", "regex",
    "filesystem", "path", "any", "bitset", "initializer_list", "streamsize", "basic_string",
}
CPP_STORAGE = (STORAGE - {"auto"}) | {"virtual", "explicit", "constexpr", "consteval", "constinit", "mutable",
                                      "friend", "thread_local"}
CPP_TYPE_KEYWORDS = TYPE_KEYWORDS | {"bool", "wchar_t", "char8_t", "char16_t", "char32_t", "auto"}
CASTS = {"static_cast", "dynamic_cast", "reinterpret_cast", "const_cast"}
LITERAL_KEYWORDS = {"true", "false", "nullptr", "this"}
ACCESS = {"public", "private", "protected"}

CPP_PRECEDENCE = {**BINARY_PRECEDENCE, "<=>": 7}


class CppParser(SharedSyntax, Parser):
    LANGUAGE = "C++"
    GRAMMAR = GRAMMAR
    BINARY_PRECEDENCE = CPP_PRECEDENCE
    ASSIGNABLE = (A.Identifier, A.Index, A.Member, A.UnaryOp, A.Cast, A.Call)

    def __init__(self, tokens: list[Token], constants: Optional[dict[str, int]] = None):
        super().__init__(tokens, constants)
        self.typedefs = set(BUILTIN_TYPEDEFS) | STD_TYPES
        self.class_stack: list[str] = []
        self.in_params = 0

    # ----------------------------------------------------- name lookahead
    def is_known_type(self, name: str) -> bool:
        if not name:
            return False
        bare = name.split("<")[0]
        last = bare.split("::")[-1]
        return bare in self.typedefs or last in self.typedefs or bare.startswith("std::")

    def scan_qualified(self, i: int) -> tuple[int, str]:
        """Scan '::'? IDENT (<…>)? ('::' IDENT (<…>)?)* — returns (index after, bare name) or (-1, '')."""
        parts: list[str] = []
        if self.tok_at(i).is_op("::"):
            parts.append("::")
            i += 1
        if self.tok_at(i).type != TokenType.IDENTIFIER:
            return -1, ""
        while True:
            parts.append(self.tok_at(i).lexeme)
            i += 1
            if self.tok_at(i).is_op("<"):
                k = self.scan_angle(i)
                if k != -1:
                    i = k
            if self.tok_at(i).is_op("::") and self.tok_at(i + 1).type == TokenType.IDENTIFIER:
                parts.append("::")
                i += 1
                continue
            return i, "".join(parts)

    def skip_ptr_ops(self, i: int) -> int:
        while self.tok_at(i).is_op("*", "&", "&&") or self.tok_at(i).is_kw("const", "volatile"):
            i += 1
        return i

    def type_name_ahead(self) -> bool:
        j, name = self.scan_qualified(self.pos)
        if j == -1:
            return False
        if self.is_known_type(name):
            nxt = self.tok_at(j)
            # A known type name directly followed by '(' is a functional cast / constructor call, not a type.
            return not (nxt.is_op("(", ".", "->") and not self.in_params) or bool(self.in_params)
        k = self.skip_ptr_ops(j)
        nxt = self.tok_at(k)
        if nxt.type == TokenType.IDENTIFIER or nxt.is_kw("operator"):
            return True
        if self.in_params and nxt.is_op(")", ",", "=", "[", "..."):
            return True
        return False

    def starts_declaration(self) -> bool:
        tok = self.cur
        if tok.type == TokenType.KEYWORD:
            return tok.lexeme in CPP_TYPE_KEYWORDS | QUALIFIERS | CPP_STORAGE | {
                "struct", "union", "enum", "class", "typename", "decltype", "typedef"}
        if tok.type == TokenType.IDENTIFIER or tok.is_op("::"):
            j, name = self.scan_qualified(self.pos)
            if j == -1:
                return False
            k = self.skip_ptr_ops(j)
            nxt = self.tok_at(k)
            if nxt.type != TokenType.IDENTIFIER:
                return False
            return self.tok_at(k + 1).is_op("=", ";", ",", "(", "{", "[", ":", ")") or self.is_known_type(name)
        return False

    def is_type_start(self, tok: Token) -> bool:
        if tok.type == TokenType.KEYWORD:
            return tok.lexeme in CPP_TYPE_KEYWORDS | QUALIFIERS | {"struct", "union", "enum", "class", "typename"}
        if tok.type == TokenType.IDENTIFIER:
            i = self.pos if tok is self.cur else self.pos + 1 if tok is self.peek() else self.tokens.index(tok)
            j, name = self.scan_qualified(i)
            return j != -1 and self.is_known_type(name)
        return False

    @production("qualified_id")
    def parse_qualified_type(self) -> str:
        parts: list[str] = []
        if self.accept("::"):
            parts.append("::")
        parts.append(self.expect_ident("in qualified name").lexeme)
        while True:
            if self.check("<") and self.scan_angle(self.pos) != -1:
                parts.append(self.angle_text())
            if self.check("::") and self.peek().type == TokenType.IDENTIFIER:
                self.advance()
                parts.append("::")
                parts.append(self.advance().lexeme)
                continue
            return "".join(parts)

    # ---------------------------------------------------------- specifiers
    @production("decl_specifiers")
    def parse_decl_specifiers(self) -> dict:
        words: list[str] = []
        storage = ""
        const = False
        records: list[A.Node] = []
        have_type = False
        while True:
            tok = self.cur
            if tok.type == TokenType.KEYWORD and tok.lexeme in CPP_STORAGE:
                if tok.lexeme in ("typedef", "static", "extern"):
                    storage = tok.lexeme
                self.advance()
            elif tok.type == TokenType.KEYWORD and tok.lexeme in QUALIFIERS:
                const = const or tok.lexeme == "const"
                if tok.lexeme == "const":
                    words.append("const")
                self.advance()
            elif tok.is_kw("typename"):
                self.advance()
            elif tok.type == TokenType.KEYWORD and tok.lexeme in CPP_TYPE_KEYWORDS:
                self.count("type_specifier")
                words.append(tok.lexeme)
                have_type = True
                self.advance()
            elif tok.type == TokenType.KEYWORD and tok.lexeme in ("class", "struct", "union") and not have_type:
                name, record = self.parse_class_specifier()
                words.append(f"{tok.lexeme} {name}".strip())
                if record:
                    records.append(record)
                have_type = True
            elif tok.is_kw("enum") and not have_type:
                name, enum = self.parse_enum_specifier()
                words.append(f"enum {name}".strip())
                if enum:
                    records.append(enum)
                have_type = True
            elif tok.is_kw("decltype") and not have_type:
                self.advance()
                close = self.matching(self.pos)
                self.pos = close + 1 if close != -1 else self.pos
                words.append("decltype(…)")
                have_type = True
            elif (tok.type == TokenType.IDENTIFIER or tok.is_op("::")) and not have_type and self.type_name_ahead():
                self.count("type_specifier")
                words.append(self.parse_qualified_type())
                have_type = True
            else:
                break
        if not have_type:
            if not words and not storage:
                raise ParseError(f"expected a declaration but found '{self.cur.lexeme or 'end of input'}'", self.cur)
            words.append("int")
        return {"type": " ".join(words), "storage": storage, "const": const, "records": records}

    @production("enum_specifier")
    def parse_enum_specifier(self) -> tuple[str, Optional[A.Node]]:
        kw = self.advance()
        if self.check_kw("class", "struct"):
            self.advance()  # scoped enumeration
        name = self.advance().lexeme if self.cur.type == TokenType.IDENTIFIER else ""
        if name:
            self.typedefs.add(name)
        if self.accept(":"):
            self.parse_decl_specifiers()  # underlying type
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

    @production("class_specifier")
    def parse_class_specifier(self) -> tuple[str, Optional[A.Node]]:
        kw = self.advance()
        name = ""
        if self.cur.type == TokenType.IDENTIFIER or self.check("::"):
            name = self.parse_qualified_type()
        if self.cur.type == TokenType.IDENTIFIER and self.cur.lexeme == "final":
            self.advance()
        if not (self.check("{") or self.check(":")):
            if name:
                self.typedefs.add(name.split("::")[-1])
            return name, None
        short = name.split("::")[-1].split("<")[0]
        if short:
            self.typedefs.add(short)
        bases: list[str] = []
        if self.accept(":"):
            while True:
                while self.check_kw("virtual", *ACCESS):
                    self.advance()
                bases.append(self.parse_qualified_type())
                if not self.accept(","):
                    break
        self.expect("{", "to open class body")
        cls = A.ClassDecl(tag=kw.lexeme, name=name, bases=bases, line=kw.line, col=kw.col)
        self.note("match", f"{kw.lexeme} '{name or '<anonymous>'}' registered as a type name", kw)
        self.class_stack.append(short)
        access = "private" if kw.lexeme == "class" else "public"
        try:
            while not self.check("}") and not self.at_end():
                before = self.pos
                try:
                    if self.check_kw(*ACCESS) and self.peek().is_op(":"):
                        access = self.advance().lexeme
                        self.advance()
                        self.count("member_specification")
                        continue
                    cls.members.extend(self.parse_member(short, access))
                except ParseError as err:
                    self.record_error(err, "")
                    self.errors[-1].recovery = self.sync_statement()
                if self.pos == before:
                    self.advance()
        finally:
            self.class_stack.pop()
        self.expect("}", "to close class body")
        return name, cls

    @production("member_specification")
    def parse_member(self, class_name: str, access: str) -> list[A.Node]:
        if self.accept(";"):
            return []
        tok = self.cur
        if self.check_kw("template"):
            self.skip_template_header()
            return self.parse_member(class_name, access)
        if self.check_kw("using"):
            return [self.parse_using()]
        if self.check_kw("static_assert"):
            self.skip_to_semicolon()
            return []
        if self.check_kw("friend"):
            self.advance()
            if self.check_kw("class", "struct") and self.tok_at(self.pos + 2).is_op(";"):
                self.skip_to_semicolon()
                return []
            return self.parse_member(class_name, access)
        if self.ctor_ahead(class_name):
            return [self.parse_constructor(access)]
        start = self.cur
        spec = self.parse_decl_specifiers()
        spec["storage"] = " ".join(x for x in (access, spec["storage"]) if x)
        if self.accept(";"):
            return spec["records"]
        out = list(spec["records"])
        while True:
            decl = self.parse_declarator()
            if decl.params is not None and not decl.func_pointer and (self.check("{") or self.check_kw("try")):
                out.append(self.parse_function_definition(spec, decl, start))
                return out
            if self.accept(":"):  # bit-field width
                self.parse_conditional()
            out.append(self.build_declaration(spec, decl, False))
            if not self.accept(","):
                break
        self.expect(";", "after member declaration")
        return out

    # --------------------------------------------------------- constructors
    def ctor_ahead(self, class_name: Optional[str] = None) -> bool:
        i = self.pos
        while self.tok_at(i).is_kw("explicit", "inline", "constexpr", "virtual"):
            i += 1
        names: list[str] = []
        while True:
            tilde = self.tok_at(i).is_op("~")
            if tilde:
                i += 1
            if self.tok_at(i).type != TokenType.IDENTIFIER:
                return False
            names.append(("~" if tilde else "") + self.tok_at(i).lexeme)
            i += 1
            if self.tok_at(i).is_op("<"):
                k = self.scan_angle(i)
                if k == -1:
                    return False
                i = k
            if self.tok_at(i).is_op("::"):
                i += 1
                continue
            break
        if not self.tok_at(i).is_op("("):
            return False
        last = names[-1].lstrip("~")
        if len(names) == 1:
            return class_name is not None and last == class_name
        return last == names[-2]

    @production("constructor_definition")
    def parse_constructor(self, access: str = "") -> A.Node:
        start = self.cur
        storage: list[str] = [access] if access else []
        while self.check_kw("explicit", "inline", "constexpr", "virtual"):
            storage.append(self.advance().lexeme)
        parts: list[str] = []
        while True:
            if self.accept("~"):
                parts.append("~")
            parts.append(self.expect_ident("in constructor name").lexeme)
            if self.check("<"):
                self.angle_text()
            if self.accept("::"):
                parts.append("::")
                continue
            break
        name = "".join(parts)
        params, variadic = self.parse_parameter_list()
        self.skip_function_qualifiers()
        if self.accept("="):  # = default / = delete
            self.advance()
            self.expect(";", "after defaulted constructor")
            return A.FunctionDecl(name=name, params=params, line=start.line, col=start.col)
        if self.accept(";"):
            return A.FunctionDecl(name=name, params=params, line=start.line, col=start.col)
        inits: list[A.Node] = []
        if self.accept(":"):  # member initialiser list becomes assignments at the top of the body
            while True:
                mtok = self.cur
                member = self.parse_qualified_type()
                if self.check("{"):
                    value: A.Node = self.parse_initializer()
                else:
                    self.expect("(", "in member initializer")
                    args: list[A.Node] = []
                    while not self.check(")") and not self.at_end():
                        args.append(self.parse_assignment())
                        if not self.accept(","):
                            break
                    self.expect(")", "to close member initializer")
                    value = args[0] if len(args) == 1 else A.InitList(items=args, line=mtok.line, col=mtok.col)
                inits.append(A.ExprStmt(expr=A.Assignment(op="=", target=A.Identifier(name=member, line=mtok.line,
                                                                                     col=mtok.col),
                                                          value=value, line=mtok.line, col=mtok.col),
                                        line=mtok.line, col=mtok.col))
                if not self.accept(","):
                    break
        body = self.parse_compound()
        body.items[:0] = inits
        kind = "destructor" if "~" in name else "constructor"
        self.note("match", f"{kind} '{name}'", start)
        return A.FunctionDef(name=name, return_type="", storage=" ".join(storage), params=params,
                             variadic=variadic, body=body, line=start.line, col=start.col)

    def skip_function_qualifiers(self) -> None:
        while True:
            if self.check_kw("const", "volatile") or self.check("&", "&&"):
                self.advance()
            elif self.check_kw("noexcept", "throw"):
                self.advance()
                if self.check("("):
                    self.pos = self.matching(self.pos) + 1
            elif self.cur.type == TokenType.IDENTIFIER and self.cur.lexeme in ("override", "final"):
                self.advance()
            elif self.check("->"):  # trailing return type
                self.advance()
                self.parse_type_name()
            else:
                return

    # ---------------------------------------------------------- declarators
    def args_ahead(self) -> bool:
        """At '(' after a declarator name: constructor arguments rather than a parameter list?"""
        nxt = self.peek()
        if nxt.is_op(")") or nxt.is_op("..."):
            return False
        if nxt.type == TokenType.KEYWORD:
            return not (nxt.lexeme in CPP_TYPE_KEYWORDS | QUALIFIERS | CPP_STORAGE |
                        {"struct", "class", "enum", "union", "typename", "decltype"})
        if nxt.type == TokenType.IDENTIFIER or nxt.is_op("::"):
            j, name = self.scan_qualified(self.pos + 1)
            if j == -1:
                return True
            k = self.skip_ptr_ops(j)
            if self.tok_at(k).type == TokenType.IDENTIFIER:
                return False
            return not self.is_known_type(name)
        return True

    @production("declarator")
    def parse_declarator(self, abstract: bool = False) -> Declarator:
        d = Declarator()
        refs = ""
        while True:
            if self.accept("*"):
                d.pointer_depth += 1
            elif self.check("&", "&&"):
                refs += self.advance().lexeme
            elif self.check_kw(*QUALIFIERS):
                self.advance()
            else:
                break
        if self.check("(") and (self.peek().is_op("*") or self.peek().is_op("&") or self.peek().is_op("(")):
            self.advance()
            inner = self.parse_declarator(abstract)
            self.expect(")", "after parenthesised declarator")
            d.name, d.token = inner.name, inner.token
            d.func_pointer = inner.pointer_depth > 0
            d.pointer_depth += max(inner.pointer_depth - 1, 0)
            d.array_dims = inner.array_dims
        elif self.check("[") and not abstract:  # structured binding: auto [a, b] = …
            tok = self.advance()
            names = [self.expect_ident("in structured binding").lexeme]
            while self.accept(","):
                names.append(self.expect_ident("in structured binding").lexeme)
            self.expect("]", "to close structured binding")
            d.name, d.token = f"[{', '.join(names)}]", tok
        elif self.accept("..."):
            if self.cur.type == TokenType.IDENTIFIER:
                d.token = self.advance()
                d.name = d.token.lexeme
        elif self.cur.type == TokenType.IDENTIFIER or self.check("::", "~") or self.check_kw("operator"):
            d.token = self.cur
            d.name = self.parse_declarator_name()
        elif not abstract:
            found = self.cur.lexeme or "end of input"
            raise ParseError(f"expected identifier in declarator but found '{found}'", self.cur)
        while True:
            if self.accept("["):
                if self.check("]"):
                    d.array_dims.append(None)
                else:
                    d.array_dims.append(self.const_value(self.parse_assignment()))
                self.expect("]", "to close array size")
            elif self.check("(") and d.params is None:
                if not abstract and d.name and not self.in_params and self.args_ahead():
                    self.enter("constructor_arguments")
                    try:
                        self.advance()
                        args: list[A.Node] = []
                        while not self.check(")") and not self.at_end():
                            args.append(self.parse_assignment())
                            if not self.accept(","):
                                break
                        self.expect(")", "to close constructor arguments")
                    finally:
                        self.depth -= 1
                    d.ctor_args = args  # type: ignore[attr-defined]
                    break
                params, variadic = self.parse_parameter_list()
                d.params, d.variadic = params, variadic
                self.skip_function_qualifiers()
            else:
                break
        d.refs = refs  # type: ignore[attr-defined]
        return d

    def parse_declarator_name(self) -> str:
        parts: list[str] = []
        if self.accept("::"):
            parts.append("::")
        while True:
            if self.accept("~"):
                parts.append("~")
            if self.check_kw("operator"):
                self.advance()
                op = []
                if self.check("(") and self.peek().is_op(")"):
                    op = ["()"]
                    self.advance()
                    self.advance()
                elif self.check("[") and self.peek().is_op("]"):
                    op = ["[]"]
                    self.advance()
                    self.advance()
                else:
                    while not self.check("(") and not self.at_end():
                        op.append(self.advance().lexeme)
                parts.append("operator" + "".join(op))
                return "".join(parts)
            parts.append(self.expect_ident("in declarator").lexeme)
            if self.check("<") and self.tok_at(self.scan_angle(self.pos)).is_op("::"):
                parts.append(self.angle_text())
            if self.check("::"):
                self.advance()
                parts.append("::")
                continue
            return "".join(parts)

    @production("parameter_list")
    def parse_parameter_list(self) -> tuple[list[A.Param], bool]:
        self.in_params += 1
        try:
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
                if self.accept("="):  # default argument
                    self.parse_assignment()
                depth = d.pointer_depth + (1 if d.func_pointer else 0)
                type_str = spec["type"] + (" " + "*" * depth if depth else "") + getattr(d, "refs", "")
                params.append(A.Param(name=d.name, type=type_str.strip(), pointer_depth=depth,
                                      array_dims=d.array_dims, line=(d.token or tok).line,
                                      col=(d.token or tok).col))
                if not self.accept(","):
                    break
            self.expect(")", "to close parameter list")
            return params, variadic
        finally:
            self.in_params -= 1

    def build_declaration(self, spec: dict, decl: Declarator, top_level: bool) -> A.Node:
        tok = decl.token or self.cur
        self.count("init_declarator")
        refs = getattr(decl, "refs", "")
        ptr = " " + "*" * decl.pointer_depth if decl.pointer_depth else ""
        if spec["storage"].endswith("typedef"):
            self.typedefs.add(decl.name)
            self.note("match", f"typedef name '{decl.name}' added to the type table", tok)
            return A.TypedefDecl(name=decl.name, type=(spec["type"] + ptr).strip(), line=tok.line, col=tok.col)
        if decl.params is not None and not decl.func_pointer:
            if self.accept("="):  # = 0 / = default / = delete
                self.advance()
            return A.FunctionDecl(name=decl.name, return_type=(spec["type"] + ptr + refs).strip(),
                                  params=decl.params, variadic=decl.variadic, line=tok.line, col=tok.col)
        init: Optional[A.Node] = None
        ctor_args = getattr(decl, "ctor_args", None)
        if ctor_args is not None:
            init = A.Call(callee=A.Identifier(name=spec["type"].replace("const ", ""), line=tok.line, col=tok.col),
                          args=ctor_args, line=tok.line, col=tok.col)
        elif self.accept("="):
            init = self.parse_initializer()
        elif self.check("{"):  # brace (list) initialisation
            init = self.parse_initializer()
        type_str = (spec["type"] + ptr + refs).strip()
        if decl.func_pointer:
            type_str = spec["type"] + " (*)()"
        return A.VarDecl(name=decl.name, type=type_str, base_type=spec["type"],
                         pointer_depth=decl.pointer_depth + (1 if decl.func_pointer else 0),
                         array_dims=decl.array_dims, storage=spec["storage"], is_const=spec["const"],
                         init=init, line=tok.line, col=tok.col)

    # ------------------------------------------------------------ top level
    def skip_template_header(self) -> None:
        tok = self.advance()  # template
        self.enter("template_declaration")
        try:
            if self.check("<"):
                header = self.angle_text()
                # template parameters behave like type names inside the declaration
                params = [p.split()[-1] for p in header[1:-1].split(",") if p.strip().startswith(("typename", "class"))
                          and len(p.split()) > 1]
                self.typedefs.update(params)
                self.note("match", f"template header {header} skipped; type parameters: {', '.join(params) or '—'}",
                          tok)
        finally:
            self.depth -= 1

    def skip_to_semicolon(self) -> None:
        while not self.at_end() and not self.check(";"):
            if self.check("{", "("):
                end = self.matching(self.pos)
                self.pos = end if end != -1 else self.pos
            self.advance()
        self.accept(";")

    @production("using_declaration")
    def parse_using(self) -> A.Node:
        tok = self.advance()
        if self.check_kw("namespace"):
            self.advance()
            module = self.parse_qualified_type()
            self.expect(";", "after using-directive")
            self.note("match", f"names from namespace '{module}' are visible unqualified", tok)
            return A.ImportDecl(tag="using namespace", module=module, line=tok.line, col=tok.col)
        if self.cur.type == TokenType.IDENTIFIER and self.peek().is_op("="):
            name = self.advance().lexeme
            self.advance()
            type_name = self.parse_type_name()
            self.expect(";", "after alias declaration")
            self.typedefs.add(name)
            return A.TypedefDecl(name=name, type=type_name, line=tok.line, col=tok.col)
        self.accept_kw_typename()
        module = self.parse_qualified_type()
        self.expect(";", "after using-declaration")
        self.typedefs.add(module.split("::")[-1]) if self.is_known_type(module) else None
        return A.ImportDecl(tag="using", module=module, names=[module.split("::")[-1]], line=tok.line, col=tok.col)

    def accept_kw_typename(self) -> None:
        if self.check_kw("typename"):
            self.advance()

    @production("namespace_definition")
    def parse_namespace(self) -> A.Node:
        tok = self.cur
        if self.check_kw("inline"):
            self.advance()
        self.advance()  # namespace
        name = self.parse_qualified_type() if self.cur.type == TokenType.IDENTIFIER else ""
        if self.accept("="):  # namespace alias
            self.parse_qualified_type()
            self.expect(";")
            return A.ImportDecl(tag="namespace alias", module=name, line=tok.line, col=tok.col)
        ns = A.ClassDecl(tag="namespace", name=name, line=tok.line, col=tok.col)
        self.expect("{", "to open namespace")
        ns.members = self.parse_declaration_seq()
        self.expect("}", "to close namespace")
        return ns

    def parse_declaration_seq(self) -> list[A.Node]:
        out: list[A.Node] = []
        while not self.check("}") and not self.at_end():
            before = self.pos
            try:
                out.extend(self.parse_external_declaration())
            except ParseError as err:
                self.pos = max(self.pos, before)
                self.record_error(err, "")
                self.errors[-1].recovery = self.sync_top_level()
            if self.pos == before:
                self.advance()
        return out

    @production("external_declaration")
    def parse_external_declaration(self) -> list[A.Node]:
        if self.accept(";"):
            return []
        tok = self.cur
        if self.check_kw("template"):
            self.skip_template_header()
            return self.parse_external_declaration()
        if self.check_kw("namespace") or (self.check_kw("inline") and self.peek().is_kw("namespace")):
            return [self.parse_namespace()]
        if self.check_kw("using"):
            return [self.parse_using()]
        if self.check_kw("static_assert"):
            self.skip_to_semicolon()
            return []
        if self.check_kw("extern") and self.peek().type == TokenType.STRING_LITERAL:
            self.advance()
            self.advance()
            self.note("match", "linkage specification extern \"…\"", tok)
            if self.accept("{"):
                decls = self.parse_declaration_seq()
                self.expect("}", "to close linkage block")
                return decls
            return self.parse_external_declaration()
        if self.ctor_ahead():
            return [self.parse_constructor()]
        if not self.starts_top_level_declaration():
            # Snippet support: statements pasted outside any function.
            return [self.parse_statement()]
        return Parser.parse_external_declaration.__wrapped__(self)

    def starts_top_level_declaration(self) -> bool:
        tok = self.cur
        if tok.type == TokenType.KEYWORD:
            return tok.lexeme not in ("if", "for", "while", "do", "switch", "return", "try", "throw", "delete",
                                      "new", "this", "break", "continue", "goto", "case", "default", "sizeof",
                                      "true", "false", "nullptr") and tok.lexeme not in CASTS
        if tok.type == TokenType.IDENTIFIER or tok.is_op("::"):
            j, name = self.scan_qualified(self.pos)
            if j == -1:
                return False
            k = self.skip_ptr_ops(j)
            nxt = self.tok_at(k)
            return nxt.type == TokenType.IDENTIFIER or nxt.is_kw("operator") or nxt.is_op("~") or \
                (self.is_known_type(name) and not self.tok_at(j).is_op("(", "<<", ">>", ".", "->", "="))
        return False

    @production("function_definition")
    def parse_function_definition(self, spec: dict, decl: Declarator, start: Token) -> A.FunctionDef:
        ptr = " " + "*" * decl.pointer_depth if decl.pointer_depth else ""
        ret = (spec["type"] + ptr + getattr(decl, "refs", "")).strip()
        self.note("match", f"function '{decl.name}' returns {ret}", decl.token)
        if self.check_kw("try"):  # function-try-block
            node = self.parse_try()
            body = A.Compound(items=[node], line=node.line, col=node.col)
        else:
            body = self.parse_compound()
        return A.FunctionDef(name=decl.name, return_type=ret, storage=spec["storage"], params=decl.params or [],
                             variadic=decl.variadic, body=body, line=start.line, col=start.col)

    # ------------------------------------------------------------ statements
    @production("statement")
    def parse_statement(self) -> A.Node:
        tok = self.cur
        if tok.type == TokenType.KEYWORD:
            if tok.lexeme == "try":
                return self.parse_try()
            if tok.lexeme == "throw":
                return self.parse_throw()
            if tok.lexeme == "using":
                return self.parse_using()
            if tok.lexeme == "static_assert":
                self.skip_to_semicolon()
                return A.EmptyStmt(line=tok.line, col=tok.col)
            if tok.lexeme == "if" and self.peek().is_kw("constexpr"):
                self.tokens.pop(self.pos + 1)
        return Parser.parse_statement.__wrapped__(self)

    @production("for_statement")
    def parse_for(self) -> A.Node:
        tok = self.advance()
        self.expect("(", "after 'for'")
        init = None
        if self.starts_declaration():
            start = self.cur
            spec = self.parse_decl_specifiers()
            decl = self.parse_declarator()
            if self.accept(":"):
                self.enter("range_based_for")
                try:
                    var = self.build_declaration(spec, decl, False)
                    iterable = self.parse_expression()
                    self.expect(")", "to close for header")
                    body = self.parse_statement()
                finally:
                    self.depth -= 1
                return A.ForEach(decl=var, iterable=iterable, body=body, line=tok.line, col=tok.col)
            init = A.DeclStmt(decls=self.finish_declaration(spec, decl, start, top_level=False),
                              line=start.line, col=start.col)
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

    def parse_catch_param(self) -> Optional[A.Param]:
        if self.accept("..."):
            return None
        tok = self.cur
        self.in_params += 1
        try:
            spec = self.parse_decl_specifiers()
            d = self.parse_declarator(abstract=True)
        finally:
            self.in_params -= 1
        type_str = (spec["type"] + ("*" * d.pointer_depth) + getattr(d, "refs", "")).strip()
        return A.Param(name=d.name, type=type_str, pointer_depth=d.pointer_depth,
                       line=(d.token or tok).line, col=(d.token or tok).col)

    # ----------------------------------------------------------- expressions
    def parse_unary(self) -> A.Node:
        tok = self.cur
        if tok.is_kw("delete") or (tok.is_op("::") and self.peek().is_kw("delete")):
            if tok.is_op("::"):
                self.advance()
            dtok = self.advance()
            self.enter("delete_expression")
            try:
                is_array = False
                if self.check("[") and self.peek().is_op("]"):
                    self.advance()
                    self.advance()
                    is_array = True
                operand = self.parse_cast()
            finally:
                self.depth -= 1
            return A.Delete(is_array=is_array, operand=operand, line=dtok.line, col=dtok.col)
        if tok.is_kw("throw"):
            self.advance()
            return A.UnaryOp(op="throw", operand=self.parse_assignment(), line=tok.line, col=tok.col)
        return super().parse_unary()

    @production("new_expression")
    def parse_new(self) -> A.Node:
        if self.check("::"):
            self.advance()
        tok = self.advance()
        if self.check("(") and not self.is_type_start(self.peek()):  # placement new
            self.pos = self.matching(self.pos) + 1
        parenthesised = self.accept("(")
        words: list[str] = []
        while self.check_kw(*QUALIFIERS) or self.check_kw(*CPP_TYPE_KEYWORDS):
            words.append(self.advance().lexeme)
        if not words or words == ["const"]:
            words.append(self.parse_qualified_type())
        stars = 0
        while self.accept("*"):
            stars += 1
        if parenthesised:
            self.expect(")", "to close new type")
        type_name = " ".join(words) + ("*" * stars)
        node = A.New(type=type_name, line=tok.line, col=tok.col)
        if self.check("["):
            node.is_array = True
            while self.accept("["):
                size = self.parse_expression()
                if node.array_size is None:
                    node.array_size = size
                self.expect("]", "to close array size")
        if self.check("("):
            self.advance()
            while not self.check(")") and not self.at_end():
                node.args.append(self.parse_assignment())
                if not self.accept(","):
                    break
            self.expect(")", "to close constructor arguments")
        elif self.check("{"):
            node.init = self.parse_initializer()
        self.note("match", f"dynamic allocation 'new {type_name}{'[]' if node.is_array else ''}'", tok)
        return node

    @production("lambda_expression")
    def parse_lambda(self) -> A.Node:
        tok = self.advance()  # [
        close = self.matching(self.pos - 1)
        captures = join_lexemes([t.lexeme for t in self.tokens[self.pos:close]]) if close != -1 else ""
        self.pos = close + 1 if close != -1 else self.pos
        params: list[A.Param] = []
        if self.check("("):
            params, _ = self.parse_parameter_list()
        while self.check_kw("mutable", "constexpr", "noexcept") or (self.cur.type == TokenType.IDENTIFIER
                                                                   and self.cur.lexeme == "mutable"):
            self.advance()
        if self.accept("->"):
            self.parse_type_name()
        body = self.parse_compound()
        return A.Lambda(params=params, captures=f"[{captures}]", body=body, line=tok.line, col=tok.col)

    @production("cpp_cast")
    def parse_cpp_cast(self) -> A.Node:
        tok = self.advance()
        if not self.check("<"):
            raise ParseError(f"expected '<' after {tok.lexeme}", self.cur)
        target = self.angle_text()
        self.expect("(", f"after {tok.lexeme}<…>")
        expr = self.parse_expression()
        self.expect(")", f"to close {tok.lexeme}")
        return A.Cast(type=f"{tok.lexeme}{target}", expr=expr, line=tok.line, col=tok.col)

    def parse_primary(self) -> A.Node:
        tok = self.cur
        if tok.type == TokenType.KEYWORD:
            if tok.lexeme in LITERAL_KEYWORDS:
                self.count("primary_expression")
                self.advance()
                return A.KeywordLiteral(value=tok.lexeme, line=tok.line, col=tok.col)
            if tok.lexeme == "new":
                return self.parse_new()
            if tok.lexeme in CASTS:
                return self.parse_cpp_cast()
            if tok.lexeme in ("typeid", "alignof", "noexcept", "decltype"):
                self.advance()
                close = self.matching(self.pos)
                self.pos = close + 1 if close != -1 else self.pos
                return A.Identifier(name=tok.lexeme, line=tok.line, col=tok.col)
            if tok.lexeme in CPP_TYPE_KEYWORDS and self.peek().is_op("(", "{"):  # functional cast int(x)
                self.advance()
                return self.finish_construction(A.Identifier(name=tok.lexeme, line=tok.line, col=tok.col))
        if tok.is_op("::") and self.peek().is_kw("new"):
            return self.parse_new()
        if self.check("["):
            return self.parse_lambda()
        if tok.type == TokenType.IDENTIFIER or tok.is_op("::"):
            self.count("primary_expression")
            name = self.parse_expression_name()
            ident = A.Identifier(name=name, line=tok.line, col=tok.col)
            if self.check("{") and self.is_known_type(name):
                return self.finish_construction(ident)
            return ident
        return super().parse_primary()

    def finish_construction(self, callee: A.Node) -> A.Node:
        """T(args) or T{args}: a temporary of type T, represented as a call to its constructor."""
        if self.check("("):
            return self.parse_call(callee)
        init = self.parse_initializer()
        items = init.items if isinstance(init, A.InitList) else [init]
        return A.Call(callee=callee, args=items, line=callee.line, col=callee.col)

    def parse_expression_name(self) -> str:
        parts: list[str] = []
        if self.accept("::"):
            parts.append("::")
        while True:
            if self.accept("~"):
                parts.append("~")
            parts.append(self.expect_ident("in name").lexeme)
            if self.check("<"):
                k = self.scan_angle(self.pos)
                if k != -1 and self.tok_at(k).is_op("(", "::", "{"):
                    parts.append(self.angle_text())
            if self.check("::") and (self.peek().type == TokenType.IDENTIFIER or self.peek().is_op("~")):
                self.advance()
                parts.append("::")
                continue
            return "".join(parts)


def parse_cpp(tokens: list[Token], constants: Optional[dict[str, int]] = None):
    result = CppParser(tokens, constants).parse()
    A.link_tree(result.ast)
    return result
