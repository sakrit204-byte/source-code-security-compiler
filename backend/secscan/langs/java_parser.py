"""Recursive-descent parser for Java (Java 17 subset: packages, imports,
classes / interfaces / enums / records, generics, lambdas, method
references, try-with-resources, enhanced for and arrow-form switch).

Local variable declarations are recognised by bounded lookahead: a type
(primitive or qualified name with optional type arguments and '[]') followed
by an identifier. Nested generics such as List<List<String>> are closed by
splitting the '>>' token produced by the maximal-munch lexer.
"""

from __future__ import annotations

from typing import Optional

from .. import ast_nodes as A
from ..parser import ASSIGN_OPS, BINARY_PRECEDENCE, ParseError, Parser, production
from ..tokens import Token, TokenType
from .common import SharedSyntax

GRAMMAR = [
    ("compilation_unit", "package_declaration? import_declaration* type_declaration*"),
    ("package_declaration", "package qualified_name ';'"),
    ("import_declaration", "import static? qualified_name ('.' '*')? ';'"),
    ("type_declaration", "modifier* (class_declaration | interface_declaration | enum_declaration | record_declaration)"),
    ("class_declaration", "class IDENTIFIER type_parameters? (extends type)? (implements type_list)? class_body"),
    ("class_body", "'{' class_member* '}'"),
    ("class_member", "field_declaration | method_declaration | constructor_declaration | initializer_block | type_declaration | ';'"),
    ("field_declaration", "modifier* type variable_declarator (',' variable_declarator)* ';'"),
    ("method_declaration", "modifier* type_parameters? (type | void) IDENTIFIER '(' formal_parameters? ')' dims? (throws type_list)? (block | ';')"),
    ("constructor_declaration", "modifier* IDENTIFIER '(' formal_parameters? ')' (throws type_list)? block"),
    ("formal_parameters", "modifier* type '...'? IDENTIFIER dims? (',' …)*"),
    ("type", "(primitive_type | qualified_name type_arguments?) ('[' ']')*"),
    ("type_arguments", "'<' (type | '?' ((extends | super) type)?) (',' …)* '>'"),
    ("enum_declaration", "enum IDENTIFIER (implements type_list)? '{' enum_constant (',' enum_constant)* (';' class_member*)? '}'"),
    ("block", "'{' block_statement* '}'"),
    ("local_variable_declaration", "final? (type | var) variable_declarator (',' variable_declarator)* ';'"),
    ("variable_declarator", "IDENTIFIER dims? ('=' (expression | array_initializer))?"),
    ("statement", "block | if | while | do_while | for | enhanced_for | switch | try | throw | return | break | continue | synchronized | assert | labeled | expression_statement"),
    ("enhanced_for", "for '(' final? type IDENTIFIER ':' expression ')' statement"),
    ("for_statement", "for '(' (local_variable_declaration | expression_list? ';') expression? ';' expression_list? ')' statement"),
    ("switch_statement", "switch '(' expression ')' '{' (case expression (',' expression)* (':' | '->') … | default (':' | '->') …)* '}'"),
    ("try_statement", "try ('(' resource (';' resource)* ')')? block catch_clause* (finally block)?"),
    ("catch_clause", "catch '(' final? type ('|' type)* IDENTIFIER ')' block"),
    ("throw_statement", "throw expression ';'"),
    ("jump_statement", "return expression? ';' | break IDENTIFIER? ';' | continue IDENTIFIER? ';'"),
    ("expression", "assignment_expression"),
    ("assignment_expression", "lambda_expression | conditional_expression (assign_op assignment_expression)?"),
    ("lambda_expression", "(IDENTIFIER | '(' parameters ')') '->' (expression | block)"),
    ("conditional_expression", "binary_expression ('?' expression ':' conditional_expression)?"),
    ("binary_expression", "unary_expression (binary_op unary_expression)*   — precedence climbing, instanceof type"),
    ("cast_expression", "'(' type ')' unary_expression"),
    ("unary_expression", "('++' | '--' | '+' | '-' | '~' | '!') unary_expression | cast_expression | postfix_expression"),
    ("postfix_expression", "primary ('.' IDENTIFIER | '[' expression ']' | arguments | '::' IDENTIFIER | '++' | '--')*"),
    ("function_call", "postfix_expression '(' (expression (',' expression)*)? ')'"),
    ("object_creation", "new type ('(' arguments? ')' class_body? | ('[' expression ']')+ ('[' ']')* | ('[' ']')+ array_initializer)"),
    ("array_initializer", "'{' (variable_initializer (',' variable_initializer)*)? ','? '}'"),
    ("primary_expression", "literal | this | super | IDENTIFIER | primitive_type '.' class | '(' expression ')' | object_creation"),
]

PRIMITIVES = {"boolean", "byte", "char", "short", "int", "long", "float", "double", "void"}
MODIFIERS = {"public", "private", "protected", "static", "final", "abstract", "native", "synchronized",
             "transient", "volatile", "strictfp", "default"}
CONTEXTUAL_MODIFIERS = {"sealed"}
LITERAL_KEYWORDS = {"true", "false", "null", "this", "super"}
TYPE_DECL_KEYWORDS = {"class", "interface", "enum"}

JAVA_PRECEDENCE = {**BINARY_PRECEDENCE, ">>>": 8, "instanceof": 7}


class JavaParser(SharedSyntax, Parser):
    LANGUAGE = "Java"
    GRAMMAR = GRAMMAR
    BINARY_PRECEDENCE = JAVA_PRECEDENCE
    ASSIGN_OPS = ASSIGN_OPS | {">>>="}
    UNARY_OPS = {"++", "--", "+", "-", "~", "!"}
    ASSIGNABLE = (A.Identifier, A.Index, A.Member)

    def __init__(self, tokens: list[Token], constants: Optional[dict[str, int]] = None):
        super().__init__(tokens, constants)
        self.typedefs = set()
        self.class_names: set[str] = set()

    def binary_prec(self, tok: Token) -> Optional[int]:
        if tok.type == TokenType.KEYWORD and tok.lexeme == "instanceof":
            return 7
        return super().binary_prec(tok)

    def parse_binary_rhs(self, op: Token, prec: int) -> A.Node:
        if op.lexeme == "instanceof":
            tok = self.cur
            self.accept_kw("final")
            type_name = self.parse_type()
            if self.cur.type == TokenType.IDENTIFIER:  # pattern matching: x instanceof Foo f
                self.advance()
            return A.Identifier(name=type_name, line=tok.line, col=tok.col)
        return super().parse_binary_rhs(op, prec)

    def accept_kw(self, *words: str) -> Optional[Token]:
        return self.advance() if self.check_kw(*words) else None

    # -------------------------------------------------------- type lookahead
    def scan_type(self, i: int) -> int:
        """Index after a type starting at i, or -1 when the tokens there cannot form a type."""
        t = self.tok_at(i)
        if t.type == TokenType.KEYWORD and t.lexeme in PRIMITIVES:
            i += 1
        elif t.type == TokenType.IDENTIFIER:
            i += 1
            while True:
                if self.tok_at(i).is_op("<"):
                    i = self.scan_angle(i)
                    if i == -1:
                        return -1
                if self.tok_at(i).is_op(".") and self.tok_at(i + 1).type == TokenType.IDENTIFIER:
                    i += 2
                    continue
                break
        else:
            return -1
        while self.tok_at(i).is_op("[") and self.tok_at(i + 1).is_op("]"):
            i += 2
        return i

    def declaration_ahead(self, i: Optional[int] = None) -> bool:
        """type IDENTIFIER followed by '=', ';', ',', ':' or '[' starts a variable declaration."""
        i = self.pos if i is None else i
        while self.tok_at(i).is_kw("final"):
            i += 1
        j = self.scan_type(i)
        if j == -1 or self.tok_at(j).type != TokenType.IDENTIFIER:
            return False
        return self.tok_at(j + 1).is_op("=", ";", ",", ":", "[") or self.tok_at(j + 1).type == TokenType.EOF

    @production("type")
    def parse_type(self) -> str:
        tok = self.cur
        if tok.type == TokenType.KEYWORD and tok.lexeme in PRIMITIVES:
            text = self.advance().lexeme
        elif tok.type == TokenType.IDENTIFIER:
            text = self.advance().lexeme
            while True:
                if self.check("<"):
                    self.count("type_arguments")
                    text += self.angle_text()
                if self.check(".") and self.peek().type == TokenType.IDENTIFIER:
                    self.advance()
                    text += "." + self.advance().lexeme
                    continue
                break
        else:
            raise ParseError(f"expected a type but found '{tok.lexeme or 'end of input'}'", tok)
        while self.check("[") and self.peek().is_op("]"):
            self.advance()
            self.advance()
            text += "[]"
        return text

    def parse_modifiers(self) -> list[str]:
        mods: list[str] = []
        while True:
            if self.cur.type == TokenType.KEYWORD and self.cur.lexeme in MODIFIERS and \
                    not (self.cur.lexeme == "default" and self.peek().is_op(":", "->")):
                mods.append(self.advance().lexeme)
            elif self.cur.type == TokenType.IDENTIFIER and self.cur.lexeme in CONTEXTUAL_MODIFIERS and \
                    self.peek().type in (TokenType.KEYWORD, TokenType.IDENTIFIER):
                mods.append(self.advance().lexeme)
            elif self.cur.type == TokenType.IDENTIFIER and self.cur.lexeme == "non" and self.peek().is_op("-"):
                self.advance()
                self.advance()
                mods.append("non-" + self.advance().lexeme)
            else:
                return mods

    def type_decl_ahead(self) -> bool:
        t = self.cur
        return t.type == TokenType.KEYWORD and t.lexeme in TYPE_DECL_KEYWORDS or \
            (t.type == TokenType.IDENTIFIER and t.lexeme == "record" and self.peek().type == TokenType.IDENTIFIER
             and self.tok_at(self.pos + 2).is_op("(", "<"))

    # ------------------------------------------------------------ top level
    def parse_translation_unit(self) -> A.TranslationUnit:
        self.enter("compilation_unit")
        try:
            unit = A.TranslationUnit(line=1, col=1)
            while not self.at_end():
                before = self.pos
                try:
                    unit.decls.extend(self.parse_external_declaration())
                except ParseError as err:
                    self.pos = max(self.pos, before)
                    self.record_error(err, "")
                    self.errors[-1].recovery = self.sync_top_level()
                if self.pos == before:
                    self.advance()
            return unit
        finally:
            self.depth -= 1

    def parse_external_declaration(self) -> list[A.Node]:
        if self.accept(";"):
            return []
        tok = self.cur
        if self.check_kw("package", "import"):
            return [self.parse_import()]
        start = self.pos
        mods = self.parse_modifiers()
        if self.type_decl_ahead():
            return [self.parse_type_declaration(mods, tok)]
        # Snippet support: a bare method, field or statement pasted without a class.
        if self.member_ahead():
            self.pos = start
            member = self.parse_class_member("")
            return [member] if member is not None else []
        self.pos = start
        return [self.parse_statement()]

    def member_ahead(self) -> bool:
        i = self.pos
        if self.tok_at(i).is_op("<"):
            i = self.scan_angle(i)
            if i == -1:
                return False
        j = self.scan_type(i)
        return j != -1 and self.tok_at(j).type == TokenType.IDENTIFIER and \
            (self.tok_at(j + 1).is_op("(") or self.declaration_ahead(i))

    @production("import_declaration")
    def parse_import(self) -> A.Node:
        tok = self.advance()
        parts: list[str] = []
        static = bool(self.accept_kw("static"))
        while not self.check(";") and not self.at_end():
            parts.append(self.advance().lexeme)
        self.expect(";", f"after {tok.lexeme} declaration")
        module = "".join(parts)
        if tok.lexeme == "package":
            self.note("match", f"package {module}", tok)
        return A.ImportDecl(tag=("import static" if static else tok.lexeme), module=module,
                            names=[module.rsplit(".", 1)[-1]], line=tok.line, col=tok.col)

    @production("type_declaration")
    def parse_type_declaration(self, mods: list[str], start: Token) -> A.ClassDecl:
        kw = self.advance()
        tag = kw.lexeme
        name_tok = self.expect_ident(f"after '{tag}'")
        self.class_names.add(name_tok.lexeme)
        cls = A.ClassDecl(tag=tag, name=name_tok.lexeme, modifiers=" ".join(mods), line=start.line, col=start.col)
        if self.check("<"):
            self.angle_text()
        if tag == "record" and self.check("("):
            for p in self.parse_formal_parameters():
                cls.members.append(A.VarDecl(name=p.name, type=p.type, base_type=p.type, storage="private final",
                                             is_const=True, line=p.line, col=p.col))
        while self.check_kw("extends", "implements") or (self.cur.type == TokenType.IDENTIFIER
                                                        and self.cur.lexeme == "permits"):
            self.advance()
            cls.bases.append(self.parse_type())
            while self.accept(","):
                cls.bases.append(self.parse_type())
        self.note("match", f"{tag} '{cls.name}'" + (f" extends/implements {', '.join(cls.bases)}" if cls.bases else ""),
                  kw)
        cls.members.extend(self.parse_class_body(cls.name, enum=tag == "enum"))
        return cls

    @production("class_body")
    def parse_class_body(self, class_name: str, enum: bool = False) -> list[A.Node]:
        self.expect("{", "to open class body")
        members: list[A.Node] = []
        if enum:
            members.extend(self.parse_enum_constants(class_name))
        while not self.check("}") and not self.at_end():
            before = self.pos
            try:
                member = self.parse_class_member(class_name)
                if member is not None:
                    members.append(member)
            except ParseError as err:
                self.record_error(err, "")
                self.errors[-1].recovery = self.sync_statement()
            if self.pos == before:
                self.advance()
        self.expect("}", "to close class body")
        return members

    def parse_enum_constants(self, enum_name: str) -> list[A.Node]:
        out: list[A.Node] = []
        while self.cur.type == TokenType.IDENTIFIER:
            tok = self.advance()
            init = A.New(type=enum_name, line=tok.line, col=tok.col)
            if self.check("("):
                init.args = self.parse_arguments()
            if self.check("{"):
                init.init = A.ClassDecl(tag="class", name="", members=self.parse_class_body(""),
                                        line=tok.line, col=tok.col)
            out.append(A.VarDecl(name=tok.lexeme, type=enum_name, base_type=enum_name, storage="public static final",
                                 is_const=True, init=init, line=tok.line, col=tok.col))
            if not self.accept(","):
                break
        self.accept(";")
        return out

    @production("class_member")
    def parse_class_member(self, class_name: str) -> Optional[A.Node]:
        if self.accept(";"):
            return None
        start = self.cur
        mods = self.parse_modifiers()
        if self.check("{"):
            block = self.parse_compound()  # instance / static initialiser
            return block
        if self.type_decl_ahead():
            return self.parse_type_declaration(mods, start)
        if self.check("<"):  # generic method: <T> T pick(...)
            self.angle_text()
        storage = " ".join(mods)
        if self.cur.type == TokenType.IDENTIFIER and self.cur.lexeme == class_name and self.peek().is_op("("):
            name_tok = self.advance()
            self.enter("constructor_declaration")
            try:
                params = self.parse_formal_parameters()
                self.skip_throws()
                body = self.parse_compound()
            finally:
                self.depth -= 1
            return A.FunctionDef(name=name_tok.lexeme, return_type="", storage=storage, params=params, body=body,
                                 line=start.line, col=start.col)
        type_name = self.parse_type()
        name_tok = self.expect_ident("in member declaration")
        if self.check("("):
            return self.parse_method_rest(type_name, name_tok, storage, start)
        decls = self.parse_declarators_after_name(type_name, name_tok, storage, "final" in mods)
        self.expect(";", "after field declaration")
        if len(decls) == 1:
            return decls[0]
        return A.DeclStmt(decls=decls, line=start.line, col=start.col)

    @production("method_declaration")
    def parse_method_rest(self, type_name: str, name_tok: Token, storage: str, start: Token) -> A.Node:
        params = self.parse_formal_parameters()
        while self.check("[") and self.peek().is_op("]"):
            self.advance()
            self.advance()
            type_name += "[]"
        self.skip_throws()
        if self.check_kw("default"):  # annotation element default value
            self.advance()
            self.parse_assignment()
        if self.check("{"):
            self.note("match", f"method '{name_tok.lexeme}' returns {type_name}", name_tok)
            body = self.parse_compound()
            return A.FunctionDef(name=name_tok.lexeme, return_type=type_name, storage=storage, params=params,
                                 body=body, line=start.line, col=start.col)
        self.expect(";", "after abstract method")
        return A.FunctionDecl(name=name_tok.lexeme, return_type=type_name, params=params,
                              line=start.line, col=start.col)

    def skip_throws(self) -> None:
        if self.check_kw("throws"):
            self.advance()
            self.parse_type()
            while self.accept(","):
                self.parse_type()

    @production("formal_parameters")
    def parse_formal_parameters(self) -> list[A.Param]:
        self.expect("(", "to open parameter list")
        params: list[A.Param] = []
        while not self.check(")") and not self.at_end():
            self.parse_modifiers()
            type_name = self.parse_type()
            if self.accept("..."):
                type_name += "..."
            if self.check_kw("this"):  # receiver parameter
                self.advance()
                if not self.accept(","):
                    break
                continue
            name = self.expect_ident("in parameter list")
            dims = []
            while self.check("[") and self.peek().is_op("]"):
                self.advance()
                self.advance()
                type_name += "[]"
            dims = [None] * type_name.count("[]") + ([None] if type_name.endswith("...") else [])
            params.append(A.Param(name=name.lexeme, type=type_name, array_dims=dims, line=name.line, col=name.col))
            if not self.accept(","):
                break
        self.expect(")", "to close parameter list")
        return params

    # ------------------------------------------------------- declarations
    def starts_declaration(self) -> bool:
        return self.declaration_ahead()

    @production("local_variable_declaration")
    def parse_local_declaration(self) -> A.Node:
        start = self.cur
        mods = self.parse_modifiers()
        type_name = self.parse_type()
        name_tok = self.expect_ident("in variable declaration")
        decls = self.parse_declarators_after_name(type_name, name_tok, " ".join(mods), "final" in mods)
        self.expect(";", "after variable declaration")
        return A.DeclStmt(decls=decls, line=start.line, col=start.col)

    def parse_declarators_after_name(self, type_name: str, name_tok: Token, storage: str,
                                     final: bool) -> list[A.Node]:
        decls: list[A.Node] = []
        while True:
            self.count("variable_declarator")
            this_type = type_name
            while self.check("[") and self.peek().is_op("]"):
                self.advance()
                self.advance()
                this_type += "[]"
            init = None
            if self.accept("="):
                init = self.parse_array_initializer() if self.check("{") else self.parse_assignment()
            dims = [None] * this_type.count("[]")
            base = this_type.split("<")[0].replace("[]", "")
            decls.append(A.VarDecl(name=name_tok.lexeme, type=this_type.replace("[]", ""), base_type=base, array_dims=dims,
                                   storage=storage, is_const=final, init=init,
                                   line=name_tok.line, col=name_tok.col))
            if not self.accept(","):
                return decls
            name_tok = self.expect_ident("in variable declaration")

    @production("array_initializer")
    def parse_array_initializer(self) -> A.Node:
        tok = self.expect("{")
        node = A.ArrayLiteral(line=tok.line, col=tok.col)
        while not self.check("}") and not self.at_end():
            node.items.append(self.parse_array_initializer() if self.check("{") else self.parse_assignment())
            if not self.accept(","):
                break
        self.expect("}", "to close array initializer")
        return node

    # ------------------------------------------------------------ statements
    @production("statement")
    def parse_statement(self) -> A.Node:
        tok = self.cur
        if tok.type == TokenType.KEYWORD:
            if tok.lexeme == "try":
                return self.parse_try()
            if tok.lexeme == "throw":
                return self.parse_throw()
            if tok.lexeme == "synchronized" and self.peek().is_op("("):
                self.advance()
                self.paren_condition("synchronized")
                return self.parse_compound()
            if tok.lexeme == "assert":
                self.advance()
                cond = self.parse_expression()
                if self.accept(":"):
                    self.parse_expression()
                self.expect(";", "after assert")
                return A.ExprStmt(expr=A.Call(callee=A.Identifier(name="assert", line=tok.line, col=tok.col),
                                              args=[cond], line=tok.line, col=tok.col), line=tok.line, col=tok.col)
            if tok.lexeme in TYPE_DECL_KEYWORDS or tok.lexeme in ("final", "abstract", "static") and \
                    self.peek().is_kw(*TYPE_DECL_KEYWORDS):
                start = self.cur
                return self.parse_type_declaration(self.parse_modifiers(), start)
        if tok.type == TokenType.IDENTIFIER and tok.lexeme == "yield" and not self.peek().is_op("=", "(", "."):
            self.advance()
            value = self.parse_expression()
            self.expect(";", "after yield")
            return A.Return(value=value, line=tok.line, col=tok.col)
        if self.starts_declaration():
            return self.parse_local_declaration()
        return Parser.parse_statement.__wrapped__(self)

    @production("for_statement")
    def parse_for(self) -> A.Node:
        tok = self.advance()
        self.expect("(", "after 'for'")
        if self.starts_declaration():
            i = self.pos
            while self.tok_at(i).is_kw("final"):
                i += 1
            j = self.scan_type(i)
            if self.tok_at(j + 1).is_op(":"):
                self.enter("enhanced_for")
                try:
                    start = self.cur
                    mods = self.parse_modifiers()
                    type_name = self.parse_type()
                    name = self.expect_ident("in enhanced for")
                    self.expect(":")
                    iterable = self.parse_expression()
                    self.expect(")", "to close for header")
                    body = self.parse_statement()
                finally:
                    self.depth -= 1
                decl = A.VarDecl(name=name.lexeme, type=type_name, base_type=type_name,
                                 array_dims=[None] * type_name.count("[]"), is_const="final" in mods,
                                 line=name.line, col=name.col)
                return A.ForEach(decl=decl, iterable=iterable, body=body, line=start.line, col=start.col)
            init: Optional[A.Node] = self.parse_local_declaration()
        else:
            init = None
            if not self.check(";"):
                init = self.parse_expression()
            self.expect(";", "in for header")
        cond = None if self.check(";") else self.parse_expression()
        self.expect(";", "in for header")
        step = None
        if not self.check(")"):
            step = self.parse_expression()
            if self.check(","):
                comma = A.Comma(exprs=[step], line=step.line, col=step.col)
                while self.accept(","):
                    comma.exprs.append(self.parse_expression())
                step = comma
        self.expect(")", "to close for header")
        body = self.parse_statement()
        return A.For(init=init, cond=cond, step=step, body=body, line=tok.line, col=tok.col)

    def parse_case_body(self, tok: Token) -> Optional[A.Node]:
        if self.accept("->"):  # arrow form: no fall-through
            if self.check("{"):
                return self.parse_compound()
            if self.check_kw("throw"):
                return self.parse_throw()
            expr = self.parse_expression()
            self.expect(";", "after switch rule")
            return A.ExprStmt(expr=expr, line=expr.line, col=expr.col)
        self.expect(":", "after case label")
        if self.check("}") or self.check_kw("case") or (self.check_kw("default") and self.peek().is_op(":", "->")):
            return None
        return self.parse_statement()

    @production("labeled_statement")
    def parse_case(self) -> A.Node:
        tok = self.advance()
        value = self.parse_case_label()
        while self.accept(","):
            self.parse_case_label()
        return A.Case(value=value, body=self.parse_case_body(tok), line=tok.line, col=tok.col)

    def parse_case_label(self) -> A.Node:
        if self.declaration_ahead() or (self.scan_type(self.pos) != -1 and
                                        self.tok_at(self.scan_type(self.pos)).type == TokenType.IDENTIFIER):
            tok = self.cur
            type_name = self.parse_type()  # type pattern: case Circle c ->
            self.expect_ident("in type pattern")
            return A.Identifier(name=type_name, line=tok.line, col=tok.col)
        return self.parse_conditional()

    @production("labeled_statement")
    def parse_default(self) -> A.Node:
        tok = self.advance()
        return A.Default(body=self.parse_case_body(tok), line=tok.line, col=tok.col)

    def parse_resources(self) -> list[A.Node]:
        self.expect("(")
        resources: list[A.Node] = []
        while not self.check(")") and not self.at_end():
            if self.declaration_ahead():
                mods = self.parse_modifiers()
                type_name = self.parse_type()
                name = self.expect_ident("in resource")
                self.expect("=", "in resource declaration")
                resources.append(A.VarDecl(name=name.lexeme, type=type_name, base_type=type_name,
                                           is_const="final" in mods, init=self.parse_assignment(),
                                           line=name.line, col=name.col))
            else:
                resources.append(self.parse_expression())
            if not self.accept(";"):
                break
        self.expect(")", "to close resources")
        return resources

    def parse_catch_param(self) -> Optional[A.Param]:
        self.parse_modifiers()
        types = [self.parse_type()]
        while self.accept("|"):
            types.append(self.parse_type())
        name = self.expect_ident("in catch clause")
        return A.Param(name=name.lexeme, type=" | ".join(types), line=name.line, col=name.col)

    # ----------------------------------------------------------- expressions
    def lambda_ahead(self) -> bool:
        t = self.cur
        if t.type == TokenType.IDENTIFIER:
            return self.peek().is_op("->")
        if t.is_op("("):
            close = self.matching(self.pos)
            return close != -1 and self.tok_at(close + 1).is_op("->")
        return False

    def parse_assignment(self) -> A.Node:
        if self.lambda_ahead():
            return self.parse_lambda()
        return super().parse_assignment()

    @production("lambda_expression")
    def parse_lambda(self) -> A.Node:
        tok = self.cur
        params: list[A.Param] = []
        if self.cur.type == TokenType.IDENTIFIER:
            name = self.advance()
            params.append(A.Param(name=name.lexeme, line=name.line, col=name.col))
        else:
            self.expect("(")
            while not self.check(")") and not self.at_end():
                self.parse_modifiers()
                if self.cur.type == TokenType.IDENTIFIER and self.peek().is_op(",", ")"):
                    name = self.advance()
                    params.append(A.Param(name=name.lexeme, line=name.line, col=name.col))
                else:
                    type_name = self.parse_type()
                    name = self.expect_ident("in lambda parameters")
                    params.append(A.Param(name=name.lexeme, type=type_name, line=name.line, col=name.col))
                if not self.accept(","):
                    break
            self.expect(")", "to close lambda parameters")
        self.expect("->", "in lambda expression")
        body = self.parse_compound() if self.check("{") else self.parse_assignment()
        return A.Lambda(params=params, body=body, line=tok.line, col=tok.col)

    def cast_ahead(self) -> bool:
        if not self.check("("):
            return False
        nxt = self.peek()
        j = self.scan_type(self.pos + 1)
        if j == -1 or not self.tok_at(j).is_op(")"):
            return False
        if nxt.type == TokenType.KEYWORD and nxt.lexeme in PRIMITIVES:
            return True
        after = self.tok_at(j + 1)
        return after.type in (TokenType.IDENTIFIER, TokenType.STRING_LITERAL, TokenType.INT_LITERAL,
                              TokenType.FLOAT_LITERAL, TokenType.CHAR_LITERAL) or \
            after.is_op("(", "!", "~") or after.is_kw("this", "new", "super", "true", "false", "null")

    def parse_cast(self) -> A.Node:
        if self.cast_ahead():
            open_tok = self.advance()
            self.enter("cast_expression")
            try:
                type_name = self.parse_type()
                while self.accept("&"):  # intersection cast
                    type_name += " & " + self.parse_type()
                self.expect(")", "to close cast")
                expr = self.parse_cast()
            finally:
                self.depth -= 1
            return A.Cast(type=type_name, expr=expr, line=open_tok.line, col=open_tok.col)
        return self.parse_unary()

    def parse_unary(self) -> A.Node:
        tok = self.cur
        if tok.type == TokenType.OPERATOR and tok.lexeme in self.UNARY_OPS:
            self.advance()
            self.enter("unary_expression")
            try:
                operand = self.parse_unary() if tok.lexeme in ("++", "--") else self.parse_cast()
            finally:
                self.depth -= 1
            return A.UnaryOp(op=tok.lexeme, operand=operand, line=tok.line, col=tok.col)
        return self.parse_postfix()

    def parse_postfix(self) -> A.Node:
        node = self.parse_primary()
        while True:
            tok = self.cur
            if tok.lexeme in ("[", "(", ".", "::", "++", "--"):
                self.count("postfix_expression")
            if self.accept("."):
                if self.check("<"):  # explicit generic call: obj.<T>method()
                    self.angle_text()
                if self.check_kw("new"):  # inner class creation: outer.new Inner()
                    node = self.parse_new()
                    continue
                if self.cur.type in (TokenType.IDENTIFIER, TokenType.KEYWORD):
                    name = self.advance().lexeme
                else:
                    raise ParseError(f"expected a member name after '.' but found '{self.cur.lexeme}'", self.cur)
                node = A.Member(obj=node, field_name=name, line=node.line, col=node.col)
            elif self.accept("::"):
                name = self.advance().lexeme  # method reference: Foo::bar / Foo::new
                node = A.Member(obj=node, field_name=name, line=node.line, col=node.col)
            elif self.check("["):
                self.advance()
                index = self.parse_expression()
                self.expect("]", "to close subscript")
                node = A.Index(array=node, index=index, line=node.line, col=node.col)
            elif self.check("("):
                node = self.parse_call(node)
            elif tok.type == TokenType.OPERATOR and tok.lexeme in ("++", "--"):
                self.advance()
                node = A.UnaryOp(op=tok.lexeme, postfix=True, operand=node, line=node.line, col=node.col)
            else:
                return node

    @production("function_call")
    def parse_call(self, callee: A.Node) -> A.Node:
        call = A.Call(callee=callee, line=callee.line, col=callee.col)
        path = A.callee_path(callee)
        if path:
            self.note("match", f"call to '{path}'")
        call.args = self.parse_arguments()
        return call

    def parse_arguments(self) -> list[A.Node]:
        self.expect("(", "to open argument list")
        args: list[A.Node] = []
        while not self.check(")") and not self.at_end():
            args.append(self.parse_assignment())
            if not self.accept(","):
                break
        self.expect(")", "to close argument list")
        return args

    @production("object_creation")
    def parse_new(self) -> A.Node:
        tok = self.advance()
        base = self.cur
        if base.type == TokenType.KEYWORD and base.lexeme in PRIMITIVES:
            type_name = self.advance().lexeme
        else:
            type_name = self.expect_ident("after 'new'").lexeme
            while True:
                if self.check("<"):
                    type_name += self.angle_text()
                if self.check(".") and self.peek().type == TokenType.IDENTIFIER:
                    self.advance()
                    type_name += "." + self.advance().lexeme
                    continue
                break
        node = A.New(type=type_name, line=tok.line, col=tok.col)
        if self.check("["):
            node.is_array = True
            while self.check("["):
                self.advance()
                if self.check("]"):
                    self.advance()
                    continue
                size = self.parse_expression()
                if node.array_size is None:
                    node.array_size = size
                self.expect("]", "to close array dimension")
            if self.check("{"):
                node.init = self.parse_array_initializer()
        else:
            node.args = self.parse_arguments()
            if self.check("{"):  # anonymous class
                self.note("match", f"anonymous subclass of {type_name}", tok)
                node.init = A.ClassDecl(tag="class", name="", bases=[type_name],
                                        members=self.parse_class_body(""), line=tok.line, col=tok.col)
        self.note("match", f"object creation 'new {type_name}{'[]' if node.is_array else '()'}'", tok)
        return node

    def parse_primary(self) -> A.Node:
        self.count("primary_expression")
        tok = self.cur
        if tok.type == TokenType.KEYWORD:
            if tok.lexeme in LITERAL_KEYWORDS:
                self.advance()
                return A.KeywordLiteral(value=tok.lexeme, line=tok.line, col=tok.col)
            if tok.lexeme == "new":
                return self.parse_new()
            if tok.lexeme in PRIMITIVES:  # int.class, int[].class
                self.advance()
                name = tok.lexeme
                while self.check("[") and self.peek().is_op("]"):
                    self.advance()
                    self.advance()
                    name += "[]"
                return A.Identifier(name=name, line=tok.line, col=tok.col)
            if tok.lexeme == "switch":  # switch expression
                self.advance()
                cond = self.paren_condition("switch")
                body = self.parse_compound()
                return A.Call(callee=A.Identifier(name="switch", line=tok.line, col=tok.col), args=[cond, body],
                              line=tok.line, col=tok.col)
        if tok.type == TokenType.STRING_LITERAL:
            self.advance()  # Java has no adjacent-literal concatenation
            return A.StringLiteral(value=tok.value or "", raw=tok.lexeme, line=tok.line, col=tok.col)
        return super().parse_primary()


def parse_java(tokens: list[Token], constants: Optional[dict[str, int]] = None):
    result = JavaParser(tokens, constants).parse()
    A.link_tree(result.ast)
    return result
