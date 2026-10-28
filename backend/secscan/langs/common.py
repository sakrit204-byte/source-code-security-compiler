"""Syntax shared by the C++, Java and JavaScript recursive-descent parsers.

Each language parser derives from the C parser (token helpers, tracing,
panic-mode recovery, statements and precedence climbing) and mixes in the
constructs C lacks: try/catch/finally, throw, labelled jumps and generic
angle brackets.
"""

from __future__ import annotations

from typing import Optional

from .. import ast_nodes as A
from ..parser import ParseError, production
from ..tokens import Token, TokenType

CLOSERS = {"(": ")", "[": "]", "{": "}"}


def join_lexemes(parts: list[str]) -> str:
    """Render tokens as compact source text: 'Map<String, List<Integer>>'."""
    text = ""
    for p in parts:
        if not p:
            continue
        if text and (p[0].isalnum() or p[0] in "_$?") and (text[-1].isalnum() or text[-1] in "_$?"):
            text += " "
        text += p
        if p == ",":
            text += " "
    return text


class SharedSyntax:
    tokens: list[Token]
    pos: int

    # ----------------------------------------------------------- lookahead
    def tok_at(self, i: int) -> Token:
        return self.tokens[min(max(i, 0), len(self.tokens) - 1)]

    def matching(self, i: int) -> int:
        """Index of the bracket closing the one at position i, or -1."""
        open_ = self.tok_at(i).lexeme
        close = CLOSERS.get(open_)
        if close is None:
            return -1
        depth = 0
        while i < len(self.tokens):
            tok = self.tokens[i]
            if tok.type == TokenType.EOF:
                return -1
            if tok.type == TokenType.DELIMITER:
                if tok.lexeme in CLOSERS:
                    depth += 1
                elif tok.lexeme in CLOSERS.values():
                    depth -= 1
                    if depth == 0:
                        return i if tok.lexeme == close else -1
            i += 1
        return -1

    ANGLE_OK = {"::", ".", ",", "?", "*", "&", "&&", "[", "]", "(", ")", "...", "-", "+"}

    def scan_angle(self, i: int) -> int:
        """Scan generic / template arguments starting at '<'. Returns the index after the closing '>' or -1."""
        if not self.tok_at(i).is_op("<"):
            return -1
        depth = 0
        while i < len(self.tokens):
            tok = self.tokens[i]
            lx = tok.lexeme
            if tok.type == TokenType.OPERATOR and lx in ("<", ">", ">>", ">>>"):
                depth += 1 if lx == "<" else -len(lx)
                if depth <= 0:
                    return i + 1 if depth == 0 else -1
            elif tok.type in (TokenType.IDENTIFIER, TokenType.KEYWORD, TokenType.INT_LITERAL):
                pass
            elif tok.type in (TokenType.OPERATOR, TokenType.DELIMITER) and lx in self.ANGLE_OK:
                pass
            else:
                return -1
            i += 1
        return -1

    def expect_close_angle(self) -> None:
        """Consume one '>' — splitting '>>' / '>>>' as needed for nested generics."""
        tok = self.cur
        if tok.type == TokenType.OPERATOR and tok.lexeme == ">":
            self.advance()
            return
        if tok.type == TokenType.OPERATOR and tok.lexeme.startswith(">") and len(tok.lexeme) > 1:
            rest = Token(TokenType.OPERATOR, tok.lexeme[1:], tok.line, tok.col + 1, tok.end_line, tok.end_col,
                         tok.index, None, tok.pattern, ["split from '" + tok.lexeme + "' to close a generic"])
            self.tokens[self.pos] = rest
            self.note("match", f"split '{tok.lexeme}' to close nested type arguments", tok)
            return
        raise ParseError(f"expected '>' to close type arguments but found '{tok.lexeme or 'end of input'}'", tok)

    def angle_text(self) -> str:
        """Consume <...> and return its text (used for generics / template arguments)."""
        parts = ["<"]
        self.advance()
        depth = 1
        while not self.at_end():
            tok = self.cur
            if tok.type == TokenType.OPERATOR and tok.lexeme.startswith(">") and tok.lexeme in (">", ">>", ">>>"):
                self.expect_close_angle()
                parts.append(">")
                depth -= 1
                if depth == 0:
                    break
                continue
            if tok.is_op("<"):
                depth += 1
            parts.append(tok.lexeme)
            self.advance()
        return join_lexemes(parts)

    def same_line(self) -> bool:
        prev = self.prev
        return prev is None or self.cur.line == prev.end_line

    # ------------------------------------------------------------ statements
    @production("jump_statement")
    def parse_jump(self) -> A.Node:
        tok = self.advance()
        if tok.lexeme == "goto":
            target = self.expect_ident("after goto").lexeme
            self.expect(";", "after goto")
            return A.Goto(target=target, line=tok.line, col=tok.col)
        label = ""
        if self.cur.type == TokenType.IDENTIFIER and self.same_line():
            label = self.advance().lexeme  # labelled break / continue
        self.expect(";", f"after '{tok.lexeme}'")
        node = (A.Break if tok.lexeme == "break" else A.Continue)(line=tok.line, col=tok.col)
        if label:
            self.note("match", f"{tok.lexeme} to label '{label}'", tok)
        return node

    @production("throw_statement")
    def parse_throw(self) -> A.Node:
        tok = self.advance()
        value = None if self.check(";") else self.parse_expression()
        self.expect(";", "after throw")
        return A.Throw(value=value, line=tok.line, col=tok.col)

    @production("try_statement")
    def parse_try(self) -> A.Node:
        tok = self.advance()
        node = A.Try(line=tok.line, col=tok.col)
        if self.check("("):  # Java try-with-resources
            node.resources = self.parse_resources()
        node.body = self.parse_compound()
        while self.check_kw("catch"):
            ctok = self.advance()
            self.enter("catch_clause")
            try:
                param = None
                if self.accept("("):
                    param = self.parse_catch_param()
                    self.expect(")", "to close catch parameter")
                body = self.parse_compound()
            finally:
                self.depth -= 1
            node.handlers.append(A.Catch(param=param, body=body, line=ctok.line, col=ctok.col))
        if self.check_kw("finally"):
            self.advance()
            node.final = self.parse_compound()
        if not node.handlers and node.final is None and not node.resources:  # try (res) { } is complete
            raise ParseError("expected 'catch' or 'finally' after try block", self.cur)
        return node

    def parse_resources(self) -> list[A.Node]:  # pragma: no cover - overridden by Java
        raise ParseError("unexpected '(' after try", self.cur)

    def parse_catch_param(self) -> Optional[A.Param]:  # pragma: no cover - overridden
        raise NotImplementedError
