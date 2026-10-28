"""Lexical analyser for C++ and Java.

It extends the hand-written C scanner: the same left-to-right, maximal-munch
automaton, with the keyword table, operator table and literal forms taken
from a LanguageSpec. Language-specific automata are added for raw strings
and digit separators (C++), and for text blocks, annotations and unicode
escapes (Java).
"""

from __future__ import annotations

import textwrap

from ..lexer import LexResult, Lexer, decode_escapes
from ..tokens import DELIMITERS, Token, TokenType
from .spec import LanguageSpec, spec_for


def decode_unicode_escapes(body: str) -> str:
    """Decode Java \\uXXXX escapes before the C-style escapes."""
    out: list[str] = []
    i = 0
    while i < len(body):
        if body.startswith("\\u", i):
            j = i + 2
            while j < len(body) and body[j] == "u":  # Java allows \\uuuu0041
                j += 1
            hexpart = body[j:j + 4]
            if len(hexpart) == 4 and all(c in "0123456789abcdefABCDEF" for c in hexpart):
                out.append(chr(int(hexpart, 16)))
                i = j + 4
                continue
        if body[i] == "\\" and i + 1 < len(body):
            out.append(body[i:i + 2])
            i += 2
            continue
        out.append(body[i])
        i += 1
    return decode_escapes("".join(out))


class LanguageLexer(Lexer):
    def __init__(self, source: str, spec: LanguageSpec):
        super().__init__(source)
        self.spec = spec

    def is_ident_start(self, ch: str) -> bool:
        return ch.isalpha() or ch == "_" or (ch != "" and ch in self.spec.ident_extra)

    def is_ident_char(self, ch: str) -> bool:
        return ch.isalnum() or ch == "_" or (ch != "" and ch in self.spec.ident_extra)

    # ----------------------------------------------------------- main loop
    def tokenize(self) -> LexResult:
        spec = self.spec
        self.log.append(f"Input: {len(self.src)} characters, {self.src.count(chr(10)) + 1} lines")
        self.log.append(f"Scanner configured for {spec.name}: {len(spec.keywords)} keywords, "
                        f"{len(spec.operators)} operators")
        while self.pos < len(self.src):
            ch = self.peek()
            if ch == "\n":
                self.advance()
                self.at_line_start = True
                continue
            if ch in " \t\f\v﻿":
                self.advance()
                continue
            if ch == "\\" and self.peek(1) == "\n":
                self.advance(2)
                continue

            start, line, col = self.pos, self.line, self.col
            if ch == "#" and self.at_line_start and spec.preprocessor:
                self.scan_preprocessor(start, line, col)
            elif ch == "/" and self.peek(1) == "/":
                self.scan_line_comment(start, line, col)
            elif ch == "/" and self.peek(1) == "*":
                self.scan_block_comment(start, line, col)
            elif ch == "@" and spec.annotations and self.is_ident_start(self.peek(1)):
                self.scan_annotation(start, line, col)
            elif self.is_ident_start(ch):
                self.scan_identifier(start, line, col)
            elif ch.isdigit() or (ch == "." and self.peek(1).isdigit()):
                self.scan_number(start, line, col)
            elif ch == '"' and spec.text_blocks and self.src.startswith('"""', self.pos):
                self.scan_text_block(start, line, col)
            elif ch == '"':
                self.scan_string_literal(start, line, col)
            elif ch == "'":
                self.scan_char(start, line, col)
            elif ch in DELIMITERS:
                self.advance()
                self.emit(TokenType.DELIMITER, start, line, col, spec.patterns.get("delimiter", ""))
            else:
                self.scan_operator(start, line, col)
            self.at_line_start = False

        eof = Token(TokenType.EOF, "", self.line, self.col, self.line, self.col, len(self.tokens),
                    pattern="end of input")
        self.tokens.append(eof)
        result = LexResult(self.tokens, self.errors, self.log)
        stats = ", ".join(f"{k}={v}" for k, v in sorted(result.stats().items()))
        self.log.append(f"Produced {len(self.tokens) - 1} tokens ({stats})")
        hidden = "comments and annotations" if spec.annotations else "comments and directives"
        self.log.append(f"Parser stream: {len(result.parser_tokens) - 1} tokens after removing {hidden}")
        if self.errors:
            self.log.append(f"{len(self.errors)} lexical error(s) recovered by skipping the offending characters")
        return result

    # ------------------------------------------------------------ scanners
    def scan_identifier(self, start: int, line: int, col: int) -> None:
        while self.is_ident_char(self.peek()):
            self.advance()
        word = self.src[start:self.pos]
        if self.spec.raw_strings and word in ("R", "u8R", "uR", "UR", "LR") and self.peek() == '"':
            self.scan_raw_string(start, line, col, word)
            return
        if self.spec.id == "cpp" and word in ("L", "u", "U", "u8") and self.peek() in "\"'":
            if self.peek() == '"':
                self.scan_string(start, line, col, prefix=word)
            else:
                self.scan_char(start, line, col, prefix=word)
            return
        pattern = self.spec.patterns.get("identifier", r"[A-Za-z_][A-Za-z0-9_]*")
        if word in self.spec.keywords:
            self.emit(TokenType.KEYWORD, start, line, col, pattern,
                      notes=[f"keyword table lookup: '{word}' found → KEYWORD"])
        else:
            self.emit(TokenType.IDENTIFIER, start, line, col, pattern,
                      notes=[f"keyword table lookup: '{word}' not found → IDENTIFIER"])

    def digits(self, allowed: str) -> None:
        sep = self.spec.digit_separator
        while self.peek() and (self.peek() in allowed or
                               (sep and self.peek() == sep and self.peek(1) != "" and self.peek(1) in allowed)):
            self.advance()

    def scan_number(self, start: int, line: int, col: int) -> None:
        pats = self.spec.patterns
        dec, hexd = "0123456789", "0123456789abcdefABCDEF"
        is_float, base = False, 10
        nxt = self.peek(1)
        if self.peek() == "0" and nxt in ("x", "X"):
            self.advance(2)
            self.digits(hexd)
            base, pattern = 16, pats.get("hex", "")
        elif self.peek() == "0" and nxt in ("b", "B"):
            self.advance(2)
            self.digits("01")
            base, pattern = 2, pats.get("binary", pats.get("decimal", ""))
        else:
            self.digits(dec)
            if self.peek() == "." and self.peek(1) != "." and not self.is_ident_start(self.peek(1)):
                is_float = True
                self.advance()
                self.digits(dec)
            if self.peek() in ("e", "E") and self.peek():
                after = self.peek(1)
                if after.isdigit() or (after in "+-" and self.peek(2).isdigit()):
                    is_float = True
                    self.advance(2)
                    self.digits(dec)
            pattern = pats.get("float" if is_float else "decimal", "")
        suffix_start = self.pos
        while self.peek() and self.peek() in self.spec.number_suffixes:
            self.advance()
        suffix = self.src[suffix_start:self.pos]
        body = self.src[start:suffix_start]
        if self.is_ident_char(self.peek()):
            while self.is_ident_char(self.peek()):
                self.advance()
            self.error(f"malformed numeric literal '{self.src[start:self.pos]}'", line, col)
            self.emit(TokenType.ERROR, start, line, col, pattern, notes=["malformed number"])
            return
        clean = body.replace("_", "").replace("'", "")
        notes: list[str] = []
        if clean != body:
            notes.append("digit separators removed")
        if suffix:
            notes.append(f"suffix '{suffix}'")
        float_suffix = base == 10 and any(c in "fFdD" for c in suffix) and not (self.spec.id == "cpp" and "d" in suffix.lower())
        if is_float or float_suffix:
            try:
                value: object = float(clean)
            except ValueError:
                value = None
            self.emit(TokenType.FLOAT_LITERAL, start, line, col, pattern, value, [f"value = {value}"] + notes)
            return
        try:
            if base == 10 and len(clean) > 1 and clean.startswith("0"):
                value = int(clean, 8)
                notes.append("base 8 (leading zero)")
            else:
                value = int(clean[2:] if base != 10 else clean, base)
                if base != 10:
                    notes.append(f"base {base}")
        except ValueError:
            value = None
        self.emit(TokenType.INT_LITERAL, start, line, col, pattern, value, [f"value = {value}"] + notes)

    def scan_string_literal(self, start: int, line: int, col: int) -> None:
        if self.spec.id != "java":
            self.scan_string(start, line, col)
            return
        ok = self.scan_quoted('"', line, col, "string")
        lexeme = self.src[start:self.pos]
        value = decode_unicode_escapes(lexeme[1:-1 if ok else None])
        pattern = self.spec.patterns.get("string", "")
        if not ok:
            self.emit(TokenType.ERROR, start, line, col, pattern, value, ["unterminated"])
            return
        self.emit(TokenType.STRING_LITERAL, start, line, col, pattern, value,
                  [f"decoded length = {len(value)} (java.lang.String, no NUL terminator)"])

    def scan_char(self, start: int, line: int, col: int, prefix: str = "") -> None:
        if self.spec.id != "java":
            super().scan_char(start, line, col, prefix)
            return
        ok = self.scan_quoted("'", line, col, "character")
        body = self.src[start + 1:self.pos - 1 if ok else self.pos]
        decoded = decode_unicode_escapes(body)
        pattern = self.spec.patterns.get("char", "")
        if not ok or not decoded:
            if ok:
                self.error("empty character literal", line, col)
            self.emit(TokenType.ERROR, start, line, col, pattern, decoded, ["invalid char literal"])
            return
        self.emit(TokenType.CHAR_LITERAL, start, line, col, pattern, ord(decoded[0]),
                  [f"value = {ord(decoded[0])} ({decoded[0]!r})"])

    def scan_text_block(self, start: int, line: int, col: int) -> None:
        self.advance(3)
        while self.pos < len(self.src) and not self.src.startswith('"""', self.pos):
            self.advance(2 if self.peek() == "\\" else 1)
        if self.pos >= len(self.src):
            self.error("unterminated text block", line, col)
            self.emit(TokenType.ERROR, start, line, col, self.spec.patterns["text_block"], notes=["unterminated"])
            return
        self.advance(3)
        body = self.src[start + 3:self.pos - 3]
        body = body.split("\n", 1)[1] if "\n" in body else body
        value = decode_unicode_escapes(textwrap.dedent(body))
        self.emit(TokenType.STRING_LITERAL, start, line, col, self.spec.patterns["text_block"], value,
                  [f"text block, incidental indentation stripped, length = {len(value)}"])

    def scan_raw_string(self, start: int, line: int, col: int, prefix: str) -> None:
        self.advance()  # opening quote
        delim_start = self.pos
        while self.peek() and self.peek() not in '(\n" ':
            self.advance()
        delim = self.src[delim_start:self.pos]
        if self.peek() != "(":
            self.error("malformed raw string delimiter", line, col)
            self.emit(TokenType.ERROR, start, line, col, self.spec.patterns["raw_string"], notes=["bad delimiter"])
            return
        self.advance()
        closing = ")" + delim + '"'
        end = self.src.find(closing, self.pos)
        if end == -1:
            self.error("unterminated raw string literal", line, col)
            body = self.src[self.pos:]
            self.advance(len(self.src) - self.pos)
            self.emit(TokenType.ERROR, start, line, col, self.spec.patterns["raw_string"], body, ["unterminated"])
            return
        body = self.src[self.pos:end]
        self.advance(end + len(closing) - self.pos)
        self.emit(TokenType.STRING_LITERAL, start, line, col, self.spec.patterns["raw_string"], body,
                  [f"raw string (prefix '{prefix}', delimiter '{delim}'): escapes are not processed",
                   f"length = {len(body)}"])

    def scan_annotation(self, start: int, line: int, col: int) -> None:
        self.advance()  # '@'
        while self.is_ident_char(self.peek()) or (self.peek() == "." and self.is_ident_start(self.peek(1))):
            self.advance()
        name = self.src[start + 1:self.pos]
        args = ""
        save = (self.pos, self.line, self.col)
        while self.peek() in (" ", "\t") and self.peek() != "":
            self.advance()
        if self.peek() == "(":  # arguments belong to the annotation: @SuppressWarnings("unchecked")
            depth = 0
            arg_start = self.pos
            while self.pos < len(self.src):
                ch = self.peek()
                if ch in "\"'":
                    self.scan_quoted(ch, self.line, self.col, "string")
                    continue
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        self.advance()
                        break
                self.advance()
            args = self.src[arg_start:self.pos]
        else:
            self.pos, self.line, self.col = save
        self.emit(TokenType.ANNOTATION, start, line, col, self.spec.patterns["annotation"],
                  {"name": name, "args": args}, [f"annotation @{name}: metadata, removed before parsing"])

    def scan_operator(self, start: int, line: int, col: int) -> None:
        for op in self.spec.operators:
            if self.src.startswith(op, self.pos):
                self.advance(len(op))
                notes = [f"maximal munch: '{op}' preferred over '{op[0]}'"] if len(op) > 1 else []
                self.emit(TokenType.OPERATOR, start, line, col, self.spec.patterns.get("operator", ""), notes=notes)
                return
        bad = self.advance()
        self.error(f"unexpected character {bad!r}", line, col)
        self.emit(TokenType.ERROR, start, line, col, "no pattern matches", notes=["skipped"])


def tokenize_language(source: str, language: str) -> LexResult:
    if language == "c":
        return Lexer(source).tokenize()
    return LanguageLexer(source, spec_for(language)).tokenize()
