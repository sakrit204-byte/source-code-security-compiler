"""Hand-written lexical analyser for C source code.

The scanner walks the character stream once, left to right. At every position
it chooses a token class from the current character (the start state of the
corresponding automaton) and then consumes the longest valid lexeme for that
class (maximal munch). Every token records the pattern that recognised it so
the UI can explain how the lexer reached its decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .tokens import DELIMITERS, KEYWORDS, OPERATORS, TRIVIA, Token, TokenType

PATTERNS = {
    "identifier": r"[A-Za-z_][A-Za-z0-9_]*",
    "keyword": r"identifier ∈ KEYWORDS",
    "hex": r"0[xX][0-9A-Fa-f]+[uUlL]*",
    "decimal": r"[0-9]+[uUlL]*",
    "float": r"[0-9]*\.[0-9]+([eE][+-]?[0-9]+)?[fFlL]?",
    "string": r'"([^"\\\n]|\\.)*"',
    "char": r"'([^'\\\n]|\\.)+'",
    "line_comment": r"//[^\n]*",
    "block_comment": r"/\*(.|\n)*?\*/",
    "preprocessor": r"^\s*#[^\n]*(\\\n[^\n]*)*",
    "operator": "longest match from OPERATORS table",
    "delimiter": r"[(){}\[\];,]",
}

ESCAPES = {
    "n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", "'": "'",
    '"': '"', "a": "\a", "b": "\b", "f": "\f", "v": "\v", "?": "?",
}


@dataclass
class LexError:
    message: str
    line: int
    col: int

    def to_dict(self) -> dict:
        return {"message": self.message, "line": self.line, "col": self.col}


@dataclass
class LexResult:
    tokens: list[Token]
    errors: list[LexError] = field(default_factory=list)
    log: list[str] = field(default_factory=list)

    @property
    def parser_tokens(self) -> list[Token]:
        """Token stream handed to the parser: trivia and error tokens removed."""
        return [t for t in self.tokens if t.type not in TRIVIA and t.type != TokenType.ERROR]

    def stats(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for tok in self.tokens:
            if tok.type == TokenType.EOF:
                continue
            counts[tok.type.value] = counts.get(tok.type.value, 0) + 1
        return counts


def decode_escapes(body: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt == "x":
                j = i + 2
                while j < len(body) and body[j] in "0123456789abcdefABCDEF":
                    j += 1
                out.append(chr(int(body[i + 2 : j] or "0", 16) & 0xFF))
                i = j
                continue
            if nxt in "01234567" and nxt != "0" or (nxt == "0" and i + 2 < len(body) and body[i + 2] in "01234567"):
                j = i + 1
                while j < len(body) and j < i + 4 and body[j] in "01234567":
                    j += 1
                out.append(chr(int(body[i + 1 : j], 8) & 0xFF))
                i = j
                continue
            out.append(ESCAPES.get(nxt, nxt))
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


class Lexer:
    def __init__(self, source: str):
        self.src = source.replace("\r\n", "\n").replace("\r", "\n")
        self.pos = 0
        self.line = 1
        self.col = 1
        self.tokens: list[Token] = []
        self.errors: list[LexError] = []
        self.log: list[str] = []
        self.at_line_start = True

    # ------------------------------------------------------------------ helpers
    def peek(self, offset: int = 0) -> str:
        i = self.pos + offset
        return self.src[i] if i < len(self.src) else ""

    def advance(self, n: int = 1) -> str:
        text = self.src[self.pos : self.pos + n]
        for ch in text:
            if ch == "\n":
                self.line += 1
                self.col = 1
            else:
                self.col += 1
        self.pos += n
        return text

    def emit(self, type_: TokenType, start: int, line: int, col: int, pattern: str,
             value: object = None, notes: list[str] | None = None) -> Token:
        lexeme = self.src[start : self.pos]
        tok = Token(type_, lexeme, line, col, self.line, self.col, len(self.tokens),
                    value, pattern, notes or [])
        self.tokens.append(tok)
        return tok

    def error(self, message: str, line: int, col: int) -> None:
        self.errors.append(LexError(message, line, col))
        self.log.append(f"[{line}:{col}] lexical error: {message}")

    # --------------------------------------------------------------- main loop
    def tokenize(self) -> LexResult:
        self.log.append(f"Input: {len(self.src)} characters, {self.src.count(chr(10)) + 1} lines")
        while self.pos < len(self.src):
            ch = self.peek()
            if ch == "\n":
                self.advance()
                self.at_line_start = True
                continue
            if ch in " \t\f\v":
                self.advance()
                continue
            if ch == "\\" and self.peek(1) == "\n":
                self.advance(2)
                continue

            start, line, col = self.pos, self.line, self.col
            if ch == "#" and self.at_line_start:
                self.scan_preprocessor(start, line, col)
            elif ch == "/" and self.peek(1) == "/":
                self.scan_line_comment(start, line, col)
            elif ch == "/" and self.peek(1) == "*":
                self.scan_block_comment(start, line, col)
            elif ch.isalpha() or ch == "_":
                self.scan_identifier(start, line, col)
            elif ch.isdigit() or (ch == "." and self.peek(1).isdigit()):
                self.scan_number(start, line, col)
            elif ch == '"':
                self.scan_string(start, line, col)
            elif ch == "'":
                self.scan_char(start, line, col)
            elif ch in DELIMITERS:
                self.advance()
                self.emit(TokenType.DELIMITER, start, line, col, PATTERNS["delimiter"])
            else:
                self.scan_operator(start, line, col)
            self.at_line_start = False

        eof = Token(TokenType.EOF, "", self.line, self.col, self.line, self.col, len(self.tokens),
                    pattern="end of input")
        self.tokens.append(eof)
        result = LexResult(self.tokens, self.errors, self.log)
        stats = ", ".join(f"{k}={v}" for k, v in sorted(result.stats().items()))
        self.log.append(f"Produced {len(self.tokens) - 1} tokens ({stats})")
        self.log.append(f"Parser stream: {len(result.parser_tokens) - 1} tokens after removing comments/directives")
        if self.errors:
            self.log.append(f"{len(self.errors)} lexical error(s) recovered by skipping the offending characters")
        return result

    # ---------------------------------------------------------------- scanners
    def scan_preprocessor(self, start: int, line: int, col: int) -> None:
        while self.pos < len(self.src):
            if self.peek() == "\\" and self.peek(1) == "\n":
                self.advance(2)
                continue
            if self.peek() == "\n":
                break
            if self.peek() in "\"'":  # skip quoted text so "http://…" is not mistaken for a comment
                quote = self.advance()
                while self.pos < len(self.src) and self.peek() not in (quote, "\n"):
                    self.advance(2 if self.peek() == "\\" and self.peek(1) not in ("", "\n") else 1)
                if self.peek() == quote:
                    self.advance()
                continue
            # A trailing comment is left for the comment scanner.
            if self.peek() == "/" and self.peek(1) in "/*":
                break
            self.advance()
        text = self.src[start : self.pos].replace("\\\n", " ").strip()
        directive = text[1:].strip().split(None, 1)
        name = directive[0] if directive else ""
        notes = [f"directive: #{name}"] if name else ["null directive"]
        value = {"directive": name, "body": directive[1] if len(directive) > 1 else ""}
        if name == "define" and len(directive) > 1:
            parts = directive[1].split(None, 1)
            value["macro"] = parts[0].split("(")[0]
            value["replacement"] = parts[1].strip() if len(parts) > 1 else ""
            notes.append(f"macro {value['macro']!r} recorded (not expanded)")
        self.emit(TokenType.PREPROCESSOR, start, line, col, PATTERNS["preprocessor"], value, notes)

    def scan_line_comment(self, start: int, line: int, col: int) -> None:
        while self.pos < len(self.src) and self.peek() != "\n":
            self.advance()
        text = self.src[start + 2 : self.pos]
        self.emit(TokenType.COMMENT, start, line, col, PATTERNS["line_comment"], text.strip(),
                  ["removed before parsing"])

    def scan_block_comment(self, start: int, line: int, col: int) -> None:
        self.advance(2)
        while self.pos < len(self.src) and not (self.peek() == "*" and self.peek(1) == "/"):
            self.advance()
        if self.pos >= len(self.src):
            self.error("unterminated block comment", line, col)
            body = self.src[start + 2 : self.pos]
        else:
            body = self.src[start + 2 : self.pos]
            self.advance(2)
        self.emit(TokenType.COMMENT, start, line, col, PATTERNS["block_comment"], body.strip(),
                  ["removed before parsing"])

    def scan_identifier(self, start: int, line: int, col: int) -> None:
        while self.peek().isalnum() or self.peek() == "_":
            self.advance()
        word = self.src[start : self.pos]
        # Wide / unicode string and char prefixes: L"..", u8"..", u"..", U"..".
        if word in ("L", "u", "U", "u8") and self.peek() in "\"'":
            if self.peek() == '"':
                self.scan_string(start, line, col, prefix=word)
            else:
                self.scan_char(start, line, col, prefix=word)
            return
        if word in KEYWORDS:
            self.emit(TokenType.KEYWORD, start, line, col, PATTERNS["identifier"],
                      notes=[f"keyword table lookup: '{word}' found → KEYWORD"])
        else:
            self.emit(TokenType.IDENTIFIER, start, line, col, PATTERNS["identifier"],
                      notes=[f"keyword table lookup: '{word}' not found → IDENTIFIER"])

    def scan_number(self, start: int, line: int, col: int) -> None:
        is_float = False
        if self.peek() == "0" and self.peek(1) in "xX":
            self.advance(2)
            while self.peek() and self.peek() in "0123456789abcdefABCDEF":
                self.advance()
            pattern = PATTERNS["hex"]
        else:
            while self.peek().isdigit():
                self.advance()
            if self.peek() == "." and self.peek(1) != ".":
                is_float = True
                self.advance()
                while self.peek().isdigit():
                    self.advance()
            if self.peek() in ("e", "E") and self.peek():
                nxt = self.peek(1)
                if nxt.isdigit() or (nxt in "+-" and self.peek(2).isdigit()):
                    is_float = True
                    self.advance(2)
                    while self.peek().isdigit():
                        self.advance()
            pattern = PATTERNS["float"] if is_float else PATTERNS["decimal"]
        suffix_start = self.pos
        while self.peek() and self.peek() in "uUlLfF":
            self.advance()
        suffix = self.src[suffix_start : self.pos]
        digits = self.src[start:suffix_start]
        if self.peek().isalpha() or self.peek() == "_":
            # e.g. 123abc — malformed numeric literal
            while self.peek().isalnum() or self.peek() == "_":
                self.advance()
            self.error(f"malformed numeric literal '{self.src[start:self.pos]}'", line, col)
            self.emit(TokenType.ERROR, start, line, col, pattern, notes=["malformed number"])
            return
        if is_float or ("f" in suffix.lower() and not digits.lower().startswith("0x")):
            try:
                value: object = float(digits)
            except ValueError:
                value = None
            self.emit(TokenType.FLOAT_LITERAL, start, line, col, pattern, value,
                      [f"value = {value}"] + ([f"suffix '{suffix}'"] if suffix else []))
            return
        try:
            if digits.lower().startswith("0x"):
                value = int(digits, 16)
            elif len(digits) > 1 and digits.startswith("0"):
                value = int(digits, 8)
            else:
                value = int(digits)
        except ValueError:
            value = None
        notes = [f"value = {value}"]
        if digits.lower().startswith("0x"):
            notes.append("base 16")
        elif len(digits) > 1 and digits.startswith("0"):
            notes.append("base 8 (leading zero)")
        if suffix:
            notes.append(f"suffix '{suffix}'")
        self.emit(TokenType.INT_LITERAL, start, line, col, pattern, value, notes)

    def scan_quoted(self, quote: str, line: int, col: int, what: str) -> bool:
        self.advance()  # opening quote
        while self.pos < len(self.src):
            ch = self.peek()
            if ch == "\\":
                self.advance(2 if self.peek(1) else 1)
                continue
            if ch == "\n":
                self.error(f"unterminated {what} literal", line, col)
                return False
            if ch == quote:
                self.advance()
                return True
            self.advance()
        self.error(f"unterminated {what} literal", line, col)
        return False

    def scan_string(self, start: int, line: int, col: int, prefix: str = "") -> None:
        ok = self.scan_quoted('"', line, col, "string")
        lexeme = self.src[start : self.pos]
        body = lexeme[len(prefix) + 1 : -1 if ok else None]
        value = decode_escapes(body)
        notes = [f"decoded length = {len(value)} (+1 for '\\0' terminator)"]
        if prefix:
            notes.append(f"encoding prefix '{prefix}'")
        if not ok:
            self.emit(TokenType.ERROR, start, line, col, PATTERNS["string"], value, notes + ["unterminated"])
            return
        self.emit(TokenType.STRING_LITERAL, start, line, col, PATTERNS["string"], value, notes)

    def scan_char(self, start: int, line: int, col: int, prefix: str = "") -> None:
        ok = self.scan_quoted("'", line, col, "character")
        lexeme = self.src[start : self.pos]
        body = lexeme[len(prefix) + 1 : -1 if ok else None]
        decoded = decode_escapes(body)
        if not ok or not decoded:
            if ok:
                self.error("empty character literal", line, col)
            self.emit(TokenType.ERROR, start, line, col, PATTERNS["char"], decoded, ["invalid char literal"])
            return
        value = ord(decoded[0])
        notes = [f"value = {value} ({decoded[0]!r})"]
        if len(decoded) > 1:
            notes.append("multi-character constant (implementation-defined)")
        self.emit(TokenType.CHAR_LITERAL, start, line, col, PATTERNS["char"], value, notes)

    def scan_operator(self, start: int, line: int, col: int) -> None:
        for op in OPERATORS:
            if self.src.startswith(op, self.pos):
                self.advance(len(op))
                notes = []
                if len(op) > 1:
                    notes.append(f"maximal munch: '{op}' preferred over '{op[0]}'")
                self.emit(TokenType.OPERATOR, start, line, col, PATTERNS["operator"], notes=notes)
                return
        bad = self.advance()
        self.error(f"unexpected character {bad!r}", line, col)
        self.emit(TokenType.ERROR, start, line, col, "no pattern matches", notes=["skipped"])


def tokenize(source: str) -> LexResult:
    return Lexer(source).tokenize()
