"""Token definitions shared by the lexer, parser and lexical security rules."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class TokenType(str, Enum):
    KEYWORD = "KEYWORD"
    IDENTIFIER = "IDENTIFIER"
    INT_LITERAL = "INT_LITERAL"
    FLOAT_LITERAL = "FLOAT_LITERAL"
    CHAR_LITERAL = "CHAR_LITERAL"
    STRING_LITERAL = "STRING_LITERAL"
    OPERATOR = "OPERATOR"
    DELIMITER = "DELIMITER"
    PREPROCESSOR = "PREPROCESSOR"
    ANNOTATION = "ANNOTATION"  # Java @Annotation(...)
    COMMENT = "COMMENT"
    ERROR = "ERROR"
    EOF = "EOF"


KEYWORDS = frozenset(
    """
    auto break case char const continue default do double else enum extern
    float for goto if inline int long register restrict return short signed
    sizeof static struct switch typedef union unsigned void volatile while
    _Bool _Complex _Imaginary _Noreturn _Static_assert _Thread_local _Alignas _Alignof
    """.split()
)

# Ordered longest-first so the scanner can apply the maximal-munch principle.
OPERATORS = sorted(
    [
        "...", "<<=", ">>=",
        "->", "++", "--", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||",
        "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
        "+", "-", "*", "/", "%", "<", ">", "=", "!", "&", "|", "^", "~",
        "?", ":", ".",
    ],
    key=len,
    reverse=True,
)

DELIMITERS = frozenset("(){}[];,")

# Tokens the parser never sees: they are kept for lexical analysis only.
TRIVIA = frozenset({TokenType.COMMENT, TokenType.PREPROCESSOR, TokenType.ANNOTATION})


@dataclass
class Token:
    type: TokenType
    lexeme: str
    line: int
    col: int
    end_line: int
    end_col: int
    index: int = -1
    value: object = None
    pattern: str = ""
    notes: list[str] = field(default_factory=list)
    extra: object = field(default=None, repr=False)  # parser-only payload

    def is_(self, type_: TokenType, lexeme: str | None = None) -> bool:
        return self.type == type_ and (lexeme is None or self.lexeme == lexeme)

    def is_op(self, *lexemes: str) -> bool:
        return self.type in (TokenType.OPERATOR, TokenType.DELIMITER) and self.lexeme in lexemes

    def is_kw(self, *lexemes: str) -> bool:
        return self.type == TokenType.KEYWORD and self.lexeme in lexemes

    def to_dict(self) -> dict:
        value = self.value
        if value is not None and not isinstance(value, (int, float, str, bool)):
            value = str(value)
        return {
            "index": self.index,
            "type": self.type.value,
            "lexeme": self.lexeme,
            "line": self.line,
            "col": self.col,
            "end_line": self.end_line,
            "end_col": self.end_col,
            "value": value,
            "pattern": self.pattern,
            "notes": self.notes,
        }

    def __repr__(self) -> str:
        return f"Token({self.type.value}, {self.lexeme!r}, {self.line}:{self.col})"
