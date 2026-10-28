"""Per-language lexical tables: keywords, operators and literal forms.

The scanner for every language is the same maximal-munch automaton; a
LanguageSpec only switches individual literal forms on or off (raw strings,
text blocks, annotations, digit separators …).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..lexer import PATTERNS as C_PATTERNS
from ..tokens import KEYWORDS as C_KEYWORDS
from ..tokens import OPERATORS as C_OPERATORS


def longest_first(ops: list[str]) -> list[str]:
    return sorted(set(ops), key=len, reverse=True)


@dataclass(frozen=True)
class LanguageSpec:
    id: str
    name: str
    extensions: tuple[str, ...]
    keywords: frozenset
    operators: list[str]
    preprocessor: bool = False
    raw_strings: bool = False  # C++ R"delim(...)delim"
    text_blocks: bool = False  # Java """ ... """
    annotations: bool = False  # Java @Name(...)
    ident_extra: str = ""  # extra identifier characters ('$' in Java)
    digit_separator: str = ""
    number_suffixes: str = "uUlLfF"
    patterns: dict = field(default_factory=dict)


CPP_KEYWORDS = frozenset(set(C_KEYWORDS) | set("""
    alignas alignof bool catch char8_t char16_t char32_t class concept consteval constexpr constinit
    const_cast co_await co_return co_yield decltype delete dynamic_cast explicit export false friend
    mutable namespace new noexcept nullptr operator private protected public reinterpret_cast requires
    static_assert static_cast template this thread_local throw true try typeid typename using virtual
    wchar_t
""".split()))

JAVA_KEYWORDS = frozenset("""
    abstract assert boolean break byte case catch char class const continue default do double else enum
    extends final finally float for goto if implements import instanceof int interface long native new
    package private protected public return short static strictfp super switch synchronized this throw
    throws transient try void volatile while true false null
""".split())

JAVA_OPERATORS = longest_first([
    "++", "--", "<<", ">>", ">>>", "<=", ">=", "==", "!=", "&&", "||",
    "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", ">>>=",
    "+", "-", "*", "/", "%", "<", ">", "=", "!", "&", "|", "^", "~", "?", ":", ".",
    "...", "->", "::", "@",
])

C = LanguageSpec(
    id="c", name="C", extensions=(".c", ".h"), keywords=C_KEYWORDS, operators=C_OPERATORS,
    preprocessor=True, patterns=C_PATTERNS,
)

CPP = LanguageSpec(
    id="cpp", name="C++", extensions=(".cpp", ".cc", ".cxx", ".c++", ".hpp", ".hh", ".hxx", ".h++", ".ipp"),
    keywords=CPP_KEYWORDS, operators=longest_first(list(C_OPERATORS) + ["::", "->*", ".*", "<=>"]),
    preprocessor=True, raw_strings=True, digit_separator="'", number_suffixes="uUlLfFzZ",
    patterns={**C_PATTERNS,
              "keyword": "identifier ∈ C++ KEYWORDS (C keywords + class, new, delete, template, …)",
              "raw_string": r'(u8|u|U|L)?R"delim( … )delim"',
              "decimal": r"[0-9]('?[0-9])*[uUlLzZ]*",
              "operator": "longest match from OPERATORS table (adds ::, ->*, .*, <=>)"},
)

JAVA = LanguageSpec(
    id="java", name="Java", extensions=(".java",), keywords=JAVA_KEYWORDS, operators=JAVA_OPERATORS,
    text_blocks=True, annotations=True, ident_extra="$", digit_separator="_", number_suffixes="lLfFdD",
    patterns={
        "identifier": r"[A-Za-z_$][A-Za-z0-9_$]*",
        "keyword": "identifier ∈ Java KEYWORDS (true/false/null are literal keywords)",
        "hex": r"0[xX][0-9A-Fa-f_]+[lL]?",
        "binary": r"0[bB][01_]+[lL]?",
        "decimal": r"[0-9][0-9_]*[lL]?",
        "float": r"[0-9_]*\.[0-9_]+([eE][+-]?[0-9]+)?[fFdD]?",
        "string": r'"([^"\\\n]|\\.)*"',
        "text_block": r'"""\n( … )"""',
        "char": r"'([^'\\\n]|\\.)'",
        "annotation": r"@[A-Za-z_][\w.]*(\( … \))?   (kept for Module 1, hidden from the parser)",
        "line_comment": r"//[^\n]*",
        "block_comment": r"/\*(.|\n)*?\*/   (Javadoc /** … */ included)",
        "operator": "longest match from OPERATORS table (adds >>>, ->, ::)",
        "delimiter": r"[(){}\[\];,]",
    },
)

LANGUAGES: dict[str, LanguageSpec] = {spec.id: spec for spec in (C, CPP, JAVA)}


def spec_for(language: str) -> LanguageSpec:
    return LANGUAGES.get(language, C)
