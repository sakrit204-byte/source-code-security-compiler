"""Language front ends: C (the original), C++ and Java.

Every language provides the same four pieces, so the pipeline, rule engine and
report are shared: a scanner, a recursive-descent parser with its grammar, a
taint profile for semantic analysis, and a rule set.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from .. import ast_nodes as A
from ..lexer import LexResult
from ..parser import ParseResult, Parser
from ..semantic import TaintProfile
from .cpp_parser import CppParser
from .java_parser import JavaParser
from .lexer import tokenize_language
from .profiles import profile_for
from .spec import LANGUAGES, LanguageSpec, spec_for


@dataclass(frozen=True)
class FrontEnd:
    spec: LanguageSpec
    parser_class: type[Parser]

    @property
    def id(self) -> str:
        return self.spec.id

    @property
    def name(self) -> str:
        return self.spec.name

    @property
    def grammar(self) -> list[tuple[str, str]]:
        return self.parser_class.GRAMMAR

    @property
    def patterns(self) -> dict:
        return self.spec.patterns

    def tokenize(self, source: str) -> LexResult:
        return tokenize_language(source, self.spec.id)

    def parse(self, tokens: list, constants: Optional[dict[str, int]] = None) -> ParseResult:
        result = self.parser_class(tokens, constants).parse()
        A.link_tree(result.ast)
        return result

    @property
    def profile(self) -> TaintProfile:
        return profile_for(self.spec.id)


FRONT_ENDS: dict[str, FrontEnd] = {
    "c": FrontEnd(LANGUAGES["c"], Parser),
    "cpp": FrontEnd(LANGUAGES["cpp"], CppParser),
    "java": FrontEnd(LANGUAGES["java"], JavaParser),
}

LANGUAGE_IDS = tuple(FRONT_ENDS)


def front_end(language: str) -> FrontEnd:
    return FRONT_ENDS.get(language, FRONT_ENDS["c"])


__all__ = ["FRONT_ENDS", "LANGUAGE_IDS", "FrontEnd", "front_end", "spec_for"]
