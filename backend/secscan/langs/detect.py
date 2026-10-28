"""Automatic source-language detection for pasted code.

Detection runs in two steps:
  1. The file extension decides when it is unambiguous (.java, .cpp, .c …).
  2. Otherwise weighted lexical signals are counted for each language. C++ is a
     superset of most C, so C++ only wins on C++-specific evidence
     (std::, classes, templates, new/delete, iostream …).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePath

from .spec import LANGUAGES

# (regex, weight, description)
SIGNALS: dict[str, list[tuple[re.Pattern, float, str]]] = {
    "java": [
        (re.compile(r"^\s*package\s+[\w.]+\s*;", re.M), 5, "package declaration"),
        (re.compile(r"^\s*import\s+(static\s+)?java[x]?\.", re.M), 5, "import java.*"),
        (re.compile(r"^\s*import\s+[\w.]+(\.\*)?\s*;", re.M), 2, "import statement"),
        (re.compile(r"\bpublic\s+(final\s+|abstract\s+)?(class|interface|enum|record)\b"), 4, "public class"),
        (re.compile(r"\bpublic\s+static\s+void\s+main\s*\(\s*(final\s+)?String"), 6, "main(String[] args)"),
        (re.compile(r"\bSystem\.(out|err)\.print"), 5, "System.out.print"),
        (re.compile(r"@(Override|Autowired|Test|Deprecated|SuppressWarnings|Entity|RestController)\b"), 4,
         "annotation"),
        (re.compile(r"\bString\s*\[\]"), 3, "String[]"),
        (re.compile(r"\b(extends|implements)\s+[A-Z]\w*"), 2, "extends / implements"),
        (re.compile(r"\bthrows\s+[A-Z]\w*"), 3, "throws clause"),
        (re.compile(r"\b(private|protected|public)\s+(static\s+)?(final\s+)?[A-Z]\w*(<[^>]*>)?\s+\w+\s*[=;(]"), 2,
         "access-modified member"),
        (re.compile(r"\bnew\s+[A-Z]\w*(<[^>]*>)?\s*\("), 1, "new Object(…)"),
        (re.compile(r"\b(ArrayList|HashMap|StringBuilder|Scanner|Integer\.parseInt|equals\()"), 2, "Java library"),
        (re.compile(r"\bboolean\b"), 1, "boolean"),
    ],
    "cpp": [
        (re.compile(r"#\s*include\s*<(iostream|string|vector|map|memory|algorithm|fstream|sstream|thread|"
                    r"unordered_map|set|cstring|cstdio|cstdlib|random|functional|utility)>"), 6, "C++ standard header"),
        (re.compile(r"\bstd::"), 5, "std:: qualified name"),
        (re.compile(r"\busing\s+namespace\s+\w+\s*;"), 6, "using namespace"),
        (re.compile(r"\b(cout|cin|cerr)\s*(<<|>>)"), 5, "iostream operators"),
        (re.compile(r"\bclass\s+\w+\s*(final\s*)?(:\s*(public|private|protected)\s+\w+)?\s*\{"), 3, "class definition"),
        (re.compile(r"^\s*(public|private|protected)\s*:", re.M), 4, "access specifier"),
        (re.compile(r"\btemplate\s*<"), 5, "template"),
        (re.compile(r"\bnamespace\s+\w+\s*\{"), 4, "namespace"),
        (re.compile(r"\bnew\s+\w+(\s*\[|\s*\(|\s*;)"), 2, "new expression"),
        (re.compile(r"\bdelete\s*(\[\s*\])?\s*\w+"), 2, "delete expression"),
        (re.compile(r"\bnullptr\b"), 4, "nullptr"),
        (re.compile(r"\b(static_cast|reinterpret_cast|dynamic_cast|const_cast)\s*<"), 5, "C++ cast"),
        (re.compile(r"\b\w+::\w+\s*\("), 2, "scope resolution ::"),
        (re.compile(r"\bauto\s*[&*]?\s*\w+\s*[=:]"), 2, "auto type deduction"),
        (re.compile(r"\bbool\b"), 1, "bool"),
        (re.compile(r"\b(virtual|override|constexpr|noexcept)\b"), 3, "C++ keyword"),
    ],
    "c": [
        (re.compile(r"#\s*include\s*<\w+\.h>"), 3, "C header (.h)"),
        (re.compile(r"\b(printf|scanf|fprintf|sprintf|snprintf)\s*\("), 2, "stdio call"),
        (re.compile(r"\b(malloc|calloc|realloc|free)\s*\("), 2, "manual memory management"),
        (re.compile(r"\b(strcpy|strcat|strncpy|strlen|memcpy|memset|gets|fgets)\s*\("), 2, "string.h call"),
        (re.compile(r"\bint\s+main\s*\("), 2, "int main(…)"),
        (re.compile(r"\bstruct\s+\w+"), 1, "struct"),
        (re.compile(r"\bchar\s*\*"), 1, "char *"),
        (re.compile(r"#\s*define\s+\w+"), 1, "#define"),
        (re.compile(r"\btypedef\b"), 1, "typedef"),
    ],
}

EXTENSIONS = {ext: spec.id for spec in LANGUAGES.values() for ext in spec.extensions}


@dataclass
class Detection:
    language: str
    name: str
    confidence: float
    method: str  # "user" | "extension" | "content" | "default"
    signals: list[str] = field(default_factory=list)
    scores: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"language": self.language, "name": self.name, "confidence": round(self.confidence, 2),
                "method": self.method, "signals": self.signals, "scores": self.scores}


def strip_literals(source: str) -> str:
    """Drop comments and string contents so words inside them do not count as evidence."""
    source = re.sub(r"/\*.*?\*/", " ", source, flags=re.S)
    source = re.sub(r"//[^\n]*", " ", source)
    return re.sub(r'"(?:[^"\\\n]|\\.)*"', '""', source)


def score(source: str) -> dict[str, tuple[float, list[str]]]:
    text = strip_literals(source)
    out: dict[str, tuple[float, list[str]]] = {}
    for lang, signals in SIGNALS.items():
        total, hits = 0.0, []
        for pattern, weight, label in signals:
            count = len(pattern.findall(text))
            if count:
                total += weight * min(count, 3) ** 0.5
                hits.append(label)
        out[lang] = (round(total, 1), hits)
    return out


def detect_language(source: str, filename: str = "") -> Detection:
    ext = PurePath(filename or "").suffix.lower() if filename else ""
    scores = score(source)
    flat = {k: v[0] for k, v in scores.items()}
    if ext in EXTENSIONS and ext != ".h":
        lang = EXTENSIONS[ext]
        return Detection(lang, LANGUAGES[lang].name, 1.0, "extension", [f"file extension '{ext}'"], flat)

    java, cpp, c = flat["java"], flat["cpp"], flat["c"]
    if java >= 4 and java > cpp:
        lang = "java"
    elif cpp >= 4 and cpp >= java:
        lang = "cpp"
    elif c > 0 or not source.strip():
        lang = "c"
    elif java > 0 and java >= cpp:
        lang = "java"
    elif cpp > 0:
        lang = "cpp"
    else:
        lang = "c"
    best = flat[lang]
    others = sorted((v for k, v in flat.items() if k != lang), reverse=True)
    margin = best - (others[0] if others else 0)
    confidence = 0.5 if best == 0 else min(0.99, 0.55 + 0.45 * margin / (best + 4))
    method = "content" if best > 0 else "default"
    signals = scores[lang][1] or (["no distinctive signals; C is the default"] if lang == "c" else [])
    if ext == ".h":
        signals = [f"header '.h' resolved by content"] + signals
    return Detection(lang, LANGUAGES[lang].name, confidence, method, signals[:6], flat)
