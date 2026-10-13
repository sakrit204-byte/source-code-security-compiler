from secscan.lexer import tokenize
from secscan.tokens import TokenType


def kinds(src):
    return [(t.type, t.lexeme) for t in tokenize(src).tokens if t.type != TokenType.EOF]


def test_keywords_identifiers_and_positions():
    toks = tokenize("int count = 42;\nreturn count;").tokens
    assert toks[0].type == TokenType.KEYWORD and toks[0].lexeme == "int"
    assert toks[1].type == TokenType.IDENTIFIER and (toks[1].line, toks[1].col) == (1, 5)
    assert toks[3].type == TokenType.INT_LITERAL and toks[3].value == 42
    ret = toks[5]
    assert ret.lexeme == "return" and (ret.line, ret.col) == (2, 1)


def test_maximal_munch_operators():
    ops = [lex for typ, lex in kinds("a >>= b; c->d; e++ + ++f; g <<= 1; x ... y") if typ == TokenType.OPERATOR]
    assert ops == [">>=", "->", "++", "+", "++", "<<=", "..."]


def test_numeric_literals():
    toks = {t.lexeme: t for t in tokenize("0x1F 017 3.5e2 10UL 1.0f .5").tokens}
    assert toks["0x1F"].value == 31
    assert toks["017"].value == 15
    assert toks["3.5e2"].type == TokenType.FLOAT_LITERAL and toks["3.5e2"].value == 350.0
    assert toks["10UL"].value == 10
    assert toks["1.0f"].type == TokenType.FLOAT_LITERAL
    assert toks[".5"].value == 0.5


def test_strings_chars_and_escapes():
    src = 'char *s = "a\\tb\\n"; char c = \'\\n\'; wchar_t *w = L"wide";'
    toks = tokenize(src).tokens
    s = next(t for t in toks if t.type == TokenType.STRING_LITERAL)
    assert s.value == "a\tb\n"
    c = next(t for t in toks if t.type == TokenType.CHAR_LITERAL)
    assert c.value == 10
    assert any(t.lexeme == 'L"wide"' for t in toks)


def test_comments_and_directives_are_trivia():
    res = tokenize('#include <stdio.h>\n#define URL "http://x.y"\n// line\n/* block\n */ int x;')
    types = [t.type for t in res.tokens]
    assert types.count(TokenType.PREPROCESSOR) == 2
    assert types.count(TokenType.COMMENT) == 2
    assert [t.lexeme for t in res.parser_tokens] == ["int", "x", ";", ""]
    define = res.tokens[1]
    assert define.value["macro"] == "URL" and define.value["replacement"] == '"http://x.y"'


def test_lexical_errors_are_recovered():
    res = tokenize('int a = 1 @ 2; char *s = "open\nint b;')
    messages = [e.message for e in res.errors]
    assert any("unexpected character" in m for m in messages)
    assert any("unterminated string" in m for m in messages)
    assert any(t.lexeme == "b" for t in res.tokens)  # scanning continued
