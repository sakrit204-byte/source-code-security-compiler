from secscan.lexer import tokenize
from secscan.parser import parse
from secscan.semantic import analyze


def sem(src):
    return analyze(parse(tokenize(src).parser_tokens).ast)


def test_scopes_and_resolution():
    res = sem("int g; int main(void) { int x = g; { int x = 2; x++; } return x; }")
    names = [(s.name, s.scope) for s in res.symbols]
    assert ("g", "global") in names and ("main", "global") in names
    assert sum(1 for s in res.symbols if s.name == "x") == 2
    assert any("shadows" in d.message for d in res.diagnostics)


def test_undeclared_and_unused():
    res = sem("int main(void) { int unused; return missing; }")
    msgs = [d.message for d in res.diagnostics]
    assert any("undeclared identifier 'missing'" in m for m in msgs)
    assert any("'unused' is declared but never used" in m for m in msgs)


def test_input_tagging_propagates():
    res = sem("""
    int main(int argc, char **argv) {
        char a[16], b[16], c[16];
        fgets(a, sizeof a, stdin);
        strcpy(b, a);
        char *home = getenv("HOME");
        sprintf(c, "%s", home);
        return 0;
    }""")
    tainted = {s.name for s in res.symbols if s.tainted}
    assert {"argv", "a", "b", "home", "c"} <= tainted


def test_array_size_inferred_from_literal():
    res = sem('int main(void) { char msg[] = "hello"; return msg[0]; }')
    msg = next(s for s in res.symbols if s.name == "msg")
    assert msg.array_size == 6
