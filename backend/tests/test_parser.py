from secscan import ast_nodes as A
from secscan.lexer import tokenize
from secscan.parser import parse


def parse_src(src, constants=None):
    return parse(tokenize(src).parser_tokens, constants)


def test_function_and_declarations():
    res = parse_src("int add(int a, int b) { int c = a + b * 2; return c; }")
    assert not res.errors
    fn = res.ast.decls[0]
    assert isinstance(fn, A.FunctionDef) and fn.name == "add"
    assert [p.name for p in fn.params] == ["a", "b"]
    decl = fn.body.items[0].decls[0]
    assert isinstance(decl.init, A.BinaryOp) and decl.init.op == "+"
    assert isinstance(decl.init.right, A.BinaryOp) and decl.init.right.op == "*"  # precedence


def test_precedence_and_associativity():
    expr = parse_src("void f(void){ x = a - b - c || d && e; }").ast.decls[0].body.items[0].expr
    assert isinstance(expr, A.Assignment)
    top = expr.value
    assert top.op == "||" and top.right.op == "&&"
    assert top.left.op == "-" and top.left.left.op == "-"  # left-associative


def test_arrays_pointers_and_constants():
    res = parse_src("enum { SMALL = 4 }; char buf[N * 2], *p, grid[3][SMALL];", {"N": 8})
    decls = [d for d in res.ast.decls if isinstance(d, A.VarDecl)]
    assert decls[0].array_dims == [16]
    assert decls[1].pointer_depth == 1
    assert decls[2].array_dims == [3, 4]


def test_statements_and_typedefs():
    src = """
    typedef struct node { int v; struct node *next; } node_t;
    int main(int argc, char **argv) {
        node_t n; int i;
        for (i = 0; i < 3; i++) { if (i == 1) continue; else n.v += i; }
        while (argc--) ;
        do { i--; } while (i > 0);
        switch (i) { case 0: break; default: return 1; }
        return (int) sizeof(node_t);
    }"""
    res = parse_src(src)
    assert not res.errors, res.errors
    kinds = {n.kind for n in res.ast.walk()}
    assert {"For", "If", "While", "DoWhile", "Switch", "Case", "Default", "Cast", "SizeOf", "Member"} <= kinds
    assert "node_t" in res.typedef_names


def test_call_and_string_concatenation():
    call = parse_src('void f(void){ printf("a" "b", x); }').ast.decls[0].body.items[0].expr
    assert isinstance(call, A.Call) and call.func_name == "printf"
    assert call.args[0].value == "ab"


def test_panic_mode_recovery_keeps_going():
    res = parse_src("int main(void) { int x = ; gets(b); return 0 }\nint g(void) { return 1; }")
    assert res.errors
    names = [d.name for d in res.ast.decls if isinstance(d, A.FunctionDef)]
    assert "g" in names
    calls = [n.func_name for n in res.ast.walk() if isinstance(n, A.Call)]
    assert "gets" in calls


def test_trace_and_parent_links():
    res = parse_src("int main(void){ return 0; }")
    assert res.trace[0]["rule"] == "translation_unit"
    ret = next(n for n in res.ast.walk() if isinstance(n, A.Return))
    assert isinstance(ret.parent, A.Compound) and ret.id > 0
