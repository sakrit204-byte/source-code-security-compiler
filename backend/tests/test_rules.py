from pathlib import Path

import pytest

from secscan import run_pipeline

SAMPLES = Path(__file__).resolve().parents[2] / "samples"


def rules_hit(src):
    report = run_pipeline(src, "t.c")["report"]
    return {f["rule_id"] for f in report["findings"]}, report


def wrap(body, globals_=""):
    return f"#include <stdio.h>\n{globals_}\nint main(int argc, char **argv) {{\n{body}\nreturn 0;\n}}\n"


@pytest.mark.parametrize("code,rule", [
    ('char b[8]; gets(b);', "AST001"),
    ('char b[4]; strcpy(b, "too long");', "AST001"),
    ('printf(argv[1]);', "AST002"),
    ('char c[64]; sprintf(c, "rm %s", argv[1]); system(c);', "AST003"),
    ('char w[8]; scanf("%s", w);', "AST004"),
    ('char l[8]; fgets(l, 64, stdin);', "AST004"),
    ('char *password = "x1y2z3"; if (strcmp(password, "Secr3t!") == 0) {}', "AST005"),
    ('unsigned session_key = rand();', "AST006"),
    ('char *p = malloc(argc * 8); p[0] = 1;', "AST007"),
    ('int a[4]; a[4] = 1;', "AST008"),
    ('int a[4]; int i; for (i = 0; i <= 4; i++) a[i] = 0;', "AST009"),
    ('char *p = malloc(4); if (!p) return 1; free(p); p[0] = 1;', "AST010"),
    ('int is_admin = 0; if (is_admin = 1) {}', "AST011"),
    ('char *n = tmpnam(NULL);', "AST012"),
    ('char d[4]; memcpy(d, argv[0], 16);', "AST013"),
    ('int n = atoi(argv[1]);', "AST014"),
    ('chmod("/tmp/x", 0777);', "AST015"),
    ('MD5(0, 0, 0);', "AST016"),
])
def test_ast_rules_fire(code, rule):
    hits, _ = rules_hit(wrap(code))
    assert rule in hits


@pytest.mark.parametrize("src,rule", [
    ('#define DB_PASSWORD "pa55word"\nint main(void){return 0;}', "LEX001"),
    ('const char *k = "AKIAIOSFODNN7EXAMPLE";', "LEX002"),
    ('void (*f)(char *) = gets;', "LEX003"),
    ('int backdoor_enabled = 1;', "LEX004"),
    ('/* FIXME: password check is insecure */ int x;', "LEX005"),
    ('const char *u = "http://example.com/api";', "LEX006"),
])
def test_lexical_rules_fire(src, rule):
    result = run_pipeline(src, "t.c")
    lex_stage = next(s for s in result["stages"] if s["id"] == "lexical_security")
    assert rule in {f["rule_id"] for f in lex_stage["data"]["findings"]}


def test_lexical_and_ast_findings_are_correlated():
    result = run_pipeline(wrap("char b[8]; gets(b);"), "t.c")
    report = result["report"]
    gets = next(f for f in report["findings"] if f["rule_id"] == "AST001")
    assert gets["detected_by"] == ["lexical", "ast"]
    assert not any(f["rule_id"] == "LEX003" for f in report["findings"])  # merged, not duplicated


def test_safe_usage_is_not_flagged():
    src = wrap('char b[16]; if (fgets(b, sizeof b, stdin) == NULL) return 1; '
               'char *p = malloc(16); if (p == NULL) return 1; snprintf(p, 16, "%s", b); free(p); p = NULL;')
    hits, report = rules_hit(src)
    assert report["total"] == 0, hits


def test_comment_mention_is_not_an_ast_finding():
    hits, _ = rules_hit(wrap("/* never call gets() here */ int x = 1;"))
    assert "AST001" not in hits and "LEX003" not in hits


def test_strcpy_literal_that_fits_is_low():
    _, report = rules_hit(wrap('char b[16]; strcpy(b, "ok");'))
    f = next(f for f in report["findings"] if f["rule_id"] == "AST001")
    assert f["severity"] == "low"


def test_free_inside_branch_is_not_use_after_free():
    hits, _ = rules_hit(wrap('char *p = malloc(4); if (!p) return 1; if (argc > 2) { free(p); return 1; } p[0] = 1; free(p);'))
    assert "AST010" not in hits


@pytest.mark.parametrize("sample", sorted(p.name for p in (SAMPLES / "c").glob("*.c")))
def test_samples_run_end_to_end(sample):
    result = run_pipeline((SAMPLES / "c" / sample).read_text(), sample)
    assert [s["id"] for s in result["stages"]] == [
        "source", "lexer", "lexical_security", "parser", "ast", "semantic", "ast_security", "rule_engine", "report"]
    if sample.startswith("06"):
        assert result["report"]["total"] == 0
    elif not sample.startswith("07"):
        assert result["report"]["total"] > 0
