from pathlib import Path

import pytest

from secscan import ast_nodes as A
from secscan import run_pipeline
from secscan.langs import front_end
from secscan.langs.detect import detect_language
from secscan.tokens import TokenType

SAMPLES = Path(__file__).resolve().parents[2] / "samples"


def parse(code, language):
    fe = front_end(language)
    lex = fe.tokenize(code)
    return lex, fe.parse(lex.parser_tokens)


def rules_hit(code, language):
    result = run_pipeline(code, "snippet", language=language)
    return {f["rule_id"] for f in result["report"]["findings"]}, result


# ------------------------------------------------------------------ detection
@pytest.mark.parametrize("code, expected", [
    ("#include <stdio.h>\nint main(void) { char b[8]; gets(b); printf(\"%s\", b); }", "c"),
    ("#include <iostream>\nusing namespace std;\nint main() { cout << \"hi\" << endl; }", "cpp"),
    ("template <typename T> T twice(T v) { return v * 2; }", "cpp"),
    ("public class Main { public static void main(String[] args) { System.out.println(1); } }", "java"),
    ("import java.util.List;\nclass A { private List<String> xs; }", "java"),
    ("", "c"),
])
def test_detect_from_content(code, expected):
    assert detect_language(code).language == expected


def test_extension_wins_over_content():
    assert detect_language("int main() { return 0; }", "x.cpp").language == "cpp"
    assert detect_language("int x;", "Main.java").method == "extension"
    assert detect_language("#include <iostream>\nint main(){ std::cout << 1; }", "x.h").language == "cpp"


def test_user_choice_overrides_detection():
    result = run_pipeline("int main() { return 0; }", "x", language="cpp")
    assert result["meta"]["language_id"] == "cpp"
    assert result["meta"]["detection"]["method"] == "user"


# ------------------------------------------------------------------ lexers
def test_java_lexer_features():
    lex, _ = parse('@Override\nString s = """\n  text\n  """; long n = 1_000L; int u = x >>> 2; String $a = "\\u0041";',
                   "java")
    kinds = [(t.type, t.lexeme) for t in lex.tokens]
    assert (TokenType.ANNOTATION, "@Override") in kinds
    assert any(t.type == TokenType.STRING_LITERAL and "text" in str(t.value) for t in lex.tokens)
    assert (TokenType.OPERATOR, ">>>") in kinds
    assert not lex.errors


def test_cpp_lexer_features():
    lex, _ = parse('auto r = R"(raw "quoted")"; int big = 1\'000\'000; std::string s;', "cpp")
    assert any(t.type == TokenType.STRING_LITERAL and t.value == 'raw "quoted"' for t in lex.tokens)
    assert any(t.type == TokenType.INT_LITERAL and t.value == 1000000 for t in lex.tokens)
    assert any(t.lexeme == "::" for t in lex.tokens)
    assert not lex.errors


# ------------------------------------------------------------------ parsers
def test_java_parser_builds_classes_lambdas_and_generics():
    code = """
    package a.b;
    import java.util.*;
    public class Box<T extends Comparable<T>> implements Iterable<T> {
        private final Map<String, List<Integer>> index = new HashMap<>();
        public Box() { super(); }
        @Override public Iterator<T> iterator() { return null; }
        int sum(int[] xs) {
            int total = 0;
            for (int x : xs) total += x;
            Runnable r = () -> System.out.println(total);
            try (var in = open()) { r.run(); } catch (IOException | RuntimeException e) { throw e; }
            return switch (total) { case 0 -> 1; default -> total; };
        }
    }"""
    _, result = parse(code, "java")
    assert not result.errors, result.errors
    kinds = {n.kind for n in result.ast.walk()}
    assert {"ClassDecl", "ImportDecl", "Lambda", "ForEach", "Try", "Catch", "New"} <= kinds


def test_cpp_parser_builds_classes_templates_and_new_delete():
    code = """
    #include <vector>
    namespace app {
    template <typename T> class Stack : public Base {
    public:
        explicit Stack(int n) : data_(new T[n]), size_(n) {}
        ~Stack() { delete[] data_; }
        T& top() const noexcept { return data_[size_ - 1]; }
    private:
        T* data_; int size_;
    };
    }
    int main() {
        std::vector<int> v{1, 2, 3};
        for (const auto& x : v) { std::cout << x; }
        auto f = [&](int a) { return a + 1; };
        int* p = static_cast<int*>(nullptr);
        try { throw 1; } catch (...) { }
        return f(v.size());
    }"""
    _, result = parse(code, "cpp")
    assert not result.errors, result.errors
    kinds = {n.kind for n in result.ast.walk()}
    assert {"ClassDecl", "Delete", "New", "Lambda", "ForEach", "Try", "Cast"} <= kinds
    casts = [n for n in result.ast.walk() if isinstance(n, A.Cast)]
    assert casts[0].type.startswith("static_cast")


# ------------------------------------------------------------------ Java rules
def wrap_java(body, extra=""):
    return f"""import javax.servlet.http.*;
public class T {{
    {extra}
    void handle(HttpServletRequest request, HttpServletResponse response) throws Exception {{
        {body}
    }}
}}"""


@pytest.mark.parametrize("body, rule", [
    ('stmt.executeQuery("SELECT * FROM t WHERE id=" + request.getParameter("id"));', "AST017"),
    ('Runtime.getRuntime().exec("ping " + request.getParameter("h"));', "JAVA001"),
    ('new ProcessBuilder("sh", "-c", request.getParameter("c")).start();', "JAVA001"),
    ('Object o = new java.io.ObjectInputStream(request.getInputStream()).readObject();', "JAVA002"),
    ('java.security.MessageDigest.getInstance("SHA-1");', "JAVA003"),
    ('javax.crypto.Cipher c = Cipher.getInstance("AES");', "JAVA003"),
    ('String resetToken = Long.toString(new java.util.Random().nextLong());', "JAVA004"),
    ('new java.io.File("/data/" + request.getParameter("f"));', "JAVA005"),
    ('response.getWriter().println(request.getParameter("q"));', "JAVA006"),
    ('DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();', "JAVA007"),
    ('HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true);', "JAVA008"),
    ('try { work(); } catch (Exception e) { e.printStackTrace(); }', "JAVA009"),
    ('response.sendRedirect(request.getParameter("next"));', "JAVA010"),
    ('Class.forName(request.getParameter("cls"));', "JAVA011"),
    ('Cookie c = new Cookie("session", "x"); response.addCookie(c);', "JAVA012"),
    ('try { work(); } catch (Exception e) { }', "AST018"),
    ('String password = request.getParameter("p"); if (password.equals("hunter22")) { work(); }', "AST005"),
])
def test_java_rules_fire(body, rule):
    hits, result = rules_hit(wrap_java(body), "java")
    assert rule in hits, [f["rule_id"] for f in result["report"]["findings"]]


@pytest.mark.parametrize("body, rule", [
    ('PreparedStatement ps = conn.prepareStatement("SELECT * FROM t WHERE id = ?"); ps.setString(1, request.getParameter("id"));', "AST017"),
    ('new ProcessBuilder("/usr/bin/uptime").start();', "JAVA001"),
    ('java.security.MessageDigest.getInstance("SHA-256");', "JAVA003"),
    ('byte[] b = new byte[16]; new java.security.SecureRandom().nextBytes(b);', "JAVA004"),
    ('DocumentBuilderFactory f = DocumentBuilderFactory.newInstance(); f.setFeature("x", true);', "JAVA007"),
    ('Cookie c = new Cookie("session", "x"); c.setSecure(true); c.setHttpOnly(true);', "JAVA012"),
    ('executor.execute(task);', "AST017"),
])
def test_java_rules_stay_quiet_on_safe_code(body, rule):
    hits, _ = rules_hit(wrap_java(body), "java")
    assert rule not in hits


# ------------------------------------------------------------------ C++ rules
def wrap_cpp(body, extra=""):
    return f"""#include <iostream>
#include <random>
#include <string>
{extra}
int main(int argc, char* argv[]) {{
    {body}
    return 0;
}}"""


@pytest.mark.parametrize("body, extra, rule", [
    ("int* a = new int[8]; delete a;", "", "CPP001"),
    ("char* m = (char*)malloc(8); delete m;", "", "CPP001"),
    ("char name[8]; std::cin >> name;", "", "CPP002"),
    ("char name[8]; std::cin.getline(name, 64);", "", "CPP002"),
    ("auto* p = reinterpret_cast<unsigned char*>(argv);", "", "CPP003"),
    ("std::mt19937 rng(42); int x = rng();", "", "CPP004"),
    ("std::mt19937 rng(time(nullptr)); int x = rng();", "", "CPP004"),
    ("int* leak = new int(5); *leak = 1;", "", "CPP005"),
    ("int* p = new int(1); delete p; *p = 2;", "", "AST010"),
    ("", "char* name() { char buf[8]; return buf; }", "AST019"),
    ("", "const std::string& name() { std::string s = \"x\"; return s; }", "AST019"),
    ("std::string q = std::string(\"SELECT * FROM t WHERE n='\") + argv[1]; sqlite3_exec(db, q.c_str(), 0, 0, 0);",
     "", "AST017"),
    ("try { throw 1; } catch (...) { }", "", "AST018"),
    ("char buf[4]; strcpy(buf, argv[1]);", "", "AST001"),
])
def test_cpp_rules_fire(body, extra, rule):
    hits, result = rules_hit(wrap_cpp(body, extra), "cpp")
    assert rule in hits, [f["rule_id"] for f in result["report"]["findings"]]


@pytest.mark.parametrize("body, rule", [
    ("int* a = new int[8]; delete[] a;", "CPP001"),
    ("char name[8]; std::cin >> std::setw(8) >> name;", "CPP002"),
    ("std::string name; std::cin >> name;", "CPP002"),
    ("std::random_device rd; std::mt19937 rng(rd()); int x = rng();", "CPP004"),
    ("int* p = new int(5); delete p;", "CPP005"),
    ("auto p = std::unique_ptr<int>(new int(5));", "CPP005"),
])
def test_cpp_rules_stay_quiet_on_safe_code(body, rule):
    hits, _ = rules_hit(wrap_cpp(body), "cpp")
    assert rule not in hits


def test_language_specific_rules_do_not_leak_across_languages():
    result = run_pipeline("int main(void) { return 0; }", "x.c")
    rule_ids = {r["id"] for r in next(s for s in result["stages"] if s["id"] == "rule_engine")["data"]["rules"]}
    assert not any(r.startswith(("JAVA", "CPP")) for r in rule_ids)
    assert "AST019" in rule_ids and "AST018" not in rule_ids


# ------------------------------------------------------------------ samples
@pytest.mark.parametrize("path", sorted(p.relative_to(SAMPLES).as_posix() for p in SAMPLES.rglob("*")
                                        if p.suffix in (".cpp", ".java")))
def test_language_samples_end_to_end(path):
    code = (SAMPLES / path).read_text(encoding="utf-8")
    result = run_pipeline(code, "pasted")
    expected = "java" if path.endswith(".java") else "cpp"
    assert result["meta"]["language_id"] == expected
    parser = next(s for s in result["stages"] if s["id"] == "parser")
    assert not parser["data"]["errors"]
    engine = next(s for s in result["stages"] if s["id"] == "rule_engine")
    assert not [r for r in engine["data"]["rules"] if r["error"]]
    if "secure" in path:
        assert result["report"]["total"] == 0
    else:
        assert result["report"]["total"] >= 5
