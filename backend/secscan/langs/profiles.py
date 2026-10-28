"""Where external input enters a program, per language (used by semantic analysis)."""

from __future__ import annotations

from ..semantic import (INPUT_RETURNS, INPUT_WRITERS, KNOWN_GLOBALS, PROPAGATORS, SCANF_FORMAT_INDEX,
                        TaintProfile)

CPP_PROFILE = TaintProfile(
    language="cpp",
    input_writers={**INPUT_WRITERS, "getline": [0, 1]},  # std::getline(std::cin, line)
    scanf_index=dict(SCANF_FORMAT_INDEX),
    input_returns=set(INPUT_RETURNS),
    receiver_writers={"getline": [0], "get": [0], "read": [0], "readsome": [0]},  # cin.getline(buf, n)
    receiver_propagators={"append", "push_back", "emplace_back", "insert", "assign", "push", "emplace"},
    propagators=set(PROPAGATORS),
    stream_sources={"cin", "std::cin", "wcin", "std::wcin"},
    stream_types=("istream", "ifstream", "fstream", "stringstream", "istringstream"),
    known_globals=set(KNOWN_GLOBALS) | {
        "cout", "cin", "cerr", "clog", "endl", "flush", "nullptr", "string", "vector", "map", "set",
        "std", "size_t", "move", "forward", "make_unique", "make_shared", "to_string", "stoi", "stol",
        "begin", "end", "sort", "find", "min", "max", "swap", "this",
    },
    undeclared_severity="info",
)

JAVA_PROFILE = TaintProfile(
    language="java",
    input_writers={},
    scanf_index={},
    input_returns=set(),
    input_methods={
        # Servlet / HTTP request data
        "getParameter", "getParameterValues", "getParameterMap", "getHeader", "getHeaders", "getQueryString",
        "getCookies", "getRequestURI", "getRequestURL", "getPathInfo", "getInputStream", "getReader",
        "getPart", "getRemoteUser",
        # console, files, sockets and environment
        "readLine", "nextLine", "nextInt", "nextLong", "nextDouble", "readAllBytes", "readString",
        "readAllLines", "getenv",
    },
    receiver_writers={"read": [0], "readFully": [0]},
    stream_types=("InputStream", "Reader", "DataInput", "Socket"),
    receiver_propagators={"append", "insert", "add", "addAll", "put", "putAll", "set", "setString", "push",
                          "offer"},
    propagators=set(),
    tainted_params=set(),
    known_globals={"length", "this", "super", "args"},
    undeclared_severity="info",
)

PROFILES = {"cpp": CPP_PROFILE, "java": JAVA_PROFILE}


def profile_for(language: str) -> TaintProfile:
    return PROFILES.get(language, TaintProfile())
