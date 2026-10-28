"""HTTP API and static UI server.

Run:  python app.py            (serves the built UI and the API on http://127.0.0.1:8000)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from secscan import VERSION, run_pipeline
from secscan.engine import rule_catalog
from secscan.langs import FRONT_ENDS
from secscan.langs.detect import EXTENSIONS, detect_language
from secscan.pipeline import MAX_SOURCE_BYTES, STAGE_INFO
from secscan.report import to_html, to_text

ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = ROOT / "samples"
DIST_DIR = ROOT / "frontend" / "dist"

app = FastAPI(title="Source Code Security Compiler", version=VERSION)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


LanguageChoice = Literal["auto", "c", "cpp", "java"]
DEFAULT_NAMES = {"c": "input.c", "cpp": "input.cpp", "java": "Input.java"}


class ScanRequest(BaseModel):
    code: str = Field(..., max_length=MAX_SOURCE_BYTES)
    filename: str = Field("", max_length=200)
    language: LanguageChoice = "auto"
    disabled_rules: list[str] = Field(default_factory=list)


class DetectRequest(BaseModel):
    code: str = Field(..., max_length=MAX_SOURCE_BYTES)
    filename: str = Field("", max_length=200)


class ExportRequest(ScanRequest):
    format: Literal["html", "text", "json"] = "html"


def safe_filename(name: str, language: str = "c") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", Path(name).name) if name else ""
    return (cleaned or DEFAULT_NAMES.get(language, "input.c"))[:100]


def resolved_filename(req: ScanRequest) -> str:
    """Pasted code has no name: give it one with the right extension once the language is known."""
    if req.filename:
        return safe_filename(req.filename)
    language = req.language if req.language != "auto" else detect_language(req.code).language
    return DEFAULT_NAMES[language]


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "version": VERSION}


@app.get("/api/rules")
def rules() -> dict:
    return {"rules": rule_catalog()}


@app.get("/api/languages")
def languages() -> dict:
    return {"languages": [{"id": fe.id, "name": fe.name, "extensions": list(fe.spec.extensions)}
                          for fe in FRONT_ENDS.values()]}


@app.post("/api/detect")
def detect(req: DetectRequest) -> dict:
    return detect_language(req.code, safe_filename(req.filename) if req.filename else "").to_dict()


@app.get("/api/stages")
def stages() -> dict:
    return {"stages": [{"id": k, "title": t, "module": m, "explain": e} for k, (t, m, e) in STAGE_INFO.items()]}


@app.get("/api/samples")
def samples() -> dict:
    out = []
    order = list(FRONT_ENDS)
    paths = [p for p in SAMPLES_DIR.rglob("*") if p.is_file() and p.suffix in EXTENSIONS]
    for path in sorted(paths, key=lambda p: (order.index(EXTENSIONS[p.suffix]), p.name)):
        code = path.read_text(encoding="utf-8")
        first = code.lstrip().splitlines()[0] if code.strip() else ""
        m = re.match(r"(?:/\*\s*(.*?)\s*\*/|//\s*(.*))", first)
        title = path.stem.split("_", 1)[-1].replace("_", " ").title()
        language = EXTENSIONS[path.suffix]
        out.append({"id": f"{language}-{path.stem}", "filename": path.name, "title": title, "language": language,
                    "description": (m.group(1) or m.group(2) or "") if m else "", "code": code})
    return {"samples": out}


@app.post("/api/scan")
def scan(req: ScanRequest) -> dict:
    if not req.code.strip():
        raise HTTPException(status_code=400, detail="Source code is empty.")
    try:
        return run_pipeline(req.code, resolved_filename(req), req.disabled_rules, req.language,
                            named=bool(req.filename))
    except ValueError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc


@app.post("/api/export")
def export(req: ExportRequest) -> Response:
    result = scan(req)
    stem = Path(result["meta"]["filename"]).stem
    if req.format == "text":
        return PlainTextResponse(to_text(result["report"]),
                                 headers={"Content-Disposition": f'attachment; filename="{stem}-report.txt"'})
    if req.format == "json":
        import json
        return Response(json.dumps(result["report"], indent=2), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{stem}-report.json"'})
    return Response(to_html(result["report"], result["source"]), media_type="text/html",
                    headers={"Content-Disposition": f'attachment; filename="{stem}-report.html"'})


if DIST_DIR.exists():
    app.mount("/assets", StaticFiles(directory=DIST_DIR / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str) -> FileResponse:
        candidate = (DIST_DIR / path).resolve()
        if path and candidate.is_file() and DIST_DIR.resolve() in candidate.parents:
            return FileResponse(candidate)
        return FileResponse(DIST_DIR / "index.html")


def main(host: str = "127.0.0.1", port: int = 8000, reload: Optional[bool] = False) -> None:
    import uvicorn

    print(f"Source Code Security Compiler v{VERSION} -> http://{host}:{port}")
    uvicorn.run("app:app", host=host, port=port, reload=bool(reload))


if __name__ == "__main__":
    main()
