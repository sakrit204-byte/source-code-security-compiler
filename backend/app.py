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


class ScanRequest(BaseModel):
    code: str = Field(..., max_length=MAX_SOURCE_BYTES)
    filename: str = Field("input.c", max_length=200)
    disabled_rules: list[str] = Field(default_factory=list)


class ExportRequest(ScanRequest):
    format: Literal["html", "text", "json"] = "html"


def safe_filename(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", Path(name).name) or "input.c"
    return cleaned[:100]


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "version": VERSION}


@app.get("/api/rules")
def rules() -> dict:
    return {"rules": rule_catalog()}


@app.get("/api/stages")
def stages() -> dict:
    return {"stages": [{"id": k, "title": t, "module": m, "explain": e} for k, (t, m, e) in STAGE_INFO.items()]}


@app.get("/api/samples")
def samples() -> dict:
    out = []
    for path in sorted(SAMPLES_DIR.glob("*.c")):
        code = path.read_text(encoding="utf-8")
        first = code.lstrip().splitlines()[0] if code.strip() else ""
        m = re.match(r"/\*\s*(.*?)\s*\*/", first)
        title = path.stem.split("_", 1)[-1].replace("_", " ").title()
        out.append({"id": path.stem, "filename": path.name, "title": title,
                    "description": m.group(1) if m else "", "code": code})
    return {"samples": out}


@app.post("/api/scan")
def scan(req: ScanRequest) -> dict:
    if not req.code.strip():
        raise HTTPException(status_code=400, detail="Source code is empty.")
    try:
        return run_pipeline(req.code, safe_filename(req.filename), req.disabled_rules)
    except ValueError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc


@app.post("/api/export")
def export(req: ExportRequest) -> Response:
    result = scan(req)
    stem = Path(safe_filename(req.filename)).stem
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
