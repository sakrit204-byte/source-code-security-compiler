"""Command-line interface: python -m secscan FILE.c [--format text|json|html] [-o OUT]"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .pipeline import run_pipeline
from .report import to_html, to_text


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="secscan", description="Compiler-based source code security scanner for C")
    ap.add_argument("file", help="C source file to scan")
    ap.add_argument("--format", choices=["text", "json", "html", "stages"], default="text")
    ap.add_argument("-o", "--output", help="write the report to this file instead of stdout")
    ap.add_argument("--fail-on", choices=["critical", "high", "medium", "low"],
                    help="exit with status 2 if a finding of this severity or worse exists")
    args = ap.parse_args(argv)

    path = Path(args.file)
    source = path.read_text(encoding="utf-8", errors="replace")
    result = run_pipeline(source, path.name)
    report = result["report"]

    if args.format == "json":
        out = json.dumps(result, indent=2, default=str)
    elif args.format == "html":
        out = to_html(report, result["source"])
    elif args.format == "stages":
        out = "\n".join(
            f"[{s['module']:>16}] {s['title']:<32} {s['duration_ms']:>8.2f} ms  {s['status']:<7}  {s['summary']}"
            for s in result["stages"])
    else:
        out = to_text(report)

    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        sys.stdout.reconfigure(encoding="utf-8")
        print(out)

    if args.fail_on:
        order = ["low", "medium", "high", "critical"]
        threshold = order.index(args.fail_on)
        if any(order.index(f["severity"]) >= threshold for f in report["findings"] if f["severity"] in order):
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
