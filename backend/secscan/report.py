"""Security Report Generator: scoring plus text / HTML rendering."""

from __future__ import annotations

import html
from collections import Counter

from .rules.base import SEVERITIES, Finding

SEVERITY_WEIGHT = {"critical": 25.0, "high": 12.0, "medium": 5.0, "low": 1.5, "info": 0.0}


def grade_for(score: float) -> tuple[str, str]:
    if score >= 90:
        return "A", "Low risk"
    if score >= 75:
        return "B", "Moderate risk"
    if score >= 55:
        return "C", "Elevated risk"
    if score >= 35:
        return "D", "High risk"
    return "F", "Critical risk"


def build_report(findings: list[Finding], meta: dict) -> dict:
    counts = Counter(f.severity for f in findings)
    penalty = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    score = max(0.0, round(100.0 - penalty, 1))
    grade, risk = grade_for(score)
    by_category = Counter(f.category for f in findings)
    by_cwe = Counter(f.cwe for f in findings)
    affected_lines = sorted({f.line for f in findings})
    return {
        "meta": meta,
        "score": score,
        "grade": grade,
        "risk": risk,
        "total": len(findings),
        "severity_counts": {s: counts.get(s, 0) for s in SEVERITIES},
        "by_category": dict(by_category.most_common()),
        "by_cwe": dict(by_cwe.most_common()),
        "by_module": {
            "lexical_only": sum(1 for f in findings if f.detected_by == ["lexical"]),
            "ast_only": sum(1 for f in findings if f.detected_by == ["ast"]),
            "both": sum(1 for f in findings if len(f.detected_by) > 1),
        },
        "affected_lines": affected_lines,
        "findings": [f.to_dict() for f in findings],
        "scoring": "score = 100 − Σ weight(severity), weights: "
                   + ", ".join(f"{k}={v:g}" for k, v in SEVERITY_WEIGHT.items()),
    }


def to_text(report: dict) -> str:
    meta = report["meta"]
    lines = [
        "=" * 72,
        " SOURCE CODE SECURITY REPORT",
        "=" * 72,
        f" File      : {meta.get('filename', '<input>')}",
        f" Lines     : {meta.get('lines')}    Tokens: {meta.get('tokens')}    AST nodes: {meta.get('ast_nodes')}",
        f" Score     : {report['score']}/100   Grade: {report['grade']} ({report['risk']})",
        " Findings  : " + ", ".join(f"{k}={v}" for k, v in report["severity_counts"].items()),
        "-" * 72,
    ]
    if not report["findings"]:
        lines.append(" No security findings. (Rule-based analysis: absence of findings is not proof of safety.)")
    for f in report["findings"]:
        lines += [
            f" [{f['severity'].upper():8}] {f['rule_id']} {f['title']}  ({f['cwe']})",
            f"   at line {f['line']}, col {f['col']}   detected by: {' + '.join(f['detected_by'])}",
            f"   code : {f['snippet']}",
            f"   why  : {f['message']}",
            f"   fix  : {f['recommendation']}",
            "",
        ]
    lines.append("=" * 72)
    return "\n".join(lines)


SEV_COLORS = {"critical": "#b42318", "high": "#d9480f", "medium": "#b7791f", "low": "#2b6cb0", "info": "#4a5568"}


def to_html(report: dict, source: str = "") -> str:
    meta = report["meta"]
    esc = html.escape
    rows = []
    for f in report["findings"]:
        color = SEV_COLORS[f["severity"]]
        rows.append(f"""
        <article class="finding">
          <header><span class="sev" style="background:{color}">{esc(f['severity'].upper())}</span>
          <strong>{esc(f['rule_id'])} · {esc(f['title'])}</strong>
          <span class="muted">line {f['line']} · {esc(f['cwe'])} · {esc(' + '.join(f['detected_by']))}</span></header>
          <pre>{esc(f['snippet'])}</pre>
          <p>{esc(f['message'])}</p>
          <p class="fix"><b>Recommendation:</b> {esc(f['recommendation'])}</p>
          <p class="muted mono">{esc(f['evidence'])}</p>
        </article>""")
    flagged = set(report["affected_lines"])
    code = "".join(
        f'<div class="ln{" hit" if i in flagged else ""}"><span>{i}</span>{esc(line) or " "}</div>'
        for i, line in enumerate(source.splitlines(), 1)
    )
    counts = " ".join(
        f'<span class="pill" style="border-color:{SEV_COLORS[k]};color:{SEV_COLORS[k]}">{k}: {v}</span>'
        for k, v in report["severity_counts"].items()
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Report – {esc(meta.get('filename', 'input'))}</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:0;background:#f7f7f8;color:#1f2328}}
main{{max-width:960px;margin:0 auto;padding:32px 16px}}
h1{{margin:0 0 4px}} .muted{{color:#667085;font-size:13px}} .mono{{font-family:ui-monospace,Consolas,monospace}}
.score{{display:flex;gap:24px;align-items:center;background:#fff;border:1px solid #e4e7ec;border-radius:12px;padding:20px;margin:20px 0}}
.grade{{font-size:48px;font-weight:700}} .pill{{border:1px solid;border-radius:999px;padding:2px 10px;font-size:12px;margin-right:6px}}
.finding{{background:#fff;border:1px solid #e4e7ec;border-radius:12px;padding:16px;margin:12px 0}}
.finding header{{display:flex;gap:10px;align-items:center;flex-wrap:wrap}}
.sev{{color:#fff;border-radius:6px;padding:2px 8px;font-size:11px;font-weight:700}}
pre{{background:#f2f4f7;border-radius:8px;padding:8px 12px;overflow:auto}} .fix{{color:#065f46}}
.code{{background:#fff;border:1px solid #e4e7ec;border-radius:12px;font:13px ui-monospace,Consolas,monospace;overflow:auto}}
.ln{{white-space:pre;padding:0 12px}} .ln span{{display:inline-block;width:40px;color:#98a2b3}} .ln.hit{{background:#fee4e2}}
</style></head><body><main>
<h1>Source Code Security Report</h1>
<div class="muted">{esc(meta.get('filename', 'input'))} · {meta.get('lines')} lines · {meta.get('tokens')} tokens · {meta.get('ast_nodes')} AST nodes · generated {esc(meta.get('generated_at', ''))}</div>
<section class="score"><div class="grade">{report['grade']}</div>
<div><div><b>{report['score']}/100</b> — {esc(report['risk'])}</div><div style="margin-top:8px">{counts}</div>
<div class="muted" style="margin-top:8px">{esc(report['scoring'])}</div></div></section>
<h2>Findings ({report['total']})</h2>{''.join(rows) or '<p>No findings.</p>'}
<h2>Annotated source</h2><div class="code">{code}</div>
</main></body></html>"""
