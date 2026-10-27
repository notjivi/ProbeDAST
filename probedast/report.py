"""Generates the end-of-scan JSON and Markdown report (design doc Section 1.1,
Phase 4 Day 25)."""
from __future__ import annotations
import json

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def generate_report(scan: dict, endpoints: list[dict], findings: list[dict], fmt: str = "json"):
    findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
    summary = {
        "scan_id": scan["scan_id"], "target": scan["target"], "status": scan["status"],
        "started_at": scan["started_at"], "finished_at": scan.get("finished_at"),
        "endpoints_discovered": len(endpoints), "findings_confirmed": len(findings),
        "by_severity": {sev: sum(1 for f in findings if f["severity"] == sev)
                        for sev in ("critical", "high", "medium", "low")},
        "by_type": _count_by(findings, "vuln_type"),
    }
    if fmt == "json":
        return {"summary": summary, "findings": findings}
    if fmt == "markdown":
        return _markdown(summary, findings)
    raise ValueError(f"unknown report format: {fmt}")


def _count_by(findings, key):
    out = {}
    for f in findings:
        out[f[key]] = out.get(f[key], 0) + 1
    return out


def _markdown(summary: dict, findings: list[dict]) -> str:
    lines = [
        f"# ProbeDAST Report — {summary['target']}",
        "",
        f"- Scan ID: `{summary['scan_id']}`",
        f"- Status: {summary['status']}",
        f"- Started: {summary['started_at']}",
        f"- Finished: {summary.get('finished_at') or '—'}",
        f"- Endpoints discovered: {summary['endpoints_discovered']}",
        f"- Confirmed findings: {summary['findings_confirmed']}",
        "",
        "## By severity",
        "",
    ]
    for sev in ("critical", "high", "medium", "low"):
        lines.append(f"- **{sev}**: {summary['by_severity'].get(sev, 0)}")
    lines += ["", "## Findings", ""]
    for f in findings:
        lines.append(f"### [{f['severity'].upper()}] {f['vuln_type']} — `{f.get('param') or 'n/a'}`")
        lines.append(f"- Confidence: {f['confidence']}")
        lines.append(f"- Endpoint ID: `{f['endpoint_id']}`")
        lines.append(f"- Evidence: `{json.dumps(f['evidence'])}`")
        lines.append("")
    return "\n".join(lines)
