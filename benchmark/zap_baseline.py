"""Run OWASP ZAP's baseline/active scan against the same target via ZAP's API
and normalize its alerts into the same (vuln_type, endpoint, param) shape
ProbeDAST findings use, so metrics.py can compare the two honestly (design
doc Section 7: "run OWASP ZAP against the same targets and compare
honestly. Report where ZAP wins.")

Requires a running ZAP daemon, e.g.:
    docker run -u zap -p 8090:8090 -i zaproxy/zap-stable \\
        zap.sh -daemon -host 0.0.0.0 -port 8090 \\
        -config api.addrs.addr.name=.* -config api.disablekey=true

    python -m benchmark.zap_baseline --target http://127.0.0.1:4280/ --zap-url http://127.0.0.1:8090
"""
from __future__ import annotations
import argparse
import json
import time
import urllib.request
import urllib.parse

ZAP_TO_PROBEDAST_TYPE = {
    "Cross Site Scripting": "xss",
    "SQL Injection": "sqli",
    "Path Traversal": "path_traversal",
    "Insecure HTTP Method": "header",
    "X-Content-Type-Options Header Missing": "header",
    "X-Frame-Options Header Not Set": "header",
    "Content Security Policy (CSP) Header Not Set": "header",
    "Cookie No HttpOnly Flag": "cookie",
    "Cookie Without Secure Flag": "cookie",
    "Cross-Domain Misconfiguration": "cors",
}


def _get(zap_url: str, path: str, params: dict) -> dict:
    qs = urllib.parse.urlencode(params)
    with urllib.request.urlopen(f"{zap_url}{path}?{qs}", timeout=30) as r:
        return json.loads(r.read())


def run_zap_scan(zap_url: str, target: str, max_wait_s: int = 1800) -> list[dict]:
    print(f"[zap] spidering {target}")
    scan_id = _get(zap_url, "/JSON/spider/action/scan/", {"url": target})["scan"]
    t0 = time.monotonic()
    while True:
        status = int(_get(zap_url, "/JSON/spider/view/status/", {"scanId": scan_id})["status"])
        if status >= 100 or time.monotonic() - t0 > max_wait_s:
            break
        time.sleep(2)

    print(f"[zap] active-scanning {target}")
    ascan_id = _get(zap_url, "/JSON/ascan/action/scan/", {"url": target, "recurse": "true"})["scan"]
    t0 = time.monotonic()
    while True:
        status = int(_get(zap_url, "/JSON/ascan/view/status/", {"scanId": ascan_id})["status"])
        if status >= 100 or time.monotonic() - t0 > max_wait_s:
            break
        time.sleep(3)

    alerts = _get(zap_url, "/JSON/core/view/alerts/", {"baseurl": target, "start": "0", "count": "5000"})["alerts"]
    return alerts


def normalize_alerts(alerts: list[dict]) -> list[dict]:
    out = []
    for a in alerts:
        vuln_type = ZAP_TO_PROBEDAST_TYPE.get(a.get("alert", ""), "other")
        out.append({
            "vuln_type": vuln_type, "zap_alert_name": a.get("alert"),
            "url": a.get("url"), "param": a.get("param") or None,
            "risk": a.get("risk"), "confidence": a.get("confidence"),
        })
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--target", required=True)
    p.add_argument("--zap-url", default="http://127.0.0.1:8090")
    p.add_argument("--out", default="/tmp/zap_findings.json")
    args = p.parse_args()

    alerts = run_zap_scan(args.zap_url, args.target)
    normalized = normalize_alerts(alerts)
    with open(args.out, "w") as f:
        json.dump(normalized, f, indent=2)
    print(f"[zap] {len(normalized)} alerts written to {args.out}")
    by_type = {}
    for n in normalized:
        by_type[n["vuln_type"]] = by_type.get(n["vuln_type"], 0) + 1
    print("[zap] by type:", by_type)


if __name__ == "__main__":
    main()
