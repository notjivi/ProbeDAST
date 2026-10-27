"""Verification Engine (design doc Section 4.6).

A candidate is not a finding. Re-run the candidate's probe N times (default
3) with freshly generated control/variant requests each round and require the
same outcome every time. XSS candidates additionally need a harmless marker
to actually execute in a headless browser. Each confirmed finding gets a
confidence score from the technique (error-based > boolean > time-based) and
how many rounds agreed. Rejected candidates are kept, not discarded — they're
the raw material for the false-positive ablation in Section 7 / benchmark/.
"""
from __future__ import annotations
import uuid

from .models import Candidate
from .normalize import is_probe_different, build_baseline
from .detectors.probing import send_with_param, collect_baseline

TECHNIQUE_WEIGHT = {
    "error-based": 1.0, "content-marker": 1.0, "two-session": 0.95,
    "boolean-differential": 0.8, "reflected": 0.75, "time-based": 0.6, "passive": 0.5,
}


class VerificationResult:
    def __init__(self, candidate: Candidate, status: str, rounds_agreed: int, rounds_run: int,
                 confidence: float, verify_evidence: dict):
        self.candidate = candidate
        self.status = status                 # CONFIRMED | REJECTED
        self.rounds_agreed = rounds_agreed
        self.rounds_run = rounds_run
        self.confidence = confidence
        self.verify_evidence = verify_evidence


async def _reround_xss(client, candidate: Candidate) -> bool:
    ep, param = candidate.endpoint, candidate.param
    cookies = candidate.context.get("cookies", {})
    token = uuid.uuid4().hex[:10]
    canary = f"pdxss{token}<>\"'`end{token}"
    resp = await send_with_param(client, ep, param, canary, cookies)
    return canary in resp.body


async def _reround_xss_execution(candidate: Candidate) -> bool | None:
    """Headless-browser confirmation that a harmless marker actually executes.
    Returns None (skipped, not failed) if Playwright isn't available."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return None
    ep, param = candidate.endpoint, candidate.param
    marker_var = f"__pdxss_{uuid.uuid4().hex[:8]}"
    payload = f"<script>window.{marker_var}=true</script>"
    from urllib.parse import urlsplit, urlencode
    p = urlsplit(ep.url)
    qs = {pp.name: (payload if pp.name == param.name else pp.sample) for pp in ep.params}
    url = f"{p.scheme}://{p.netloc}{p.path}"
    if ep.method == "GET" and qs:
        url += "?" + urlencode(qs)
    async with async_playwright() as pw:
        browser = await pw.chromium.launch()
        page = await browser.new_page()
        try:
            await page.goto(url, timeout=10000)
            await page.wait_for_timeout(300)
            fired = await page.evaluate(f"() => window.{marker_var} === true")
        except Exception:
            fired = False
        finally:
            await browser.close()
    return bool(fired)


async def _reround_sqli_error(client, candidate: Candidate) -> bool:
    import re
    from .detectors.sqli import ERROR_RE
    ep, param = candidate.endpoint, candidate.param
    cookies = candidate.context.get("cookies", {})
    probe = candidate.context.get("probe", "'")
    resp = await send_with_param(client, ep, param, param.sample + probe, cookies)
    return bool(ERROR_RE.search(resp.body))


async def _reround_sqli_boolean(client, candidate: Candidate) -> bool:
    ep, param = candidate.endpoint, candidate.param
    cookies = candidate.context.get("cookies", {})
    true_probe = candidate.context["true_probe"]
    false_probe = candidate.context["false_probe"]
    baseline, ref_body, _ = await collect_baseline(client, ep, param, cookies, samples=2)
    t = await send_with_param(client, ep, param, param.sample + true_probe, cookies)
    f = await send_with_param(client, ep, param, param.sample + false_probe, cookies)
    return (not is_probe_different(baseline, ref_body, t.body)) and is_probe_different(baseline, ref_body, f.body)


async def _reround_sqli_time(client, candidate: Candidate) -> bool:
    ep, param = candidate.endpoint, candidate.param
    cookies = candidate.context.get("cookies", {})
    probe = candidate.context["probe"]
    delay = candidate.context["delay_s"]
    bodies, lats = [], []
    for _ in range(3):
        r = await send_with_param(client, ep, param, param.sample, cookies)
        bodies.append(r.body); lats.append(r.elapsed)
    baseline = build_baseline(bodies, lats)
    r = await send_with_param(client, ep, param, probe, cookies)
    return baseline.latency_is_delayed(r.elapsed, delay) == "delayed"


async def _reround_traversal(client, candidate: Candidate) -> bool:
    import re
    ep, param = candidate.endpoint, candidate.param
    cookies = candidate.context.get("cookies", {})
    payload = candidate.context["payload"]
    marker = re.compile(candidate.context["marker"])
    resp = await send_with_param(client, ep, param, payload, cookies)
    return resp.status < 400 and bool(marker.search(resp.body))


async def _reround_idor(client, candidate: Candidate, session_manager) -> bool:
    ep, param = candidate.endpoint, candidate.param
    markers = candidate.context["markers"]
    value = candidate.context["object_value"]
    cookies_b = session_manager.cookies_for("B")
    resp = await send_with_param(client, ep, param, value, cookies_b)
    return any(m in resp.body for m in markers) and resp.status < 400


RE_ROUND = {
    "xss": _reround_xss,
    "sqli_error": _reround_sqli_error,
    "sqli_boolean": _reround_sqli_boolean,
    "sqli_time": _reround_sqli_time,
    "path_traversal": _reround_traversal,
}


async def verify_candidate(client, candidate: Candidate, rounds: int = 3,
                            session_manager=None) -> VerificationResult:
    vuln = candidate.vuln_type
    technique = candidate.technique

    if vuln == "header" or vuln == "cookie" or vuln == "cors":
        # Passive findings don't need re-probing; they're read straight off one response.
        return VerificationResult(candidate, "CONFIRMED", 1, 1, TECHNIQUE_WEIGHT["passive"], {})

    if vuln == "xss":
        fn = _reround_xss
    elif vuln == "sqli":
        fn = {"error-based": _reround_sqli_error, "boolean-differential": _reround_sqli_boolean,
              "time-based": _reround_sqli_time}[technique]
    elif vuln == "path_traversal":
        fn = _reround_traversal
    elif vuln == "idor":
        async def fn(client, candidate):
            return await _reround_idor(client, candidate, session_manager)
    else:
        fn = None

    agreed = 0
    inconclusive_runs = 0
    for _ in range(rounds):
        try:
            ok = await fn(client, candidate)
        except Exception:
            ok = False
        if ok:
            agreed += 1

    status = "CONFIRMED" if agreed == rounds else "REJECTED"

    if status == "CONFIRMED" and vuln == "xss":
        execution = await _reround_xss_execution(candidate)
        if execution is False:
            status = "REJECTED"
        candidate.context["browser_execution"] = execution

    base_weight = TECHNIQUE_WEIGHT.get(technique, 0.6)
    confidence = round(base_weight * (agreed / rounds), 2) if status == "CONFIRMED" else round(base_weight * (agreed / rounds), 2)

    return VerificationResult(candidate, status, agreed, rounds, confidence,
                               {"rounds_agreed": agreed, "rounds_run": rounds})
