"""Verification Engine (design doc Section 4.6).

A candidate is not a finding. Re-run the candidate's probe N times and
require the same outcome every round. XSS candidates additionally use a
headless browser to check whether a harmless marker executes.
"""
from __future__ import annotations

import uuid

from .models import Candidate
from .normalize import is_probe_different, build_baseline
from .detectors.probing import send_with_param, collect_baseline


TECHNIQUE_WEIGHT = {
    "error-based": 1.0,
    "content-marker": 1.0,
    "two-session": 0.95,
    "boolean-differential": 0.8,
    "reflected": 0.75,
    "time-based": 0.6,
    "passive": 0.5,
}


class VerificationResult:
    def __init__(
        self,
        candidate: Candidate,
        status: str,
        rounds_agreed: int,
        rounds_run: int,
        confidence: float,
        verify_evidence: dict,
    ):
        self.candidate = candidate
        self.status = status
        self.rounds_agreed = rounds_agreed
        self.rounds_run = rounds_run
        self.confidence = confidence
        self.verify_evidence = verify_evidence


async def _reround_xss(client, candidate: Candidate) -> bool:
    ep = candidate.endpoint
    param = candidate.param
    cookies = candidate.context.get("cookies", {})

    token = uuid.uuid4().hex[:10]
    canary = f"""pdxss{token}<>"'`end{token}"""

    response = await send_with_param(
        client,
        ep,
        param,
        canary,
        cookies,
    )

    return canary in response.body


async def _reround_xss_execution(
    candidate: Candidate,
) -> bool | None:
    """Check execution in a browser with the candidate's authentication.

    Returns None if browser verification cannot be performed or if the
    endpoint uses a method this browser check does not currently support.
    """
    ep = candidate.endpoint
    param = candidate.param
    cookies = candidate.context.get("cookies", {})

    # This browser check currently constructs a GET URL. Do not pretend a
    # POST endpoint was checked by merely navigating to it with GET.
    if ep.method.upper() != "GET":
        return None

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return None

    from urllib.parse import urlsplit, urlencode

    marker_var = f"__pdxss_{uuid.uuid4().hex[:8]}"
    payload = f"<script>window.{marker_var}=true</script>"

    parsed = urlsplit(ep.url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    query = {
        item.name: (
            payload if item.name == param.name else item.sample
        )
        for item in ep.params
        if item.location == "query"
    }

    url = f"{origin}{parsed.path}"

    if query:
        url += "?" + urlencode(query)

    # Token-based auth stores an Authorization header in the session dict.
    # It must be sent as a header, not mistakenly added as a browser cookie.
    auth_headers = {
        key: value
        for key, value in cookies.items()
        if key.lower() == "authorization"
    }

    browser_cookies = [
        {
            "name": name,
            "value": str(value),
            "url": f"{origin}/",
        }
        for name, value in cookies.items()
        if name.lower() != "authorization"
    ]

    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch()

            try:
                browser_context = await browser.new_context()

                try:
                    if browser_cookies:
                        await browser_context.add_cookies(
                            browser_cookies
                        )

                    if auth_headers:
                        await browser_context.set_extra_http_headers(
                            auth_headers
                        )

                    page = await browser_context.new_page()

                    try:
                        await page.goto(url, timeout=10000)
                        await page.wait_for_timeout(300)

                        fired = await page.evaluate(
                            f"() => window.{marker_var} === true"
                        )
                    except Exception:
                        fired = False
                    finally:
                        await page.close()

                finally:
                    await browser_context.close()

            finally:
                await browser.close()

        return bool(fired)

    except Exception:
        # A browser launch or setup failure is inconclusive, not proof
        # that the vulnerability is absent.
        return None


async def _reround_sqli_error(
    client,
    candidate: Candidate,
) -> bool:
    from .detectors.sqli import ERROR_RE

    ep = candidate.endpoint
    param = candidate.param
    cookies = candidate.context.get("cookies", {})
    probe = candidate.context.get("probe", "'")

    response = await send_with_param(
        client,
        ep,
        param,
        param.sample + probe,
        cookies,
    )

    return bool(ERROR_RE.search(response.body))


async def _reround_sqli_boolean(
    client,
    candidate: Candidate,
) -> bool:
    ep = candidate.endpoint
    param = candidate.param
    cookies = candidate.context.get("cookies", {})

    true_probe = candidate.context["true_probe"]
    false_probe = candidate.context["false_probe"]

    baseline, reference_body, _ = await collect_baseline(
        client,
        ep,
        param,
        cookies,
        samples=2,
    )

    true_response = await send_with_param(
        client,
        ep,
        param,
        param.sample + true_probe,
        cookies,
    )

    false_response = await send_with_param(
        client,
        ep,
        param,
        param.sample + false_probe,
        cookies,
    )

    true_matches = not is_probe_different(
        baseline,
        reference_body,
        true_response.body,
    )
    false_differs = is_probe_different(
        baseline,
        reference_body,
        false_response.body,
    )

    return true_matches and false_differs


async def _reround_sqli_time(
    client,
    candidate: Candidate,
) -> bool:
    ep = candidate.endpoint
    param = candidate.param
    cookies = candidate.context.get("cookies", {})
    probe = candidate.context["probe"]
    delay = candidate.context["delay_s"]

    bodies = []
    latencies = []

    for _ in range(3):
        response = await send_with_param(
            client,
            ep,
            param,
            param.sample,
            cookies,
        )
        bodies.append(response.body)
        latencies.append(response.elapsed)

    baseline = build_baseline(bodies, latencies)

    response = await send_with_param(
        client,
        ep,
        param,
        probe,
        cookies,
    )

    return (
        baseline.latency_is_delayed(response.elapsed, delay)
        == "delayed"
    )


async def _reround_traversal(
    client,
    candidate: Candidate,
) -> bool:
    import re

    ep = candidate.endpoint
    param = candidate.param
    cookies = candidate.context.get("cookies", {})
    payload = candidate.context["payload"]
    marker = re.compile(candidate.context["marker"])

    response = await send_with_param(
        client,
        ep,
        param,
        payload,
        cookies,
    )

    return (
        response.status < 400
        and bool(marker.search(response.body))
    )


async def _reround_idor(
    client,
    candidate: Candidate,
    session_manager,
) -> bool:
    ep = candidate.endpoint
    param = candidate.param

    markers = candidate.context["markers"]
    object_value = candidate.context["object_value"]
    cookies_b = session_manager.cookies_for("B")

    response = await send_with_param(
        client,
        ep,
        param,
        object_value,
        cookies_b,
    )

    return (
        any(marker in response.body for marker in markers)
        and response.status < 400
    )


RE_ROUND = {
    "xss": _reround_xss,
    "sqli_error": _reround_sqli_error,
    "sqli_boolean": _reround_sqli_boolean,
    "sqli_time": _reround_sqli_time,
    "path_traversal": _reround_traversal,
}


async def verify_candidate(
    client,
    candidate: Candidate,
    rounds: int = 3,
    session_manager=None,
) -> VerificationResult:
    vuln = candidate.vuln_type
    technique = candidate.technique

    # Passive findings are checked from the original response.
    if vuln in ("header", "cookie", "cors"):
        return VerificationResult(
            candidate,
            "CONFIRMED",
            1,
            1,
            TECHNIQUE_WEIGHT["passive"],
            {},
        )

    if vuln == "xss":
        verify_function = _reround_xss

    elif vuln == "sqli":
        verify_function = {
            "error-based": _reround_sqli_error,
            "boolean-differential": _reround_sqli_boolean,
            "time-based": _reround_sqli_time,
        }[technique]

    elif vuln == "path_traversal":
        verify_function = _reround_traversal

    elif vuln == "idor":
        async def verify_function(client, candidate):
            return await _reround_idor(
                client,
                candidate,
                session_manager,
            )

    else:
        raise ValueError(
            f"Unsupported vulnerability type: {vuln}"
        )

    agreed = 0

    for _ in range(rounds):
        try:
            result = await verify_function(client, candidate)
        except Exception:
            result = False

        if result:
            agreed += 1

    status = (
        "CONFIRMED"
        if agreed == rounds
        else "REJECTED"
    )

    if status == "CONFIRMED" and vuln == "xss":
        execution = await _reround_xss_execution(candidate)

        if execution is False:
            status = "REJECTED"

        candidate.context["browser_execution"] = execution

    base_weight = TECHNIQUE_WEIGHT.get(technique, 0.6)
    confidence = round(base_weight * (agreed / rounds), 2)

    evidence = {
        "rounds_agreed": agreed,
        "rounds_run": rounds,
    }

    if vuln == "xss":
        evidence["browser_execution"] = candidate.context.get(
            "browser_execution"
        )

    return VerificationResult(
        candidate,
        status,
        agreed,
        rounds,
        confidence,
        evidence,
    )