"""Reflected XSS detector (design doc Section 4.5).

Send a unique harmless canary, find where it lands in the response, and
classify the context (HTML body, attribute value, script block, URL). The
context decides which characters must survive unescaped for exploitation to
be possible — a canary that comes back HTML-encoded is not a finding, just a
reflection. Execution is confirmed later by the Verification Engine's
headless-browser round, not here.
"""
from __future__ import annotations
import html
import re
import uuid

from ..models import Candidate
from .base import Detector, register
from .probing import send_with_param

BREAK_CHARS = "<>\"'`"


def classify_context(body: str, canary: str) -> str | None:
    idx = body.find(canary)
    if idx == -1:
        return None
    window = body[max(0, idx - 80): idx + len(canary) + 80]
    # inside a <script> block?
    last_script_open = body.rfind("<script", 0, idx)
    last_script_close = body.rfind("</script", 0, idx)
    if last_script_open != -1 and last_script_open > last_script_close:
        return "script"
    # inside an attribute value: canary preceded by `attr="` or `attr='` before the next `>`
    attr_match = re.search(r'=["\'][^"\'<>]*$', body[max(0, idx - 120): idx])
    if attr_match:
        return "attribute"
    # inside an href/src that looks like a URL context
    if re.search(r'(href|src)\s*=\s*["\']?\s*$', body[max(0, idx - 40): idx], re.I):
        return "url"
    return "html_body"


def survives_unescaped(body: str, canary: str) -> bool:
    idx = body.find(canary)
    return idx != -1  # exact, unescaped canary string is present


@register("xss_reflected")
class ReflectedXSSDetector(Detector):
    name = "xss_reflected"
    applies_to_types = ()  # any text-bearing parameter is worth probing

    async def run(self, client, endpoint, param, context) -> list:
        if param.type == "boolean":
            return []
        cookies = context["cookies"]
        token = uuid.uuid4().hex[:10]
        canary = f"pdxss{token}{''.join(BREAK_CHARS)}end{token}"

        resp = await send_with_param(client, endpoint, param, canary, cookies)
        body = resp.body

        candidates = []
        if canary in body:
            ctx = classify_context(body, canary)
            candidates.append(Candidate(
                vuln_type="xss", technique="reflected", detector=self.name,
                endpoint=endpoint, param=param, severity="high",
                evidence={"canary": canary, "context": ctx, "request_url": endpoint.url,
                          "snippet": body[max(0, body.find(canary) - 60): body.find(canary) + 100]},
                context={"canary": canary, "reflection_context": ctx, "cookies": cookies},
            ))
        elif html.escape(canary) in body:
            pass  # reflected but encoded: not exploitable, not a candidate
        return candidates
