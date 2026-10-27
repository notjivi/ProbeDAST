"""Passive checks (design doc Section 4.5): missing security headers, cookie
flags, permissive CORS. Cheap, send no attack traffic beyond the plain GET
the crawler already made — run once per endpoint, not per parameter.
"""
from __future__ import annotations
from ..models import Candidate
from .base import Detector, register

SECURITY_HEADERS = {
    "content-security-policy": "medium",
    "x-frame-options": "low",
    "x-content-type-options": "low",
    "strict-transport-security": "medium",
    "referrer-policy": "low",
}


@register("passive_checks")
class PassiveChecksDetector(Detector):
    name = "passive_checks"
    endpoint_level = True   # orchestrator runs this once per endpoint, no parameter loop

    async def run(self, client, endpoint, param, context) -> list:
        cookies = context["cookies"]
        resp = await client.get(endpoint.url, cookies=cookies)
        candidates = []

        for header, severity in SECURITY_HEADERS.items():
            if not resp.header(header):
                candidates.append(Candidate(
                    vuln_type="header", technique="passive", detector=self.name,
                    endpoint=endpoint, param=None, severity=severity,
                    evidence={"missing_header": header}, context={},
                ))

        for sc in resp.set_cookies:
            lowered = sc.lower()
            name = sc.split("=", 1)[0]
            missing = [f for f in ("secure", "httponly", "samesite") if f not in lowered]
            if missing:
                candidates.append(Candidate(
                    vuln_type="cookie", technique="passive", detector=self.name,
                    endpoint=endpoint, param=None, severity="medium",
                    evidence={"cookie": name, "missing_flags": missing}, context={},
                ))

        acao = resp.header("access-control-allow-origin")
        acac = resp.header("access-control-allow-credentials")
        if acao == "*" and acac.lower() == "true":
            candidates.append(Candidate(
                vuln_type="cors", technique="passive", detector=self.name,
                endpoint=endpoint, param=None, severity="high",
                evidence={"access-control-allow-origin": acao, "access-control-allow-credentials": acac},
                context={},
            ))
        elif acao == "*":
            candidates.append(Candidate(
                vuln_type="cors", technique="passive", detector=self.name,
                endpoint=endpoint, param=None, severity="low",
                evidence={"access-control-allow-origin": acao}, context={},
            ))
        return candidates
