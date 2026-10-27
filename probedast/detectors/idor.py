"""Broken access control / IDOR detector (design doc Section 4.5).

Replay user A's request for an object A owns, using user B's session. If B
receives A's private data, that's a finding. This two-session differential
catches a bug class signature-matching scanners miss entirely: the response
is perfectly well-formed, it's just the wrong person's data.

Needs context["session_manager"] with both roles logged in and
context["owned_markers"][role] (strings that only appear in that role's own
data, from the login recipe) to tell "B got A's data" apart from "B just got
a normal page".
"""
from __future__ import annotations
from ..models import Candidate
from .base import Detector, register
from .probing import send_with_param


@register("idor_two_session")
class IDORDetector(Detector):
    name = "idor_two_session"
    applies_to_types = ("int", "uuid")  # object-id-shaped parameters

    async def run(self, client, endpoint, param, context) -> list:
        sm = context.get("session_manager")
        owned = context.get("owned_markers", {})
        if sm is None or "A" not in sm.sessions or "B" not in sm.sessions:
            return []
        if "A" not in owned or not owned["A"]:
            return []  # nothing distinguishes A's own data; can't judge this safely

        cookies_a = sm.cookies_for("A")
        cookies_b = sm.cookies_for("B")

        resp_as_a = await send_with_param(client, endpoint, param, param.sample, cookies_a)
        if not any(marker in resp_as_a.body for marker in owned["A"]):
            return []  # this endpoint+value doesn't even return A's own marked data for A

        resp_as_b = await send_with_param(client, endpoint, param, param.sample, cookies_b)
        leaked = [m for m in owned["A"] if m in resp_as_b.body]
        if leaked and resp_as_b.status < 400:
            return [Candidate(
                vuln_type="idor", technique="two-session", detector=self.name,
                endpoint=endpoint, param=param, severity="high",
                evidence={"object_value": param.sample, "leaked_markers": leaked,
                          "status_as_b": resp_as_b.status},
                context={"object_value": param.sample, "markers": leaked},
            )]
        return []
