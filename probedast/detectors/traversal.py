"""Path traversal detector (design doc Section 4.5): request a file the OS is
known to contain and check for a content marker, not just a status code,
since many apps return 200 with a generic error page for any bad path.
"""
from __future__ import annotations
import re

from ..models import Candidate
from .base import Detector, register
from .probing import send_with_param

# path -> (payload-ready value, regex that must appear for the file to actually be that file)
MARKERS = [
    ("../../../../../../etc/passwd", re.compile(r"root:.*:0:0:")),
    ("..\\..\\..\\..\\..\\..\\windows\\win.ini", re.compile(r"\[fonts\]", re.I)),
    ("....//....//....//....//....//....//etc/passwd", re.compile(r"root:.*:0:0:")),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", re.compile(r"root:.*:0:0:")),
]


@register("path_traversal")
class PathTraversalDetector(Detector):
    name = "path_traversal"
    applies_to_types = ("text",)

    async def run(self, client, endpoint, param, context) -> list:
        cookies = context["cookies"]
        for payload, marker in MARKERS:
            resp = await send_with_param(client, endpoint, param, payload, cookies)
            if resp.status < 400 and marker.search(resp.body):
                return [Candidate(
                    vuln_type="path_traversal", technique="content-marker", detector=self.name,
                    endpoint=endpoint, param=param, severity="critical",
                    evidence={"payload": payload, "marker": marker.pattern, "status": resp.status},
                    context={"payload": payload, "marker": marker.pattern},
                )]
        return []
