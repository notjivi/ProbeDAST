"""Scope allowlist enforcement. ScopedClient (http.py) is the only caller of
Scope.check, and the only place in the codebase that makes outbound requests.
That makes this the single choke point to audit for "did the scanner leave
scope" — see Section 6 of the design doc.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit


class OutOfScope(Exception):
    pass


class Denied(Exception):
    """Request refused by safe mode or the dangerous-URL denylist."""


# Path-name based denylist. Never requested in safe mode, regardless of method.
DANGEROUS = re.compile(
    r"(log[-_]?out|sign[-_]?out|delete|remove|destroy|reset|setup|payment|checkout|"
    r"purchase|unsubscribe|deactivate|drop|wipe|shutdown)", re.I)

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _netloc(url: str) -> tuple[str, int | None]:
    p = urlsplit(url)
    return (p.hostname or "").lower(), p.port


@dataclass
class Scope:
    hosts: set = field(default_factory=set)        # "localhost" (any port) or "localhost:4280"
    path_prefixes: list = field(default_factory=lambda: ["/"])
    schemes: tuple = ("http", "https")

    def allows(self, url: str) -> bool:
        p = urlsplit(url)
        if p.scheme.lower() not in self.schemes:
            return False
        host, port = _netloc(url)
        if not host:
            return False
        host_ok = host in self.hosts or (port is not None and f"{host}:{port}" in self.hosts)
        if not host_ok:
            return False
        path = p.path or "/"
        return any(path.startswith(pref) for pref in self.path_prefixes)

    def check(self, url: str) -> None:
        if not self.allows(url):
            raise OutOfScope(f"out of scope: {url}")

    @staticmethod
    def is_dangerous(url_or_path: str) -> bool:
        path = urlsplit(url_or_path).path or url_or_path
        return bool(DANGEROUS.search(path))
