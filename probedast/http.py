"""ScopedClient: the single choke point for every outbound request ProbeDAST
makes. Crawler, detectors and the verification engine all go through this —
none of them is allowed to hold its own aiohttp session. That's what makes
"did we ever leave scope" an auditable property instead of a promise.

Falls back to a stdlib-only transport (urllib) when aiohttp isn't installed,
so the rest of the codebase and its tests run in environments without network
package installs. In production, aiohttp is used.
"""
from __future__ import annotations
import asyncio
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .models import RawResponse
from .ratelimit import MemoryRateLimiter
from .scope import Scope, OutOfScope, Denied, SAFE_METHODS

try:
    import aiohttp
    HAVE_AIOHTTP = True
except ImportError:
    HAVE_AIOHTTP = False

MAX_REDIRECTS = 5
DEFAULT_TIMEOUT = 15.0


@dataclass
class ScopedClient:
    scope: Scope
    rate_limiter: MemoryRateLimiter = field(default_factory=MemoryRateLimiter)
    safe_mode: bool = True
    max_bytes: int = 1_000_000
    timeout: float = DEFAULT_TIMEOUT
    user_agent: str = "ProbeDAST/1.0 (authorized-scan)"
    insecure_tls: bool = False
    cookies: dict = field(default_factory=dict)       # shared jar, role-less; auth.py keeps per-role jars
    _session: "object" = None
    _request_count: int = 0

    async def __aenter__(self):
        if HAVE_AIOHTTP:
            connector = aiohttp.TCPConnector(limit_per_host=20, ssl=not self.insecure_tls)
            self._session = aiohttp.ClientSession(connector=connector)
        return self

    async def __aexit__(self, *exc):
        if self._session is not None:
            await self._session.close()

    async def request(self, method: str, url: str, *, headers: dict | None = None,
                       data=None, params: dict | None = None, cookies: dict | None = None,
                       allow_dangerous: bool = False, follow_redirects: bool = True,
                       _redirects: int = 0) -> RawResponse:
        method = method.upper()

        # --- the choke point: every request is checked before it leaves the process ---
        self.scope.check(url)
        if self.safe_mode and not allow_dangerous:
            if method not in SAFE_METHODS and self._looks_state_changing(url, method):
                raise Denied(f"safe mode: refusing {method} {url}")
            if Scope.is_dangerous(url):
                raise Denied(f"safe mode: refusing dangerous path {url}")
        # -------------------------------------------------------------------------

        host, _ = urlsplit(url).hostname, None
        await self.rate_limiter.acquire(host or "")

        merged_cookies = {**self.cookies, **(cookies or {})}
        hdrs = {"User-Agent": self.user_agent, **(headers or {})}

        self._request_count += 1
        t0 = time.monotonic()
        try:
            if HAVE_AIOHTTP:
                resp = await self._request_aiohttp(method, url, hdrs, data, params, merged_cookies)
            else:
                resp = await self._request_urllib(method, url, hdrs, data, params, merged_cookies)
        except Exception as e:
            self.rate_limiter.penalize(host or "")
            raise

        if resp.status == 429 or resp.status >= 500:
            self.rate_limiter.penalize(host or "")
        else:
            self.rate_limiter.reward(host or "")

        if follow_redirects and resp.status in (301, 302, 303, 307, 308) and _redirects < MAX_REDIRECTS:
            loc = resp.header("location")
            if loc:
                from .canon import canonicalize_url
                next_url = canonicalize_url(loc, base=url)
                self.scope.check(next_url)  # redirects that leave scope are rejected too
                next_method = "GET" if resp.status in (302, 303) else method
                return await self.request(next_method, next_url, headers=headers,
                                           cookies=cookies, allow_dangerous=allow_dangerous,
                                           follow_redirects=follow_redirects, _redirects=_redirects + 1)
        resp.elapsed = time.monotonic() - t0
        return resp

    def _looks_state_changing(self, url: str, method: str) -> bool:
        return method in ("POST", "PUT", "PATCH", "DELETE")

    async def _request_aiohttp(self, method, url, headers, data, params, cookies) -> RawResponse:
        async with self._session.request(
            method, url, headers=headers, data=data, params=params, cookies=cookies,
            timeout=aiohttp.ClientTimeout(total=self.timeout), allow_redirects=False
        ) as r:
            raw = await r.content.read(self.max_bytes + 1)
            truncated = len(raw) > self.max_bytes
            encoding = r.charset or "utf-8"
            body = raw[: self.max_bytes].decode(encoding, errors="replace")
            set_cookies = [c for c in r.headers.getall("Set-Cookie", [])] if hasattr(r.headers, "getall") else []
            return RawResponse(status=r.status, headers={k.lower(): v for k, v in r.headers.items()},
                                body=body, elapsed=0.0, url=str(r.url), set_cookies=set_cookies,
                                truncated=truncated)

    async def _request_urllib(self, method, url, headers, data, params, cookies) -> RawResponse:
        """Blocking stdlib fallback, run off the event loop. Enough to keep
        ProbeDAST runnable (and its unit tests green) without aiohttp installed."""
        import urllib.request
        import urllib.error
        from urllib.parse import urlencode

        def _do():
            u = url
            if params:
                sep = "&" if "?" in u else "?"
                u = u + sep + urlencode(params)
            body = None
            if data is not None:
                body = urlencode(data).encode() if isinstance(data, dict) else \
                    (data.encode() if isinstance(data, str) else data)
            hdrs = dict(headers)
            if cookies:
                hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
            req = urllib.request.Request(u, data=body, headers=hdrs, method=method)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    raw = r.read(self.max_bytes + 1)
                    status = r.status
                    rheaders = {k.lower(): v for k, v in r.getheaders()}
                    final_url = r.geturl()
            except urllib.error.HTTPError as e:
                raw = e.read(self.max_bytes + 1)
                status = e.code
                rheaders = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
                final_url = u
            truncated = len(raw) > self.max_bytes
            text = raw[: self.max_bytes].decode("utf-8", errors="replace")
            return RawResponse(status=status, headers=rheaders, body=text, elapsed=0.0,
                                url=final_url, set_cookies=[], truncated=truncated)

        return await asyncio.get_event_loop().run_in_executor(None, _do)

    async def get(self, url: str, **kw) -> RawResponse:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, data=None, **kw) -> RawResponse:
        return await self.request("POST", url, data=data, **kw)
