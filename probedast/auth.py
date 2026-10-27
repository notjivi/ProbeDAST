"""Authentication and session handling (design doc Section 4.3 / 5.2).

Several workers share one logged-in session per role. If a worker triggers a
logout or the server expires the session, every other worker starts seeing
401s/redirects — a naive detector reads "the response changed" as "the probe
worked" and floods false findings, and all workers then race to log back in
at once. The fix is three layers:

  1. The dangerous-URL denylist (scope.py) stops the crawler requesting
     logout in the first place.
  2. `SessionManager.health_check` validates the session before any finding
     from a changed response is accepted.
  3. Re-authentication is serialized with a SETNX lock
     (`session:lock:{scan}:{role}`, 10s TTL) — the same pattern as the
     FleetOS trip-state race, applied here. One worker wins the lock, logs
     in, and refreshes the shared session; everyone else waits and reads the
     refreshed session instead of also logging in.
"""
from __future__ import annotations
import asyncio
import time

from .config import LoginRecipe
from .http import ScopedClient


class MemoryLock:
    """SETNX-equivalent for a single process: first caller to acquire wins,
    others wait for release or TTL expiry. Swap for Redis SETNX at scale —
    same semantics, shared across worker processes instead of one."""
    _locks: dict = {}

    @classmethod
    async def acquire(cls, key: str, ttl: float = 10.0) -> bool:
        now = time.monotonic()
        expiry = cls._locks.get(key)
        if expiry is not None and expiry > now:
            return False
        cls._locks[key] = now + ttl
        return True

    @classmethod
    def release(cls, key: str):
        cls._locks.pop(key, None)


class RedisLock:
    def __init__(self, redis):
        self.r = redis

    async def acquire(self, key: str, ttl: float = 10.0) -> bool:
        return bool(await self.r.set(key, "1", nx=True, ex=int(ttl)))

    async def release(self, key: str):
        await self.r.delete(key)


class SessionManager:
    """Cookie-session auth: POSTs form fields, reads the session back from
    Set-Cookie. Fits DVWA- and WebGoat-style apps. For an API that returns a
    bearer token in a JSON body instead (Juice Shop's /rest/user/login), use
    TokenSessionManager below."""

    def __init__(self, client: ScopedClient, recipe: LoginRecipe, scan_id: str, lock=None):
        self.client = client
        self.recipe = recipe
        self.scan_id = scan_id
        self.lock = lock or MemoryLock()
        self.sessions: dict = {}     # role -> cookie dict

    async def login(self, role: str) -> dict:
        creds = self.recipe.users[role]
        data = {self.recipe.username_field: creds["username"], self.recipe.password_field: creds["password"]}
        data.update(self.recipe.extra_fields)
        resp = await self.client.post(self.recipe.login_url, data=data, allow_dangerous=True)
        cookies = self._parse_set_cookies(resp.set_cookies)
        self.sessions[role] = cookies
        return cookies

    def _parse_set_cookies(self, raw: list[str]) -> dict:
        out = {}
        for sc in raw:
            kv = sc.split(";", 1)[0]
            if "=" in kv:
                k, v = kv.split("=", 1)
                out[k.strip()] = v.strip()
        return out

    async def health_check(self, role: str) -> bool:
        """A response that looks like a login page triggers this before any
        finding from the probe that produced it is accepted."""
        if not self.recipe.check_url:
            return True
        resp = await self.client.get(self.recipe.check_url, cookies=self.sessions.get(role, {}))
        return self.recipe.success_indicator in resp.body

    async def ensure_valid(self, role: str) -> dict:
        """Called before accepting a suspicious diff as a candidate. If the
        session is dead, acquire the lock and re-authenticate; if another
        worker already holds the lock, wait briefly and reuse what it produces."""
        if await self.health_check(role):
            return self.sessions.get(role, {})

        key = f"session:lock:{self.scan_id}:{role}"
        if isinstance(self.lock, MemoryLock) or hasattr(self.lock, "acquire") and not asyncio.iscoroutinefunction(self.lock.acquire):
            got = await self.lock.acquire(key)
        else:
            got = await self.lock.acquire(key)

        if got:
            try:
                await self.login(role)
            finally:
                release = self.lock.release(key)
                if asyncio.iscoroutine(release):
                    await release
        else:
            for _ in range(20):
                await asyncio.sleep(0.5)
                if await self.health_check(role):
                    break
        return self.sessions.get(role, {})

    def cookies_for(self, role: str | None) -> dict:
        if role is None:
            return {}
        return self.sessions.get(role, {})


class TokenSessionManager(SessionManager):
    """For APIs that authenticate with a JSON body (`{"email":..,"password":..}`)
    and hand back a bearer token in the response JSON (Juice Shop's
    /rest/user/login: `{"authentication": {"token": "..."}}`) rather than a
    Set-Cookie session. Same health-check / SETNX re-auth contract as the
    base class -- ensure_valid() and the orchestrator don't need to know the
    difference -- but `cookies_for` instead returns an Authorization header,
    and `login` POSTs JSON instead of a form body.
    """

    def __init__(self, client: ScopedClient, recipe: LoginRecipe, scan_id: str,
                 token_json_path=("authentication", "token"), lock=None):
        super().__init__(client, recipe, scan_id, lock)
        self.token_json_path = token_json_path
        self.tokens: dict = {}   # role -> token string

    async def login(self, role: str) -> dict:
        import json
        creds = self.recipe.users[role]
        body = {self.recipe.username_field: creds["username"], self.recipe.password_field: creds["password"]}
        body.update(self.recipe.extra_fields)
        resp = await self.client.post(self.recipe.login_url, data=json.dumps(body),
                                       headers={"Content-Type": "application/json"},
                                       allow_dangerous=True)
        try:
            data = json.loads(resp.body)
            token = data
            for key in self.token_json_path:
                token = token[key]
        except Exception:
            token = None
        self.tokens[role] = token
        self.sessions[role] = {}  # no cookies for this auth style
        return {"token": token}

    async def health_check(self, role: str) -> bool:
        if not self.recipe.check_url or not self.tokens.get(role):
            return bool(self.tokens.get(role))
        resp = await self.client.get(self.recipe.check_url,
                                      headers=self._auth_header(role))
        return resp.status < 400 and self.recipe.success_indicator in resp.body

    def _auth_header(self, role: str) -> dict:
        token = self.tokens.get(role)
        return {"Authorization": f"Bearer {token}"} if token else {}

    def cookies_for(self, role: str | None) -> dict:
        # kept for interface compatibility; callers that need the auth header
        # should use headers_for instead. Detectors built against the base
        # SessionManager only ever read cookies, so a Juice-Shop-style scan
        # additionally needs its probes sent with headers_for(role) merged in --
        # see probedast/detectors/probing.py's extra_headers parameter.
        return {}

    def headers_for(self, role: str | None) -> dict:
        if role is None:
            return {}
        return self._auth_header(role)
