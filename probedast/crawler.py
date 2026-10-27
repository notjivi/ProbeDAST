"""The crawler: async workers pulling from a frontier, extracting links/forms,
canonicalizing, and deduping on structural signature so /item/1..N collapses
to one Endpoint. See Section 4.1 of the design doc for the four hard problems
this addresses: canonicalization, structural dedupe, the scope guard, and the
dangerous-URL denylist (the latter two live in scope.py / http.py).
"""
from __future__ import annotations
import asyncio
import re
from urllib.parse import urlsplit, urljoin, parse_qsl

from bs4 import BeautifulSoup

from .canon import canonicalize_url, path_template, make_signature, infer_type
from .models import Endpoint, Param, new_id
from .scope import OutOfScope, Denied
from .http import ScopedClient

LINK_ATTRS = [("a", "href"), ("link", "href"), ("script", "src"), ("img", "src")]


class Frontier:
    """In-process frontier + visited set. Swap for Redis (List + Set, SADD is
    atomic so two workers can never both enqueue the same URL) at multi-process scale."""
    def __init__(self, seeds: list[str]):
        self._queue: asyncio.Queue = asyncio.Queue()
        self._visited: set[str] = set()
        self._lock = asyncio.Lock()
        for s in seeds:
            self._queue.put_nowait(s)
            self._visited.add(s)

    async def push(self, url: str) -> bool:
        async with self._lock:
            if url in self._visited:
                return False
            self._visited.add(url)
        await self._queue.put(url)
        return True

    async def pop(self, timeout: float = 0.5) -> str | None:
        try:
            return await asyncio.wait_for(self._queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    def visited_count(self) -> int:
        return len(self._visited)


def extract_forms(html: str, base_url: str) -> list[dict]:
    soup = BeautifulSoup(html, "lxml")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or base_url
        method = (form.get("method") or "GET").upper()
        fields = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            value = inp.get("value", "") if inp.name != "textarea" else (inp.text or "")
            itype = inp.get("type", "text")
            if itype in ("submit", "button", "image", "reset", "hidden"):
                continue
            fields.append((name, value or "sample"))
        if fields:
            forms.append({"action": urljoin(base_url, action), "method": method, "fields": fields})
    return forms


def extract_links(html: str, base_url: str) -> set[str]:
    soup = BeautifulSoup(html, "lxml")
    links = set()
    for tag, attr in LINK_ATTRS:
        for el in soup.find_all(tag):
            v = el.get(attr)
            if v and not v.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
                links.add(urljoin(base_url, v))
    return links


def looks_js_only(html: str) -> bool:
    """Heuristic: no real link set and a root div typical of an SPA shell."""
    links = extract_links(html, "")
    return len(links) == 0 and bool(re.search(r'id=["\'](root|app)["\']', html))


class Crawler:
    def __init__(self, client: ScopedClient, config, store, scan_id: str):
        self.client = client
        self.config = config
        self.store = store
        self.scan_id = scan_id
        self.frontier = Frontier([config.target])
        self.endpoints: dict[str, Endpoint] = {}   # signature -> Endpoint
        self._pages = 0
        self._lock = asyncio.Lock()
        self._browser = None  # lazily created Playwright browser, JS-rendered routes only

    async def run(self):
        workers = [asyncio.create_task(self._worker(i)) for i in range(self.config.crawl_workers)]
        # Stop when the frontier has been empty across a full sweep of workers, or caps hit.
        idle_rounds = 0
        while idle_rounds < 3:
            await asyncio.sleep(0.3)
            if self.frontier._queue.empty():
                idle_rounds += 1
            else:
                idle_rounds = 0
            if self._pages >= self.config.max_pages or len(self.endpoints) >= self.config.max_endpoints:
                break
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        if self._browser:
            await self._browser.close()
        return list(self.endpoints.values())

    async def _worker(self, idx: int):
        while True:
            url = await self.frontier.pop()
            if url is None:
                await asyncio.sleep(0.05)
                continue
            if self._pages >= self.config.max_pages or len(self.endpoints) >= self.config.max_endpoints:
                return
            try:
                await self._visit(url)
            except (OutOfScope, Denied):
                continue
            except Exception:
                continue

    async def _visit(self, url: str):
        canon = canonicalize_url(url)
        try:
            resp = await self.client.get(canon)
        except (OutOfScope, Denied):
            return
        self._pages += 1
        if resp.status >= 400:
            return

        html = resp.body
        if self.config.js_fallback and looks_js_only(html):
            html = await self._render_with_browser(canon) or html

        for link in extract_links(html, canon):
            try:
                c = canonicalize_url(link)
            except Exception:
                continue
            if urlsplit(c).hostname != urlsplit(self.config.target).hostname:
                continue
            await self.frontier.push(c)

        for form in extract_forms(html, canon):
            params = {name: val for name, val in form["fields"]}
            self._register_endpoint(form["method"], canonicalize_url(form["action"]), params,
                                     state_changing=(form["method"] != "GET"))

        # register the GET request itself -- with its query params if it has any,
        # as one endpoint either way, instead of a paramless + a params registration
        # that would otherwise collide on path but differ on signature.
        q = dict(parse_qsl(urlsplit(canon).query))
        self._register_endpoint("GET", canon, q)

    def _register_endpoint(self, method: str, url: str, params: dict, state_changing: bool = False):
        p = urlsplit(url)
        template = path_template(p.path)
        names = list(params.keys())
        sig = make_signature(method, p.netloc, template, names)
        if sig in self.endpoints:
            return
        param_objs = [Param(name=n, location="query" if method == "GET" else "body",
                             sample=v, type=infer_type(v)) for n, v in params.items()]
        ep = Endpoint(method=method, url=f"{p.scheme}://{p.netloc}{p.path}", path_template=template,
                       params=param_objs, signature=sig, state_changing=state_changing,
                       scan_id=self.scan_id, endpoint_id=new_id())
        self.endpoints[sig] = ep

    async def _render_with_browser(self, url: str) -> str | None:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return None
        if self._browser is None:
            self._pw = await async_playwright().start()
            self._browser = await self._pw.chromium.launch()
        page = await self._browser.new_page()
        try:
            await page.goto(url, timeout=10000)
            await page.wait_for_timeout(500)
            return await page.content()
        except Exception:
            return None
        finally:
            await page.close()
