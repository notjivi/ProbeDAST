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

LINK_ATTRS = [
    ("a", "href"),
    ("link", "href"),
    ("script", "src"),
    ("img", "src"),
]


class Frontier:
    """In-process frontier + visited set."""

    def __init__(self, seeds: list[str]):
        self._queue: asyncio.Queue = asyncio.Queue()
        self._visited: set[str] = set()
        self._lock = asyncio.Lock()

        for seed in seeds:
            self._queue.put_nowait(seed)
            self._visited.add(seed)

    async def push(self, url: str) -> bool:
        async with self._lock:
            if url in self._visited:
                return False
            self._visited.add(url)

        await self._queue.put(url)
        return True

    async def pop(self, timeout: float = 0.5) -> str | None:
        try:
            return await asyncio.wait_for(
                self._queue.get(),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            return None

    def visited_count(self) -> int:
        return len(self._visited)


def extract_forms(html: str, base_url: str) -> list[dict]:
    """Extract form inputs, preserving support fields without attacking them."""
    soup = BeautifulSoup(html, "lxml")
    forms = []

    for form in soup.find_all("form"):
        action = form.get("action") or base_url
        method = (form.get("method") or "GET").upper()
        fields = []
        support_fields = []

        for inp in form.find_all(
            ["input", "textarea", "select", "button"]
        ):
            name = inp.get("name")
            if not name:
                continue

            if inp.name == "textarea":
                value = inp.text or ""

            elif inp.name == "select":
                option = (
                    inp.find("option", selected=True)
                    or inp.find("option")
                )
                if option is None:
                    value = ""
                else:
                    value = (
                        option.get("value")
                        or option.get_text(strip=True)
                    )

            else:
                value = inp.get("value", "")

            if inp.name == "button":
                input_type = (inp.get("type") or "submit").lower()
            else:
                input_type = (inp.get("type") or "text").lower()

            # Hidden fields frequently contain CSRF tokens or session state.
            if input_type == "hidden":
                support_fields.append((name, value))
                continue

            if input_type in ("reset", "button"):
                continue

            # Submit controls must be included in requests, but should not be
            # treated as injection parameters.
            if input_type in ("submit", "image"):
                support_fields.append((name, value or "Submit"))
                continue

            fields.append((name, value or "sample"))

        if fields:
            forms.append({
                "action": urljoin(base_url, action),
                "method": method,
                "fields": fields,
                "support_fields": support_fields,
            })

    return forms


def extract_links(html: str, base_url: str) -> set[str]:
    soup = BeautifulSoup(html, "lxml")
    links = set()

    for tag, attr in LINK_ATTRS:
        for element in soup.find_all(tag):
            value = element.get(attr)

            if value and not value.startswith(
                ("javascript:", "mailto:", "tel:", "data:", "#")
            ):
                links.add(urljoin(base_url, value))

    return links


def looks_js_only(html: str) -> bool:
    """Heuristic: no real links and a root div typical of an SPA shell."""
    links = extract_links(html, "")
    has_app_root = bool(
        re.search(r"""id=["'](?:root|app)["']""", html)
    )
    return len(links) == 0 and has_app_root


class Crawler:
    def __init__(
        self,
        client: ScopedClient,
        config,
        store,
        scan_id: str,
    ):
        self.client = client
        self.config = config
        self.store = store
        self.scan_id = scan_id

        self.frontier = Frontier([config.target])
        self.endpoints: dict[str, Endpoint] = {}

        self._pages = 0
        self._lock = asyncio.Lock()
        self._browser = None
        self._pw = None

    async def run(self):
        workers = [
            asyncio.create_task(self._worker(i))
            for i in range(self.config.crawl_workers)
        ]

        idle_rounds = 0

        try:
            while idle_rounds < 3:
                await asyncio.sleep(0.3)

                if self.frontier._queue.empty():
                    idle_rounds += 1
                else:
                    idle_rounds = 0

                if (
                    self._pages >= self.config.max_pages
                    or len(self.endpoints) >= self.config.max_endpoints
                ):
                    break

        finally:
            for worker in workers:
                worker.cancel()

            await asyncio.gather(
                *workers,
                return_exceptions=True,
            )

            if self._browser:
                await self._browser.close()
                self._browser = None

            if self._pw:
                await self._pw.stop()
                self._pw = None

        return list(self.endpoints.values())

    async def _worker(self, idx: int):
        while True:
            url = await self.frontier.pop()

            if url is None:
                await asyncio.sleep(0.05)
                continue

            if (
                self._pages >= self.config.max_pages
                or len(self.endpoints) >= self.config.max_endpoints
            ):
                return

            try:
                await self._visit(url)
            except (OutOfScope, Denied):
                continue
            except Exception:
                # A malformed page should not terminate the whole crawl.
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

        # Discover links.
        for link in extract_links(html, canon):
            try:
                canonical_link = canonicalize_url(link)
            except Exception:
                continue

            if (
                urlsplit(canonical_link).hostname
                != urlsplit(self.config.target).hostname
            ):
                continue

            await self.frontier.push(canonical_link)

        # Discover forms. Support fields are included in requests but marked
        # non-attackable so detectors do not inject into CSRF or submit fields.
        for form in extract_forms(html, canon):
            params = dict(form["fields"])
            support_fields = dict(form.get("support_fields", []))
            params.update(support_fields)

            self._register_endpoint(
                form["method"],
                canonicalize_url(form["action"]),
                params,
                state_changing=(form["method"] != "GET"),
                non_attackable=set(support_fields),
            )

        # Register the GET request itself, including URL query parameters.
        query_params = dict(parse_qsl(urlsplit(canon).query))

        self._register_endpoint(
            "GET",
            canon,
            query_params,
        )

    def _register_endpoint(
        self,
        method: str,
        url: str,
        params: dict,
        state_changing: bool = False,
        non_attackable: set[str] | None = None,
    ):
        parsed = urlsplit(url)
        template = path_template(parsed.path)
        names = list(params.keys())

        signature = make_signature(
            method,
            parsed.netloc,
            template,
            names,
        )

        if signature in self.endpoints:
            return

        support_names = non_attackable or set()

        param_objects = [
            Param(
                name=name,
                location="query" if method == "GET" else "body",
                sample=value,
                type=infer_type(value),
                attackable=name not in support_names,
            )
            for name, value in params.items()
        ]

        endpoint = Endpoint(
            method=method,
            url=f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
            path_template=template,
            params=param_objects,
            signature=signature,
            state_changing=state_changing,
            scan_id=self.scan_id,
            endpoint_id=new_id(),
        )

        self.endpoints[signature] = endpoint

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