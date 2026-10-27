import pytest

from probedast.config import Config
from probedast.scope import Scope
from probedast.http import ScopedClient
from probedast.crawler import Crawler
from probedast.store import Store


@pytest.mark.asyncio
async def test_crawler_discovers_known_endpoints(vuln_app_base_url, tmp_path):
    host = vuln_app_base_url.split("//")[1]
    cfg = Config(target=vuln_app_base_url + "/", scope_hosts=[host], scope_paths=["/"],
                 max_pages=20, max_endpoints=50)
    scope = Scope(hosts=set(cfg.scope_hosts), path_prefixes=cfg.scope_paths)
    store = Store(str(tmp_path / "crawl.db"))

    async with ScopedClient(scope=scope, safe_mode=True) as client:
        crawler = Crawler(client, cfg, store, "scan1")
        endpoints = await crawler.run()

    urls = {e.url for e in endpoints}
    assert any("/search" in u for u in urls)
    assert any("/user" in u for u in urls)
    assert any("/file" in u for u in urls)


@pytest.mark.asyncio
async def test_crawler_dedupes_structurally_identical_endpoints(vuln_app_base_url, tmp_path):
    """/user?id=1 and /user?id=2 should collapse to one endpoint by signature."""
    host = vuln_app_base_url.split("//")[1]
    cfg = Config(target=vuln_app_base_url + "/user?id=1", scope_hosts=[host], scope_paths=["/"],
                 max_pages=5, max_endpoints=50)
    scope = Scope(hosts=set(cfg.scope_hosts), path_prefixes=cfg.scope_paths)
    store = Store(str(tmp_path / "dedupe.db"))

    async with ScopedClient(scope=scope, safe_mode=True) as client:
        crawler = Crawler(client, cfg, store, "scan2")
        await crawler._visit(cfg.target)
        await crawler._visit(vuln_app_base_url + "/user?id=2")

    user_endpoints = [e for e in crawler.endpoints.values() if "/user" in e.url]
    assert len(user_endpoints) == 1


@pytest.mark.asyncio
async def test_crawler_never_leaves_scope(vuln_app_base_url, tmp_path):
    cfg = Config(target=vuln_app_base_url + "/", scope_hosts=["definitely-not-this-host"],
                 scope_paths=["/"], max_pages=5, max_endpoints=10)
    scope = Scope(hosts=set(cfg.scope_hosts), path_prefixes=cfg.scope_paths)
    store = Store(str(tmp_path / "oos.db"))

    async with ScopedClient(scope=scope, safe_mode=True) as client:
        crawler = Crawler(client, cfg, store, "scan3")
        endpoints = await crawler.run()

    assert endpoints == []
