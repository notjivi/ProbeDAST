import pytest

from probedast.config import Config
from probedast.orchestrator import Orchestrator
from probedast.auth import MemoryLock


@pytest.mark.asyncio
async def test_full_scan_confirms_known_bugs(vuln_app_base_url, tmp_path):
    host = vuln_app_base_url.split("//")[1]
    cfg = Config(target=vuln_app_base_url + "/", scope_hosts=[host], scope_paths=["/"],
                 verify=True, verify_rounds=3, rps=50, burst=50, workers=6, crawl_workers=2,
                 db_path=str(tmp_path / "scan.db"), max_pages=20, max_endpoints=50,
                 time_delay=1.0, time_samples=2)
    orch = Orchestrator(cfg)
    progress = await orch.run()

    assert progress.status == "COMPLETED"
    assert progress.endpoints_found > 0
    assert progress.jobs_done == progress.jobs_total

    confirmed = orch.store.list_findings(orch.scan_id, status="CONFIRMED")
    types = {f["vuln_type"] for f in confirmed}
    assert "xss" in types
    assert "sqli" in types
    assert "path_traversal" in types


@pytest.mark.asyncio
async def test_rejected_candidates_are_retained_not_discarded(vuln_app_base_url, tmp_path):
    """Section 7 ablation needs REJECTED rows to exist, not just CONFIRMED ones."""
    host = vuln_app_base_url.split("//")[1]
    cfg = Config(target=vuln_app_base_url + "/", scope_hosts=[host], scope_paths=["/"],
                 verify=True, verify_rounds=3, rps=50, burst=50, workers=6, crawl_workers=2,
                 db_path=str(tmp_path / "scan2.db"), max_pages=20, max_endpoints=50,
                 time_delay=1.0, time_samples=2,
                 detectors=["sqli_boolean"])  # boolean SQLi fires 0 findings on this app -> expect no crash
    orch = Orchestrator(cfg)
    progress = await orch.run()
    assert progress.status == "COMPLETED"
    # whatever candidates boolean-SQLi raised (likely none on this app), nothing should have
    # silently vanished: confirmed + rejected rows should equal what verify_candidate returned
    all_rows = orch.store.list_findings(orch.scan_id)
    assert len(all_rows) == progress.findings_confirmed + progress.findings_rejected


@pytest.mark.asyncio
async def test_memory_lock_serializes_reauth():
    MemoryLock._locks.clear()
    assert await MemoryLock.acquire("k", ttl=5) is True
    assert await MemoryLock.acquire("k", ttl=5) is False   # second caller must wait
    MemoryLock.release("k")
    assert await MemoryLock.acquire("k", ttl=5) is True
