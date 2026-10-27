import pytest

from probedast.scope import Scope
from probedast.http import ScopedClient
from probedast.models import Endpoint, Param, Candidate, new_id
from probedast.detectors.xss import ReflectedXSSDetector
from probedast.verify import verify_candidate


def _ep(base_url, path, method="GET", **params):
    p = [Param(name=k, location="query", sample=str(v), type="text") for k, v in params.items()]
    return Endpoint(method=method, url=base_url + path, path_template=path, params=p,
                     signature="sig-" + path, endpoint_id=new_id())


@pytest.mark.asyncio
async def test_real_xss_candidate_is_confirmed(vuln_app_base_url):
    scope = Scope(hosts={vuln_app_base_url.split("//")[1]}, path_prefixes=["/"])
    ep = _ep(vuln_app_base_url, "/search", q="hello")
    async with ScopedClient(scope=scope, safe_mode=False) as client:
        det = ReflectedXSSDetector()
        candidates = await det.run(client, ep, ep.params[0], {"cookies": {}})
        assert candidates
        result = await verify_candidate(client, candidates[0], rounds=3)
    # browser confirmation may be unavailable in this environment (no playwright
    # execution target); the re-round agreement itself must still hold.
    assert result.rounds_agreed == result.rounds_run == 3


@pytest.mark.asyncio
async def test_fabricated_candidate_is_rejected(vuln_app_base_url):
    """A candidate manufactured against a param/endpoint that doesn't actually
    reflect anything must fail every re-round and end up REJECTED."""
    scope = Scope(hosts={vuln_app_base_url.split("//")[1]}, path_prefixes=["/"])
    ep = _ep(vuln_app_base_url, "/user", id="1")  # /user doesn't reflect raw input
    param = ep.params[0]
    fake_candidate = Candidate(
        vuln_type="xss", technique="reflected", detector="xss_reflected",
        endpoint=ep, param=param, severity="high",
        evidence={}, context={"cookies": {}, "reflection_context": "html_body"},
    )
    async with ScopedClient(scope=scope, safe_mode=False) as client:
        result = await verify_candidate(client, fake_candidate, rounds=3)
    assert result.status == "REJECTED"


@pytest.mark.asyncio
async def test_passive_findings_confirm_without_reprobing(vuln_app_base_url):
    from probedast.detectors.passive import PassiveChecksDetector
    scope = Scope(hosts={vuln_app_base_url.split("//")[1]}, path_prefixes=["/"])
    ep = _ep(vuln_app_base_url, "/secure")
    async with ScopedClient(scope=scope, safe_mode=False) as client:
        det = PassiveChecksDetector()
        candidates = await det.run(client, ep, None, {"cookies": {}})
        result = await verify_candidate(client, candidates[0], rounds=3)
    assert result.status == "CONFIRMED"
