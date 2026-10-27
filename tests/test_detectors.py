import pytest

from probedast.scope import Scope
from probedast.http import ScopedClient
from probedast.models import Endpoint, Param, new_id
from probedast.detectors.xss import ReflectedXSSDetector, classify_context
from probedast.detectors.sqli import ErrorBasedSQLiDetector, BooleanDifferentialSQLiDetector
from probedast.detectors.traversal import PathTraversalDetector
from probedast.detectors.idor import IDORDetector
from probedast.detectors.passive import PassiveChecksDetector


def _ep(base_url, path, method="GET", **params):
    p = [Param(name=k, location="query", sample=str(v), type="text") for k, v in params.items()]
    return Endpoint(method=method, url=base_url + path, path_template=path, params=p,
                     signature="sig-" + path, endpoint_id=new_id())


@pytest.mark.asyncio
async def test_classify_context_html_body():
    body = "<p>results for pdxss1234<>'`end1234</p>"
    assert classify_context(body, "pdxss1234<>'`end1234") == "html_body"


@pytest.mark.asyncio
async def test_classify_context_script():
    body = "<script>var x = 'pdxss1234<>end1234';</script>"
    assert classify_context(body, "pdxss1234<>end1234") == "script"


@pytest.mark.asyncio
async def test_classify_context_attribute():
    body = '<input value="pdxss1234end1234">'
    assert classify_context(body, "pdxss1234end1234") == "attribute"


@pytest.mark.asyncio
async def test_reflected_xss_detector_finds_known_bug(vuln_app_base_url):
    scope = Scope(hosts={vuln_app_base_url.split("//")[1]}, path_prefixes=["/"])
    ep = _ep(vuln_app_base_url, "/search", q="hello")
    async with ScopedClient(scope=scope, safe_mode=False) as client:
        det = ReflectedXSSDetector()
        candidates = await det.run(client, ep, ep.params[0], {"cookies": {}})
    assert len(candidates) == 1
    assert candidates[0].vuln_type == "xss"


@pytest.mark.asyncio
async def test_error_based_sqli_finds_known_bug(vuln_app_base_url):
    scope = Scope(hosts={vuln_app_base_url.split("//")[1]}, path_prefixes=["/"])
    ep = _ep(vuln_app_base_url, "/user", id="1")
    async with ScopedClient(scope=scope, safe_mode=False) as client:
        det = ErrorBasedSQLiDetector()
        candidates = await det.run(client, ep, ep.params[0], {"cookies": {}})
    assert len(candidates) == 1
    assert candidates[0].technique == "error-based"


@pytest.mark.asyncio
async def test_path_traversal_detector_finds_known_bug(vuln_app_base_url):
    scope = Scope(hosts={vuln_app_base_url.split("//")[1]}, path_prefixes=["/"])
    ep = _ep(vuln_app_base_url, "/file", name="readme.txt")
    async with ScopedClient(scope=scope, safe_mode=False) as client:
        det = PathTraversalDetector()
        candidates = await det.run(client, ep, ep.params[0], {"cookies": {}})
    assert len(candidates) == 1
    assert candidates[0].vuln_type == "path_traversal"


@pytest.mark.asyncio
async def test_passive_checks_flag_missing_headers(vuln_app_base_url):
    scope = Scope(hosts={vuln_app_base_url.split("//")[1]}, path_prefixes=["/"])
    ep = _ep(vuln_app_base_url, "/secure")
    async with ScopedClient(scope=scope, safe_mode=False) as client:
        det = PassiveChecksDetector()
        candidates = await det.run(client, ep, None, {"cookies": {}})
    missing = {c.evidence.get("missing_header") for c in candidates if c.vuln_type == "header"}
    assert "x-frame-options" in missing


@pytest.mark.asyncio
async def test_idor_detector_catches_cross_user_leak(vuln_app_base_url):
    from probedast.auth import SessionManager
    from probedast.config import LoginRecipe

    scope = Scope(hosts={vuln_app_base_url.split("//")[1]}, path_prefixes=["/"])
    ep = _ep(vuln_app_base_url, "/user", id="1")
    recipe = LoginRecipe(login_url=vuln_app_base_url + "/user",
                          owned_markers={"A": ["alice-private-marker"]})
    async with ScopedClient(scope=scope, safe_mode=False) as client:
        sm = SessionManager(client, recipe, "scan1")
        sm.sessions["A"] = {"sid": "sidA"}
        sm.sessions["B"] = {"sid": "sidB"}
        det = IDORDetector()
        context = {"cookies": {}, "session_manager": sm, "owned_markers": recipe.owned_markers}
        candidates = await det.run(client, ep, ep.params[0], context)
    assert len(candidates) == 1
    assert "alice-private-marker" in candidates[0].evidence["leaked_markers"]


@pytest.mark.asyncio
async def test_boolean_sqli_does_not_false_positive_on_safe_endpoint(vuln_app_base_url):
    """/search has no SQL behind it at all -- boolean-differential must not fire."""
    scope = Scope(hosts={vuln_app_base_url.split("//")[1]}, path_prefixes=["/"])
    ep = _ep(vuln_app_base_url, "/search", q="hello")
    async with ScopedClient(scope=scope, safe_mode=False) as client:
        det = BooleanDifferentialSQLiDetector()
        candidates = await det.run(client, ep, ep.params[0], {"cookies": {}})
    assert candidates == []
