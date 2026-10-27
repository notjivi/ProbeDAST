"""Shared helpers for sending a probe through one specific parameter, and for
collecting the 3-control baseline every detector needs before judging a diff.
"""
from __future__ import annotations
from urllib.parse import urlsplit

from ..normalize import build_baseline, Baseline


async def send_with_param(client, endpoint, param, value: str, cookies: dict, extra_headers=None):
    """Re-send the endpoint's request with `param` replaced by `value`, every
    other parameter kept at its sampled value."""
    params = {}
    data = {}
    for p in endpoint.params:
        v = value if p.name == param.name else p.sample
        if p.location == "query":
            params[p.name] = v
        else:
            data[p.name] = v
    kwargs = {"cookies": cookies}
    if extra_headers:
        kwargs["headers"] = extra_headers
    if endpoint.method == "GET":
        return await client.get(endpoint.url, params=params or None, **kwargs)
    return await client.request(endpoint.method, endpoint.url, data=data or None,
                                 params=params or None, **kwargs)


async def collect_baseline(client, endpoint, param, cookies: dict, samples: int = 3) -> tuple[Baseline, str, float]:
    """3 control requests (the parameter's own sampled value, unchanged).
    Returns (baseline, last_reference_body, last_elapsed)."""
    bodies, latencies = [], []
    ref_body = ""
    for _ in range(samples):
        resp = await send_with_param(client, endpoint, param, param.sample, cookies)
        bodies.append(resp.body)
        latencies.append(resp.elapsed)
        ref_body = resp.body
    return build_baseline(bodies, latencies), ref_body, (latencies[-1] if latencies else 0.0)
