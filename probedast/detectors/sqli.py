"""SQL injection detector, three techniques ordered cheapest-first (design doc
Section 4.5):

  error-based      -- look for a database error signature in the response.
  boolean-differential -- a logically-true and logically-false variant; flag
                          only if true matches baseline and false consistently
                          differs.
  time-based       -- ask the DB to pause; only flagged when latency shifts
                       well beyond the baseline's own noise (normalize.py,
                       Section 5.3). Runs serially per host — see verify.py /
                       orchestrator.py for the dedicated low-concurrency lane.
"""
from __future__ import annotations
import re

from ..models import Candidate
from ..normalize import is_probe_different
from .base import Detector, register
from .probing import send_with_param, collect_baseline

ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"sqlite3.OperationalError",
    r"sqlite_(step|exec)",
    r"pg_query\(\)",
    r"postgresql.*error",
    r"ORA-\d{5}",
    r"microsoft ole db provider for sql server",
    r"supplied argument is not a valid .*sql",
]
ERROR_RE = re.compile("|".join(ERROR_SIGNATURES), re.I)

ERROR_PROBES = ["'", "\"", "' OR '1'='1", "';--", '" --']
BOOL_TRUE = "' OR '1'='1' -- "
BOOL_FALSE = "' AND '1'='2' -- "


@register("sqli_error")
class ErrorBasedSQLiDetector(Detector):
    name = "sqli_error"
    applies_to_types = ("text", "int", "email")

    async def run(self, client, endpoint, param, context) -> list:
        cookies = context["cookies"]
        for probe in ERROR_PROBES:
            resp = await send_with_param(client, endpoint, param, param.sample + probe, cookies)
            m = ERROR_RE.search(resp.body)
            if m:
                return [Candidate(
                    vuln_type="sqli", technique="error-based", detector=self.name,
                    endpoint=endpoint, param=param, severity="critical",
                    evidence={"probe": probe, "signature": m.group(0), "status": resp.status},
                    context={"probe": probe},
                )]
        return []


@register("sqli_boolean")
class BooleanDifferentialSQLiDetector(Detector):
    name = "sqli_boolean"
    applies_to_types = ("text", "int", "email")

    async def run(self, client, endpoint, param, context) -> list:
        cookies = context["cookies"]
        baseline, ref_body, _ = await collect_baseline(client, endpoint, param, cookies)

        true_resp = await send_with_param(client, endpoint, param, param.sample + BOOL_TRUE, cookies)
        false_resp = await send_with_param(client, endpoint, param, param.sample + BOOL_FALSE, cookies)

        true_matches = not is_probe_different(baseline, ref_body, true_resp.body)
        false_differs = is_probe_different(baseline, ref_body, false_resp.body)

        if true_matches and false_differs:
            return [Candidate(
                vuln_type="sqli", technique="boolean-differential", detector=self.name,
                endpoint=endpoint, param=param, severity="high",
                evidence={"true_probe": BOOL_TRUE, "false_probe": BOOL_FALSE,
                          "true_matched_baseline": True, "false_differed": True},
                context={"true_probe": BOOL_TRUE, "false_probe": BOOL_FALSE,
                         "baseline_threshold": baseline.diff_threshold},
            )]
        return []


@register("sqli_time")
class TimeBasedSQLiDetector(Detector):
    """Serial, low-concurrency by construction: the orchestrator routes jobs
    with this detector name onto a dedicated single-flight lane per host so
    queueing latency on the target can't be mistaken for a delayed query."""
    name = "sqli_time"
    applies_to_types = ("text", "int", "email")

    def __init__(self, delay: float = 3.0, samples: int = 5):
        self.delay = delay
        self.samples = samples

    async def run(self, client, endpoint, param, context) -> list:
        cookies = context["cookies"]
        delay = context.get("time_delay", self.delay)
        samples = context.get("time_samples", self.samples)

        bodies, latencies = [], []
        for _ in range(samples):
            resp = await send_with_param(client, endpoint, param, param.sample, cookies)
            bodies.append(resp.body)
            latencies.append(resp.elapsed)
        from ..normalize import build_baseline
        baseline = build_baseline(bodies, latencies)

        probe = f"{param.sample}' OR SLEEP({delay})-- -"
        results = []
        for _ in range(2):  # 2 probe samples, judged with the same robust comparison
            resp = await send_with_param(client, endpoint, param, probe, cookies)
            verdict = baseline.latency_is_delayed(resp.elapsed, delay)
            results.append(verdict)

        if all(r == "delayed" for r in results):
            return [Candidate(
                vuln_type="sqli", technique="time-based", detector=self.name,
                endpoint=endpoint, param=param, severity="high",
                evidence={"probe": probe, "delay_s": delay, "latency_median": baseline.latency_median,
                          "latency_mad": baseline.latency_mad},
                context={"probe": probe, "delay_s": delay},
            )]
        if any(r == "inconclusive" for r in results):
            return []  # baseline too noisy to draw a conclusion; report nothing rather than guess
        return []
