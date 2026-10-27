"""Scan Orchestrator (design doc Section 1.1 / 1.2).

Turns endpoints into jobs, one per (endpoint, parameter, detector), and runs
them against a worker pool. In-process by default (asyncio.Queue): swap
`JobQueue` for the RabbitMQ-backed implementation in queue_amqp.py to get
durable jobs and checkpoint/resume across process crashes (Section 5.1,
Phase 4 of the build plan) without changing anything else here.

Time-based SQLi jobs are routed onto a dedicated single-flight queue per host
so concurrent requests can't inflate the latency signal (Section 5.3).
"""
from __future__ import annotations
import asyncio
import itertools
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .auth import SessionManager
from .config import Config
from .crawler import Crawler
from .detectors import ALL_DETECTORS, ENDPOINT_LEVEL, PARAM_LEVEL, instantiate
from .http import ScopedClient
from .models import new_id, Endpoint, Param
from .ratelimit import MemoryRateLimiter
from .scope import Scope
from .store import Store
from .verify import verify_candidate


@dataclass
class ScanProgress:
    scan_id: str
    status: str = "RUNNING"
    endpoints_found: int = 0
    jobs_total: int = 0
    jobs_done: int = 0
    findings_confirmed: int = 0
    findings_rejected: int = 0


class JobQueue:
    """In-process job queue. One asyncio.Queue for ordinary jobs, a separate
    serial lane per host for sqli_time so timing probes never run concurrently
    against the same target (Section 5.3)."""
    def __init__(self):
        self.main: asyncio.Queue = asyncio.Queue()
        self.time_lanes: dict[str, asyncio.Queue] = {}

    def time_lane(self, host: str) -> asyncio.Queue:
        if host not in self.time_lanes:
            self.time_lanes[host] = asyncio.Queue()
        return self.time_lanes[host]


class Orchestrator:
    def __init__(self, config: Config, store: Store | None = None, on_finding=None):
        self.config = config
        self.store = store or Store(config.db_path)
        self.on_finding = on_finding   # optional async callback(finding_dict) -> None, e.g. WebSocket push
        self.scan_id = new_id()
        self.progress = ScanProgress(self.scan_id)
        self.scope = Scope(hosts=set(config.scope_hosts or [urlsplit(config.target).hostname]),
                            path_prefixes=config.scope_paths)
        self.rate_limiter = MemoryRateLimiter(rps=config.rps, burst=config.burst)
        self.session_manager: SessionManager | None = None

    async def run(self) -> ScanProgress:
        self.store.create_scan(self.scan_id, self.config.target,
                                {"hosts": list(self.scope.hosts), "paths": self.scope.path_prefixes})
        try:
            async with ScopedClient(scope=self.scope, rate_limiter=self.rate_limiter,
                                     safe_mode=self.config.safe_mode,
                                     max_bytes=self.config.max_bytes,
                                     insecure_tls=self.config.insecure_tls) as client:

                if self.config.login:
                    self.session_manager = SessionManager(client, self.config.login, self.scan_id)
                    for role in self.config.login.users:
                        await self.session_manager.login(role)
                    client.cookies.update(self.session_manager.cookies_for(self.config.crawl_role))

                crawler = Crawler(client, self.config, self.store, self.scan_id)
                endpoints = await crawler.run()
                for ep in endpoints:
                    ep.endpoint_id = self.store.upsert_endpoint(ep)
                self.progress.endpoints_found = len(endpoints)

                await self._scan_endpoints(client, endpoints)

            self.progress.status = "COMPLETED"
            self.store.set_scan_status(self.scan_id, "COMPLETED", finished=True)
        except Exception:
            self.progress.status = "FAILED"
            self.store.set_scan_status(self.scan_id, "FAILED", finished=True)
            raise
        return self.progress

    async def _scan_endpoints(self, client: ScopedClient, endpoints: list[Endpoint]):
        detector_names = self.config.detectors or ALL_DETECTORS
        queue = JobQueue()

        jobs = []
        for ep in endpoints:
            for dname in detector_names:
                if dname in ENDPOINT_LEVEL:
                    jobs.append((ep, None, dname))
                else:
                    det = instantiate(dname, self.config)
                    for p in ep.params:
                        if not p.attackable or not det.applies(p):
                            continue
                        jobs.append((ep, p, dname))
        self.progress.jobs_total = len(jobs)

        for job in jobs:
            _, _, dname = job
            if dname == "sqli_time":
                host = urlsplit(job[0].url).hostname or ""
                await queue.time_lane(host).put(job)
            else:
                await queue.main.put(job)

        main_workers = [asyncio.create_task(self._worker(client, queue.main))
                        for _ in range(self.config.workers)]
        # one worker per host-lane keeps timing probes serial per host, parallel across hosts
        time_workers = [asyncio.create_task(self._worker(client, q)) for q in queue.time_lanes.values()]

        # _worker returns once its queue has been empty for one timeout cycle, so this
        # simply waits for every worker to notice its queue is drained.
        await asyncio.gather(*main_workers, *time_workers, return_exceptions=True)

    async def _worker(self, client: ScopedClient, queue: asyncio.Queue):
        while True:
            try:
                ep, param, dname = await asyncio.wait_for(queue.get(), timeout=0.3)
            except asyncio.TimeoutError:
                return
            try:
                await self._run_job(client, ep, param, dname)
            except Exception as e:
                if self.config.debug:
                    import traceback
                    traceback.print_exc()
            finally:
                self.progress.jobs_done += 1

    async def _run_job(self, client: ScopedClient, ep: Endpoint, param: Param | None, dname: str):
        role = self.config.crawl_role
        cookies = self.session_manager.cookies_for(role) if self.session_manager else {}

        # Section 5.2: validate the session before accepting any finding from this job.
        if self.session_manager:
            cookies = await self.session_manager.ensure_valid(role)

        det = instantiate(dname, self.config)
        context = {
            "cookies": cookies,
            "time_delay": self.config.time_delay,
            "time_samples": self.config.time_samples,
            "session_manager": self.session_manager,
            "owned_markers": self.config.login.owned_markers if self.config.login else {},
        }
        candidates = await det.run(client, ep, param, context)
        for cand in candidates:
            if self.config.verify:
                result = await verify_candidate(client, cand, rounds=self.config.verify_rounds,
                                                 session_manager=self.session_manager)
            else:
                result = await _skip_verify(cand)
            fid = self.store.record_finding(
                self.scan_id, ep.endpoint_id, cand.vuln_type,
                cand.param.name if cand.param else None, cand.severity,
                result.confidence, result.status, {**cand.evidence, **result.verify_evidence})
            if result.status == "CONFIRMED":
                self.progress.findings_confirmed += 1
                if self.on_finding:
                    await self.on_finding({"finding_id": fid, "scan_id": self.scan_id,
                                            "vuln_type": cand.vuln_type, "severity": cand.severity,
                                            "endpoint": ep.url, "status": "CONFIRMED"})
            else:
                self.progress.findings_rejected += 1


async def _skip_verify(cand):
    from .verify import VerificationResult
    return VerificationResult(cand, "CONFIRMED", 1, 1, 0.5, {"verification": "skipped"})
