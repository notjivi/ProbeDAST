"""Findings API and scan control (design doc Section 1.1).

FastAPI serves findings, evidence and scan status; the dashboard (dashboard/)
connects over WebSocket for live updates as findings are confirmed. Kept
framework-light on purpose: the Orchestrator does all the real work, this
module is a thin adapter plus the kill switch mentioned in Section 6.
"""
from __future__ import annotations
import asyncio
import json
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .config import Config, LoginRecipe
from .orchestrator import Orchestrator
from .store import Store
from .report import generate_report

app = FastAPI(title="ProbeDAST Findings API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

STORE = Store()
RUNNING: dict[str, Orchestrator] = {}
SOCKETS: dict[str, list[WebSocket]] = {}
TASKS: dict[str, asyncio.Task] = {}


class ScanRequest(BaseModel):
    target: str
    scope_hosts: Optional[list[str]] = None
    scope_paths: Optional[list[str]] = None
    detectors: Optional[list[str]] = None
    safe_mode: bool = True
    verify: bool = True
    login: Optional[dict] = None
    max_pages: int = 200
    max_endpoints: int = 300
    rps: float = 10.0


async def _push(scan_id: str, finding: dict):
    for ws in SOCKETS.get(scan_id, [])[:]:
        try:
            await ws.send_json(finding)
        except Exception:
            SOCKETS[scan_id].remove(ws)


@app.post("/scans")
async def start_scan(req: ScanRequest):
    login = LoginRecipe(**req.login) if req.login else None
    cfg = Config(target=req.target, scope_hosts=req.scope_hosts or [], scope_paths=req.scope_paths or ["/"],
                 detectors=req.detectors, safe_mode=req.safe_mode, verify=req.verify, login=login,
                 max_pages=req.max_pages, max_endpoints=req.max_endpoints, rps=req.rps,
                 db_path=STORE.db_path)
    orch = Orchestrator(cfg, store=STORE, on_finding=lambda f: _push(orch.scan_id, f))
    RUNNING[orch.scan_id] = orch
    SOCKETS[orch.scan_id] = []
    TASKS[orch.scan_id] = asyncio.create_task(orch.run())
    return {"scan_id": orch.scan_id, "status": "RUNNING"}


@app.post("/scans/{scan_id}/stop")
async def stop_scan(scan_id: str):
    """Kill switch (design doc Section 6): stops a scan immediately."""
    task = TASKS.get(scan_id)
    if not task:
        raise HTTPException(404, "scan not found")
    task.cancel()
    STORE.set_scan_status(scan_id, "PAUSED")
    return {"scan_id": scan_id, "status": "PAUSED"}


@app.get("/scans")
async def list_scans():
    return STORE.list_scans()


@app.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    scan = STORE.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    orch = RUNNING.get(scan_id)
    progress = None
    if orch:
        p = orch.progress
        progress = {"endpoints_found": p.endpoints_found, "jobs_total": p.jobs_total,
                    "jobs_done": p.jobs_done, "findings_confirmed": p.findings_confirmed,
                    "findings_rejected": p.findings_rejected}
    return {**scan, "progress": progress}


@app.get("/scans/{scan_id}/endpoints")
async def get_endpoints(scan_id: str):
    return STORE.list_endpoints(scan_id)


@app.get("/scans/{scan_id}/findings")
async def get_findings(scan_id: str, status: Optional[str] = None):
    return STORE.list_findings(scan_id, status=status)


@app.get("/scans/{scan_id}/report")
async def get_report(scan_id: str, fmt: str = "json"):
    scan = STORE.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    findings = STORE.list_findings(scan_id, status="CONFIRMED")
    endpoints = STORE.list_endpoints(scan_id)
    return generate_report(scan, endpoints, findings, fmt=fmt)


@app.websocket("/scans/{scan_id}/live")
async def live_findings(ws: WebSocket, scan_id: str):
    await ws.accept()
    SOCKETS.setdefault(scan_id, []).append(ws)
    try:
        while True:
            await ws.receive_text()   # client doesn't need to send anything; keeps the socket open
    except WebSocketDisconnect:
        SOCKETS.get(scan_id, []).remove(ws) if ws in SOCKETS.get(scan_id, []) else None
