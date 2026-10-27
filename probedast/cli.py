"""Command-line entry point.

    python -m probedast.cli scan --target http://localhost:3000 --scope-host localhost:3000
    python -m probedast.cli scan --config recipes/juiceshop.json --report-out report.md --report-fmt markdown
"""
from __future__ import annotations
import argparse
import asyncio
import json
import sys

from .config import Config
from .orchestrator import Orchestrator
from .report import generate_report


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="probedast")
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="run a scan")
    scan.add_argument("--config", help="path to a JSON config/recipe file")
    scan.add_argument("--target")
    scan.add_argument("--scope-host", action="append", default=[])
    scan.add_argument("--detectors", help="comma-separated detector names, default: all")
    scan.add_argument("--no-verify", action="store_true")
    scan.add_argument("--no-safe-mode", action="store_true",
                       help="DANGEROUS. Only against systems you own / local vuln labs.")
    scan.add_argument("--rps", type=float, default=10.0)
    scan.add_argument("--max-pages", type=int, default=200)
    scan.add_argument("--max-endpoints", type=int, default=300)
    scan.add_argument("--db", default="probedast.db")
    scan.add_argument("--report-out")
    scan.add_argument("--report-fmt", choices=["json", "markdown"], default="json")
    return p


async def run_scan(args) -> int:
    if args.config:
        cfg = Config.from_file(args.config)
        if args.target:
            cfg.target = args.target
    else:
        if not args.target:
            print("error: --target or --config is required", file=sys.stderr)
            return 2
        cfg = Config(target=args.target)

    if args.scope_host:
        cfg.scope_hosts = args.scope_host
    if args.detectors:
        cfg.detectors = args.detectors.split(",")
    if args.no_verify:
        cfg.verify = False
    if args.no_safe_mode:
        cfg.safe_mode = False
    cfg.rps = args.rps
    cfg.max_pages = args.max_pages
    cfg.max_endpoints = args.max_endpoints
    cfg.db_path = args.db

    print(f"[probedast] scanning {cfg.target} (safe_mode={cfg.safe_mode}, verify={cfg.verify})")
    orch = Orchestrator(cfg)
    progress = await orch.run()
    print(f"[probedast] status={progress.status} endpoints={progress.endpoints_found} "
          f"jobs={progress.jobs_done}/{progress.jobs_total} "
          f"confirmed={progress.findings_confirmed} rejected={progress.findings_rejected}")

    endpoints = orch.store.list_endpoints(orch.scan_id)
    findings = orch.store.list_findings(orch.scan_id, status="CONFIRMED")
    scan_row = orch.store.get_scan(orch.scan_id)
    report = generate_report(scan_row, endpoints, findings, fmt=args.report_fmt)

    if args.report_out:
        with open(args.report_out, "w") as f:
            f.write(report if isinstance(report, str) else json.dumps(report, indent=2))
        print(f"[probedast] report written to {args.report_out}")
    else:
        print(report if isinstance(report, str) else json.dumps(report, indent=2))
    return 0 if progress.status == "COMPLETED" else 1


def main():
    parser = build_arg_parser()
    args = parser.parse_args()
    if args.command == "scan":
        sys.exit(asyncio.run(run_scan(args)))


if __name__ == "__main__":
    main()
