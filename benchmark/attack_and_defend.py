"""Attack-and-defend run (design doc Section 7 / Q&A 10): place the Runtime
API Firewall in front of a target, rescan, and report what share of probes it
flagged or blocked, and how scanner recall changed relative to an unprotected
run.

This script is intentionally thin: it assumes the Runtime API Firewall
project exposes two things ProbeDAST can observe --
  1. a proxied target URL (the firewall sits in front of the real target), and
  2. an admin/metrics endpoint reporting how many requests it flagged/blocked.
Point --proxied-target and --firewall-metrics-url at those and this script
does the comparison; it does not implement the firewall itself.

    python -m benchmark.attack_and_defend \\
        --recipe recipes/dvwa.json \\
        --proxied-target http://127.0.0.1:9000/ \\
        --firewall-metrics-url http://127.0.0.1:9001/metrics
"""
from __future__ import annotations
import argparse
import asyncio
import copy
import json
import urllib.request

from probedast.config import Config
from probedast.orchestrator import Orchestrator


def fetch_firewall_metrics(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.loads(r.read())


async def scan(cfg: Config) -> dict:
    orch = Orchestrator(cfg)
    progress = await orch.run()
    confirmed = orch.store.list_findings(orch.scan_id, status="CONFIRMED")
    return {"progress": progress, "confirmed": confirmed, "scan_id": orch.scan_id}


async def main(args):
    base_cfg = Config.from_file(args.recipe)

    direct_cfg = copy.deepcopy(base_cfg)
    direct_cfg.db_path = f"{args.db_prefix}_direct.db"
    print(f"[attack-and-defend] scanning {direct_cfg.target} directly (no firewall)")
    direct = await scan(direct_cfg)

    proxied_cfg = copy.deepcopy(base_cfg)
    proxied_cfg.target = args.proxied_target
    proxied_cfg.scope_hosts = [args.proxied_target.split("//")[1].split("/")[0]]
    proxied_cfg.db_path = f"{args.db_prefix}_proxied.db"
    print(f"[attack-and-defend] scanning {proxied_cfg.target} through the firewall")
    proxied = await scan(proxied_cfg)

    firewall_stats = None
    if args.firewall_metrics_url:
        try:
            firewall_stats = fetch_firewall_metrics(args.firewall_metrics_url)
        except Exception as e:
            print(f"[attack-and-defend] couldn't fetch firewall metrics: {e}")

    direct_types = {f["vuln_type"] for f in direct["confirmed"]}
    proxied_types = {f["vuln_type"] for f in proxied["confirmed"]}
    missed = direct_types - proxied_types

    print("\n--- Results ---")
    print(f"Confirmed findings direct:  {len(direct['confirmed'])} ({sorted(direct_types)})")
    print(f"Confirmed findings proxied: {len(proxied['confirmed'])} ({sorted(proxied_types)})")
    if direct_types:
        recall_drop = len(missed) / len(direct_types)
        print(f"Vuln types the firewall suppressed detection of: {sorted(missed) or 'none'} "
              f"({recall_drop * 100:.0f}% of types found directly)")
    if firewall_stats:
        print(f"Firewall-reported stats: {json.dumps(firewall_stats, indent=2)}")
    else:
        print("No firewall metrics endpoint provided/reachable -- report detect/block "
              "rate manually from the firewall's own logs for this run.")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--recipe", required=True)
    p.add_argument("--proxied-target", required=True)
    p.add_argument("--firewall-metrics-url")
    p.add_argument("--db-prefix", default="/tmp/pdast_aad")
    args = p.parse_args()
    asyncio.run(main(args))
