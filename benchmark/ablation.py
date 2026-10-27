"""Verification ablation (design doc Section 7): run ProbeDAST against a
target with the Verification Engine off, then on, and report the drop in
confirmed-but-wrong findings against any change in recall.

    python -m benchmark.ablation --recipe recipes/dvwa.json

With verify=False, every detector candidate is auto-confirmed at low
confidence (see orchestrator._skip_verify) so "confirmed" in that run means
"the detector's first probe looked suspicious" -- not "re-tested and still
suspicious". That's the number verification exists to cut down.
"""
from __future__ import annotations
import argparse
import asyncio
import copy
import time

from probedast.config import Config
from probedast.orchestrator import Orchestrator


async def run_once(cfg: Config, label: str) -> dict:
    t0 = time.monotonic()
    orch = Orchestrator(cfg)
    progress = await orch.run()
    duration = time.monotonic() - t0
    confirmed = orch.store.list_findings(orch.scan_id, status="CONFIRMED")
    return {
        "label": label, "scan_id": orch.scan_id, "duration_s": duration,
        "endpoints": progress.endpoints_found,
        "confirmed": len(confirmed),
        "rejected": progress.findings_rejected,
        "by_type": _count_by_type(confirmed),
        "requests_sent": None,  # wire up ScopedClient._request_count via orchestrator if needed
    }


def _count_by_type(findings):
    out = {}
    for f in findings:
        out[f["vuln_type"]] = out.get(f["vuln_type"], 0) + 1
    return out


async def main(recipe_path: str, db_prefix: str):
    base_cfg = Config.from_file(recipe_path)

    cfg_off = copy.deepcopy(base_cfg)
    cfg_off.verify = False
    cfg_off.db_path = f"{db_prefix}_verify_off.db"

    cfg_on = copy.deepcopy(base_cfg)
    cfg_on.verify = True
    cfg_on.db_path = f"{db_prefix}_verify_on.db"

    off = await run_once(cfg_off, "verification OFF")
    on = await run_once(cfg_on, "verification ON")

    print(f"\n{'':20} {'OFF':>10} {'ON':>10}")
    print(f"{'confirmed findings':20} {off['confirmed']:>10} {on['confirmed']:>10}")
    print(f"{'rejected candidates':20} {off['rejected']:>10} {on['rejected']:>10}")
    if off["confirmed"]:
        drop = 1 - (on["confirmed"] / off["confirmed"])
        print(f"\nVerification changed the confirmed count by {drop * 100:.1f}%.")
    print("\nBy type (OFF):", off["by_type"])
    print("By type (ON): ", on["by_type"])
    print(
        "\nNote: a drop here only tells you verification is removing candidates;\n"
        "it does NOT by itself tell you whether those candidates were false positives.\n"
        "Cross-check the ON run's confirmed findings against benchmark/ground_truth.py\n"
        "(see metrics.py) to report an honest false-positive-rate number, not just a count."
    )


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--recipe", required=True)
    p.add_argument("--db-prefix", default="/tmp/pdast_ablation")
    args = p.parse_args()
    asyncio.run(main(args.recipe, args.db_prefix))
