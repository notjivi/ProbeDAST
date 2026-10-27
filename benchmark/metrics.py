"""Precision, recall and false-positive rate against ground truth (design doc
Section 7). Takes a ProbeDAST Store and a scan_id, plus ground truth entries,
and reports only measured numbers -- no claim is made that isn't computed
here against this run's own findings table.
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class Metrics:
    true_positives: int
    false_positives: int
    known_vulns: int
    found_known: int
    requests_sent: int
    duration_s: float
    out_of_scope_findings: int = 0   # confirmed findings outside scored_vuln_types (e.g. passive checks)

    @property
    def precision(self) -> float:
        total = self.true_positives + self.false_positives
        return self.true_positives / total if total else 0.0

    @property
    def recall(self) -> float:
        return self.found_known / self.known_vulns if self.known_vulns else 0.0

    @property
    def false_positive_rate(self) -> float:
        total_confirmed = self.true_positives + self.false_positives
        return self.false_positives / total_confirmed if total_confirmed else 0.0

    def as_dict(self) -> dict:
        return {
            "true_positives": self.true_positives, "false_positives": self.false_positives,
            "known_vulns": self.known_vulns, "found_known": self.found_known,
            "precision": round(self.precision, 3), "recall": round(self.recall, 3),
            "false_positive_rate": round(self.false_positive_rate, 3),
            "requests_sent": self.requests_sent, "duration_s": round(self.duration_s, 1),
            "out_of_scope_findings": self.out_of_scope_findings,
        }


def _hits_ground_truth(finding: dict, endpoint_url: str, ground_truth: list) -> bool:
    for vuln_type, substring, param in ground_truth:
        if finding["vuln_type"] != vuln_type:
            continue
        if substring not in endpoint_url:
            continue
        if param is not None and finding.get("param") != param:
            continue
        return True
    return False


def compute_metrics(store, scan_id: str, ground_truth: list, requests_sent: int,
                     duration_s: float, judged_manually_false: set | None = None,
                     scored_vuln_types: set | None = None) -> Metrics:
    """`judged_manually_false` is an optional set of finding_ids a human has
    reviewed and determined are NOT real vulnerabilities (i.e. a false
    positive that nonetheless passed verification) -- report these honestly
    as false positives rather than inflating precision.

    `scored_vuln_types` restricts precision/recall to vuln types your ground
    truth actually enumerates (default: inferred from `ground_truth` itself).
    Passive checks (header/cookie/cors) are usually not catalogued per-target
    the way XSS/SQLi/traversal/IDOR instances are; leaving them out of the
    denominator avoids penalizing ProbeDAST's precision for finding real
    issues the ground truth list simply doesn't track. Report their count
    separately instead of folding them into this precision/recall number.
    """
    judged_manually_false = judged_manually_false or set()
    scored_types = scored_vuln_types or {vt for vt, _, _ in ground_truth}
    confirmed = store.list_findings(scan_id, status="CONFIRMED")
    endpoints = {e["endpoint_id"]: e["method"] + " " + e.get("path_template", "")
                 for e in store.list_endpoints(scan_id)}
    # endpoint url isn't stored directly on the finding row; join via endpoint_id -> template
    # the ground truth matches on path_template substrings, which is stable across scans.

    tp, fp = 0, 0
    matched_truth = set()
    out_of_scope_count = 0
    for f in confirmed:
        if f["vuln_type"] not in scored_types:
            out_of_scope_count += 1
            continue
        ep_desc = endpoints.get(f["endpoint_id"], "")
        is_real = f["finding_id"] not in judged_manually_false
        hit = _hits_ground_truth(f, ep_desc, ground_truth)
        if hit:
            matched_truth.add((f["vuln_type"], ep_desc))
        if is_real and hit:
            tp += 1
        else:
            fp += 1

    return Metrics(
        true_positives=tp, false_positives=fp,
        known_vulns=len(ground_truth), found_known=len(matched_truth),
        requests_sent=requests_sent, duration_s=duration_s,
        out_of_scope_findings=out_of_scope_count,
    )
