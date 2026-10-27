"""Response normalization and diffing (design doc Section 4.4).

Naive string comparison fails because pages contain timestamps, CSRF tokens,
nonces and ads. We strip those by pattern, mask the reflected probe value
itself, and compare structure (tag/text-length shape) rather than raw bytes.
The similarity threshold is never a hard-coded constant: it is derived from
the baseline's own natural variance (send the control 3x, measure the spread,
require a probe response to differ by more than that).
"""
from __future__ import annotations
import re
import statistics
from dataclasses import dataclass

from bs4 import BeautifulSoup

CSRF_RE = re.compile(r'(name=["\']?(csrf|_token|authenticity_token)["\']?[^>]*value=["\'])[^"\']+', re.I)
NONCE_RE = re.compile(r'nonce=["\'][^"\']+["\']', re.I)
TIMESTAMP_RE = re.compile(r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?\b')
EPOCH_RE = re.compile(r'\b1[5-9]\d{8}\b')  # plausible unix-seconds timestamps, 2017-2028ish
UUID_RE = re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', re.I)


def strip_dynamic(body: str) -> str:
    """Remove tokens, nonces and timestamps before anything else runs."""
    s = CSRF_RE.sub(r"\1[REDACTED]", body)
    s = NONCE_RE.sub("nonce=[REDACTED]", s)
    s = TIMESTAMP_RE.sub("[TIMESTAMP]", s)
    s = EPOCH_RE.sub("[TIMESTAMP]", s)
    s = UUID_RE.sub("[UUID]", s)
    return s


def mask_value(body: str, value: str) -> str:
    """Mask the probe value itself so its own presence doesn't register as 'different'."""
    if not value:
        return body
    return body.replace(value, "[PROBE]")


def structural_shape(body: str) -> dict:
    """Coarse structural fingerprint: tag counts and total text length, not raw bytes.
    Falls back to a plain-text shape (line/word counts) for non-HTML bodies."""
    try:
        soup = BeautifulSoup(body, "lxml")
        tags = {}
        for t in soup.find_all(True):
            tags[t.name] = tags.get(t.name, 0) + 1
        text_len = len(soup.get_text())
        return {"tags": tags, "text_len": text_len, "html": True}
    except Exception:
        return {"tags": {}, "text_len": len(body), "lines": body.count("\n"), "html": False}


def shape_distance(a: dict, b: dict) -> float:
    """0.0 = identical shape, grows with tag-count and text-length divergence."""
    tag_keys = set(a.get("tags", {})) | set(b.get("tags", {}))
    tag_delta = sum(abs(a.get("tags", {}).get(k, 0) - b.get("tags", {}).get(k, 0)) for k in tag_keys)
    len_a, len_b = a.get("text_len", 0), b.get("text_len", 0)
    len_delta = abs(len_a - len_b) / max(len_a, len_b, 1)
    return tag_delta + len_delta * 10


def normalized_diff(body_a: str, body_b: str, probe_value: str = "") -> float:
    a = mask_value(strip_dynamic(body_a), probe_value)
    b = mask_value(strip_dynamic(body_b), probe_value)
    if a == b:
        return 0.0
    return shape_distance(structural_shape(a), structural_shape(b))


@dataclass
class Baseline:
    """Baseline variance for one endpoint+param: how much the control response
    naturally differs from itself across repeated requests."""
    diffs: list
    latencies: list

    @property
    def diff_threshold(self) -> float:
        """A probe must differ by more than the baseline's own natural spread
        (plus a floor so a perfectly stable page doesn't get a zero threshold)."""
        if not self.diffs:
            return 1.0
        mean = statistics.mean(self.diffs)
        spread = statistics.pstdev(self.diffs) if len(self.diffs) > 1 else 0.0
        return max(mean + 3 * spread, 0.5)

    @property
    def latency_median(self) -> float:
        return statistics.median(self.latencies) if self.latencies else 0.0

    @property
    def latency_mad(self) -> float:
        """Median absolute deviation: robust to the occasional slow outlier
        in a way the mean/stdev is not (Section 5.3)."""
        if not self.latencies:
            return 0.0
        med = self.latency_median
        return statistics.median([abs(x - med) for x in self.latencies]) or 0.05

    def is_different(self, body: str, probe_value: str = "") -> bool:
        pass  # computed per-call against a reference body; see is_probe_different

    def latency_is_delayed(self, elapsed: float, delay_s: float, k: float = 6.0) -> str:
        """Returns 'delayed', 'normal' or 'inconclusive'. Robust (MAD-based) comparison
        so queueing jitter under concurrency doesn't masquerade as a time-based SQLi hit."""
        mad = self.latency_mad
        if mad > delay_s * 0.5:
            return "inconclusive"   # too noisy to draw a conclusion; don't guess
        threshold = self.latency_median + max(delay_s * 0.7, k * mad)
        return "delayed" if elapsed >= threshold else "normal"


def build_baseline(control_bodies: list[str], control_latencies: list[float],
                    probe_value: str = "") -> Baseline:
    diffs = []
    for i in range(len(control_bodies)):
        for j in range(i + 1, len(control_bodies)):
            diffs.append(normalized_diff(control_bodies[i], control_bodies[j], probe_value))
    return Baseline(diffs=diffs, latencies=control_latencies)


def is_probe_different(baseline: Baseline, reference_body: str, probe_body: str, probe_value: str = "") -> bool:
    d = normalized_diff(reference_body, probe_body, probe_value)
    return d > baseline.diff_threshold
