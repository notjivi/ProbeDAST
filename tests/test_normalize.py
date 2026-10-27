import random
import string

from probedast.normalize import (
    strip_dynamic, normalized_diff, build_baseline, is_probe_different, Baseline,
)


def _dynamic_page(seed: int) -> str:
    token = "".join(random.Random(seed).choices(string.hexdigits, k=32))
    return (f'<html><body><input type=hidden name=csrf value="{token}">'
            f'<p>2026-10-27T10:00:{seed % 60:02d}Z</p><p>same content every time</p></body></html>')


def test_strip_dynamic_removes_csrf_and_timestamp():
    body = '<input name="csrf" value="abc123"> at 2026-10-27T10:00:00Z'
    cleaned = strip_dynamic(body)
    assert "abc123" not in cleaned
    assert "2026-10-27T10:00:00Z" not in cleaned


def test_identical_pages_have_zero_diff():
    assert normalized_diff("<p>hello</p>", "<p>hello</p>") == 0.0


def test_dynamic_but_equivalent_pages_score_low():
    a, b = _dynamic_page(1), _dynamic_page(2)
    assert normalized_diff(a, b) < 1.0


def test_structurally_different_pages_score_higher():
    a = _dynamic_page(1)
    b = _dynamic_page(1) + "<p>" + "EXTRA " * 50 + "</p>"
    assert normalized_diff(a, b) > normalized_diff(a, _dynamic_page(3))


def test_baseline_absorbs_natural_noise_no_false_positive():
    bodies = [_dynamic_page(i) for i in range(3)]
    baseline = build_baseline(bodies, [0.1, 0.11, 0.09])
    probe_body = _dynamic_page(99)  # just more natural noise, not an attack response
    assert is_probe_different(baseline, bodies[0], probe_body) is False


def test_baseline_catches_real_difference():
    bodies = [_dynamic_page(i) for i in range(3)]
    baseline = build_baseline(bodies, [0.1, 0.11, 0.09])
    different = _dynamic_page(5) + "<p>" + "INJECTED CONTENT HERE " * 30 + "</p>"
    assert is_probe_different(baseline, bodies[0], different) is True


def test_mask_value_prevents_reflection_self_match():
    probe_value = "zzqqprobe123"
    a = f"<p>hello {probe_value} world</p>"
    b = "<p>hello world</p>"
    # without masking these would look very different; with masking, closer
    diff_masked = normalized_diff(a, b, probe_value=probe_value)
    diff_unmasked = normalized_diff(a, b, probe_value="")
    assert diff_masked <= diff_unmasked


def test_latency_delayed_vs_normal():
    baseline = Baseline(diffs=[0.1], latencies=[0.05, 0.06, 0.05, 0.07, 0.05])
    assert baseline.latency_is_delayed(0.06, delay_s=3.0) == "normal"
    assert baseline.latency_is_delayed(3.1, delay_s=3.0) == "delayed"


def test_latency_inconclusive_when_baseline_too_noisy():
    # genuinely spread-out baseline (not just one or two outliers, which the
    # median/MAD comparison is specifically robust against) relative to a
    # short delay -- the detector should decline to guess rather than report
    # a false time-based SQLi hit.
    baseline = Baseline(diffs=[0.1], latencies=[0.1, 1.0, 2.0, 3.0, 4.0])
    assert baseline.latency_is_delayed(2.5, delay_s=1.0) == "inconclusive"
