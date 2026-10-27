# ProbeDAST

Asynchronous black-box web application security scanner (DAST). Given a
target URL and a scope, it crawls the application (including logged-in
areas), builds a model of the attack surface, runs vulnerability detectors
against every parameter, **verifies each candidate finding to remove false
positives**, and reports confirmed vulnerabilities with reproducible
request/response evidence.

It's the dynamic-testing counterpart to a CVE-to-Patch pipeline (dependency
scanning) and a Runtime API Firewall (defense). See `benchmark/attack_and_defend.py`
for running ProbeDAST against a target sitting behind such a firewall.

> **Only ever point this at intentionally vulnerable local containers (DVWA,
> Juice Shop, WebGoat) or systems you own.** `safe_mode=True` is the default,
> scope is enforced in code (`probedast/scope.py`, `probedast/http.py`), not
> by promise — but a determined misuser can edit the code, so the
> responsible framing is *guardrails*, not a guarantee. See [Safety](#safety).

## Status

This repository implements the full pipeline described below and it is
**tested against a small hand-built vulnerable app** (`tests/vuln_app.py`) in
an environment without outbound network access, with 56 passing unit and
integration tests (`pytest -v`). **It has not yet been run against DVWA,
Juice Shop or WebGoat themselves** — do that first with `make lab && make
scan-dvwa` before trusting any specific number from this README. The
benchmark/ numbers in Section 7 of the design doc are explicitly
`[placeholder]` until you've run them for real; see
[docs/benchmark.md](docs/benchmark.md).

## Architecture

```
            ┌────────────┐      ┌──────────────────┐      ┌─────────────────┐
  target →  │  Crawler   │ ───▶ │ Attack Surface    │ ───▶ │ Scan             │
            │ (Redis     │      │ Model (Endpoint + │      │ Orchestrator     │
            │  frontier) │      │  Param, dedup'd)  │      │ (jobs → workers) │
            └────────────┘      └──────────────────┘      └────────┬─────────┘
                                                                     │ one job per
                                                                     │ (endpoint, param, detector)
                                                                     ▼
                                                           ┌──────────────────┐
                                                           │ Detector Plugins  │
                                                           │ xss / sqli /      │
                                                           │ traversal / idor /│
                                                           │ passive           │
                                                           └────────┬─────────┘
                                                                     │ candidates
                                                                     ▼
                                                           ┌──────────────────┐
                                                           │ Verification      │
                                                           │ Engine (re-test   │
                                                           │ N rounds)         │
                                                           └────────┬─────────┘
                                                                     │ CONFIRMED / REJECTED
                                                                     ▼
                                                 ┌───────────────────────────────┐
                                                 │ Findings API (FastAPI) +       │
                                                 │ Dashboard (WebSocket live feed)│
                                                 └───────────────────────────────┘
```

Every outbound request from every one of these pieces goes through
`ScopedClient` (`probedast/http.py`) — the single choke point that enforces
the scope allowlist, the dangerous-URL denylist, and safe mode. That's what
makes "did the scanner ever leave scope" an auditable property instead of a
promise; see `probedast/scope.py`.

| Component | File |
|---|---|
| Crawler | `probedast/crawler.py` |
| Canonicalization + structural signatures | `probedast/canon.py` |
| Scope guard + dangerous-URL denylist | `probedast/scope.py` |
| Rate limiting + backoff | `probedast/ratelimit.py` |
| Scoped HTTP client (the one choke point) | `probedast/http.py` |
| Auth, session health, SETNX re-auth lock | `probedast/auth.py` |
| Response normalization + baseline diffing | `probedast/normalize.py` |
| Detectors | `probedast/detectors/*.py` |
| Verification Engine | `probedast/verify.py` |
| Scan Orchestrator | `probedast/orchestrator.py` |
| Findings store (SQLite; schema matches `sql/schema.sql` 1:1) | `probedast/store.py` |
| Findings API + WebSocket | `probedast/api.py` |
| Report generator (JSON/Markdown) | `probedast/report.py` |
| CLI | `probedast/cli.py` |
| Dashboard | `dashboard/index.html` |

## Quick start (single process, no Docker)

```bash
pip install -r requirements.txt
playwright install chromium   # only needed for JS-rendered routes / XSS execution confirmation

# in one terminal: any local target, e.g. the test app used by the test suite
python -c "from tests.vuln_app import start; start(8765); import time; [time.sleep(1) for _ in iter(int,1)]"

# in another terminal
python -m probedast.cli scan --target http://127.0.0.1:8765/ --scope-host 127.0.0.1:8765
```

## Quick start (real benchmark targets, Docker)

```bash
make install
make lab                 # docker compose up -d dvwa juice-shop webgoat
make scan-dvwa           # writes dvwa_report.md
```

DVWA needs its security level set to "low" (via the DVWA Security page, after
logging in as admin/password) for a meaningful first pass. Juice Shop's
login returns a bearer token rather than a cookie session — see the note in
`recipes/juiceshop.json` and `docs/benchmark.md` before trusting its IDOR
results.

## Dashboard + API

```bash
make api          # FastAPI on :8000
make dashboard     # static dashboard on :8080
```

Open `http://localhost:8080`, point it at a target and scope host, hit
**Start scan**. Findings stream in live over WebSocket as the Verification
Engine confirms them; **Kill switch** calls `POST /scans/{id}/stop`
immediately (Section 6's safety requirement).

## Tests

```bash
pytest -v
```

56 tests across canonicalization, scope enforcement, response normalization
(including the false-positive-resistance property — dynamic-but-benign pages
must *not* trigger a diff), the crawler, every detector, the verification
engine (both the confirm and the reject path), and a full end-to-end scan.
All run against `tests/vuln_app.py`, a small stdlib-only deliberately
vulnerable app, so the suite needs no Docker and no network.

## Evaluation and benchmarking

See `benchmark/`:

- `ground_truth.py` — known-vulnerable endpoints per target. **These are
  starting points, not verified** — confirm each entry against your own
  running container before trusting a precision/recall number derived from
  it.
- `metrics.py` — precision, recall, false-positive rate against ground
  truth. Passive checks (headers/cookies/CORS) are reported separately
  (`out_of_scope_findings`) rather than folded into precision, since they
  aren't the kind of thing a per-target ground-truth list usually catalogues.
- `ablation.py` — runs Verification Engine off vs on and reports the change
  in confirmed-candidate count. A drop tells you verification removed
  candidates; cross-check against `metrics.py` to know whether those were
  false positives.
- `zap_baseline.py` — runs OWASP ZAP via its API against the same target and
  normalizes its alerts into the same shape, for an honest side-by-side.
- `attack_and_defend.py` — scans a target directly vs. through a Runtime API
  Firewall and reports which vuln types the firewall suppressed detection of.

A defensible claim looks like: *"Confirmed X of Y known SQLi/XSS vectors in
DVWA at a Z% false-positive rate; verification cut the confirmed-candidate
count by W%."* Don't write resume numbers until you've actually run these
scripts against the real targets — see `docs/resume_framing.md`.

## Safety

- **Allowlist at one choke point**: `ScopedClient` (`probedast/http.py`)
  rejects every out-of-scope request, including redirects that leave scope,
  before it leaves the process.
- **Safe mode by default**: no state-changing methods against discovered
  endpoints, no destructive paths (`probedast/scope.py`'s `DANGEROUS` regex),
  probes limited to non-destructive variants.
- **Rate caps and a kill switch**: a hard requests-per-second ceiling
  (`probedast/ratelimit.py`) and `POST /scans/{id}/stop`.
- **No stored credentials beyond the scan**; use test accounts only.

A determined misuser can edit the code to remove any of this, the same as
with ZAP or Burp. The honest position is that these reduce accidents; they
are not a guarantee against misuse.

## What it can't find

Business-logic flaws, second-order/stored XSS (payload fires on a different
page from where it was injected), race conditions, anything behind MFA or
CAPTCHA, and deep single-page-app state. A DAST tool covers a slice of the
attack surface — pair it with dependency scanning and static analysis.

## License

Choose one before publishing (MIT is a reasonable default for a portfolio
project like this).
