# ProbeDAST

**An asynchronous, black-box web application security scanner built in Python.**

ProbeDAST crawls an in-scope web application, builds an inventory of endpoints and parameters, runs vulnerability detectors, and re-tests candidate findings before writing reports. It supports authenticated crawling, response normalization, browser-assisted XSS verification, and a live dashboard for observing scans.

The project explores the dynamic-testing side of an application-security workflow: dependency scanning identifies vulnerable components, a runtime API firewall can filter suspicious requests, and ProbeDAST tests the behavior of a running application.

> **Authorized testing only.** Use ProbeDAST against intentionally vulnerable local labs, applications you own, or systems for which you have explicit permission. Its scope checks and safe-mode controls reduce accidental impact; they are not a guarantee against misuse.

## Highlights

- **Asynchronous crawling:** discovers links and forms, including authenticated areas, and records endpoint parameters.
- **Attack-surface modeling:** canonicalizes routes and deduplicates endpoints by normalizing variable path segments.
- **Pluggable detectors:** includes checks for reflected XSS, SQL injection, path traversal, IDOR-style cross-account access, and passive HTTP security issues.
- **Finding verification:** replays candidate tests over multiple rounds and compares normalized responses to reduce noise from dynamic content such as CSRF tokens, nonces, and timestamps.
- **Browser-assisted checks:** uses Playwright for JavaScript-capable validation, including XSS execution checks where supported.
- **Scope-aware HTTP layer:** routes scanner requests through a shared client that enforces the configured scope and applies request safety controls.
- **Reporting and visibility:** generates Markdown/JSON reports and exposes a FastAPI endpoint with a dashboard that streams scan updates over WebSocket.
- **Supporting infrastructure:** integrates Redis for coordination/session locking and supports a SQLite findings store; RabbitMQ is used by the broader asynchronous pipeline.

## Architecture

```text
                         ┌────────────────────┐
                         │   Target + Scope   │
                         └─────────┬──────────┘
                                   │
                                   ▼
                         ┌────────────────────┐
                         │ Scoped HTTP Client │
                         │ scope + safety     │
                         └─────────┬──────────┘
                                   │
                                   ▼
                         ┌────────────────────┐
                         │ Async Crawler      │
                         │ links, forms, auth │
                         └─────────┬──────────┘
                                   │
                                   ▼
                         ┌────────────────────┐
                         │ Attack-Surface     │
                         │ Endpoint/Param Map │
                         └─────────┬──────────┘
                                   │
                                   ▼
                         ┌────────────────────┐
                         │ Scan Orchestrator  │
                         │ endpoint × param × │
                         │ detector jobs      │
                         └─────────┬──────────┘
                                   │
                                   ▼
                         ┌────────────────────┐
                         │ Detector Plugins   │
                         │ XSS, SQLi, traversal│
                         │ IDOR, passive checks│
                         └─────────┬──────────┘
                                   │ candidates
                                   ▼
                         ┌────────────────────┐
                         │ Verification Engine│
                         │ repeat + compare   │
                         └─────────┬──────────┘
                                   │
                                   ▼
                ┌────────────────────────────────────┐
                │ Findings Store · Reports · API     │
                │ Markdown/JSON · Live Dashboard     │
                └────────────────────────────────────┘
```

Every scanner HTTP request is intended to pass through `ScopedClient` in `probedast/http.py`, which works with the scope controls in `probedast/scope.py`. This centralizes enforcement rather than leaving each detector to implement its own target checks.

### Main modules

| Area | Location | Responsibility |
|---|---|---|
| Crawler | `probedast/crawler.py` | Discovers routes and forms and builds the endpoint inventory |
| Canonicalization | `probedast/canon.py` | Normalizes URLs and structural response signatures |
| Scope controls | `probedast/scope.py`, `probedast/http.py` | Target restrictions and centralized request handling |
| Rate limiting | `probedast/ratelimit.py` | Request pacing and backoff |
| Authentication | `probedast/auth.py` | Login recipes, session health, coordinated re-authentication |
| Response normalization | `probedast/normalize.py` | Reduces dynamic response noise during comparisons |
| Detectors | `probedast/detectors/` | Vulnerability-specific probe logic |
| Verification | `probedast/verify.py` | Re-tests candidates and evaluates evidence |
| Orchestration | `probedast/orchestrator.py` | Coordinates scan jobs and workers |
| Storage | `probedast/store.py`, `sql/schema.sql` | Persists endpoints, scan state, and findings |
| API and reports | `probedast/api.py`, `probedast/report.py` | API, WebSocket updates, and Markdown/JSON output |
| CLI and dashboard | `probedast/cli.py`, `dashboard/index.html` | Command-line scanning and browser UI |

## Quick start

### 1. Install dependencies

Python and Docker are needed for the local lab workflow. From the repository root, create and activate a virtual environment, then install the project dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m playwright install chromium
```

On Windows, use `.venv\Scripts\activate` to activate the virtual environment. The Playwright browser is required for browser-assisted checks; installing system dependencies may also be necessary on a fresh Linux environment.

### 2. Run the test suite

```bash
pytest -v
```

The current suite contains **56 passing tests** covering areas such as canonicalization, scope controls, response normalization, crawling, detector behavior, verification paths, and an end-to-end scan against the project's deliberately vulnerable test application.

### 3. Run against the local test application

Start the test application in terminal 1:

```bash
python -c "from tests.vuln_app import start; import time; start(8765); [time.sleep(1) for _ in iter(int, 1)]"
```

Run the scanner in terminal 2:

```bash
python -m probedast.cli scan \
  --target http://127.0.0.1:8765/ \
  --scope-host 127.0.0.1:8765 \
  --report-fmt markdown
```

The test application is intentionally vulnerable and is meant for local testing only.

## Run against a Docker lab

ProbeDAST includes a Docker lab setup for intentionally vulnerable targets such as DVWA, OWASP Juice Shop, and WebGoat.

```bash
make install
make lab
make scan-dvwa
```

The DVWA recipe expects the lab to be available at `http://127.0.0.1:4280`. After logging in with the lab's default credentials (`admin` / `password`), set DVWA Security to **Low** for a first controlled exercise. Keep the lab bound to localhost and do not expose vulnerable containers to a public network.

A recent local DVWA run completed **148 of 148 scan jobs across 43 endpoints**. It reported path-traversal, SQL-injection, and reflected-XSS candidates. Findings should still be reviewed against the target behavior; in particular, time-based SQL-injection claims require repeatable latency evidence. No precision/recall or cross-tool superiority claim is made here.

## Dashboard and API

Start the API and dashboard in separate terminals from the repository root:

```bash
make api
```

```bash
make dashboard
```

Open [http://localhost:8080](http://localhost:8080). The API runs on port `8000`; the dashboard runs on port `8080`. Scan updates are streamed to the dashboard. The interface also exposes a scan stop control through the API.

## Evaluation and benchmarking

The `benchmark/` directory contains scripts for evaluating detections and comparing configurations:

| Script | Purpose |
|---|---|
| `ground_truth.py` | Defines expected vulnerable endpoints for supported lab targets; entries should be checked against the specific lab version and configuration |
| `metrics.py` | Calculates metrics against the ground-truth list and treats passive findings separately |
| `ablation.py` | Compares runs with the verification engine enabled and disabled |
| `zap_baseline.py` | Normalizes OWASP ZAP alerts for a side-by-side comparison |
| `attack_and_defend.py` | Exercises a target directly and through the companion Runtime API Firewall |

Benchmark results depend on target version, configuration, authentication, and ground-truth quality. Run the benchmarks and inspect their inputs before publishing precision, recall, false-positive-rate, performance, or tool-comparison figures. Do not treat placeholder values as measured results.

## Safety model

ProbeDAST includes several guardrails intended to reduce accidental impact:

- **Scope enforcement:** the shared HTTP client checks requests against the configured target scope, including redirect handling.
- **Safe-mode defaults:** scanning is designed to avoid state-changing methods and use non-destructive probe variants by default.
- **Request pacing:** rate limits and backoff reduce request pressure on the target.
- **Stop control:** scans can be stopped through the API/dashboard.
- **Test credentials:** authentication recipes should use dedicated lab accounts, not personal or production credentials.

These controls are defense-in-depth, not a security boundary against someone who modifies the source code. Only scan systems you are authorized to test.

## Limitations

- Automated DAST cannot reliably detect every business-logic issue, race condition, second-order/stored XSS, or vulnerability hidden behind MFA/CAPTCHA or complex application state.
- Coverage depends on the crawler's ability to reach routes and forms and on the quality of authentication recipes.
- Browser-based verification is available only for checks that the implementation can exercise in a supported browser context.
- Findings, especially timing-based detections, need to be interpreted against application behavior and independently reproduced before being treated as confirmed vulnerabilities.
- The benchmark framework is provided for evaluation; rigorous cross-tool or precision/recall claims require validated ground truth and recorded runs.

## Related project

ProbeDAST is designed to complement a **Runtime API Firewall** project: ProbeDAST evaluates the behavior of a running application, while the firewall inspects requests inline. The `benchmark/attack_and_defend.py` script supports experiments involving both components.

---

**Built with:** Python · `asyncio` · `aiohttp` · Playwright · FastAPI · Redis · SQLite · Docker · pytest
