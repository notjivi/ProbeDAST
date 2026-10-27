# Resume framing

Per the design doc (Section 12): write these only after the numbers exist,
from a real run against DVWA/Juice Shop/WebGoat per `docs/benchmark.md` —
not from the toy app in `tests/vuln_app.py`, which exists to make the test
suite deterministic and network-free, not to produce a number worth citing.

**Until then, the project is "in progress," and the honest version of each
bullet below is what's actually true today:**

- Built an async DAST scanner (Python, aiohttp, SQLite/PostgreSQL) with a
  scope-guarded crawler, structural endpoint dedup, five detector classes
  (reflected XSS, error/boolean/time-based SQLi, path traversal, IDOR,
  passive checks) and a re-test verification engine. 56 tests passing
  against a local integration-test target.
- RabbitMQ/Redis distributed mode, authenticated crawling against Juice
  Shop's token-based API, and real benchmark numbers against DVWA/Juice
  Shop/WebGoat are **not yet done** — see `docs/benchmark.md` for exactly
  what's left and why.

**Once you've run the real benchmarks**, fill in the brackets honestly:

> Built an async DAST scanner (Python, aiohttp, RabbitMQ, Redis, PostgreSQL)
> with authenticated crawling and detectors for XSS, SQL injection, path
> traversal and broken access control.
>
> Cut false positives by `[W]`% with a re-test verification stage and
> baseline-derived thresholds (`benchmark/ablation.py`); confirmed `[X]` of
> `[Y]` known vulnerabilities in DVWA/Juice Shop at a `[Z]`% false-positive
> rate (`benchmark/metrics.py`), benchmarked against OWASP ZAP
> (`benchmark/zap_baseline.py`).
>
> Solved a shared-session race (scanner invalidating its own login) with a
> Redis lock and session health checks (`probedast/auth.py`); paired the
> scanner with a Runtime API Firewall to measure detection and block rates
> (`benchmark/attack_and_defend.py`).

Don't publish `[W]`, `[X]`, `[Y]`, `[Z]` until a script in `benchmark/` has
actually produced them against a real target in this repo's current state —
and be ready to defend every one of them with the file and run that produced
it, the same way the design doc's Section 10 interview-prep expects.
