# Running the benchmark targets

This file is the honest, as-built companion to design doc Section 7. It says
what's actually wired up, what's a stub, and what you need to do by hand
before a number out of `benchmark/` means anything.

## DVWA

Most straightforward target. `recipes/dvwa.json` uses cookie-session auth
(`SessionManager`), which is what DVWA's `login.php` expects. Steps:

1. `make lab` (or `docker compose up -d dvwa`)
2. Log in once by hand as `admin`/`password`, go to **DVWA Security**, set
   level to **low**.
3. Fill in real values for `login.owned_markers.A` in `recipes/dvwa.json` —
   open `/vulnerabilities/sqli/` logged in as `admin`, note a string that's
   specific to that account (email, a comment only that user posted), and
   use it there. The IDOR detector (`idor_two_session`) can't tell "user B
   got user A's data" from "user B got a normal page" without this.
4. `make scan-dvwa`

Expect: `sqli_error` and `sqli_boolean` to fire on `/vulnerabilities/sqli/`
and `/vulnerabilities/sqli_blind/`; `xss_reflected` on `/vulnerabilities/xss_r/`
and the stored-XSS form (`xss_s`, reflected techniques only — ProbeDAST does
not do second-order/stored XSS, see the design doc's "What it can't find");
`path_traversal` on `/vulnerabilities/fi/`.

## Juice Shop — **auth needs one wiring change before it works end to end**

Juice Shop's `/rest/user/login` returns a bearer token in JSON, not a
Set-Cookie session. `probedast/auth.py` has `TokenSessionManager` /
`headers_for()` for exactly this, but the orchestrator's job context
(`orchestrator.py: _run_job`) currently only threads `cookies` through to
detectors — not a parallel `headers` dict. To actually run Juice Shop
end-to-end:

1. In `orchestrator.py`, swap `SessionManager` for `TokenSessionManager` when
   `cfg.login` indicates token auth (e.g. a `login.auth_style: "token"` field
   you add to `Config`/`LoginRecipe`), and add `"headers": self.session_manager.headers_for(role)`
   to the `context` dict passed to `det.run(...)`.
2. In `probedast/detectors/probing.py`'s `send_with_param`, thread an
   optional `extra_headers` through from each detector the same way `cookies`
   already flows (the parameter already exists on `send_with_param` itself;
   each detector's `context["headers"]` just needs passing through).
3. Also enable `js_fallback: true` (already set in `recipes/juiceshop.json`)
   since most of Juice Shop's UI is Angular-rendered — the crawler's static
   HTML parse alone will under-discover routes. Expect the Playwright-backed
   crawl to be noticeably slower than DVWA.

This is a half-day of wiring, not a redesign — the pieces (`TokenSessionManager`,
`headers_for`) exist specifically for this. Until it's done, run Juice Shop
with `login: null` (unauthenticated) to still exercise `xss_reflected`,
`sqli_error`/`sqli_boolean` against `/rest/products/search`, and all the
passive checks — you'll just miss anything behind a login.

## WebGoat

No seeded account — register `pdast-a` / `pdast-b` by hand through WebGoat's
self-registration page first. WebGoat issues one session per browser-like
client and its lesson pages are heavily stateful (each lesson tracks
progress server-side per session), which makes the two-session IDOR
technique unreliable here: scanning as role A can silently advance lesson
state that role B's requests then read differently for reasons that have
nothing to do with access control. Treat any WebGoat IDOR finding as a lead
to verify by hand, not a number to report as-is — this is flagged directly
in `recipes/webgoat.json`'s `_notes`.

## ZAP comparison

`benchmark/zap_baseline.py` needs a running ZAP daemon (see the docstring at
the top of that file for the docker run command) and will take substantially
longer than a ProbeDAST pass — ZAP's active scanner is thorough by brute
force where ProbeDAST is targeted by construction. Expect this asymmetry and
say so honestly in whatever you write up, rather than presenting "ProbeDAST
finished in Xs, ZAP took Ys" as if faster were simply better; it's a real
engineering tradeoff (coverage vs. speed vs. false-positive rate) with
reasons on both sides, which is exactly the kind of nuance interviewers want
to see you hold.

## What "done" looks like

Before writing any resume numbers (`docs/resume_framing.md`), you should be
able to point at:

- a `dvwa_report.md` from a real `make scan-dvwa` run,
- `benchmark/metrics.py` output against `benchmark/ground_truth.py` entries
  you've personally verified by hand against that same run,
- `benchmark/ablation.py` output from the same target, verify on vs off,
- ideally a ZAP comparison run for the same target.

Anything short of that is a plan, not a result — which is a fine thing to
say on a resume ("DAST scanner, verification pipeline and benchmark harness
built; evaluation run in progress") until the real numbers exist.
