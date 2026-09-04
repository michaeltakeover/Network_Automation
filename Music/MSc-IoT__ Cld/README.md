# Vendor-Agnostic IoT Security Platform (v2)

Rebuilt version of the assessment tool: same core idea (questionnaire → base
score → CVE/exploitation/exposure enrichment → risk score → dashboard/history),
with the data-integrity bugs from the original fixed.

## Setup

```bash
pip install -r requirements.txt
python app.py
```

Visit `http://127.0.0.1:5000`. Default login: `admin` / `ChangeMe!2026`
(set `IOT_ADMIN_USERNAME` / `IOT_ADMIN_PASSWORD` env vars to change).

Optional API keys (both work fine without a key — see below):
```bash
export NVD_API_KEY=your_key        # optional, raises NVD rate limit
export SHODAN_API_KEY=your_key     # required for exposure data to work at all
```

## What was fixed vs. the original app

Confirmed from your live database (`iot_security.db`, rows 92/93/96):

1. **Non-deterministic CVE results.** Identical device/type/answers produced
   both a 100/100 "Compliant" and a 25/100 "High Risk" verdict across two
   runs. Root cause: a failed/rate-limited NVD request was silently treated
   as "0 CVEs found." Fixed by giving every lookup an explicit `status`
   (`ok` / `no_results` / `error`) that's stored, displayed, and never
   conflated with a genuine clean result.

2. **`device_type` never affected CVE matching.** The CVE search only ever
   used the free-text device name, so "TP-Link Router" logged as type
   "Camera" pulled router CVEs into camera statistics, corrupting the
   "CVEs by Device Type" dashboard chart. Fixed: type now provides a
   fallback search keyword, and the dashboard groups strictly by the
   stored `device_type` field so the numbers are honest, given whatever
   type the user actually selects.

3. **Severity always "Unknown."** CVSS score was captured but never mapped
   to a severity band. Fixed with the standard CVSS v3 bands.

4. **Shodan always showed 0 exposure / "Unavailable."** Indistinguishable
   from "checked, found nothing." Fixed: without an API key the UI now
   says "Not Configured" explicitly, so a 0 always means "we checked."

5. **Flat CVE penalty (-5 flat, uncapped).** Could produce dashboard totals
   like "-935," which is hard to defend in a report. Fixed: penalty is
   now weighted by severity band and capped per assessment (see
   `config.py` — `CVE_PENALTY_BY_SEVERITY`, `MAX_CVE_PENALTY`).

6. **Hardcoded `admin/admin123` credential in source.** Moved to `config.py`
   with environment-variable overrides.

## Known limitations (worth stating explicitly in your report)

- NVD's public API is rate-limited without a key (~5 req/30s) — expect
  occasional `error` statuses under repeated rapid testing; this is
  reported honestly rather than hidden.
- Shodan requires a paid/academic key; without one, exposure scoring is
  simply inactive, not silently wrong.
- CISA KEV is a public feed with no key required; it's cached locally for
  24h to avoid refetching thousands of records on every assessment.
- This build could not be tested against live NVD/Shodan/CISA endpoints in
  the environment it was written in (no outbound access to those domains),
  so the failure-handling paths were verified by testing the code with no
  network access — which is exactly the "API unreachable" case and confirmed
  the app behaves correctly (explicit error banners, no fabricated data)
  rather than the success paths. Test the success paths (real CVE data
  returned) on your own machine before your demo/viva.

## Making it a live, publicly reachable app (optional)

The steps above run it live on your own machine with real API calls — that's
enough for a viva demo. If you also want a public URL (e.g. to put in your
appendix or share with a supervisor), the fastest free option is Render:

1. Push this folder to a GitHub repo (private is fine).
2. Go to [render.com](https://render.com) → New → Blueprint → connect the repo.
   It will read `render.yaml` automatically and set up the build/start commands.
3. In the Render dashboard, set the environment variables it asks for
   (`IOT_ADMIN_USERNAME`, `IOT_ADMIN_PASSWORD`, and optionally `NVD_API_KEY`
   / `SHODAN_API_KEY`) — never commit real credentials to the repo.
4. Deploy. You'll get a `https://your-app-name.onrender.com` URL.

Notes if you go this route:
- Free-tier Render apps sleep after inactivity and take ~30s to wake up on
  the first request — mention this if you demo it live so a slow first
  load doesn't look like a bug.
- SQLite on a free-tier host is not persistent across deploys/restarts on
  some platforms — fine for a demo, but don't rely on history surviving
  redeploys. For genuine persistence you'd want a managed Postgres add-on,
  which is a reasonable "future work" line in your report if you want to
  mention it.

## What's new in this round of fixes

- **Category-fallback CVEs are no longer treated as confirmed findings.**
  Discovered via testing: assessing "Amazon eero 6+" returned zero CVEs
  for the exact product, so the fallback searched the generic keyword
  "router" instead — which pulled up 20 unrelated CVEs from 1999-era
  Cisco/Ascend/3com hardware and scored the eero as Critical Risk. That's
  not a fair result. Fixed: fallback matches now carry half the CVE/
  exploitation penalty weight of a confirmed product match, the result
  page shows an explicit warning banner ("No CVEs found for the exact
  product name..."), and recommendations use softened, verification-
  requesting language instead of "URGENT" for unconfirmed matches.

## Previous round of fixes

- **CSRF protection** on the login and assessment forms — every POST now
  requires a per-session token; requests without a valid one are rejected
  (HTTP 400) rather than silently accepted.
- **Timing-safe credential comparison** (`secrets.compare_digest`) instead
  of Python's `==`, which can leak timing information about how many
  leading characters matched.
- **Hardened session cookies** (`HttpOnly`, `SameSite=Lax`).
- **Per-assessment PDF reports.** Previously every new assessment
  overwrote the same `reports/assessment_report.pdf`, so History could
  never link back to an older report. Each assessment now gets its own
  `reports/assessment_{id}.pdf`, and both the result page and every row
  in History link to the correct one.
- **27-test pytest suite** for the scoring engine.

## Running the automated tests

```bash
pip install pytest --break-system-packages
pytest tests/ -v
```

## Experimental evaluation support (Condition A / Condition B)

Every assessment now records enough data to support a baseline-vs-threat-
informed comparative evaluation without any redesign of the artefact:

- **Condition A (baseline only):** `base_score`, and the risk level /
  compliance status that score alone would produce — computed and stored
  as `baseline_risk_level` / `baseline_compliance_status`.
- **Condition B (threat-informed):** the existing final `score`,
  `risk_level`, `compliance_status` (unchanged — these already factor in
  NVD/CISA/Shodan).
- **Execution timing:** `nvd_time_ms`, `cisa_time_ms`, `shodan_time_ms`,
  `total_time_ms` — wall-clock time for each external lookup, per
  assessment.
- **API availability:** `nvd_status`, `cisa_status`, `shodan_status` were
  already stored per assessment (see earlier fixes above) — directly
  usable for an "API availability/failures" evaluation section.

The result page now shows a Condition A vs. Condition B table and flags
whether threat intelligence changed the classification for that specific
device — useful both as a live demo and as a source of concrete examples
(e.g. "TP-Link Router: Condition A = Medium Risk, Condition B = Critical
Risk") for the evaluation chapter.

To build the comparison table across your full dataset, query
`iot_security_v2.db` directly, e.g.:

```sql
SELECT device_name, base_score, baseline_risk_level, baseline_compliance_status,
       score, risk_level, compliance_status,
       nvd_time_ms, cisa_time_ms, shodan_time_ms, total_time_ms,
       nvd_status, cisa_status, shodan_status
FROM assessments
ORDER BY id;
```

## Old database

`iot_security.db` (your original file) is not migrated — its `avg_cvss`
values are known to be device-type-keyed rather than device-specific (see
fix #2 above), so migrating it would import bad data into the new schema.
The new app creates a fresh `iot_security_v2.db` on first run.
