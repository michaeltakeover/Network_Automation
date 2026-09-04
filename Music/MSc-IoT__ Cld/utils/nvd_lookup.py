"""
NVD (National Vulnerability Database) lookup.

Fixes vs. the original implementation:
  1. Explicit status reporting. A failed/timed-out request returns
     status="error" with an empty vulnerability list AND a flag saying
     so — it never silently looks identical to "genuinely 0 CVEs found".
     This was the root cause of the same device/type/answers producing
     a 100/100 "Compliant" result in one run and a 25/100 "High Risk"
     result in another: failures were being treated as "0 CVEs = safe".
  2. Falls back to a generic device-type keyword (e.g. "IP camera") if
     the free-text device name returns nothing, instead of device_type
     being completely ignored by the CVE pipeline.
  3. Retries with backoff, and a real timeout instead of hanging.
"""

import time
import requests

# Pull in the NVD key (may be blank), how long to wait per request, and how
# many times to retry a failed request before giving up entirely.
from config import NVD_API_KEY, REQUEST_TIMEOUT_SECONDS, REQUEST_RETRIES
# Reuse the same CVSS-to-severity band logic already defined in scoring.py,
# rather than duplicating that mapping in two different files.
from utils.scoring import cvss_to_severity

# The official NVD REST API endpoint for searching CVEs by keyword
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _extract_cvss(cve_item):
    """NVD 2.0 responses can carry cvssMetricV31, V30, or V2. Try in order."""
    # This means: NVD entries don't all use the same CVSS version — some only
    # have the newer v3.1 or v3.0 score, others only have the older v2 score.
    # Check for the newest version first, and only fall back to older ones if
    # the newer ones aren't present, since newer scores are more accurate.
    metrics = cve_item.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            return entries[0]["cvssData"]["baseScore"]
    # If none of the three CVSS versions are present at all, there's no score
    # available for this CVE
    return None


def _extract_description(cve_item):
    # This means: NVD entries can include descriptions in multiple languages —
    # loop through them and grab specifically the English one, since that's
    # what we want to display. If there's no English description, return
    # an empty string rather than crashing.
    for desc in cve_item.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


def _query_nvd(keyword):
    """Single NVD query with retries. Returns (list_of_raw_items, error_or_None)."""
    # This means: if we have an API key configured, attach it to the request
    # headers to get the higher rate limit. If not, just send the request
    # without it — NVD still works, just with a lower rate limit.
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    # Search by free-text keyword, capped at 20 results per page — enough for
    # a single assessment without pulling back an overwhelming amount of data
    params = {"keywordSearch": keyword, "resultsPerPage": 20}

    last_error = None
    # This means: try the request up to REQUEST_RETRIES+1 times total (so if
    # REQUEST_RETRIES is 2, that's 3 attempts) before giving up completely —
    # a single network hiccup shouldn't cause the whole lookup to fail.
    for attempt in range(REQUEST_RETRIES + 1):
        try:
            resp = requests.get(
                NVD_BASE_URL,
                headers=headers,
                params=params,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            if resp.status_code == 200:
                # Success — pull out the list of matching CVEs and return
                # immediately, no need to retry
                data = resp.json()
                return data.get("vulnerabilities", []), None
            elif resp.status_code == 429:
                # This means: NVD is telling us we've sent too many requests
                # too quickly. Rather than giving up straight away, wait a bit
                # (longer with each retry) and then try again.
                last_error = "NVD rate limit hit (429)"
                time.sleep(2 * (attempt + 1))
                continue
            else:
                # Any other non-200 status code — record it as the error for
                # this attempt, but still let the loop retry below
                last_error = f"NVD returned HTTP {resp.status_code}"
        except requests.exceptions.Timeout:
            # This means: the request took longer than REQUEST_TIMEOUT_SECONDS
            # and was cut off — record that specifically
            last_error = "NVD request timed out"
        except requests.exceptions.RequestException as e:
            # This means: some other network-level failure happened (DNS
            # issue, connection refused, etc.) — record the underlying error
            last_error = f"NVD request failed: {e}"
        # Small increasing delay between retries (except after a 429, which
        # already slept above and used `continue` to skip this line)
        time.sleep(1 * (attempt + 1))

    # If we got here, every attempt failed — return no results plus whatever
    # the last error message was, so the caller knows exactly why it failed
    return None, last_error


def search_nvd(device_name, fallback_keyword=None):
    """
    Returns a dict:
      {
        "vulnerabilities": [ {cve_id, cvss_score, severity, description}, ... ],
        "status": "ok" | "no_results" | "error",
        "keyword_used": str,
        "match_type": "product" | "category_fallback",
        "message": str,
      }

    match_type distinguishes a real product-name match from a generic
    device-type fallback (e.g. "router"). A fallback match is a much
    weaker signal — it can surface decades-old, completely unrelated
    CVEs for arbitrary hardware that happens to share the category —
    so callers should treat it with lower confidence, not as confirmed
    findings for the specific device being assessed.
    """
    # Clean up the device name first — if it's empty after stripping
    # whitespace, there's nothing to search for, so return an error straight away
    keyword = (device_name or "").strip()
    if not keyword:
        return {
            "vulnerabilities": [],
            "status": "error",
            "keyword_used": "",
            "match_type": "product",
            "message": "No device name provided.",
        }

    # First attempt: search using the exact device name the user typed in
    raw_items, error = _query_nvd(keyword)

    used_keyword = keyword
    match_type = "product"
    # This means: if the search itself failed outright (network error, etc.),
    # stop here and report the error — don't try the fallback keyword either,
    # since the whole lookup mechanism is currently broken, not just this one term.
    if error is not None:
        return {
            "vulnerabilities": [],
            "status": "error",
            "keyword_used": keyword,
            "match_type": match_type,
            "message": error,
        }

    # This means: if searching by the exact device name came back with zero
    # results (but didn't error), and we have a generic fallback keyword to
    # try (based on the device type), attempt that search instead. This is
    # what stops device_type from being completely ignored by the CVE search.
    if not raw_items and fallback_keyword:
        used_keyword = fallback_keyword
        match_type = "category_fallback"
        raw_items, error = _query_nvd(fallback_keyword)
        if error is not None:
            return {
                "vulnerabilities": [],
                "status": "error",
                "keyword_used": fallback_keyword,
                "match_type": match_type,
                "message": error,
            }

    # This means: convert NVD's raw, deeply-nested JSON response into a
    # simpler flat list of dictionaries — just the fields the rest of the
    # app actually needs (ID, CVSS score, severity band, description).
    vulnerabilities = []
    for entry in raw_items or []:
        cve = entry.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")
        cvss_score = _extract_cvss(cve)
        vulnerabilities.append({
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "severity": cvss_to_severity(cvss_score),
            "description": _extract_description(cve),
        })

    # This means: if we found at least one CVE, the status is "ok" — if the
    # search ran successfully but genuinely found nothing, the status is
    # "no_results" (which is different from "error" — the search worked,
    # it just didn't find anything).
    status = "ok" if vulnerabilities else "no_results"
    # Build a human-readable message explaining exactly what was found and
    # how confident we should be in it, depending on match_type
    if match_type == "category_fallback" and vulnerabilities:
        message = (
            f"No CVEs found for the exact product name. Showing {len(vulnerabilities)} "
            f"generic '{used_keyword}'-category CVE(s) as a lower-confidence indicator — "
            "these are not confirmed to affect this specific device/firmware."
        )
    elif vulnerabilities:
        message = f"{len(vulnerabilities)} CVE(s) found for '{used_keyword}'."
    else:
        message = f"No CVEs found for '{used_keyword}'."

    return {
        "vulnerabilities": vulnerabilities,
        "status": status,
        "keyword_used": used_keyword,
        "match_type": match_type,
        "message": message,
    }