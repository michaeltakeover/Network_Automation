"""
CISA Known Exploited Vulnerabilities (KEV) catalogue lookup.

The full feed is a public JSON file with thousands of entries — refetching
it on every single assessment is wasteful and slow, so it's cached to disk
with a TTL. Falls back gracefully (status="error") if the feed can't be
fetched and there's no usable cache yet, rather than silently saying
"no exploited CVEs" when the check never actually ran.
"""

import json
import os
import time
import requests

# Pull in settings from config.py: how long to wait before giving up on a
# request, where the local cache file lives, how long a cached copy stays
# valid before it needs refreshing, and the folder the cache file sits in.

from config import (
    REQUEST_TIMEOUT_SECONDS,
    CISA_KEV_CACHE_FILE,
    CISA_KEV_CACHE_TTL_HOURS,
    CACHE_DIR,
)
# This is the official public URL CISA publishes the full KEV catalogue at —
# a big JSON file listing every vulnerability known to be actively exploited

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _load_cache():
    # This means: try to read a previously-saved local copy of the KEV list
    # instead of hitting the internet again. If there's no cache file at all,
    # there's nothing to load, so bail out immediately.
    if not os.path.exists(CISA_KEV_CACHE_FILE):
        return None
    try:
        with open(CISA_KEV_CACHE_FILE, "r") as f:
            cache = json.load(f)
        # Work out how many hours old this cached copy is, based on the
        # timestamp that was saved alongside it when it was first fetched.
        age_hours = (time.time() - cache.get("fetched_at", 0)) / 3600
        if age_hours > CISA_KEV_CACHE_TTL_HOURS:
            return None
        return cache
    except (json.JSONDecodeError, OSError):
        # If the cache file is corrupted or unreadable for any reason, just
        # treat it as if there was no cache at all, rather than crashing.
        return None


def _save_cache(cve_ids):
    # This means: write the freshly-fetched list of exploited CVE IDs to disk,
    # along with the current timestamp, so future calls can reuse it instead
    # of re-downloading the whole feed every time.
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(CISA_KEV_CACHE_FILE, "w") as f:
        json.dump({"fetched_at": time.time(), "cve_ids": list(cve_ids)}, f)


def _fetch_kev_cve_ids():
    # First, try to use a valid cached copy so we don't hammer CISA's servers
    # unnecessarily — if we find one, return it straight away with no error.
    cache = _load_cache()
    if cache is not None:
        return set(cache["cve_ids"]), None
 
    # No usable cache was found, so go and fetch the real feed from CISA over
    # the network. Everything below is wrapped in error handling because a lot
    # can go wrong with a live network request: timeouts, bad responses,
    # unreachable servers, or a response that isn't valid JSON.
    try:
        resp = requests.get(CISA_KEV_URL, timeout=REQUEST_TIMEOUT_SECONDS)
        if resp.status_code != 200:
            return None, f"CISA KEV feed returned HTTP {resp.status_code}"
        data = resp.json()
        # Pull just the CVE ID out of every entry in the feed, building a set
        # (not a list) since we only care about fast "is this CVE in here?"
        # lookups later, and sets are much quicker for that than lists.
        cve_ids = {v["cveID"] for v in data.get("vulnerabilities", [])}
        _save_cache(cve_ids)
        return cve_ids, None
    except requests.exceptions.Timeout:
        # This means: the request took too long and was cut off — report that
        # specifically rather than lumping it in with other kinds of failure.
        return None, "CISA KEV request timed out"
    except requests.exceptions.RequestException as e:
        return None, f"CISA KEV request failed: {e}"
    except (json.JSONDecodeError, KeyError) as e:
        return None, f"CISA KEV response could not be parsed: {e}"


def check_cisa_exploitation(cve_ids):
    """
    Returns a dict:
      {
        "exploited_cves": [cve_id, ...],
        "status": "ok" | "error",
        "message": str,
      }
    """
    # This means: if there weren't any CVEs to check in the first place (e.g.
    # the NVD lookup found none), there's nothing to cross-reference against
    # CISA, so just return an empty "ok" result straight away — no need to
    # even attempt a network call.
    if not cve_ids:
        return {"exploited_cves": [], "status": "ok", "message": "No CVEs to check."}

    kev_ids, error = _fetch_kev_cve_ids()
    if error is not None:
        return {
            "exploited_cves": [],
            "status": "error",
            "message": f"Could not verify against CISA KEV: {error}",
        }
    # This means: go through every CVE ID that was found for this device, and
    # keep only the ones that also appear in CISA's known-exploited list.
    exploited = [cid for cid in cve_ids if cid in kev_ids]
    message = (
        f"{len(exploited)} of {len(cve_ids)} CVE(s) are actively exploited (CISA KEV)."
        if exploited else
        "No actively exploited vulnerabilities found in CISA KEV."
    )
    return {"exploited_cves": exploited, "status": "ok", "message": message}
