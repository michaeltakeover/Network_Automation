"""
Shodan internet-exposure lookup.

Uses /shodan/host/count instead of /shodan/host/search. The search
endpoint requires a paid Shodan membership and returns HTTP 403 on
free-tier keys (a documented, widely-reported platform limitation, not
specific to this app). The count endpoint returns the number of matching
results without consuming paid query credits, so it works on free keys —
at the cost of not returning individual host/service details.
"""

import requests

# Pull in the Shodan key (may be blank if not configured) and the shared
# request timeout setting used across all the external API lookups.
from config import SHODAN_API_KEY, REQUEST_TIMEOUT_SECONDS

# This is the "count only" Shodan endpoint — it tells you how many matching
# hosts exist without giving details about each one, and works on free keys
SHODAN_HOST_COUNT_URL = "https://api.shodan.io/shodan/host/count"


def search_shodan(device_name):
    """
    Returns a dict:
      {
        "status": "not_configured" | "ok" | "error",
        "exposure_level": "Not Configured" | "None" | "Low" | "Medium" | "High" | "Unavailable",
        "total_results": int,
        "exposure_penalty": int,
        "message": str,
      }
    """
    # This means: if there's no Shodan API key set at all, don't even attempt
    # a request — just report clearly that the check was skipped entirely.
    # This is deliberately different from "checked and found nothing", so a
    # 0 always genuinely means "we looked and found zero", never "we never looked".
    if not SHODAN_API_KEY:
        return {
            "status": "not_configured",
            "exposure_level": "Not Configured",
            "total_results": 0,
            "exposure_penalty": 0,
            "message": "Shodan API key not set — exposure check skipped (not run, not 'clean').",
        }

    try:
        # Ask Shodan how many hosts match a search for this device name
        resp = requests.get(
            SHODAN_HOST_COUNT_URL,
            params={"key": SHODAN_API_KEY, "query": device_name},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        # This means: a 403 specifically can mean the account has literally
        # zero query credits left, even on the free "count" endpoint — call
        # this out explicitly in the message so it's not confused with some
        # other kind of failure.
        if resp.status_code == 403:
            return {
                "status": "error",
                "exposure_level": "Unavailable",
                "total_results": 0,
                "exposure_penalty": 0,
                "message": "Shodan returned HTTP 403 (Access Denied). This can happen even on "
                           "/host/count if the account has no query credits at all.",
            }
        # Any other non-200, non-403 response is treated as a generic error
        if resp.status_code != 200:
            return {
                "status": "error",
                "exposure_level": "Unavailable",
                "total_results": 0,
                "exposure_penalty": 0,
                "message": f"Shodan returned HTTP {resp.status_code}.",
            }
        data = resp.json()
        # Pull out how many matching hosts Shodan found — default to 0 if the
        # field is missing for some reason
        total = data.get("total", 0)

        # This means: convert the raw host count into a simple exposure
        # level and a corresponding score penalty — more exposed hosts found
        # means a bigger penalty, in increasing bands.
        if total == 0:
            level, penalty = "None", 0
        elif total < 10:
            level, penalty = "Low", 5
        elif total < 100:
            level, penalty = "Medium", 10
        else:
            level, penalty = "High", 15

        return {
            "status": "ok",
            "exposure_level": level,
            "total_results": total,
            "exposure_penalty": penalty,
            "message": f"{total} matching host(s) found on Shodan (count-only; free-tier endpoint, "
                       "no individual host details available).",
        }
    except requests.exceptions.Timeout:
        # This means: the request took too long and was cut off — report
        # that specifically rather than a generic failure message
        return {
            "status": "error",
            "exposure_level": "Unavailable",
            "total_results": 0,
            "exposure_penalty": 0,
            "message": "Shodan request timed out.",
        }
    except requests.exceptions.RequestException as e:
        # This means: some other network-level problem happened (DNS
        # failure, connection refused, etc.) — catch it and report the
        # underlying error message
        return {
            "status": "error",
            "exposure_level": "Unavailable",
            "total_results": 0,
            "exposure_penalty": 0,
            "message": f"Shodan request failed: {e}",
        }