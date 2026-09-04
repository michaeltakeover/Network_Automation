"""
Central configuration for the IoT Security Platform.

IMPORTANT (for your report / viva): credentials and API keys live here,
not hardcoded in app.py. In a real deployment these would come from
environment variables instead of a committed file.
"""

import os

# --- Auth ---
# Change these before deploying / demoing. Defaults are intentionally
# NOT "admin/admin123" (the original app's hardcoded credential is a
# known anti-pattern worth flagging in your security discussion).
 
# This means: try to read the admin username from an environment variable first
# (IOT_ADMIN_USERNAME) — if that variable isn't set on the machine running the
# app, fall back to the default value "admin" instead. This way the real
# credentials never have to be typed directly into the code.
ADMIN_USERNAME = os.environ.get("IOT_ADMIN_USERNAME", "admin")
# Same idea as above, but for the admin password — read it from the
# IOT_ADMIN_PASSWORD environment variable if it exists, otherwise default
# to "ChangeMe!2026" (which, as the name suggests, should be changed).
ADMIN_PASSWORD = os.environ.get("IOT_ADMIN_PASSWORD", "ChangeMe!2026")
# This is the key Flask uses to cryptographically sign session cookies, so users
# can't forge or tamper with their own session data. Again, pulled from an
# environment variable if available, otherwise a dev-only fallback is used.
SECRET_KEY = os.environ.get("IOT_SECRET_KEY", "dev-secret-key-change-in-production")

# --- External APIs ---
# NVD works without a key but is rate-limited (~5 requests/30s vs ~50/30s with a key).
# Get a free key at https://nvd.nist.gov/developers/request-an-api-key
 
# This means: if an NVD_API_KEY environment variable has been set, use it when
# calling the NVD API to get a much higher rate limit. If not set, this stays
# as an empty string, and the app just uses NVD's slower unauthenticated limit.
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

# Shodan requires a paid/academic key. Without one, the platform will
# honestly report "not configured" instead of faking a 0-exposure result.
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")

# --- Network behaviour ---
REQUEST_TIMEOUT_SECONDS = 8
REQUEST_RETRIES = 2

# --- Scoring ---
# Weighted-by-severity CVE penalty instead of a flat -5/CVE.
# Points deducted per CVE, based on its CVSS band.
CVE_PENALTY_BY_SEVERITY = {
    "Critical": 15,   # CVSS 9.0 - 10.0
    "High": 10,       # CVSS 7.0 - 8.9
    "Medium": 5,      # CVSS 4.0 - 6.9
    "Low": 2,         # CVSS 0.1 - 3.9
    "Unknown": 3,      # CVSS not available from source
}
MAX_CVE_PENALTY = 60          # cap so a device with 50 CVEs doesn't blow past -1000
EXPLOITATION_PENALTY_PER_CVE = 20   # extra penalty per actively-exploited (CISA KEV) CVE
MAX_EXPLOITATION_PENALTY = 40

CACHE_DIR = os.path.join(os.path.dirname(__file__), "data")
CISA_KEV_CACHE_FILE = os.path.join(CACHE_DIR, "cisa_kev_cache.json")
CISA_KEV_CACHE_TTL_HOURS = 24
