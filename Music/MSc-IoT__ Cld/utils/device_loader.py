"""
Device type catalogue. Each type carries a generic NVD keyword used as a
FALLBACK CVE search term when the free-text device name returns no
results — this is what was missing in the original app, where device_type
was purely cosmetic and never touched CVE matching at all.
"""

# This means: a hardcoded list of every device type the assessment form
# offers. Each entry has a short internal "code" (used for storage/filtering),
# a friendlier "label" for display on the dropdown, and a generic
# "nvd_fallback_keyword" — the search term used to look up CVEs if searching
# by the exact device name comes back empty.
DEVICE_TYPES = [
    {"code": "Camera", "label": "Smart Camera (Camera)", "nvd_fallback_keyword": "IP camera"},
    {"code": "Lock", "label": "Smart Lock (Lock)", "nvd_fallback_keyword": "smart lock"},
    {"code": "Thermostat", "label": "Smart Thermostat (Thermostat)", "nvd_fallback_keyword": "smart thermostat"},
    {"code": "Router", "label": "Router / Gateway (Router)", "nvd_fallback_keyword": "router"},
]


def load_devices():
    # This means: just return the full static list of device types, used to
    # populate the dropdown on the assessment form
    return DEVICE_TYPES


def get_fallback_keyword(device_type_code):
    # This means: search through DEVICE_TYPES for the entry whose code
    # matches the one passed in (e.g. "Camera"), and return its associated
    # fallback keyword (e.g. "IP camera") for use in the CVE search.
    for d in DEVICE_TYPES:
        if d["code"] == device_type_code:
            return d["nvd_fallback_keyword"]
    # This means: if the given device_type_code doesn't match any known
    # type in the list (e.g. it was mistyped or is a legacy value), just
    # fall back to using the raw code itself as the search keyword, rather
    # than failing outright
    return device_type_code