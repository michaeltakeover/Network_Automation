"""
Scoring engine.

Fixes vs. the original implementation:
  - CVE penalty is weighted by CVSS severity band instead of a flat -5/CVE,
    and capped so it can't spiral to unrealistic negative totals.
  - Severity is derived from the CVSS score (was always "Unknown" before).
  - All penalties are capped individually before being combined.
"""

# Pull in the tunable numbers from config.py, so nobody has to hunt through
# this file to change how harsh the penalties are — it's all in one place.
from config import (
    CVE_PENALTY_BY_SEVERITY,
    MAX_CVE_PENALTY,
    EXPLOITATION_PENALTY_PER_CVE,
    MAX_EXPLOITATION_PENALTY,
)


def cvss_to_severity(cvss_score):
    """Standard CVSS v3 severity bands. Returns 'Unknown' if score is None."""
    # This means: if there's no CVSS score at all for this CVE, we can't
    # classify its severity, so just label it "Unknown" straight away.
    if cvss_score is None:
        return "Unknown"
    try:
        # Make sure the score is actually a usable number before comparing it
        # against the severity bands below — some sources might send it as
        # a string, so this converts it to a proper float.
        score = float(cvss_score)
    except (TypeError, ValueError):
        # If it can't be converted to a number at all (e.g. it's garbage
        # data), fall back to "Unknown" rather than crashing.
        return "Unknown"

    # This means: sort the numeric CVSS score into the standard industry
    # severity bands used across the security field (Critical/High/Medium/Low).
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0.0:
        return "Low"
    else:
        return "Unknown"


def calculate_score(auto_update, authentication, encryption, support):
    """Base score out of 100, 25 points per 'yes' answer."""
    # This means: take the four yes/no questionnaire answers, and award 25
    # points for each one that was answered "yes" — so a device that ticks
    # every box scores the maximum 100, and one that ticks none scores 0.
    answers = [auto_update, authentication, encryption, support]
    score = sum(25 for a in answers if str(a).lower() == "yes")
    return score


def calculate_cve_penalty(vulnerabilities, match_type="product"):
    """
    Weighted-by-severity penalty, capped at MAX_CVE_PENALTY.

    When match_type is "category_fallback" (no CVEs found for the exact
    product name, so a generic device-type keyword was used instead),
    the penalty is halved. A fallback match found decades-old CVEs for
    arbitrary unrelated hardware that happens to share a category label
    (e.g. "router") — that's a much weaker signal than a confirmed match
    on the actual product name, and scoring it identically would unfairly
    tank a device that may have no real, disclosed vulnerabilities at all.
    """
    # This means: go through every CVE found for this device, look up its
    # severity band, and add up the corresponding penalty points for each one.
    total = 0
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "Unknown")
        total += CVE_PENALTY_BY_SEVERITY.get(severity, CVE_PENALTY_BY_SEVERITY["Unknown"])

    # This means: if these CVEs weren't confirmed to belong to the exact
    # device (they came from a generic category search instead), only count
    # half the penalty, since we can't be sure they actually apply to this
    # specific product.
    if match_type == "category_fallback":
        total = total // 2

    # Never let the CVE penalty alone exceed the configured cap, no matter
    # how many CVEs were found
    return min(total, MAX_CVE_PENALTY)


def calculate_exploitation_penalty(exploited_cves, match_type="product"):
    """Extra penalty for CVEs confirmed as actively exploited (CISA KEV).
    Halved for category_fallback matches — see calculate_cve_penalty."""
    # This means: for every CVE that's confirmed to be actively exploited in
    # the wild (per CISA's list), add a fixed extra penalty on top of the
    # normal CVE penalty — active exploitation is treated as more serious
    # than a CVE simply existing.
    total = len(exploited_cves) * EXPLOITATION_PENALTY_PER_CVE
    # Same fallback-match discount logic as the CVE penalty above — halve it
    # if these CVEs weren't confirmed to belong to the exact product.
    if match_type == "category_fallback":
        total = total // 2
    # Cap this penalty separately so exploitation alone can't blow the score out
    return min(total, MAX_EXPLOITATION_PENALTY)


def get_risk_level(score):
    # This means: translate the final numeric score into one of four
    # human-readable risk labels, based on which range it falls into.
    if score >= 75:
        return "Low Risk"
    elif score >= 50:
        return "Medium Risk"
    elif score >= 25:
        return "High Risk"
    else:
        return "Critical Risk"


def get_compliance_status(score):
    # This means: a device only counts as "Compliant" if its score is 70 or
    # above — anything below that is flagged as "Non-Compliant".
    return "Compliant" if score >= 70 else "Non-Compliant"


def get_status_colour(risk_level):
    # This means: map each risk label to a colour used for displaying it on
    # the results page, so "Critical Risk" shows up visually alarming (dark
    # red) while "Low Risk" shows up reassuring (green). Falls back to grey
    # if the risk level somehow doesn't match any known label.
    return {
        "Low Risk": "green",
        "Medium Risk": "orange",
        "High Risk": "red",
        "Critical Risk": "darkred",
    }.get(risk_level, "grey")


def get_recommendations(auto_update, authentication, encryption, support, vulnerabilities=None, exploited_cves=None, match_type="product"):
    """
    Recommendations now account for real CVE/exploitation findings, not
    just the questionnaire answers. Urgency language is softened when
    the CVE data came from a category_fallback match (generic device-type
    keyword, not the confirmed product) — those findings aren't verified
    to apply to this specific device.
    """
    # Guard against None being passed in for either list, so the rest of the
    # function can safely assume it's always working with an actual list
    vulnerabilities = vulnerabilities or []
    exploited_cves = exploited_cves or []
    # Flag whether this data came from a confirmed product match or a
    # generic fallback search — used below to soften the wording where needed
    is_fallback = match_type == "category_fallback"

    recs = []
    # This means: for each questionnaire answer that wasn't "yes", add a
    # specific recommendation telling the user what control they're missing
    if str(auto_update).lower() != "yes":
        recs.append("Enable automatic firmware updates.")
    if str(authentication).lower() != "yes":
        recs.append("Use strong authentication and remove default passwords.")
    if str(encryption).lower() != "yes":
        recs.append("Enable encryption for data at rest and in transit.")
    if str(support).lower() != "yes":
        recs.append("Choose vendors offering 5+ years of security support, or plan device replacement.")

    # This means: if any CVEs were found to be actively exploited, add a
    # recommendation about it — but word it differently depending on whether
    # this is a confirmed match (urgent language) or a fallback match
    # (softer, verification-requesting language), since fallback results
    # aren't guaranteed to actually apply to this specific device.
    if exploited_cves:
        if is_fallback:
            recs.append(
                f"NOTE: {len(exploited_cves)} actively-exploited CVE(s) were found under a generic category "
                f"search (CISA KEV: {', '.join(exploited_cves)}), not a confirmed match to this exact product. "
                "Manually verify whether these apply before treating this as urgent."
            )
        else:
            recs.append(
                f"URGENT: {len(exploited_cves)} CVE(s) on this device are actively exploited in the wild "
                f"(CISA KEV: {', '.join(exploited_cves)}). Patch or isolate this device immediately."
            )

    # This means: separately, check if there are any Critical or High
    # severity CVEs (regardless of whether they're actively exploited or
    # not) and recommend checking for a firmware update — again with softer
    # wording if the data came from a fallback search rather than a
    # confirmed product match.
    critical_or_high = [v for v in vulnerabilities if v.get("severity") in ("Critical", "High")]
    if critical_or_high:
        if is_fallback:
            recs.append(
                f"{len(critical_or_high)} Critical/High severity CVE(s) were found under a generic "
                "category search — not confirmed for this exact product/firmware. Search NVD directly "
                "for the specific model and firmware version to verify before acting."
            )
        else:
            recs.append(
                f"{len(critical_or_high)} Critical/High severity CVE(s) found for this device/firmware. "
                "Check for a firmware update from the vendor or consider replacement if unpatched."
            )

    # This means: if none of the above conditions added anything to the list
    # (the device passed every questionnaire check and has no notable CVEs),
    # give a reassuring default message instead of returning an empty list.
    if not recs:
        recs.append("No control gaps found from the questionnaire and no significant CVEs detected. Continue monitoring for newly disclosed vulnerabilities.")

    return recs