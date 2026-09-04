"""
SQLite persistence layer.

Schema changes vs. the original:
  - Added nvd_status / shodan_status / cisa_status columns so a stored
    row records whether each external check actually succeeded, instead
    of an ambiguous 0 that could mean either "checked, found nothing"
    or "check failed silently".
  - Added cve_keyword_used so it's clear whether the CVE match came from
    the device name or the device-type fallback keyword.
"""

import sqlite3
import os

# This means: build the full path to the database file, placing it one
# folder up from wherever this file (database.py) actually lives — so the
# database sits in the project root regardless of what folder the app is
# run from.
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "iot_security_v2.db")


def get_connection():
    # This means: open a new connection to the SQLite database file, and
    # configure it so query results come back as row objects that can be
    # accessed by column name (like a dictionary) instead of just plain
    # unlabeled tuples — that's what row_factory does here.
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    # This means: create the "assessments" table if it doesn't already
    # exist. Using "IF NOT EXISTS" means this is safe to run every time the
    # app starts — it won't wipe or duplicate an existing table.
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_name TEXT NOT NULL,
            device_type TEXT NOT NULL,
            auto_update TEXT NOT NULL,
            authentication TEXT NOT NULL,
            encryption TEXT NOT NULL,
            support TEXT NOT NULL,
            base_score INTEGER NOT NULL,
            score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            compliance_status TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            cve_count INTEGER NOT NULL DEFAULT 0,
            cve_penalty INTEGER NOT NULL DEFAULT 0,
            avg_cvss REAL NOT NULL DEFAULT 0,
            cve_keyword_used TEXT,
            nvd_status TEXT NOT NULL DEFAULT 'error',
            exploited_count INTEGER NOT NULL DEFAULT 0,
            exploitation_penalty INTEGER NOT NULL DEFAULT 0,
            cisa_status TEXT NOT NULL DEFAULT 'error',
            exposure_penalty INTEGER NOT NULL DEFAULT 0,
            exposure_level TEXT NOT NULL DEFAULT 'Not Configured',
            shodan_status TEXT NOT NULL DEFAULT 'not_configured',
            baseline_risk_level TEXT NOT NULL DEFAULT '',
            baseline_compliance_status TEXT NOT NULL DEFAULT '',
            nvd_time_ms INTEGER NOT NULL DEFAULT 0,
            cisa_time_ms INTEGER NOT NULL DEFAULT 0,
            shodan_time_ms INTEGER NOT NULL DEFAULT 0,
            total_time_ms INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()


def save_assessment(**kwargs):
    # This means: accept any number of named keyword arguments (e.g.
    # device_name="...", score=75, ...) and insert them as one new row.
    # Using **kwargs instead of listing every parameter explicitly keeps
    # this function flexible if fields get added or reordered later.
    conn = get_connection()
    c = conn.cursor()
    # This explicit list controls exactly which fields get saved and in what
    # order — anything in kwargs that isn't in this list is simply ignored.
    fields = [
        "device_name", "device_type", "auto_update", "authentication", "encryption",
        "support", "base_score", "score", "risk_level", "compliance_status",
        "cve_count", "cve_penalty", "avg_cvss", "cve_keyword_used", "nvd_status",
        "exploited_count", "exploitation_penalty", "cisa_status",
        "exposure_penalty", "exposure_level", "shodan_status",
        "baseline_risk_level", "baseline_compliance_status",
        "nvd_time_ms", "cisa_time_ms", "shodan_time_ms", "total_time_ms",
    ]
    # Build the SQL placeholders ("?, ?, ?...") and column names dynamically
    # from the fields list above, rather than hand-writing a long INSERT statement
    placeholders = ", ".join(["?"] * len(fields))
    columns = ", ".join(fields)
    # Pull the actual value for each field name out of kwargs, in the same
    # order as the fields list, so they line up correctly with the placeholders
    values = [kwargs.get(f) for f in fields]
    # Using "?" placeholders (rather than plugging values directly into the
    # SQL string) protects against SQL injection — this is a parameterised query.
    c.execute(f"INSERT INTO assessments ({columns}) VALUES ({placeholders})", values)
    conn.commit()
    # lastrowid gives us the auto-generated ID SQLite just assigned to this
    # new row, which the rest of the app uses to name the PDF report, etc.
    new_id = c.lastrowid
    conn.close()
    return new_id


def get_all_assessments():
    # This means: fetch every row from the assessments table, newest first
    # (highest ID first), and convert each row into a plain dictionary so
    # it's easy to use in templates.
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM assessments ORDER BY id DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def get_assessment_by_id(assessment_id):
    # This means: look up exactly one assessment by its ID. Returns None if
    # no row matches that ID, rather than raising an error, so the caller
    # can easily check "does this assessment exist?"
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM assessments WHERE id = ?", (assessment_id,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


def get_device_types():
    # This means: return every unique device_type value that's actually
    # been used in a saved assessment so far, sorted alphabetically — used
    # to populate the dashboard's filter dropdown.
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT DISTINCT device_type FROM assessments ORDER BY device_type")
    types = [r[0] for r in c.fetchall()]
    conn.close()
    return types


def get_dashboard_stats(device_type="All"):
    # This means: gather a whole batch of summary numbers for the dashboard —
    # optionally filtered down to just one device type, or covering
    # everything if "All" is selected.
    conn = get_connection()
    c = conn.cursor()

    # Build the WHERE clause once here, then reuse it in every query below —
    # if device_type is "All", there's no filter at all (empty string); if
    # a specific type was chosen, the same filter condition and parameter
    # get applied everywhere.
    where = "" if device_type == "All" else "WHERE device_type = ?"
    params = () if device_type == "All" else (device_type,)

    # Total number of assessments matching the current filter
    c.execute(f"SELECT COUNT(*) FROM assessments {where}", params)
    total = c.fetchone()[0]

    # Average final score across the matching assessments
    c.execute(f"SELECT AVG(score) FROM assessments {where}", params)
    avg_score = c.fetchone()[0] or 0

    # This means: count how many assessments came back "Compliant". Note the
    # `{' AND' if where else 'WHERE'}` trick — if a device_type filter is
    # already active (so `where` starts with "WHERE ..."), this appends
    # "AND compliance_status = ..." onto it; if there's no filter at all,
    # this instead starts a fresh "WHERE compliance_status = ..." clause.
    c.execute(f"SELECT COUNT(*) FROM assessments {where}{' AND' if where else 'WHERE'} compliance_status = 'Compliant'", params)
    compliant = c.fetchone()[0]

    # Same pattern as above, but counting Non-Compliant assessments instead
    c.execute(f"SELECT COUNT(*) FROM assessments {where}{' AND' if where else 'WHERE'} compliance_status = 'Non-Compliant'", params)
    non_compliant = c.fetchone()[0]

    # Add up the total number of CVEs found across all matching assessments
    c.execute(f"SELECT SUM(cve_count) FROM assessments {where}", params)
    total_cves = c.fetchone()[0] or 0

    # Add up the total CVE penalty points deducted across all matching assessments
    c.execute(f"SELECT SUM(cve_penalty) FROM assessments {where}", params)
    total_cve_penalty = c.fetchone()[0] or 0

    # Add up the total exposure penalty points from the Shodan checks
    c.execute(f"SELECT SUM(exposure_penalty) FROM assessments {where}", params)
    total_exposure_penalty = c.fetchone()[0] or 0

    # Count how many assessments were flagged with High or Medium exposure
    # levels on Shodan — same WHERE/AND pattern as above
    c.execute(f"SELECT COUNT(*) FROM assessments {where}{' AND' if where else 'WHERE'} exposure_level IN ('High','Medium')", params)
    high_exposure = c.fetchone()[0]

    # This means: work out the average CVSS score, but only counting
    # assessments where avg_cvss is actually greater than 0 — so devices
    # with no CVEs at all (avg_cvss = 0) don't unfairly drag the average down
    c.execute(f"SELECT AVG(avg_cvss) FROM assessments {where}{' AND' if where else 'WHERE'} avg_cvss > 0", params)
    avg_cvss_row = c.fetchone()[0]

    # Count how many assessments had an NVD lookup that actually failed
    # (status = 'error'), used to surface API reliability stats
    c.execute(f"SELECT COUNT(*) FROM assessments {where}{' AND' if where else 'WHERE'} nvd_status = 'error'", params)
    nvd_failures = c.fetchone()[0]

    # Count how many assessments were run without a Shodan key configured at all
    c.execute(f"SELECT COUNT(*) FROM assessments {where}{' AND' if where else 'WHERE'} shodan_status = 'not_configured'", params)
    shodan_unconfigured = c.fetchone()[0]

    conn.close()
    # Bundle every stat calculated above into one dictionary the dashboard
    # template can read directly, rounding averages to 2 decimal places for display
    return {
        "total_assessments": total,
        "average_score": round(avg_score, 2),
        "compliant": compliant,
        "non_compliant": non_compliant,
        "total_cves": total_cves,
        "total_cve_penalty": total_cve_penalty,
        "total_exposure_penalty": total_exposure_penalty,
        "high_exposure_devices": high_exposure,
        "average_cvss": round(avg_cvss_row, 2) if avg_cvss_row else 0,
        "nvd_lookup_failures": nvd_failures,
        "shodan_unconfigured_count": shodan_unconfigured,
    }


# Fixed, deliberately ordered lists of every possible risk level and
# compliance status — used below to make sure charts always show every
# category, even ones with zero assessments, instead of only showing
# whatever categories happen to have data.
RISK_LEVELS_ORDERED = ["Critical Risk", "High Risk", "Medium Risk", "Low Risk"]
COMPLIANCE_STATUSES_ORDERED = ["Compliant", "Non-Compliant"]


def get_chart_data(device_type="All"):
    """
    Always returns the FULL fixed set of categories (all 4 risk levels,
    both compliance statuses) with explicit 0s for anything not present,
    instead of only whatever categories happen to exist in the data.
    A chart with one bar filling the whole width, or missing categories
    entirely, looks broken — this keeps the shape consistent regardless
    of how sparse the underlying data is.
    """
    conn = get_connection()
    c = conn.cursor()
    where = "" if device_type == "All" else "WHERE device_type = ?"
    params = () if device_type == "All" else (device_type,)

    # This means: ask the database how many assessments fall into each risk
    # level, but only for the levels that actually appear in the data — then
    # fill in the ones that don't appear with an explicit 0, using the fixed
    # RISK_LEVELS_ORDERED list from above, so the chart always has all 4 bars.
    c.execute(f"SELECT risk_level, COUNT(*) FROM assessments {where} GROUP BY risk_level", params)
    risk_counts = {row[0]: row[1] for row in c.fetchall()}
    risk_distribution = {level: risk_counts.get(level, 0) for level in RISK_LEVELS_ORDERED}

    # Same idea as above, but for compliance status instead of risk level
    c.execute(f"SELECT compliance_status, COUNT(*) FROM assessments {where} GROUP BY compliance_status", params)
    comp_counts = {row[0]: row[1] for row in c.fetchall()}
    compliance_distribution = {status: comp_counts.get(status, 0) for status in COMPLIANCE_STATUSES_ORDERED}

    conn.close()
    return {
        "risk_distribution": risk_distribution,
        "compliance_distribution": compliance_distribution,
    }


def get_cve_chart_data():
    """
    Grouped strictly by the stored device_type column now that CVE data
    is attached per-assessment — this reflects reality rather than the
    old bug where router CVEs were bucketed under 'Camera' because the
    lookup ignored device_type entirely.

    Always shows all 4 registered device types (Camera, Lock, Thermostat,
    Router), with 0 for any that have no assessments yet, rather than
    the chart silently shrinking to only whichever types happen to have
    data — a 2-bar chart reads as "broken," a 4-bar chart with two real
    zeros reads as "no data yet for these types."
    """
    # Import here (rather than at the top of the file) to avoid a circular
    # import between database.py and device_loader.py
    from utils.device_loader import DEVICE_TYPES

    conn = get_connection()
    c = conn.cursor()
    # This means: for each device type that has at least one assessment,
    # total up all its CVEs and work out the average CVSS score across those
    # assessments, grouped by device_type
    c.execute("""
        SELECT device_type, SUM(cve_count) as total_cves, AVG(avg_cvss) as avg_cvss
        FROM assessments
        GROUP BY device_type
    """)
    # Turn the result into a dictionary keyed by device_type name, so we can
    # easily look up "does this specific type have any data?" below
    rows = {r["device_type"]: r for r in c.fetchall()}
    conn.close()

    # This means: get the full official list of device type codes (Camera,
    # Lock, Thermostat, Router, etc.) rather than just whatever types
    # happen to have assessment data, so every type always shows up on the
    # chart, even with a genuine zero.
    all_types = [d["code"] for d in DEVICE_TYPES]
    labels, total_cves, avg_cvss = [], [], []
    for t in all_types:
        labels.append(t)
        if t in rows:
            # This type has data — use the real totals, defaulting to 0 if
            # a value happens to be null
            total_cves.append(rows[t]["total_cves"] or 0)
            avg_cvss.append(round(rows[t]["avg_cvss"], 2) if rows[t]["avg_cvss"] else 0)
        else:
            # This type has no assessments at all yet — show explicit zeros
            # rather than leaving it out of the chart entirely
            total_cves.append(0)
            avg_cvss.append(0)

    return {"labels": labels, "total_cves": total_cves, "avg_cvss": avg_cvss}