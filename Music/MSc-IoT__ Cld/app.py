import os
import time
import secrets

from flask import Flask, render_template, request, send_file, redirect, url_for, session, flash, abort
# Pulling in the sensitive/config values (secret key, admin login) from config.py
# instead of hardcoding them here, so credentials aren't sitting directly in app.py

from config import SECRET_KEY, ADMIN_USERNAME, ADMIN_PASSWORD

# load_standards() reads the compliance standards text shown on the result page.
# load_devices() gets the list of device types for the assessment form dropdown,
# and get_fallback_keyword() maps a device type (e.g. "Router") to a generic search
# term to use if searching by the exact device name doesn't find anything.

from utils.standards_loader import load_standards
from utils.device_loader import load_devices, get_fallback_keyword
from utils.report_generator import generate_report

# External API lookups: CVE data, known-exploited CVE list, and internet exposure scan

from utils.nvd_lookup import search_nvd
from utils.cisa_lookup import check_cisa_exploitation
from utils.shodan_lookup import search_shodan

# All the database read/write functions live in utils/database.py

from utils.database import (
    init_db,
    save_assessment,
    get_all_assessments,
    get_assessment_by_id,
    get_dashboard_stats,
    get_chart_data,
    get_device_types,
    get_cve_chart_data,
)

# load_standards() reads the compliance standards text shown on the result page.
# load_devices() gets the list of device types for the assessment form dropdown,
# and get_fallback_keyword() maps a device type (e.g. "Router") to a generic search
# term to use if searching by the exact device name doesn't find anything.

from utils.scoring import (
    calculate_score,
    calculate_cve_penalty,
    calculate_exploitation_penalty,
    get_risk_level,
    get_compliance_status,
    get_recommendations,
    get_status_colour,
)
# Create the actual Flask application object — this is what runs the web server

app = Flask(__name__)
# The secret key is what Flask uses to cryptographically sign session cookies,
# so a user can't tamper with their own session data (e.g. fake being logged in)

app.secret_key = SECRET_KEY

# Session cookie hardening: JS can't read the cookie, and it won't be sent
# on cross-site requests. SESSION_COOKIE_SECURE is left off because this
# runs over plain HTTP locally (127.0.0.1) — set it True behind HTTPS
# in any real deployment.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
# Run this once at startup so the SQLite file and its tables definitely exist
# before any route tries to read from or write to the database

init_db()


def login_required(view_func):
    # This is a decorator — you stick @login_required above a route function and
    # it wraps that function so it checks the session first. If the user isn't
    # logged in, they get redirected to the login page instead of the page they asked for.
    from functools import wraps

    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped


def get_csrf_token():
    """Generate (once per session) and return a CSRF token."""
    # If this session doesn't have a CSRF token yet, generate a random one and store it.
    # Reusing the same token for the whole session (rather than generating a new one
    # every request) means multiple forms open in different tabs still work correctly.
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_csrf():
    """Abort with 400 if the submitted token doesn't match the session's."""
    # Grab the token that was submitted with the form, and the one we actually
    # issued to this session earlier. If they don't match (or nothing was issued),
    # reject the request — this stops another website from tricking a logged-in
    # user's browser into submitting a form on this app without their knowledge.
    token = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    if not expected or not secrets.compare_digest(token, expected):
        abort(400, description="Invalid or missing CSRF token. Please reload the form and try again.")


app.jinja_env.globals["csrf_token"] = get_csrf_token


@app.route("/")
def home():
    # The root URL doesn't show anything itself — it just decides where to send
    # the user: straight to the dashboard if they're already logged in, or to
    # the login page if they're not.
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/assessment")
@login_required
def assessment():
    # This shows the blank assessment questionnaire. It loads the list of known
    # device types first so the form's dropdown can be populated with real options.
    devices = load_devices()
    return render_template("assessment.html", devices=devices)


@app.route("/result", methods=["POST"])
@login_required
def result():
    # This is the main route of the whole app — it's what runs when someone submits
    # the assessment form. It reads their answers, fetches live threat data about
    # the device, works out a risk score, saves everything to the database, builds
    # a PDF report, and then shows the results page.
    validate_csrf()
    # --- Read the submitted form fields ---
    # .strip() removes accidental leading/trailing spaces from typed text fields.
    # The checkbox-style fields default to "no" if they weren't included in the form at all.
    device_name = request.form.get("device_name", "").strip()
    device_type = request.form.get("device_type", "").strip()
    auto_update = request.form.get("auto_update", "no")
    authentication = request.form.get("authentication", "no")
    encryption = request.form.get("encryption", "no")
    support = request.form.get("support", "no")

    if not device_name or not device_type:
        flash("Device name and device type are required.")
        return redirect(url_for("assessment"))

    assessment_start = time.perf_counter()
    # --- CVE lookup: device name first, generic type keyword as fallback ---
    # This means: first try to find CVEs that match the exact device name typed in.
    # If that comes back empty, fall back to searching by a generic keyword based
    # on the device type instead (e.g. "router" or "camera"), so we still surface
    # something useful even when the exact product isn't in the CVE database.

    # --- CVE lookup: device name first, generic type keyword as fallback ---
    fallback_keyword = get_fallback_keyword(device_type)
    t0 = time.perf_counter()
    nvd_result = search_nvd(device_name, fallback_keyword=fallback_keyword)
    nvd_time_ms = round((time.perf_counter() - t0) * 1000)
    vulnerabilities = nvd_result["vulnerabilities"]

    # --- CISA KEV cross-check ---
    # This means: take the list of CVE IDs we just found and check them against
    # CISA's "Known Exploited Vulnerabilities" catalogue. A CVE that's actually
    # being exploited in the wild is treated as far more serious than one that's
    # just theoretically possible, so this feeds into a separate, heavier penalty later.
    cve_ids = [v["cve_id"] for v in vulnerabilities]
    t0 = time.perf_counter()
    cisa_result = check_cisa_exploitation(cve_ids)
    cisa_time_ms = round((time.perf_counter() - t0) * 1000)
    exploited_cves = cisa_result["exploited_cves"]

    # --- Shodan exposure check ---
    # This means: check whether this device (by name) actually shows up on Shodan,
    # which indexes devices that are reachable from the public internet. A device
    # that's exposed to the internet is inherently riskier than one that isn't.
    t0 = time.perf_counter()
    shodan_result = search_shodan(device_name)
    shodan_time_ms = round((time.perf_counter() - t0) * 1000)

    total_time_ms = round((time.perf_counter() - assessment_start) * 1000)

    # --- Scoring ---
    # This means: work out the "baseline" score purely from the yes/no questionnaire
    # answers (auto-update, authentication, encryption, support), then separately
    # work out how many points to subtract for CVEs found, for CVEs known to be
    # actively exploited, and for public internet exposure.
    base_score = calculate_score(auto_update, authentication, encryption, support)
    cve_penalty = calculate_cve_penalty(vulnerabilities, match_type=nvd_result["match_type"])
    exploitation_penalty = calculate_exploitation_penalty(exploited_cves, match_type=nvd_result["match_type"])
    exposure_penalty = shodan_result["exposure_penalty"]

    # Subtract all the penalties from the baseline to get the final score, but never
    # let it go below zero (a device can't be "worse than the worst possible score")
    score = max(base_score - cve_penalty - exploitation_penalty - exposure_penalty, 0)

    # Work out how many CVEs were found in total, and their average CVSS severity
    # score, for display on the results page (0 if none had a usable CVSS score)
    cve_count = len(vulnerabilities)
    cvss_scores = [v["cvss_score"] for v in vulnerabilities if v["cvss_score"] is not None]
    avg_cvss = round(sum(cvss_scores) / len(cvss_scores), 2) if cvss_scores else 0

    # This means: convert the final numeric score into something human-readable —
    # a risk label like "Low Risk"/"Critical Risk", a colour to display it in,
    # and a compliance verdict like "Compliant"/"Non-Compliant".
    risk_level = get_risk_level(score)
    status_colour = get_status_colour(risk_level)
    compliance_status = get_compliance_status(score)
    # Condition A (baseline-only) risk classification, computed alongside
    # Condition B (threat-informed) for the comparative evaluation —
    # base_score was already being calculated; this just also classifies it.
    baseline_risk_level = get_risk_level(base_score)
    baseline_compliance_status = get_compliance_status(base_score)
    standards = load_standards()
    recommendations = get_recommendations(
        auto_update, authentication, encryption, support,
        vulnerabilities=vulnerabilities,
        exploited_cves=exploited_cves,
        match_type=nvd_result["match_type"],
    )
    # This means: write everything about this assessment — the answers, the score,
    # the CVE/exploitation/exposure data, and the timing stats — into the database
    # as one row, and get back the auto-generated ID for that new row.
    assessment_id = save_assessment(
        device_name=device_name,
        device_type=device_type,
        auto_update=auto_update,
        authentication=authentication,
        encryption=encryption,
        support=support,
        base_score=base_score,
        score=score,
        risk_level=risk_level,
        compliance_status=compliance_status,
        cve_count=cve_count,
        cve_penalty=cve_penalty,
        avg_cvss=avg_cvss,
        cve_keyword_used=nvd_result["keyword_used"],
        nvd_status=nvd_result["status"],
        exploited_count=len(exploited_cves),
        exploitation_penalty=exploitation_penalty,
        cisa_status=cisa_result["status"],
        exposure_penalty=exposure_penalty,
        exposure_level=shodan_result["exposure_level"],
        shodan_status=shodan_result["status"],
        baseline_risk_level=baseline_risk_level,
        baseline_compliance_status=baseline_compliance_status,
        nvd_time_ms=nvd_time_ms,
        cisa_time_ms=cisa_time_ms,
        shodan_time_ms=shodan_time_ms,
        total_time_ms=total_time_ms,
    )
    # Bundle up everything the PDF report needs into one dictionary, so
    # generate_report() has all the context it needs to build the document
    report_ctx = {
        "device_name": device_name,
        "device_type": device_type,
        "base_score": base_score,
        "score": score,
        "risk_level": risk_level,
        "compliance_status": compliance_status,
        "cve_penalty": cve_penalty,
        "exploitation_penalty": exploitation_penalty,
        "exposure_penalty": exposure_penalty,
        "exposure_level": shodan_result["exposure_level"],
        "shodan_status": shodan_result["status"],
        "shodan_message": shodan_result["message"],
        "recommendations": recommendations,
        "standards": standards,
        "vulnerabilities": vulnerabilities,
        "nvd_status": nvd_result["status"],
        "nvd_message": nvd_result["message"],
        "exploited_cves": exploited_cves,
        "cisa_status": cisa_result["status"],
        "cisa_message": cisa_result["message"],
    }
    report_path = f"reports/assessment_{assessment_id}.pdf"
    generate_report(report_path, report_ctx)

    # Finally, render the results page, passing through everything the template
    # needs to display the score, the CVEs found, the recommendations, and so on.
    return render_template(
        "result.html",
        assessment_id=assessment_id,
        device_name=device_name,
        device_type=device_type,
        auto_update=auto_update,
        base_score=base_score,
        score=score,
        risk_level=risk_level,
        cve_penalty=cve_penalty,
        compliance_status=compliance_status,
        recommendations=recommendations,
        standards=standards,
        status_colour=status_colour,
        vulnerabilities=vulnerabilities,
        exploited_cves=exploited_cves,
        shodan_data=shodan_result,
        nvd_result=nvd_result,
        cisa_result=cisa_result,
        exposure_penalty=exposure_penalty,
        exploitation_penalty=exploitation_penalty,
        avg_cvss=avg_cvss,
        cve_count=cve_count,
        baseline_risk_level=baseline_risk_level,
        baseline_compliance_status=baseline_compliance_status,
        nvd_time_ms=nvd_time_ms,
        cisa_time_ms=cisa_time_ms,
        shodan_time_ms=shodan_time_ms,
        total_time_ms=total_time_ms,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    # This route does two jobs depending on the HTTP method: a GET request just
    # shows the empty login form, while a POST request means the form was
    # submitted and needs to be checked against the admin credentials.
    if request.method == "POST":
        validate_csrf()
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # Constant-time comparison — a plain `==` leaks timing information
        # an attacker could use to guess credentials character-by-character.
        # This means: checking each field byte-by-byte in a way that always takes
        # the same amount of time, whether the first character matches or not,
        # so an attacker can't use response speed to guess the password.
        username_ok = secrets.compare_digest(username, ADMIN_USERNAME)
        password_ok = secrets.compare_digest(password, ADMIN_PASSWORD)

        if username_ok and password_ok:
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.")

    return render_template("login.html")


@app.route("/history")
@login_required
def history():
    # This means: pull every past assessment out of the database and display them
    # all as rows in a table, most likely newest-first, so the user can browse
    # everything that's been assessed before.
    assessments = get_all_assessments()
    return render_template("history.html", assessments=assessments)


@app.route("/dashboard")
@login_required
def dashboard():
    # The dashboard can be filtered by device type using a query string parameter,
    # e.g. visiting /dashboard?device_type=Camera only shows stats for cameras.
    # If no filter is given, it defaults to "All" (i.e. show everything).
    selected_device_type = request.args.get("device_type", "All")
    stats = get_dashboard_stats(selected_device_type)
    chart_data = get_chart_data(selected_device_type)
    device_types = get_device_types()
    cve_chart_data = get_cve_chart_data()

    return render_template(
        "dashboard.html",
        stats=stats,
        chart_data=chart_data,
        cve_chart_data=cve_chart_data,
        device_types=device_types,
        selected_device_type=selected_device_type,
    )


@app.route("/logout")
def logout():
    # This means: completely wipe the session — the logged_in flag, the CSRF
    # token, everything — so the user is fully signed out, then send them back
    # to the login page.
    session.clear()
    return redirect(url_for("login"))


@app.route("/download-report/<int:assessment_id>")
@login_required
def download_report(assessment_id):
    # This means: look up the assessment by its ID first, so if someone requests
    # a download for an ID that doesn't exist, we can tell them clearly instead
    # of crashing or serving a broken file.
    assessment = get_assessment_by_id(assessment_id)
    if assessment is None:
        flash(f"No assessment found with ID {assessment_id}.")
        return redirect(url_for("history"))

    # Even if the assessment exists in the database, the actual PDF file on disk
    # might be missing (e.g. it predates PDF generation being added, or it was
    # deleted). Check for that separately and give a clear explanation if so.
    report_path = f"reports/assessment_{assessment_id}.pdf"
    if not os.path.exists(report_path):
        flash(
            f"No PDF is stored for assessment #{assessment_id} "
            "(it may predate PDF generation, or the file was deleted). "
            "Run a new assessment for this device to generate a fresh report."
        )
        return redirect(url_for("history"))
    # Send the actual PDF file to the browser as a download, and rename it on the
    # way out to something based on the device name instead of a raw numeric ID,
    # so the downloaded file is easier for the user to recognise later.
    return send_file(
        report_path,
        as_attachment=True,
        download_name=f"{assessment['device_name']}_assessment_{assessment_id}.pdf".replace(" ", "_"),
    )


if __name__ == "__main__":
    # debug=True gives auto-reload and detailed error pages — fine for local dev,
    # should be turned off for any real deployment
    # This means: only start the Flask development server if this file is being
    # run directly (python app.py), not if it's being imported by something else.
    app.run(debug=True)
