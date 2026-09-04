"""
Automated tests for the scoring engine.

Run with: pytest tests/ -v

These exist to give repeatable, citable evidence that the scoring logic
behaves correctly — useful for an evaluation/methodology chapter, and a
safety net against regressions when the scoring rules change.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.scoring import (
    cvss_to_severity,
    calculate_score,
    calculate_cve_penalty,
    calculate_exploitation_penalty,
    get_risk_level,
    get_compliance_status,
    get_recommendations,
)


class TestCvssToSeverity:
    def test_critical_band(self):
        assert cvss_to_severity(9.8) == "Critical"
        assert cvss_to_severity(9.0) == "Critical"

    def test_high_band(self):
        assert cvss_to_severity(8.9) == "High"
        assert cvss_to_severity(7.0) == "High"

    def test_medium_band(self):
        assert cvss_to_severity(6.9) == "Medium"
        assert cvss_to_severity(4.0) == "Medium"

    def test_low_band(self):
        assert cvss_to_severity(3.9) == "Low"
        assert cvss_to_severity(0.1) == "Low"

    def test_none_is_unknown(self):
        assert cvss_to_severity(None) == "Unknown"

    def test_invalid_input_is_unknown(self):
        assert cvss_to_severity("not-a-number") == "Unknown"


class TestCalculateScore:
    def test_all_yes_is_100(self):
        assert calculate_score("yes", "yes", "yes", "yes") == 100

    def test_all_no_is_0(self):
        assert calculate_score("no", "no", "no", "no") == 0

    def test_two_yes_is_50(self):
        assert calculate_score("yes", "yes", "no", "no") == 50

    def test_case_insensitive(self):
        assert calculate_score("Yes", "YES", "yes", "no") == 75


class TestCalculateCvePenalty:
    def test_no_vulnerabilities_no_penalty(self):
        assert calculate_cve_penalty([]) == 0

    def test_single_high_severity(self):
        vulns = [{"severity": "High"}]
        assert calculate_cve_penalty(vulns) == 10

    def test_penalty_is_capped(self):
        """20 Critical CVEs would be 20*15=300 uncapped — must not exceed MAX_CVE_PENALTY."""
        from config import MAX_CVE_PENALTY
        vulns = [{"severity": "Critical"}] * 20
        assert calculate_cve_penalty(vulns) == MAX_CVE_PENALTY

    def test_mixed_severities(self):
        vulns = [{"severity": "Critical"}, {"severity": "Low"}]
        assert calculate_cve_penalty(vulns) == 15 + 2


class TestCalculateExploitationPenalty:
    def test_no_exploited_cves(self):
        assert calculate_exploitation_penalty([]) == 0

    def test_single_exploited_cve(self):
        assert calculate_exploitation_penalty(["CVE-2021-1234"]) == 20

    def test_penalty_is_capped(self):
        from config import MAX_EXPLOITATION_PENALTY
        exploited = [f"CVE-2021-{i}" for i in range(10)]
        assert calculate_exploitation_penalty(exploited) == MAX_EXPLOITATION_PENALTY


class TestGetRiskLevel:
    def test_low_risk_boundary(self):
        assert get_risk_level(75) == "Low Risk"
        assert get_risk_level(100) == "Low Risk"

    def test_medium_risk_boundary(self):
        assert get_risk_level(50) == "Medium Risk"
        assert get_risk_level(74) == "Medium Risk"

    def test_high_risk_boundary(self):
        assert get_risk_level(25) == "High Risk"
        assert get_risk_level(49) == "High Risk"

    def test_critical_risk_boundary(self):
        assert get_risk_level(0) == "Critical Risk"
        assert get_risk_level(24) == "Critical Risk"


class TestGetComplianceStatus:
    def test_compliant_at_threshold(self):
        assert get_compliance_status(70) == "Compliant"

    def test_non_compliant_below_threshold(self):
        assert get_compliance_status(69) == "Non-Compliant"


class TestGetRecommendations:
    def test_all_yes_no_cves_gives_clean_message(self):
        """A device with perfect questionnaire answers AND no CVEs should
        get an all-clear message — not a contradictory 'gaps found'."""
        recs = get_recommendations("yes", "yes", "yes", "yes")
        assert len(recs) == 1
        assert "no control gaps" in recs[0].lower()

    def test_all_yes_but_exploited_cve_flags_urgent(self):
        """Regression test for the exact bug found during manual testing:
        a 100/100 base-score device with a real actively-exploited CVE
        must NOT say 'no gaps found' — it must surface the urgent risk."""
        recs = get_recommendations(
            "yes", "yes", "yes", "yes",
            vulnerabilities=[{"severity": "High"}],
            exploited_cves=["CVE-2011-4723"],
        )
        joined = " ".join(recs).lower()
        assert "urgent" in joined
        assert "cve-2011-4723" in joined
        assert "no control gaps" not in joined

    def test_all_no_flags_all_four_controls(self):
        recs = get_recommendations("no", "no", "no", "no")
        assert len(recs) == 4

    def test_critical_high_cves_are_flagged_even_without_kev_match(self):
        recs = get_recommendations(
            "yes", "yes", "yes", "yes",
            vulnerabilities=[{"severity": "Critical"}, {"severity": "High"}],
            exploited_cves=[],
        )
        joined = " ".join(recs).lower()
        assert "critical/high severity cve" in joined
