from typer.testing import CliRunner

from astraut_risk.cli import app
from astraut_risk.risk_engine import assess_company_risk


runner = CliRunner()


def test_no_mfa_increases_score() -> None:
    baseline = assess_company_risk("12-person company on AWS with tested backups and MFA enabled")
    exposed = assess_company_risk("12-person company on AWS with no MFA on admin accounts")
    assert exposed.overall_score > baseline.overall_score
    assert any(signal.signal_id == "no_mfa" for signal in exposed.matched_signals)


def test_public_api_increases_score() -> None:
    baseline = assess_company_risk("SME with private internal app and MFA enabled")
    public_api = assess_company_risk("SME with a public API and no rate limiting")
    assert public_api.overall_score > baseline.overall_score
    assert any(signal.signal_id == "public_api" for signal in public_api.matched_signals)


def test_framework_mapping_present_for_no_mfa() -> None:
    assessment = assess_company_risk("Company with no MFA on admin accounts")
    refs = assessment.framework_references.get("no_mfa", [])
    assert refs
    assert any(ref.framework == "CIS" and ref.control_id == "6.3" for ref in refs)
    assert any(ref.framework == "NIST" and ref.control_id == "PR.AC-7" for ref in refs)


def test_tested_backups_avoids_resilience_penalty() -> None:
    with_penalty = assess_company_risk("Backups are not tested and we have no incident plan")
    without_penalty = assess_company_risk("We run tested backups and have an incident plan")
    assert with_penalty.overall_score > without_penalty.overall_score
    assert all(
        signal.signal_id != "no_tested_backups" for signal in without_penalty.matched_signals
    )


def test_score_within_expected_bounds() -> None:
    assessment = assess_company_risk(
        "We have no MFA, shared accounts, weak passwords, no logging, no alerting, "
        "public API, no tested backups, and no incident plan"
    )
    assert 0 <= assessment.overall_score <= 100


def test_saas_profile_without_control_details_gets_baseline_signal() -> None:
    assessment = assess_company_risk(
        "We are a 12-person SaaS startup using AWS, Gmail, Stripe and GitHub"
    )
    assert assessment.overall_score > 0
    assert any(
        signal.signal_id == "internet_facing_saas" for signal in assessment.matched_signals
    )


def test_inspect_command_works() -> None:
    result = runner.invoke(app, ["inspect", "12-person SaaS startup with no MFA and public API"])
    assert result.exit_code == 0
    assert "Deterministic Risk Signals" in result.stdout
    assert "Calculated total score" in result.stdout
