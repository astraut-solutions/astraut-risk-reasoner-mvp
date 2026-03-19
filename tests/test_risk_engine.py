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


def test_questionnaire_context_can_trigger_no_mfa_signal() -> None:
    assessment = assess_company_risk(
        "12-person company using AWS and Google Workspace",
        questionnaire_context={
            "technical_architecture": {
                "mfa_enforced": "no",
                "public_api": "unknown",
                "network_segmentation": "unknown",
                "logging_monitoring": "unknown",
                "backup_restore_tested": "unknown",
            },
            "maturity": {"incident_response_plan": "unknown"},
        },
    )
    assert any(signal.signal_id == "no_mfa" for signal in assessment.matched_signals)


def test_overall_score_aliases_residual_risk() -> None:
    assessment = assess_company_risk("startup with public api and no mfa")
    assert assessment.overall_score == assessment.residual_risk


def test_inherent_and_residual_formula_consistency() -> None:
    assessment = assess_company_risk(
        "internet-facing startup with public api, no mfa, no segmentation, no logging",
        questionnaire_context={
            "business": {"company_size": "sme", "data_sensitivity": "high"},
            "technical_architecture": {
                "internet_exposed": "yes",
                "public_api": "yes",
                "mfa_enforced": "no",
                "network_segmentation": "no",
                "logging_monitoring": "no",
                "backup_restore_tested": "unknown",
            },
            "compliance": {"regulatory_profile": "regulated"},
            "maturity": {"incident_response_plan": "no", "identity_maturity": "basic"},
        },
    )

    expected_inherent = round(max(0.0, min(100.0, assessment.likelihood * assessment.impact * 100.0)))
    expected_residual = round(
        max(0.0, min(100.0, assessment.inherent_risk * (1.0 - assessment.control_reduction)))
    )

    assert assessment.inherent_risk == expected_inherent
    assert assessment.residual_risk == expected_residual


def test_control_reduction_uses_diminishing_returns_formula() -> None:
    assessment = assess_company_risk(
        "SaaS startup with documented controls",
        questionnaire_context={
            "business": {"company_size": "sme", "data_sensitivity": "medium"},
            "technical_architecture": {
                "internet_exposed": "yes",
                "public_api": "yes",
                "mfa_enforced": "yes",
                "network_segmentation": "yes",
                "logging_monitoring": "yes",
                "backup_restore_tested": "yes",
            },
            "compliance": {"regulatory_profile": "regulated"},
            "maturity": {"incident_response_plan": "yes", "identity_maturity": "advanced"},
        },
    )

    controls = assessment.factor_snapshot["control"]["controls"]
    reduction = 1.0
    for item in controls:
        reduction *= 1.0 - float(item["effective_reduction"])
    expected = round(max(0.0, min(1.0, 1.0 - reduction)), 4)
    assert assessment.control_reduction == expected


def test_sparse_input_still_returns_bounded_dimensions() -> None:
    assessment = assess_company_risk("small team")
    assert 0 <= assessment.overall_score <= 100
    assert 0.0 <= assessment.likelihood <= 1.0
    assert 0.0 <= assessment.impact <= 1.0
    assert 0 <= assessment.inherent_risk <= 100
    assert 0 <= assessment.residual_risk <= 100
    assert 0.0 <= assessment.confidence <= 1.0


def test_contradictory_input_keeps_signal_and_penalizes_control_reduction() -> None:
    contradictory = assess_company_risk(
        "We have no MFA on admin accounts",
        questionnaire_context={
            "technical_architecture": {
                "mfa_enforced": "yes",
                "public_api": "unknown",
                "network_segmentation": "unknown",
                "logging_monitoring": "unknown",
                "backup_restore_tested": "unknown",
            },
            "maturity": {"incident_response_plan": "unknown", "identity_maturity": "advanced"},
        },
    )
    clean = assess_company_risk(
        "We enforce MFA and least privilege",
        questionnaire_context={
            "technical_architecture": {
                "mfa_enforced": "yes",
                "public_api": "unknown",
                "network_segmentation": "unknown",
                "logging_monitoring": "unknown",
                "backup_restore_tested": "unknown",
            },
            "maturity": {"incident_response_plan": "unknown", "identity_maturity": "advanced"},
        },
    )
    assert any(signal.signal_id == "no_mfa" for signal in contradictory.matched_signals)
    assert contradictory.control_reduction < clean.control_reduction


def test_no_controls_has_lower_control_reduction_than_high_controls() -> None:
    no_controls = assess_company_risk(
        "internet-facing SaaS with public API",
        questionnaire_context={
            "technical_architecture": {
                "internet_exposed": "yes",
                "public_api": "yes",
                "mfa_enforced": "no",
                "network_segmentation": "no",
                "logging_monitoring": "no",
                "backup_restore_tested": "no",
            },
            "maturity": {"incident_response_plan": "no"},
        },
    )
    high_controls = assess_company_risk(
        "internet-facing SaaS with public API and mature controls",
        questionnaire_context={
            "technical_architecture": {
                "internet_exposed": "yes",
                "public_api": "yes",
                "mfa_enforced": "yes",
                "network_segmentation": "yes",
                "logging_monitoring": "yes",
                "backup_restore_tested": "yes",
            },
            "maturity": {"incident_response_plan": "yes", "identity_maturity": "advanced"},
        },
    )
    assert no_controls.control_reduction < high_controls.control_reduction


def test_high_controls_with_low_evidence_reduce_less_than_clean_high_controls() -> None:
    low_evidence = assess_company_risk(
        (
            "We claim strong controls but still have no MFA, shared accounts, weak passwords, "
            "no segmentation, no logging, and no tested backups."
        ),
        questionnaire_context={
            "technical_architecture": {
                "internet_exposed": "yes",
                "public_api": "yes",
                "mfa_enforced": "yes",
                "network_segmentation": "yes",
                "logging_monitoring": "yes",
                "backup_restore_tested": "yes",
            },
            "maturity": {"incident_response_plan": "yes", "identity_maturity": "advanced"},
        },
    )
    clean_high_controls = assess_company_risk(
        "Mature SaaS environment with tested controls and no major gaps mentioned.",
        questionnaire_context={
            "technical_architecture": {
                "internet_exposed": "yes",
                "public_api": "yes",
                "mfa_enforced": "yes",
                "network_segmentation": "yes",
                "logging_monitoring": "yes",
                "backup_restore_tested": "yes",
            },
            "maturity": {"incident_response_plan": "yes", "identity_maturity": "advanced"},
        },
    )
    assert low_evidence.control_reduction < clean_high_controls.control_reduction


def test_confidence_degrades_when_questionnaire_is_incomplete() -> None:
    description = "12-person SaaS company on AWS with public API and no MFA on admin accounts"
    full_context = {
        "business": {"company_size": "sme", "data_sensitivity": "high"},
        "technical_architecture": {
            "internet_exposed": "yes",
            "public_api": "yes",
            "mfa_enforced": "no",
            "network_segmentation": "no",
            "logging_monitoring": "no",
            "backup_restore_tested": "no",
        },
        "compliance": {"regulatory_profile": "regulated"},
        "maturity": {"incident_response_plan": "no", "identity_maturity": "basic"},
    }
    sparse_context = {
        "technical_architecture": {
            "internet_exposed": "unknown",
            "public_api": "unknown",
            "mfa_enforced": "unknown",
            "network_segmentation": "unknown",
            "logging_monitoring": "unknown",
            "backup_restore_tested": "unknown",
        },
        "maturity": {"incident_response_plan": "unknown"},
    }

    full = assess_company_risk(description, questionnaire_context=full_context)
    sparse = assess_company_risk(description, questionnaire_context=sparse_context)
    assert sparse.confidence < full.confidence
