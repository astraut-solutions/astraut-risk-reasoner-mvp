from typer.testing import CliRunner

from astraut_risk.cli import app
from astraut_risk.models import RequirementControl
from astraut_risk.risk_engine import assess_company_risk
from astraut_risk.security_requirements import RequirementsRepository, save_repository_index


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
    residual_adjustments = assessment.factor_snapshot.get("residual_adjustments", {})
    uncertainty_multiplier = float(
        residual_adjustments.get("uncertainty_multiplier", 1.0)
        if isinstance(residual_adjustments, dict)
        else 1.0
    )
    expected_residual = round(
        max(
            0.0,
            min(
                100.0,
                assessment.inherent_risk
                * (1.0 - assessment.control_reduction)
                * uncertainty_multiplier,
            ),
        )
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
    assert isinstance(assessment.runtime_category_layers, list)
    assert isinstance(assessment.explainability_payload, dict)
    assert "scoring" in assessment.explainability_payload


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


def test_assessment_with_requirements_root_handles_missing_repo(tmp_path) -> None:
    assessment = assess_company_risk(
        "SaaS startup with public API and IAM",
        questionnaire_context={
            "technical_architecture": {
                "internet_exposed": "yes",
                "public_api": "yes",
                "mfa_enforced": "no",
                "network_segmentation": "unknown",
                "logging_monitoring": "unknown",
                "backup_restore_tested": "unknown",
            },
            "maturity": {"incident_response_plan": "unknown"},
        },
        requirements_root=str(tmp_path / "missing"),
    )
    assert assessment.detected_security_domains
    assert assessment.control_coverage_percent == 0.0


def test_assessment_with_requirements_index_retrieves_controls(tmp_path) -> None:
    repository = RequirementsRepository(
        generated_at="2026-03-23T00:00:00Z",
        source_root=str(tmp_path),
        documents=[],
        controls=[
            RequirementControl(
                id="ctrl_cloud_1",
                category="Cloud & SaaS",
                mapped_layer="Cloud",
                document_title="Cloud Controls",
                document_version="1.0",
                document_path="/tmp/15_Cloud/cloud.pdf",
                control_text="Cloud IAM must enforce MFA for privileged users.",
                control_text_en="Cloud IAM must enforce MFA for privileged users.",
                keywords=["cloud_security", "iam"],
                severity="high",
                risk_weight=0.95,
            )
        ],
    )
    index = tmp_path / "requirements_index.json"
    save_repository_index(repository, str(index))

    assessment = assess_company_risk(
        "SaaS startup on AWS with IAM and public API",
        questionnaire_context={
            "business": {"data_sensitivity": "high"},
            "technical_architecture": {"internet_exposed": "yes", "public_api": "yes"},
            "maturity": {"incident_response_plan": "no"},
        },
        requirements_index=str(index),
    )
    assert assessment.mapped_requirements
    assert assessment.identified_requirement_risks
    assert assessment.control_coverage_percent > 0.0
    assert "requirements_retrieval" in assessment.factor_snapshot
    assert assessment.factor_snapshot["requirements_retrieval"]["top_score"] > 0.0
    assert assessment.mapped_requirements[0].retrieval_reason
    assert assessment.runtime_category_layers
    assert assessment.factor_snapshot["requirements_scoring_weights"]["normalization_multiplier"] > 0.0
