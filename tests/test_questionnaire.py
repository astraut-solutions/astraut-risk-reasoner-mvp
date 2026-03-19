from astraut_risk.questionnaire import (
    high_impact_missing_fields,
    infer_questionnaire_from_text,
    merge_questionnaire,
)


def test_infer_questionnaire_from_text_detects_key_signals() -> None:
    questionnaire = infer_questionnaire_from_text(
        "12-person SaaS startup with a public API and no MFA on admin accounts"
    )
    assert questionnaire["technical_architecture"]["public_api"] == "yes"
    assert questionnaire["technical_architecture"]["mfa_enforced"] == "no"
    assert questionnaire["technical_architecture"]["internet_exposed"] == "yes"


def test_merge_questionnaire_overrides_inferred_values() -> None:
    inferred = infer_questionnaire_from_text("company with public API")
    merged = merge_questionnaire(
        inferred,
        {
            "technical_architecture": {
                "public_api": "no",
            },
        },
    )
    assert merged["technical_architecture"]["public_api"] == "no"


def test_high_impact_missing_fields_reports_unknown_values() -> None:
    questionnaire = {
        "technical_architecture": {
            "public_api": "unknown",
            "mfa_enforced": "yes",
            "network_segmentation": "unknown",
            "logging_monitoring": "unknown",
            "backup_restore_tested": "yes",
        },
        "maturity": {
            "incident_response_plan": "unknown",
        },
    }
    missing = high_impact_missing_fields(questionnaire)
    assert ("technical_architecture", "public_api") in missing
    assert ("maturity", "incident_response_plan") in missing
