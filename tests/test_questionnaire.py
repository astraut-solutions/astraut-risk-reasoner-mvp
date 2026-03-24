from astraut_risk.questionnaire import (
    high_impact_missing_fields,
    infer_questionnaire_from_text,
    merge_questionnaire,
    normalize_questionnaire_mode,
    questionnaire_override_from_template_answers,
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


def test_normalize_questionnaire_mode_accepts_full_detailed_alias() -> None:
    assert normalize_questionnaire_mode("Full Detailed") == "detailed"
    assert normalize_questionnaire_mode("general") == "general"
    assert normalize_questionnaire_mode("unknown-mode") == "medium"


def test_questionnaire_override_from_general_answers_maps_core_fields() -> None:
    override = questionnaire_override_from_template_answers(
        "general",
        {
            "Business Profile": "Cloud/SaaS",
            "Core Exposure": "Yes",
            "Critical Data": "No",
        },
    )
    assert override["technical_architecture"]["internet_exposed"] == "yes"
    assert override["technical_architecture"]["public_api"] == "yes"
    assert override["business"]["data_sensitivity"] == "low"
    assert override["compliance"]["regulatory_profile"] == "unregulated"


def test_questionnaire_override_from_medium_answers_maps_operational_controls() -> None:
    override = questionnaire_override_from_template_answers(
        "medium",
        {
            "Architecture": ["Web app", "API", "Database"],
            "Access Security": "Not enforced",
            "Network Security": "Partially",
            "Detection": "Not implemented",
            "Resilience": "Never",
        },
    )
    assert override["technical_architecture"]["internet_exposed"] == "yes"
    assert override["technical_architecture"]["public_api"] == "yes"
    assert override["technical_architecture"]["mfa_enforced"] == "no"
    assert override["technical_architecture"]["network_segmentation"] == "unknown"
    assert override["technical_architecture"]["logging_monitoring"] == "no"
    assert override["technical_architecture"]["backup_restore_tested"] == "no"


def test_questionnaire_override_from_detailed_answers_maps_controls() -> None:
    override = questionnaire_override_from_template_answers(
        "detailed",
        {
            "Cloud & IAM": ["MFA", "Least privilege/RBAC"],
            "Infrastructure": ["Segmented network"],
            "Application Security": ["API gateway controls"],
            "Operations": ["IR playbooks", "Centralized SIEM"],
            "Compliance": ["ISO 27001"],
            "Data Security": ["Encryption at rest"],
        },
    )
    assert override["technical_architecture"]["mfa_enforced"] == "yes"
    assert override["maturity"]["identity_maturity"] == "advanced"
    assert override["technical_architecture"]["network_segmentation"] == "yes"
    assert override["technical_architecture"]["public_api"] == "yes"
    assert override["technical_architecture"]["internet_exposed"] == "yes"
    assert override["technical_architecture"]["logging_monitoring"] == "yes"
    assert override["maturity"]["incident_response_plan"] == "yes"
    assert override["compliance"]["regulatory_profile"] == "regulated"
    assert override["business"]["data_sensitivity"] == "medium"


def test_questionnaire_none_option_maps_as_explicit_feedback() -> None:
    override = questionnaire_override_from_template_answers(
        "medium",
        {
            "Architecture": ["None"],
            "Access Security": "None",
            "Network Security": "None",
            "Detection": "None",
            "Resilience": "None",
        },
    )
    assert override["technical_architecture"]["internet_exposed"] == "unknown"
    assert override["technical_architecture"]["public_api"] == "unknown"
    assert override["technical_architecture"]["mfa_enforced"] == "no"
    assert override["technical_architecture"]["network_segmentation"] == "no"
    assert override["technical_architecture"]["logging_monitoring"] == "no"
    assert override["technical_architecture"]["backup_restore_tested"] == "no"
