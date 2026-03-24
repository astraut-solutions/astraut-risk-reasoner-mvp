from astraut_risk.models import RequirementControl
from astraut_risk.questionnaire import questionnaire_templates
from astraut_risk.security_requirements import (
    derive_requirement_risks,
    infer_stack_components,
    load_repository_index,
    match_controls_for_components,
    retrieve_controls_baseline,
    save_repository_index,
    RequirementsRepository,
    translate_german_terms,
    _extract_controls,
)


def test_translate_german_terms_replaces_known_security_words() -> None:
    text = "Allgemeine Sicherheitsanforderungen: Kryptographische Algorithmen muss angewendet werden."
    translated = translate_german_terms(text)
    assert "general" in translated.lower()
    assert "security requirements" in translated.lower()
    assert "cryptographic" in translated.lower()


def test_questionnaire_templates_returns_three_modes() -> None:
    templates = questionnaire_templates()
    assert set(templates.keys()) == {"general", "medium", "detailed"}
    assert len(templates["general"]) < len(templates["detailed"])
    for mode_items in templates.values():
        for item in mode_items:
            options = [str(option).lower() for option in item.get("options", [])]
            assert "none" in options


def test_match_controls_for_components_filters_by_taxonomy_prefix() -> None:
    controls = [
        RequirementControl(
            id="ctrl_1",
            category="Cloud & SaaS",
            mapped_layer="Cloud",
            document_title="Cloud Control",
            document_version="1.0",
            document_path="/tmp/15_Cloud/cloud.pdf",
            control_text="Control text",
            control_text_en="Control text",
            keywords=["cloud_security"],
        ),
        RequirementControl(
            id="ctrl_2",
            category="Databases",
            mapped_layer="Data layer",
            document_title="DB Control",
            document_version="1.0",
            document_path="/tmp/05_Datenbanken/db.pdf",
            control_text="Control text",
            control_text_en="Control text",
            keywords=["database_security"],
        ),
    ]
    matched = match_controls_for_components(controls, {"aws"})
    assert len(matched) == 1
    assert matched[0].id == "ctrl_1"


def test_derive_requirement_risks_formula_responds_to_profile_factors() -> None:
    controls = [
        RequirementControl(
            id="ctrl_1",
            category="General Requirements",
            mapped_layer="Global policies",
            document_title="Identity Policy",
            document_version="8.0",
            document_path="/tmp/01_Allgemeine_Anforderungen/a.pdf",
            control_text="MFA must be enabled for privileged users.",
            control_text_en="MFA must be enabled for privileged users.",
            keywords=["iam"],
            severity="high",
            risk_weight=0.9,
        )
    ]
    risks, total = derive_requirement_risks(
        controls,
        questionnaire={
            "business": {"data_sensitivity": "high"},
            "technical_architecture": {"internet_exposed": "yes", "public_api": "yes"},
            "maturity": {"incident_response_plan": "no"},
        },
    )
    assert risks
    assert risks[0].score > 1.0
    assert total > 0.0


def test_derive_requirement_risks_honors_runtime_scoring_config() -> None:
    controls = [
        RequirementControl(
            id="ctrl_cfg",
            category="General Requirements",
            mapped_layer="Global policies",
            document_title="Identity Policy",
            document_version="8.0",
            document_path="/tmp/01_Allgemeine_Anforderungen/a.pdf",
            control_text="MFA must be enabled for privileged users.",
            control_text_en="MFA must be enabled for privileged users.",
            keywords=["iam"],
            severity="high",
            risk_weight=0.9,
        )
    ]
    _, baseline_total = derive_requirement_risks(
        controls,
        questionnaire={
            "business": {"data_sensitivity": "high"},
            "technical_architecture": {"internet_exposed": "yes", "public_api": "yes"},
            "maturity": {"incident_response_plan": "no"},
        },
    )
    _, tuned_total = derive_requirement_risks(
        controls,
        questionnaire={
            "business": {"data_sensitivity": "high"},
            "technical_architecture": {"internet_exposed": "yes", "public_api": "yes"},
            "maturity": {"incident_response_plan": "no"},
        },
        scoring_config={
            "control_risk_weight": 1.2,
            "data_sensitivity_weight": 1.1,
            "normalization_multiplier": 4.0,
        },
    )
    assert tuned_total > baseline_total


def test_infer_stack_components_detects_aws_and_postgres() -> None:
    components = infer_stack_components(
        "We use AWS with PostgreSQL and a public web API with IAM roles."
    )
    assert "aws" in components
    assert "postgresql" in components
    assert "api" in components
    assert "iam" in components


def test_metadata_store_roundtrip_loads_controls(tmp_path) -> None:
    repo = RequirementsRepository(
        generated_at="2026-03-23T00:00:00Z",
        source_root=str(tmp_path),
        documents=[],
        controls=[
            RequirementControl(
                id="ctrl_a",
                category="Cloud & SaaS",
                mapped_layer="Cloud",
                document_title="Cloud Policy",
                document_version="1.0",
                document_path="/tmp/15_Cloud/policy.pdf",
                control_text="Cloud access must be restricted.",
                control_text_en="Cloud access must be restricted.",
                keywords=["cloud_security", "iam"],
                severity="high",
                risk_weight=0.91,
            )
        ],
    )
    index = tmp_path / "index.json"
    save_repository_index(repo, str(index))
    loaded = load_repository_index(str(index))
    assert len(loaded.controls) == 1
    assert loaded.controls[0].id == "ctrl_a"
    assert loaded.controls[0].severity == "high"


def test_retrieve_controls_baseline_prioritizes_component_and_keyword_match() -> None:
    controls = [
        RequirementControl(
            id="ctrl_cloud",
            category="Cloud & SaaS",
            mapped_layer="Cloud",
            document_title="Cloud",
            document_version="1.0",
            document_path="/tmp/15_Cloud/cloud.pdf",
            control_text="Cloud IAM policy",
            control_text_en="Cloud IAM policy must enforce least privilege.",
            keywords=["cloud_security", "iam"],
            severity="high",
            risk_weight=0.9,
        ),
        RequirementControl(
            id="ctrl_db",
            category="Databases",
            mapped_layer="Data layer",
            document_title="Database",
            document_version="1.0",
            document_path="/tmp/05_Datenbanken/db.pdf",
            control_text="Database backups",
            control_text_en="Database backups should be tested.",
            keywords=["database_security", "backup_recovery"],
            severity="medium",
            risk_weight=0.7,
        ),
    ]
    retrieved = retrieve_controls_baseline(
        controls,
        query="AWS cloud IAM with least privilege",
        components={"aws", "iam"},
        limit=2,
    )
    assert len(retrieved) == 1
    assert retrieved[0].id == "ctrl_cloud"
    assert retrieved[0].retrieval_rank == 1
    assert retrieved[0].retrieval_score > 0.0
    assert retrieved[0].retrieval_reason
    assert "vector" in retrieved[0].retrieval_breakdown


def test_extract_controls_enriches_framework_refs_from_keywords() -> None:
    controls = _extract_controls(
        document_id="doc_test",
        category="General Requirements",
        layer="Global policies",
        title="Security Baseline",
        version="1.0",
        source_path="/tmp/01_Allgemeine_Anforderungen/base.pdf",
        text="1. MFA must be enabled for admin users.\n2. Logging and monitoring must be centralized.",
    )
    assert controls
    refs = [ref for control in controls for ref in control.framework_refs]
    assert any(ref.framework == "NIST" for ref in refs)
    assert any(ref.framework == "OWASP" for ref in refs)
    assert any("NIST" in control.compliance_tags for control in controls)
