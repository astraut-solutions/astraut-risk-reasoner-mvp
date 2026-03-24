import json
from pathlib import Path

from typer.testing import CliRunner

from astraut_risk.cli import app
from astraut_risk.enterprise import (
    build_integration_hook_payload,
    create_governance_trail,
    evaluate_policy_checks,
    policy_gate_status,
    record_governance_decision,
)
from astraut_risk.models import RequirementControl
from astraut_risk.risk_engine import assess_company_risk
from astraut_risk.security_requirements import (
    RequirementsRepository,
    compare_control_versions,
    repository_version_snapshot,
    save_repository_index,
)

runner = CliRunner()


def _repo_with_controls(version: str, controls: list[RequirementControl]) -> RequirementsRepository:
    return RequirementsRepository(
        generated_at="2026-03-23T00:00:00Z",
        source_root="/tmp/requirements",
        documents=[],
        controls=[
            RequirementControl(
                id=item.id,
                category=item.category,
                mapped_layer=item.mapped_layer,
                document_title=item.document_title,
                document_version=version,
                document_path=item.document_path,
                control_text=item.control_text,
                control_text_en=item.control_text_en,
                keywords=item.keywords,
                compliance_tags=item.compliance_tags,
                severity=item.severity,
                risk_weight=item.risk_weight,
            )
            for item in controls
        ],
    )


def test_compare_control_versions_detects_added_removed_and_version_change() -> None:
    base_controls = [
        RequirementControl(
            id="ctrl_1",
            category="Cloud & SaaS",
            mapped_layer="Cloud",
            document_title="Cloud",
            document_version="1.0",
            document_path="/tmp/15_Cloud/cloud.pdf",
            control_text="MFA is required for admin access.",
            control_text_en="MFA is required for admin access.",
            keywords=["iam"],
            compliance_tags=["NIST"],
            severity="high",
            risk_weight=0.9,
        ),
        RequirementControl(
            id="ctrl_2",
            category="Cloud & SaaS",
            mapped_layer="Cloud",
            document_title="Cloud",
            document_version="1.0",
            document_path="/tmp/15_Cloud/cloud.pdf",
            control_text="Log admin actions.",
            control_text_en="Log admin actions.",
            keywords=["logging_monitoring"],
            compliance_tags=["OWASP"],
            severity="medium",
            risk_weight=0.7,
        ),
    ]
    prev = _repo_with_controls("1.0", base_controls)
    curr = _repo_with_controls(
        "2.0",
        [
            base_controls[0],
            RequirementControl(
                id="ctrl_3",
                category="Cloud & SaaS",
                mapped_layer="Cloud",
                document_title="Cloud",
                document_version="2.0",
                document_path="/tmp/15_Cloud/cloud.pdf",
                control_text="Backups must be tested.",
                control_text_en="Backups must be tested.",
                keywords=["backup_recovery"],
                compliance_tags=["ISO 27001"],
                severity="high",
                risk_weight=0.9,
            ),
        ],
    )

    delta = compare_control_versions(prev, curr)
    assert delta["summary"]["added_controls"] == 1
    assert delta["summary"]["removed_controls"] == 1
    assert delta["summary"]["version_changed_controls"] >= 1


def test_repository_version_snapshot_has_stable_fingerprint() -> None:
    controls = [
        RequirementControl(
            id="ctrl_1",
            category="Cloud & SaaS",
            mapped_layer="Cloud",
            document_title="Cloud",
            document_version="1.0",
            document_path="/tmp/15_Cloud/cloud.pdf",
            control_text="MFA is required for admin access.",
            control_text_en="MFA is required for admin access.",
            keywords=["iam"],
            compliance_tags=["NIST"],
            severity="high",
            risk_weight=0.9,
        )
    ]
    repo = _repo_with_controls("1.0", controls)
    snap_a = repository_version_snapshot(repo)
    snap_b = repository_version_snapshot(repo)
    assert snap_a["control_fingerprint"] == snap_b["control_fingerprint"]


def test_policy_check_and_hook_payload_flow() -> None:
    questionnaire = {
        "business": {"data_sensitivity": "high"},
        "technical_architecture": {
            "public_api": "yes",
            "mfa_enforced": "no",
            "logging_monitoring": "no",
            "backup_restore_tested": "no",
        },
    }
    assessment = assess_company_risk(
        "SaaS startup with public api and no mfa",
        questionnaire_context=questionnaire,
    )
    results = evaluate_policy_checks(assessment, questionnaire)
    assert any(item.status == "fail" for item in results)
    assert policy_gate_status(results) == "fail"

    payload = build_integration_hook_payload("policy_check.completed", assessment, results)
    assert payload["policy"]["gate_status"] == "fail"
    assert payload["assessment"]["residual_risk"] == assessment.residual_risk


def test_custom_policy_pack_evaluates_external_rules(tmp_path: Path) -> None:
    pack = tmp_path / "pack.yaml"
    pack.write_text(
        (
            "name: custom-enterprise-pack\n"
            "rules:\n"
            "  - id: CUST-001\n"
            "    title: Residual Risk Must Be <= 60\n"
            "    severity: high\n"
            "    rationale_pass: Residual risk is within threshold.\n"
            "    rationale_fail: Residual risk exceeds threshold.\n"
            "    conditions:\n"
            "      - path: assessment.residual_risk\n"
            "        op: lte\n"
            "        value: 60\n"
            "  - id: CUST-002\n"
            "    title: Signal should include public API\n"
            "    severity: medium\n"
            "    conditions:\n"
            "      - path: signals\n"
            "        op: contains\n"
            "        value: public_api\n"
        ),
        encoding="utf-8",
    )
    assessment = assess_company_risk("SaaS startup with public api and no mfa")
    results = evaluate_policy_checks(
        assessment,
        questionnaire={},
        policy_pack_path=str(pack),
        include_default=False,
    )
    by_id = {item.policy_id: item for item in results}
    assert "CUST-001" in by_id
    assert "CUST-002" in by_id
    assert by_id["CUST-002"].status == "pass"


def test_governance_trail_moves_to_approved_after_all_approvers() -> None:
    trail = create_governance_trail(
        requested_by="alice",
        approvers=["bob", "carol"],
        assessment_ref="cache_abc",
        risk_level="High",
        residual_risk=62,
        policy_gate="fail",
    )
    assert trail.status == "pending"

    updated = record_governance_decision(trail, actor="bob", decision="approve")
    assert updated.status == "pending"

    updated = record_governance_decision(updated, actor="carol", decision="approve")
    assert updated.status == "approved"


def test_governance_trail_cannot_be_modified_after_terminal_state() -> None:
    trail = create_governance_trail(
        requested_by="alice",
        approvers=["bob"],
        assessment_ref="cache_abc",
        risk_level="High",
        residual_risk=62,
        policy_gate="fail",
    )
    updated = record_governance_decision(trail, actor="bob", decision="approve")
    assert updated.status == "approved"
    try:
        record_governance_decision(updated, actor="bob", decision="reject")
        assert False, "expected ValueError for finalized trail mutation"
    except ValueError as exc:
        assert "finalized" in str(exc)


def test_control_delta_cli_exports_json(tmp_path: Path) -> None:
    old_repo = RequirementsRepository(
        generated_at="2026-03-23T00:00:00Z",
        source_root=str(tmp_path),
        documents=[],
        controls=[
            RequirementControl(
                id="ctrl_old",
                category="Cloud",
                mapped_layer="Cloud",
                document_title="Old",
                document_version="1.0",
                document_path="/tmp/15_Cloud/cloud.pdf",
                control_text="MFA required",
                control_text_en="MFA required",
                keywords=["iam"],
                severity="high",
                risk_weight=0.9,
            )
        ],
    )
    new_repo = RequirementsRepository(
        generated_at="2026-03-24T00:00:00Z",
        source_root=str(tmp_path),
        documents=[],
        controls=[
            RequirementControl(
                id="ctrl_new",
                category="Cloud",
                mapped_layer="Cloud",
                document_title="New",
                document_version="2.0",
                document_path="/tmp/15_Cloud/cloud.pdf",
                control_text="MFA required and logged",
                control_text_en="MFA required and logged",
                keywords=["iam", "logging_monitoring"],
                severity="high",
                risk_weight=0.95,
            )
        ],
    )

    old_index = tmp_path / "old.json"
    new_index = tmp_path / "new.json"
    output = tmp_path / "delta.json"
    save_repository_index(old_repo, str(old_index))
    save_repository_index(new_repo, str(new_index))

    result = runner.invoke(
        app,
        ["control-delta", str(old_index), str(new_index), "--output", str(output)],
    )
    assert result.exit_code == 0
    assert output.exists()
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert "summary" in payload


def test_policy_check_cli_with_custom_pack(tmp_path: Path) -> None:
    pack = tmp_path / "pack.yaml"
    pack.write_text(
        (
            "rules:\n"
            "  - id: CLI-001\n"
            "    title: Confidence must be <= 1\n"
            "    severity: low\n"
            "    conditions:\n"
            "      - path: assessment.confidence\n"
            "        op: lte\n"
            "        value: 1\n"
        ),
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        [
            "policy-check",
            "12-person SaaS startup on AWS with public API and no MFA on admin accounts",
            "--policy-pack",
            str(pack),
            "--no-default-policies",
        ],
    )
    assert result.exit_code == 0
    assert "CLI-001" in result.stdout


def test_custom_policy_pack_yaml_yes_boolean_matches_questionnaire_yes(tmp_path: Path) -> None:
    pack = tmp_path / "pack.yaml"
    pack.write_text(
        (
            "rules:\n"
            "  - id: BOOL-YES-001\n"
            "    title: MFA must be yes\n"
            "    severity: high\n"
            "    conditions:\n"
            "      - path: questionnaire.technical_architecture.mfa_enforced\n"
            "        op: equals\n"
            "        value: yes\n"
        ),
        encoding="utf-8",
    )
    assessment = assess_company_risk(
        "SaaS startup with public api",
        questionnaire_context={"technical_architecture": {"mfa_enforced": "yes"}},
    )
    results = evaluate_policy_checks(
        assessment,
        questionnaire={"technical_architecture": {"mfa_enforced": "yes"}},
        policy_pack_path=str(pack),
        include_default=False,
    )
    assert len(results) == 1
    assert results[0].policy_id == "BOOL-YES-001"
    assert results[0].status == "pass"


def test_governance_list_status_filter(tmp_path: Path) -> None:
    trails_file = tmp_path / "governance_trails.jsonl"
    assessment_payload = {
        "cache_key": "abc",
        "deterministic": {"risk_level": "Low", "residual_risk": 10},
    }
    (tmp_path / "assessment.json").write_text(
        json.dumps(assessment_payload),
        encoding="utf-8",
    )
    submit_one = runner.invoke(
        app,
        [
            "governance-submit",
            str(tmp_path / "assessment.json"),
            "--requested-by",
            "alice",
            "--approver",
            "bob",
            "--trail-file",
            str(trails_file),
        ],
    )
    assert submit_one.exit_code == 0

    trails = [json.loads(line) for line in trails_file.read_text(encoding="utf-8").splitlines() if line]
    trail_id = trails[-1]["trail_id"]
    approve = runner.invoke(
        app,
        [
            "governance-approve",
            trail_id,
            "--actor",
            "bob",
            "--decision",
            "approve",
            "--trail-file",
            str(trails_file),
        ],
    )
    assert approve.exit_code == 0

    filtered = runner.invoke(
        app,
        ["governance-list", "--status", "approved", "--trail-file", str(trails_file)],
    )
    assert filtered.exit_code == 0
    assert "approved" in filtered.stdout.lower()


def test_governance_approve_rejects_finalized_trail(tmp_path: Path) -> None:
    trails_file = tmp_path / "governance_trails.jsonl"
    assessment_payload = {
        "cache_key": "abc",
        "deterministic": {"risk_level": "Low", "residual_risk": 10},
    }
    assessment_path = tmp_path / "assessment.json"
    assessment_path.write_text(json.dumps(assessment_payload), encoding="utf-8")

    submit = runner.invoke(
        app,
        [
            "governance-submit",
            str(assessment_path),
            "--requested-by",
            "alice",
            "--approver",
            "bob",
            "--trail-file",
            str(trails_file),
        ],
    )
    assert submit.exit_code == 0
    trails = [json.loads(line) for line in trails_file.read_text(encoding="utf-8").splitlines() if line]
    trail_id = trails[-1]["trail_id"]

    approve = runner.invoke(
        app,
        [
            "governance-approve",
            trail_id,
            "--actor",
            "bob",
            "--decision",
            "approve",
            "--trail-file",
            str(trails_file),
        ],
    )
    assert approve.exit_code == 0

    mutate = runner.invoke(
        app,
        [
            "governance-approve",
            trail_id,
            "--actor",
            "bob",
            "--decision",
            "reject",
            "--trail-file",
            str(trails_file),
        ],
    )
    assert mutate.exit_code == 1
    assert "finalized" in mutate.stdout.lower()
