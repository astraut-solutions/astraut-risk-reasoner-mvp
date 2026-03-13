from typer.testing import CliRunner

from astraut_risk.cli import app

runner = CliRunner()


def test_demo_runs_successfully() -> None:
    result = runner.invoke(app, ["demo"])
    assert result.exit_code == 0
    assert "Demo mode" in result.stdout


def test_checklist_runs_successfully() -> None:
    result = runner.invoke(app, ["checklist"])
    assert result.exit_code == 0
    assert "SME Security Checklist" in result.stdout


def test_matrix_runs_successfully() -> None:
    result = runner.invoke(app, ["matrix"])
    assert result.exit_code == 0
    assert "Cybersecurity Investment Strategy Matrix 2025" in result.stdout


def test_controls_runs_successfully() -> None:
    result = runner.invoke(app, ["controls"])
    assert result.exit_code == 0
    assert "Framework mappings enabled" in result.stdout
    assert "CIS Critical Security Controls" in result.stdout


def test_controls_filtered_by_framework() -> None:
    result = runner.invoke(app, ["controls", "cis"])
    assert result.exit_code == 0
    assert "CIS control mappings" in result.stdout
    assert "no_mfa: 6.3" in result.stdout


def test_explain_runs_successfully() -> None:
    result = runner.invoke(app, ["explain", "mfa"])
    assert result.exit_code == 0
    assert "MFA" in result.stdout


def test_assess_runs_with_mocked_llm(monkeypatch) -> None:
    monkeypatch.setattr("astraut_risk.cli._get_client", lambda: object())
    monkeypatch.setattr(
        "astraut_risk.cli.request_completion",
        lambda client, messages, model, temperature=0.2: "## Overall Risk Score\n7/10",
    )

    result = runner.invoke(app, ["assess", "12-person SaaS company on AWS"])
    assert result.exit_code == 0
    assert "Risk Assessment Result" in result.stdout


def test_assess_invalid_input_fails() -> None:
    result = runner.invoke(app, ["assess", "short"])
    assert result.exit_code == 1
    assert "Invalid Input" in result.stdout


def test_assess_export_markdown_path(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("astraut_risk.cli._get_client", lambda: object())
    monkeypatch.setattr(
        "astraut_risk.cli.request_completion",
        lambda client, messages, model, temperature=0.2: "## Risk Rationale\nok",
    )
    output_path = tmp_path / "report.md"
    result = runner.invoke(
        app,
        [
            "assess",
            "12-person SaaS company on AWS with no MFA on admin accounts",
            "--export",
            str(output_path),
        ],
    )
    assert result.exit_code == 0
    assert output_path.exists()
