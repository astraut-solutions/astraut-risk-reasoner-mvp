from astraut_risk.assessment_formatter import compose_assessment_markdown
from astraut_risk.risk_engine import assess_company_risk


def test_compose_assessment_markdown_includes_risk_dimensions() -> None:
    assessment = assess_company_risk(
        "12-person SaaS company on AWS with public API and no MFA on admin accounts"
    )
    markdown = compose_assessment_markdown(assessment)
    assert "## Risk Dimensions" in markdown
    assert "Likelihood:" in markdown
    assert "Impact:" in markdown
    assert "Inherent Risk:" in markdown
    assert "Residual Risk:" in markdown
    assert "Confidence:" in markdown


def test_compose_assessment_markdown_includes_required_report_sections() -> None:
    assessment = assess_company_risk("Small startup with basic controls")
    markdown = compose_assessment_markdown(assessment)
    assert "## Applicable Standards" in markdown
    assert "## Identified Risks" in markdown
    assert "## Recommendations" in markdown


def test_compose_assessment_markdown_includes_separate_standard_outputs() -> None:
    assessment = assess_company_risk(
        "12-person SaaS company on AWS with public API and no MFA on admin accounts"
    )
    markdown = compose_assessment_markdown(assessment)
    assert "## Standard-Specific Outputs" in markdown
    assert "## CIS Output" in markdown
    assert "## NIST Output" in markdown
    assert "## OWASP Output" in markdown
    assert "## Detailed Risk Register (Full)" in markdown


def test_compose_assessment_markdown_includes_vulnerability_control_mitigation_details() -> None:
    assessment = assess_company_risk(
        "SaaS with public API, no MFA, no segmentation, no logging, and no tested backups"
    )
    markdown = compose_assessment_markdown(assessment)
    assert "Vulnerability:" in markdown
    assert "Missing / weak controls:" in markdown
    assert "Mitigation recommendation:" in markdown
    assert "Cascading Worst-Case Projection:" in markdown
