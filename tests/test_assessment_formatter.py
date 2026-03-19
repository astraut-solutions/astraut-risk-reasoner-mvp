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
