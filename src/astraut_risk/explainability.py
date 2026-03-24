"""Explainability payload generator for deterministic risk assessments."""

from __future__ import annotations

from .models import RiskAssessment


def build_explainability_payload(assessment: RiskAssessment) -> dict[str, object]:
    """Build a stable explainability payload for reports, APIs, and UI layers."""
    scoring = {
        "overall_score": assessment.overall_score,
        "risk_level": assessment.risk_level,
        "likelihood": assessment.likelihood,
        "impact": assessment.impact,
        "inherent_risk": assessment.inherent_risk,
        "control_reduction": assessment.control_reduction,
        "residual_risk": assessment.residual_risk,
        "confidence": assessment.confidence,
        "factors": assessment.factor_snapshot,
    }

    top_signal_paths = [
        {
            "signal_id": signal.signal_id,
            "label": signal.label,
            "category": signal.category,
            "weight": signal.weight,
            "matched_phrases": signal.matched_phrases,
            "why_it_matters": signal.why_it_matters,
            "framework_refs": [
                {
                    "framework": ref.framework,
                    "control_id": ref.control_id,
                    "title": ref.title,
                    "description": ref.description,
                }
                for ref in signal.framework_refs
            ],
        }
        for signal in assessment.matched_signals
    ]

    requirement_trace = [
        {
            "risk_id": risk.id,
            "risk": risk.risk,
            "why": risk.why,
            "impact": risk.impact,
            "severity": risk.severity,
            "score": risk.score,
            "source_document": risk.source_document,
            "reference_control": risk.reference_control,
            "mapped_layer": risk.mapped_layer,
            "compliance_tags": risk.compliance_tags,
        }
        for risk in assessment.identified_requirement_risks
    ]

    return {
        "summary": {
            "top_risks": assessment.top_risks,
            "control_gaps": assessment.control_gaps,
            "detected_security_domains": assessment.detected_security_domains,
            "control_coverage_percent": assessment.control_coverage_percent,
            "applicable_standards": assessment.applicable_standards,
        },
        "runtime_category_layers": assessment.runtime_category_layers,
        "scoring": scoring,
        "signal_contribution_paths": top_signal_paths,
        "requirement_risk_trace": requirement_trace,
        "recommendations": [
            {
                "signal_id": rec.signal_id,
                "category": rec.category,
                "recommendation": rec.recommendation,
                "first_action": rec.first_action,
                "seven_day_action": rec.seven_day_action,
            }
            for rec in assessment.recommendations
        ],
    }
