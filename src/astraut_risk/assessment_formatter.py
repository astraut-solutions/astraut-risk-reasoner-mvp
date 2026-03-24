"""Shared formatting for deterministic + LLM-assisted assessment outputs."""

from __future__ import annotations

import re

from .control_map import CONTROL_MAP
from .models import RiskAssessment

_METHOD_SECTION = (
    "## Method\n"
    "- Baseline score generated from deterministic factors and control evidence quality.\n"
    "- Inherent risk: `Likelihood x Impact x 100`.\n"
    "- Unknown questionnaire values are treated pessimistically (worst-case) until confirmed.\n"
    "- Residual risk: `Inherent x (1 - ControlReduction)` with an uncertainty multiplier for missing questionnaire evidence.\n"
    "- Recommendations expanded using LLM reasoning.\n"
    "- Built for guidance, not formal audit use.\n"
)

_REQUIRED_REPORT_SECTIONS = (
    "Identified Risks",
    "Recommendations",
)


def _severity_from_signal_weight(weight: int) -> str:
    if weight >= 14:
        return "high"
    if weight >= 10:
        return "medium"
    return "low"


def _associated_risks_for_category(category: str) -> str:
    normalized = category.lower()
    if "identity" in normalized:
        return "account takeover, privilege abuse, unauthorized data access"
    if "infrastructure" in normalized or "cloud" in normalized:
        return "external exploitation, lateral movement, service disruption"
    if "backup" in normalized or "resilience" in normalized:
        return "ransomware recovery failure, prolonged outage, data loss"
    if "monitoring" in normalized or "detection" in normalized:
        return "late breach detection, forensic blind spots, delayed containment"
    if "supply chain" in normalized or "software" in normalized:
        return "known CVE exploitation, malicious dependency risk, release compromise"
    return "control failure amplification, compliance exposure, business interruption"


def _worst_case_projection(assessment: RiskAssessment) -> int:
    signal_weight_total = sum(signal.weight for signal in assessment.matched_signals)
    no_control_flags = (
        1
        for value in (
            assessment.questionnaire.get("technical_architecture", {}).get("mfa_enforced", "unknown"),
            assessment.questionnaire.get("technical_architecture", {}).get("network_segmentation", "unknown"),
            assessment.questionnaire.get("technical_architecture", {}).get("logging_monitoring", "unknown"),
            assessment.questionnaire.get("technical_architecture", {}).get("backup_restore_tested", "unknown"),
            assessment.questionnaire.get("maturity", {}).get("incident_response_plan", "unknown"),
        )
        if value == "no"
    )
    no_controls = sum(no_control_flags)
    uplift = min(35, int(round(signal_weight_total * 0.18)) + (no_controls * 2))
    return min(100, assessment.overall_score + uplift)


def extract_markdown_sections(content: str) -> dict[str, str]:
    """Split markdown content into sections keyed by normalized heading."""
    sections: dict[str, str] = {}
    current = "full_response"
    lines: list[str] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if line.startswith("## "):
            sections[current] = "\n".join(lines).strip()
            current = line[3:].strip().lower().replace(" ", "_")
            lines = []
        else:
            lines.append(raw_line)
    sections[current] = "\n".join(lines).strip()
    return {k: v for k, v in sections.items() if v}


def _extract_llm_sections(content: str) -> dict[str, str]:
    sections = extract_markdown_sections(content)
    useful_keys = {
        "risk_rationale",
        "top_3_risks",
        "top_risks",
        "personalized_recommendations_(zero_trust_first)",
        "personalized_recommendations",
        "recommendations",
        "7-day_action_checklist",
        "7_day_action_checklist",
        "7-day_action_plan",
        "action_plan",
        "suggested_investment_priorities_(2025_matrix)",
        "suggested_investment_priorities",
        "investment_priorities",
    }
    if any(key in sections for key in useful_keys):
        return sections

    heading_re = re.compile(
        r"(?:^|\n)\s*(?:#+\s*)?"
        r"(risk rationale|top 3 risks|top risks|"
        r"personalized recommendations(?:\s*\(zero trust first\))?|recommendations|"
        r"7-day action checklist|7 day action checklist|7-day action plan|action plan|"
        r"suggested investment priorities(?:\s*\([^)]*\))?|investment priorities)"
        r"\s*:?\s*",
        flags=re.IGNORECASE,
    )
    matches = list(heading_re.finditer(content))
    if not matches:
        return sections

    extracted: dict[str, str] = {}
    for idx, match in enumerate(matches):
        heading = match.group(1).strip().lower().replace(" ", "_")
        body_start = match.end()
        body_end = matches[idx + 1].start() if idx + 1 < len(matches) else len(content)
        body = content[body_start:body_end].strip()
        if body:
            extracted[heading] = body
    return extracted or sections


def _condense_section(text: str, *, max_items: int, max_chars: int) -> str:
    stripped = text.strip()
    if not stripped:
        return stripped

    lines = [line.rstrip() for line in stripped.splitlines() if line.strip()]
    list_lines = [
        line
        for line in lines
        if line.lstrip().startswith("- ")
        or bool(re.match(r"^\d+[\.\)]?\s+", line.lstrip()))
    ]

    if list_lines:
        condensed = "\n".join(list_lines[:max_items])
        return condensed[:max_chars].rstrip() + ("..." if len(condensed) > max_chars else "")

    joined = " ".join(line.strip() for line in lines)
    if len(joined) <= max_chars:
        return joined
    return joined[:max_chars].rstrip() + "..."


def _normalize_llm_explanation(llm_explanation: str, *, full_detail: bool = False) -> str:
    sections = _extract_llm_sections(llm_explanation)

    def pick(*keys: str) -> str:
        for key in keys:
            value = sections.get(key, "").strip()
            if value:
                return value
        return ""

    rationale = pick("risk_rationale", "top_3_risks", "top_risks")
    recommendations = pick(
        "personalized_recommendations_(zero_trust_first)",
        "personalized_recommendations",
        "recommendations",
    )
    seven_day = pick(
        "7-day_action_checklist",
        "7_day_action_checklist",
        "7-day_action_plan",
        "action_plan",
    )
    investments = pick(
        "suggested_investment_priorities_(2025_matrix)",
        "suggested_investment_priorities",
        "investment_priorities",
    )

    if not full_detail:
        rationale = _condense_section(rationale, max_items=4, max_chars=700) if rationale else ""
        recommendations = (
            _condense_section(recommendations, max_items=5, max_chars=700)
            if recommendations
            else ""
        )
        seven_day = _condense_section(seven_day, max_items=5, max_chars=650) if seven_day else ""
        investments = (
            _condense_section(investments, max_items=3, max_chars=500) if investments else ""
        )

    parts: list[str] = []
    if rationale:
        parts.extend(["## Risk Rationale", rationale, ""])
    if recommendations:
        parts.extend(["## Personalized Recommendations (Zero Trust first)", recommendations, ""])
    if seven_day:
        parts.extend(["## 7-day Action Checklist", seven_day, ""])
    if investments:
        parts.extend(["## Suggested Next Actions", investments, ""])

    if parts:
        return "\n".join(parts).strip()
    return "## LLM Guidance\n" + llm_explanation.strip()


def build_required_report_sections(assessment: RiskAssessment) -> dict[str, list[str]]:
    """Build the required report sections with deterministic fallback content."""

    identified_risks_lines: list[str] = []
    if assessment.matched_signals:
        for idx, signal in enumerate(assessment.matched_signals, start=1):
            mapping = CONTROL_MAP.get(signal.signal_id, {})
            category = mapping.get("category", signal.category)
            mitigation = mapping.get("recommendation", "Define targeted mitigation and control owner.")
            first_action = mapping.get("first_action", "Capture immediate containment action.")
            severity = _severity_from_signal_weight(signal.weight)
            identified_risks_lines.extend(
                [
                    (
                        f"{idx}. Vulnerability: {signal.label} "
                        f"(severity: {severity}, category: {signal.category}, signal weight: +{signal.weight})"
                    ),
                    f"   - Risk details: {signal.why_it_matters}",
                    f"   - Associated risks: {_associated_risks_for_category(signal.category)}",
                    f"   - Missing / weak controls: {category} controls lack sufficient evidence.",
                    f"   - Mitigation recommendation: {mitigation}",
                    f"   - Immediate action: {first_action}",
                ]
            )
    if assessment.identified_requirement_risks:
        start_idx = len(assessment.matched_signals) + 1
        for idx, risk in enumerate(assessment.identified_requirement_risks, start=start_idx):
            identified_risks_lines.extend(
                [
                    (
                        f"{idx}. Requirement-linked risk: {risk.risk} "
                        f"({risk.severity}, impact: {risk.impact}, score: {risk.score:.2f})"
                    ),
                    f"   - Why this risk exists: {risk.why}",
                    "   - Missing / weak controls: requirement control evidence indicates a gap.",
                    f"   - Source document: {risk.source_document}",
                    f"   - Reference control: {risk.reference_control}",
                ]
            )
    if not identified_risks_lines:
        identified_risks_lines = [
            "- No vulnerabilities were matched from current evidence; collect more architecture and control data."
        ]

    recommendation_lines: list[str] = []
    if assessment.investment_priorities:
        recommendation_lines.extend(
            [
                (
                    f"- [{item.bucket}] score contribution +{item.score_contribution}; "
                    f"related signals: {', '.join(item.related_signals)}"
                )
                for item in assessment.investment_priorities
            ]
        )
    if assessment.mapped_requirements:
        recommendation_lines.extend(
            [
                (
                    f"- [{control.mapped_layer}] {control.control_text_en} "
                    f"(source: {control.document_title} v{control.document_version}; "
                    f"retrieval: {control.retrieval_score:.2f}; "
                    f"reason: {control.retrieval_reason or 'baseline match'})"
                )
                for control in assessment.mapped_requirements
            ]
        )
    if assessment.recommendations:
        recommendation_lines.extend([f"- {item.recommendation}" for item in assessment.recommendations])
    if not recommendation_lines:
        recommendation_lines = [
            "- Capture more architecture/control evidence to generate targeted recommendations."
        ]

    return {
        "Identified Risks": identified_risks_lines,
        "Recommendations": recommendation_lines,
    }


def _build_detailed_risk_register(assessment: RiskAssessment) -> list[str]:
    lines: list[str] = []
    rec_by_signal = {item.signal_id: item for item in assessment.recommendations}

    lines.extend(
        [
            "- This section is intentionally full-detail and not truncated.",
            f"- Runtime matched signals: {len(assessment.matched_signals)}",
            f"- Requirement-linked risks: {len(assessment.identified_requirement_risks)}",
            "",
            "### Signal Risk Inventory (All)",
        ]
    )
    if assessment.matched_signals:
        for idx, signal in enumerate(assessment.matched_signals, start=1):
            recommendation = rec_by_signal.get(signal.signal_id)
            lines.append(
                f"{idx}. {signal.label} "
                f"(signal_id: {signal.signal_id}, category: {signal.category}, weight: +{signal.weight})"
            )
            lines.append(f"   - Risk description: {signal.why_it_matters}")
            if signal.matched_phrases:
                lines.append(f"   - Evidence phrases: {', '.join(signal.matched_phrases)}")
            else:
                lines.append("   - Evidence phrases: inferred baseline context (no direct phrase match).")

            if recommendation:
                lines.append(f"   - Control domain: {recommendation.category}")
                lines.append(f"   - Mitigation: {recommendation.recommendation}")
                lines.append(f"   - First action: {recommendation.first_action}")
                lines.append(f"   - 7-day action: {recommendation.seven_day_action}")
            else:
                lines.append("   - Mitigation: no recommendation generated for this signal.")

    else:
        lines.append("- No runtime risk signals matched from current input.")

    lines.extend(["", "### Requirement-Linked Risk Inventory (All)"])
    if assessment.identified_requirement_risks:
        for idx, risk in enumerate(assessment.identified_requirement_risks, start=1):
            tags = ", ".join(risk.compliance_tags) if risk.compliance_tags else "none"
            lines.extend(
                [
                    (
                        f"{idx}. {risk.risk} "
                        f"({risk.severity}, impact: {risk.impact}, score: {risk.score:.2f})"
                    ),
                    f"   - Why this risk exists: {risk.why}",
                    f"   - Source document: {risk.source_document}",
                    f"   - Reference control: {risk.reference_control}",
                    f"   - Tags: {tags}",
                ]
            )
    else:
        lines.append("- No requirement-linked risks identified.")

    lines.extend(["", "### Requirement Control Retrieval Inventory (All)"])
    if assessment.mapped_requirements:
        for control in assessment.mapped_requirements:
            refs = ", ".join(
                sorted({f"{ref.framework} {ref.control_id}" for ref in control.framework_refs})
            )
            lines.extend(
                [
                    (
                        f"- [{control.mapped_layer}] {control.control_text_en} "
                        f"(severity: {control.severity}, retrieval: {control.retrieval_score:.2f}, rank: {control.retrieval_rank})"
                    ),
                    (
                        f"  source: {control.document_title} v{control.document_version}; "
                        f"reason: {control.retrieval_reason or 'baseline retrieval match'}"
                    ),
                    f"  references: {refs or 'none'}",
                ]
            )
    else:
        lines.append("- No requirement controls retrieved.")

    return lines


def compose_assessment_markdown(
    assessment: RiskAssessment,
    llm_explanation: str | None = None,
    *,
    full_detail: bool = False,
) -> str:
    """Compose a concise, client-ready report for MVP assessments."""
    top_risks = assessment.top_risks or ["No high-confidence risk signals were matched."]
    control_gaps = assessment.control_gaps or ["No explicit control gaps detected from input text."]
    recommendations = (
        [f"- {rec.recommendation}" for rec in assessment.recommendations[:5]]
        if assessment.recommendations
        else ["- Capture more environment details to generate focused recommendations."]
    )
    seven_day = (
        [f"{idx}. {step}" for idx, step in enumerate(assessment.seven_day_plan[:5], start=1)]
        if assessment.seven_day_plan
        else ["1. Run a quick controls inventory across identity, backup, and monitoring."]
    )
    priority_lines = (
        [
            f"- {item.bucket}: signal contribution +{item.score_contribution}"
            for item in assessment.investment_priorities[:3]
        ]
        if assessment.investment_priorities
        else ["- Validate baseline controls with real configuration evidence."]
    )
    identified_risks_lines = (
        [
            f"{idx}. {signal.label} ({_severity_from_signal_weight(signal.weight)} severity)"
            for idx, signal in enumerate(assessment.matched_signals[:4], start=1)
        ]
        if assessment.matched_signals
        else ["1. No explicit high-confidence vulnerabilities detected from the current description."]
    )

    parts = [
        "## Overall Risk Score",
        f"{assessment.overall_score}/100 ({assessment.risk_level})",
        "",
        "## Executive Summary",
        f"- Residual risk is **{assessment.residual_risk}/100** with **{int(round(assessment.confidence * 100))}%** confidence.",
        f"- Current profile indicates **{len(assessment.matched_signals)} key risk signals** and **{len(control_gaps)} control gaps**.",
        "- Priority should be reducing identity, exposure, and recovery weaknesses in the next 7 days.",
        "",
        "## Risk Dimensions",
        f"- Likelihood: {assessment.likelihood:.2f} ({int(round(assessment.likelihood * 100))}/100)",
        f"- Impact: {assessment.impact:.2f} ({int(round(assessment.impact * 100))}/100)",
        f"- Inherent Risk: {assessment.inherent_risk}/100",
        f"- Control Reduction: {assessment.control_reduction:.2f} ({int(round(assessment.control_reduction * 100))}%)",
        f"- Residual Risk: {assessment.residual_risk}/100",
        f"- Cascading Worst-Case Projection: {_worst_case_projection(assessment)}/100",
        f"- Confidence: {assessment.confidence:.2f} ({int(round(assessment.confidence * 100))}%)",
        "",
        "## Top 3 Risks",
        *[f"{idx}. {risk}" for idx, risk in enumerate(top_risks[:3], start=1)],
        "",
        "## Identified Risks",
        *identified_risks_lines,
        "",
        "## Key Control Gaps",
        *[f"- {gap}" for gap in control_gaps[:5]],
    ]
    parts.extend(
        [
            "",
            "## Recommended Actions",
            *recommendations,
            "",
            "## 7-day Action Plan",
            *seven_day,
            "",
            "## Priority Focus Areas",
            *priority_lines,
        ]
    )

    if llm_explanation:
        parts.extend(["", "## Advisor Notes", _normalize_llm_explanation(llm_explanation, full_detail=False)])

    parts.extend(
        [
            "",
            "## Upgrade Potential",
            "- Paid edition can add governance workflow, policy gates, deeper control evidence, and integration hooks.",
            "- This MVP report is intentionally concise for fast executive decision-making.",
        ]
    )

    parts.extend(["", _METHOD_SECTION.strip()])
    return "\n".join(parts).strip() + "\n"
