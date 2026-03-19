"""Shared formatting for deterministic + LLM-assisted assessment outputs."""

from __future__ import annotations

import re

from .models import RiskAssessment

_METHOD_SECTION = (
    "## Method\n"
    "- Baseline score generated from rule-based SME control checks.\n"
    "- Recommendations expanded using LLM reasoning.\n"
    "- Built for guidance, not formal audit use.\n"
)


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


def _normalize_llm_explanation(llm_explanation: str) -> str:
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
        parts.extend(["## Suggested investment priorities (2025 matrix)", investments, ""])

    if parts:
        return "\n".join(parts).strip()
    return "## LLM Guidance\n" + llm_explanation.strip()


def compose_assessment_markdown(
    assessment: RiskAssessment,
    llm_explanation: str | None = None,
) -> str:
    """Compose final markdown from deterministic findings and optional LLM narrative."""
    top_risks = assessment.top_risks or ["No high-confidence risk signals were matched."]
    control_gaps = assessment.control_gaps or ["No explicit control gaps detected from input text."]
    investment_lines = (
        [
            f"{idx}. {item.bucket} (signal weight: +{item.score_contribution})"
            for idx, item in enumerate(assessment.investment_priorities[:3], start=1)
        ]
        if assessment.investment_priorities
        else ["1. Continue validating baseline controls with real configuration data."]
    )
    recommendations = (
        [f"- {rec.recommendation}" for rec in assessment.recommendations[:5]]
        if assessment.recommendations
        else ["- Capture more environment details to generate focused recommendations."]
    )
    seven_day = (
        [f"{idx}. {step}" for idx, step in enumerate(assessment.seven_day_plan[:7], start=1)]
        if assessment.seven_day_plan
        else ["1. Run a quick controls inventory across identity, backup, and monitoring."]
    )

    parts = [
        "## Overall Risk Score",
        f"{assessment.overall_score}/100 ({assessment.risk_level})",
        "",
        "## Risk Dimensions",
        f"- Likelihood: {assessment.likelihood:.2f} ({int(round(assessment.likelihood * 100))}/100)",
        f"- Impact: {assessment.impact:.2f} ({int(round(assessment.impact * 100))}/100)",
        f"- Inherent Risk: {assessment.inherent_risk}/100",
        f"- Control Reduction: {assessment.control_reduction:.2f} ({int(round(assessment.control_reduction * 100))}%)",
        f"- Residual Risk: {assessment.residual_risk}/100",
        f"- Confidence: {assessment.confidence:.2f} ({int(round(assessment.confidence * 100))}%)",
        "",
        "## Top 3 Risks",
        *[f"{idx}. {risk}" for idx, risk in enumerate(top_risks[:3], start=1)],
        "",
        "## Detected Control Gaps",
        *[f"- {gap}" for gap in control_gaps],
    ]
    if assessment.framework_references:
        grouped: dict[str, list[str]] = {}
        seen: set[tuple[str, str]] = set()
        for refs in assessment.framework_references.values():
            for ref in refs:
                key = (ref.framework, ref.control_id)
                if key in seen:
                    continue
                seen.add(key)
                label = f"{ref.control_id}"
                if ref.title:
                    label = f"{label} - {ref.title}"
                line = f"- {label}: {ref.description}" if ref.description else f"- {label}"
                grouped.setdefault(ref.framework, []).append(line)

        if grouped:
            parts.extend(["", "## Framework Mapping"])
            for framework in sorted(grouped.keys()):
                parts.append(f"### {framework}")
                parts.extend(grouped[framework])

    if llm_explanation:
        parts.extend(["", _normalize_llm_explanation(llm_explanation)])
    else:
        parts.extend(
            [
                "",
                "## Personalized Recommendations (Zero Trust first)",
                *recommendations,
                "",
                "## 7-day Action Checklist",
                *seven_day,
                "",
                "## Suggested investment priorities (2025 matrix)",
                *investment_lines,
            ]
        )

    parts.extend(["", _METHOD_SECTION.strip()])
    return "\n".join(parts).strip() + "\n"
