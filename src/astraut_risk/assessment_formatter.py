"""Shared formatting for deterministic + LLM-assisted assessment outputs."""

from __future__ import annotations

import re

from .models import RiskAssessment

_METHOD_SECTION = (
    "## Method\n"
    "- Baseline score generated from deterministic factors and control evidence quality.\n"
    "- Inherent risk: `Likelihood x Impact x 100`.\n"
    "- Unknown questionnaire values are treated pessimistically (worst-case) until confirmed.\n"
    "- Residual risk: `Inherent x (1 - ControlReduction)` with an uncertainty multiplier for missing questionnaire evidence.\n"
    "- Control coverage (runtime panel): `retrieved controls / mapped applicable controls x 100`.\n"
    "- Recommendations expanded using LLM reasoning.\n"
    "- Built for guidance, not formal audit use.\n"
)

_REQUIRED_REPORT_SECTIONS = (
    "Applicable Standards",
    "Identified Risks",
    "Recommendations",
)

_STANDARD_OUTPUT_ORDER = ("CIS", "NIST", "OWASP")


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
        parts.extend(["## Suggested investment priorities (2025 matrix)", investments, ""])

    if parts:
        return "\n".join(parts).strip()
    return "## LLM Guidance\n" + llm_explanation.strip()


def build_required_report_sections(assessment: RiskAssessment) -> dict[str, list[str]]:
    """Build the three required report sections with deterministic fallback content."""
    standards_lines = (
        [f"- {standard}" for standard in assessment.applicable_standards]
        if assessment.applicable_standards
        else ["- No standards matched from current requirements context."]
    )

    identified_risks_lines: list[str] = []
    if assessment.identified_requirement_risks:
        for idx, risk in enumerate(assessment.identified_requirement_risks, start=1):
            identified_risks_lines.extend(
                [
                    (
                        f"{idx}. {risk.risk} "
                        f"({risk.severity}, impact: {risk.impact}, score: {risk.score:.2f})"
                    ),
                    f"   - Why this risk exists: {risk.why}",
                    f"   - Source document: {risk.source_document}",
                    f"   - Reference control: {risk.reference_control}",
                ]
            )
    else:
        identified_risks_lines = [
            "- No requirement-linked risks identified (requirements calibration is optional)."
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
        "Applicable Standards": standards_lines,
        "Identified Risks": identified_risks_lines,
        "Recommendations": recommendation_lines,
    }


def _standard_specific_output_sections(assessment: RiskAssessment) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    for standard in _STANDARD_OUTPUT_ORDER:
        signal_refs: list[str] = []
        seen_signal_ref: set[tuple[str, str]] = set()
        for refs in assessment.framework_references.values():
            for ref in refs:
                if ref.framework != standard:
                    continue
                key = (ref.framework, ref.control_id)
                if key in seen_signal_ref:
                    continue
                seen_signal_ref.add(key)
                label = ref.control_id
                if ref.title:
                    label = f"{label} - {ref.title}"
                detail = f"{label}: {ref.description}" if ref.description else label
                signal_refs.append(f"- {detail}")

        req_risks = [
            risk
            for risk in assessment.identified_requirement_risks
            if standard in {tag.strip() for tag in risk.compliance_tags}
        ]

        matched_controls: list[str] = []
        for control in assessment.mapped_requirements:
            refs = [ref for ref in control.framework_refs if ref.framework == standard]
            if not refs:
                continue
            controls_text = ", ".join(sorted({ref.control_id for ref in refs if ref.control_id}))
            matched_controls.append(
                (
                    "- "
                    f"[{control.mapped_layer}] controls: {controls_text or 'mapped'}; "
                    f"source: {control.document_title} v{control.document_version}; "
                    f"retrieval: {control.retrieval_score:.2f}"
                )
            )

        lines: list[str] = [
            f"- Signal-linked control references: {len(signal_refs)}",
            f"- Requirement-linked risks tagged {standard}: {len(req_risks)}",
            f"- Matched requirement controls mapped to {standard}: {len(matched_controls)}",
            "",
            "### Signal-linked controls",
        ]
        lines.extend(signal_refs if signal_refs else ["- None mapped from matched runtime signals."])

        lines.extend(["", "### Requirement-linked risks"])
        if req_risks:
            for idx, risk in enumerate(req_risks, start=1):
                lines.extend(
                    [
                        (
                            f"{idx}. {risk.risk} "
                            f"({risk.severity}, impact: {risk.impact}, score: {risk.score:.2f})"
                        ),
                        f"   - Why: {risk.why}",
                        f"   - Source: {risk.source_document}",
                    ]
                )
        else:
            lines.append("- None tagged to this standard in current requirement risk set.")

        lines.extend(["", "### Matched requirement controls"])
        lines.extend(matched_controls if matched_controls else ["- None mapped from requirements retrieval."])

        sections[standard] = lines

    return sections


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

            refs = assessment.framework_references.get(signal.signal_id, [])
            if refs:
                lines.append("   - Framework mappings:")
                for ref in refs:
                    label = ref.control_id
                    if ref.title:
                        label = f"{label} - {ref.title}"
                    detail = f"{label}: {ref.description}" if ref.description else label
                    lines.append(f"     - {ref.framework}: {detail}")
            else:
                lines.append("   - Framework mappings: none")
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
                    f"   - Standards tags: {tags}",
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
                    f"  mapped standards: {refs or 'none'}",
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
    if assessment.detected_security_domains:
        parts.extend(
            [
                "",
                "## Detected Security Domains",
                *[f"- {domain}" for domain in assessment.detected_security_domains],
            ]
        )
    parts.extend(
        [
            "",
            "## Control Coverage",
            f"- Control Coverage %: {assessment.control_coverage_percent:.2f}",
            f"- Mapped applicable controls: {assessment.mapped_controls_count}",
            f"- Retrieved controls (ranked): {assessment.retrieved_controls_count}",
            f"- Total controls in index: {assessment.requirements_controls_total}",
        ]
    )
    if not assessment.requirements_calibration_enabled:
        parts.append("- Requirements calibration is disabled; coverage remains informational only.")

    residual_adjustments = assessment.factor_snapshot.get("residual_adjustments", {})
    if isinstance(residual_adjustments, dict):
        parts.extend(
            [
                "",
                "## Runtime Variables",
                (
                    f"- Questionnaire completeness: "
                    f"{float(residual_adjustments.get('questionnaire_completeness', 0.0)) * 100:.2f}%"
                ),
                (
                    f"- Residual before uncertainty: "
                    f"{float(residual_adjustments.get('residual_before_uncertainty', assessment.residual_risk)):.2f}/100"
                ),
                (
                    f"- Uncertainty multiplier: "
                    f"x{float(residual_adjustments.get('uncertainty_multiplier', 1.0)):.2f}"
                ),
            ]
        )
    required_sections = build_required_report_sections(assessment)
    for section in _REQUIRED_REPORT_SECTIONS:
        parts.extend(["", f"## {section}"])
        parts.extend(required_sections.get(section, []))

    parts.extend(["", "## Standard-Specific Outputs"])
    standard_sections = _standard_specific_output_sections(assessment)
    for standard in _STANDARD_OUTPUT_ORDER:
        parts.extend(["", f"## {standard} Output"])
        parts.extend(standard_sections.get(standard, [f"- No data available for {standard}."]))

    parts.extend(["", "## Detailed Risk Register (Full)"])
    parts.extend(_build_detailed_risk_register(assessment))

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
        parts.extend(["", _normalize_llm_explanation(llm_explanation, full_detail=full_detail)])
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
