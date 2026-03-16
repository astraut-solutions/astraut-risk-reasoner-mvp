"""Deterministic SME risk scoring engine."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .control_map import CONTROL_MAP
from .framework_mapping import framework_refs_for_signal
from .models import InvestmentPriority, Recommendation, RiskAssessment, RiskSignal


@dataclass(frozen=True)
class SignalRule:
    """Rule definition used for deterministic signal matching."""

    signal_id: str
    label: str
    weight: int
    patterns: tuple[str, ...]
    category: str
    negative_patterns: tuple[str, ...] = ()


_SIGNAL_RULES: tuple[SignalRule, ...] = (
    SignalRule(
        signal_id="no_mfa",
        label="MFA not enforced on key accounts",
        weight=16,
        category="Identity & Access",
        patterns=(r"\bno\s+mfa\b", r"without\s+mfa", r"mfa\s+not\s+enabled"),
        negative_patterns=(r"\bmfa\s+(enabled|enforced|required)\b",),
    ),
    SignalRule(
        signal_id="shared_accounts",
        label="Shared accounts in use",
        weight=10,
        category="Identity & Access",
        patterns=(r"shared\s+accounts?", r"shared\s+logins?"),
    ),
    SignalRule(
        signal_id="weak_passwords",
        label="Weak password hygiene",
        weight=8,
        category="Identity & Access",
        patterns=(r"weak\s+password", r"password\s+reuse", r"simple\s+password"),
    ),
    SignalRule(
        signal_id="no_least_privilege",
        label="Least privilege not applied",
        weight=11,
        category="Identity & Access",
        patterns=(r"no\s+least\s+privilege", r"over\s*privileged", r"admin\s+for\s+all"),
    ),
    SignalRule(
        signal_id="stale_users",
        label="Stale users not reviewed",
        weight=7,
        category="Identity & Access",
        patterns=(r"stale\s+users?", r"inactive\s+accounts?", r"offboarding\s+is\s+manual"),
    ),
    SignalRule(
        signal_id="public_api",
        label="Public API exposure",
        weight=12,
        category="Infrastructure / Cloud",
        patterns=(r"public\s+api", r"internet\s*facing\s+api", r"externally\s+accessible\s+api"),
    ),
    SignalRule(
        signal_id="flat_network",
        label="Flat network architecture",
        weight=12,
        category="Infrastructure / Cloud",
        patterns=(r"flat\s+network", r"network\s+is\s+flat", r"single\s+network\s+segment"),
    ),
    SignalRule(
        signal_id="no_segmentation",
        label="Network segmentation missing",
        weight=13,
        category="Infrastructure / Cloud",
        patterns=(r"no\s+segmentation", r"without\s+segmentation", r"not\s+segmented"),
        negative_patterns=(r"network\s+segmentation",),
    ),
    SignalRule(
        signal_id="exposed_admin",
        label="Admin systems exposed",
        weight=12,
        category="Infrastructure / Cloud",
        patterns=(r"exposed\s+admin", r"public\s+admin", r"admin\s+panel\s+internet"),
    ),
    SignalRule(
        signal_id="unmanaged_cloud",
        label="Unmanaged cloud resources",
        weight=9,
        category="Infrastructure / Cloud",
        patterns=(r"unmanaged\s+cloud", r"no\s+cloud\s+baseline", r"cloud\s+sprawl"),
    ),
    SignalRule(
        signal_id="no_tested_backups",
        label="Backups not tested",
        weight=14,
        category="Backups / Resilience",
        patterns=(r"no\s+tested\s+backups", r"backups\s+not\s+tested", r"never\s+test\s+backups"),
        negative_patterns=(r"tested\s+backups", r"backup\s+restore\s+test"),
    ),
    SignalRule(
        signal_id="backups_not_isolated",
        label="Backups not isolated",
        weight=11,
        category="Backups / Resilience",
        patterns=(r"backups?\s+not\s+isolated", r"no\s+immutable\s+backup", r"online\s+only\s+backup"),
    ),
    SignalRule(
        signal_id="no_incident_plan",
        label="No incident response plan",
        weight=10,
        category="Backups / Resilience",
        patterns=(r"no\s+incident\s+plan", r"no\s+incident\s+response", r"incident\s+procedures\s+undocumented"),
    ),
    SignalRule(
        signal_id="no_recovery_testing",
        label="Recovery testing missing",
        weight=10,
        category="Backups / Resilience",
        patterns=(r"no\s+recovery\s+testing", r"recovery\s+tests?\s+infrequent", r"never\s+test\s+restore"),
    ),
    SignalRule(
        signal_id="no_logging",
        label="Logging not enabled",
        weight=10,
        category="Monitoring / Detection",
        patterns=(r"no\s+logging", r"logging\s+is\s+limited", r"without\s+logs"),
        negative_patterns=(r"centralized\s+logging", r"audit\s+logging\s+enabled"),
    ),
    SignalRule(
        signal_id="no_alerting",
        label="Alerting not configured",
        weight=9,
        category="Monitoring / Detection",
        patterns=(r"no\s+alerting", r"without\s+alerts", r"alerts?\s+missing"),
    ),
    SignalRule(
        signal_id="no_centralized_monitoring",
        label="No centralized monitoring",
        weight=8,
        category="Monitoring / Detection",
        patterns=(r"no\s+centralized\s+monitoring", r"monitoring\s+is\s+missing", r"siloed\s+logs"),
        negative_patterns=(r"centralized\s+monitoring",),
    ),
    SignalRule(
        signal_id="unpatched_dependencies",
        label="Unpatched dependencies",
        weight=11,
        category="Software / Supply Chain",
        patterns=(r"unpatched\s+dependenc", r"outdated\s+packages", r"known\s+vulnerabilities\s+open"),
    ),
    SignalRule(
        signal_id="no_dependency_scanning",
        label="Dependency scanning missing",
        weight=8,
        category="Software / Supply Chain",
        patterns=(r"no\s+dependency\s+scanning", r"without\s+dependency\s+scan", r"no\s+sca"),
    ),
    SignalRule(
        signal_id="no_vendor_review",
        label="Vendor security reviews missing",
        weight=7,
        category="Software / Supply Chain",
        patterns=(r"no\s+vendor\s+review", r"vendor\s+reviews?\s+are\s+ad\s*hoc", r"third\s+party\s+risk\s+not\s+reviewed"),
    ),
    SignalRule(
        signal_id="weak_cicd_controls",
        label="Weak CI/CD controls",
        weight=9,
        category="Software / Supply Chain",
        patterns=(r"weak\s+ci/?cd\s+controls", r"no\s+branch\s+protection", r"pipeline\s+secrets?\s+exposed"),
    ),
)


def _append_inferred_baseline_signals(
    normalized_text: str,
    matched_signals: list[RiskSignal],
) -> None:
    matched_ids = {signal.signal_id for signal in matched_signals}

    saas_context = bool(
        re.search(
            r"\bsaas\b|\bstartup\b|\bweb\s*app\b|\bcustomer[\s-]*facing\b",
            normalized_text,
            flags=re.IGNORECASE,
        )
    )
    if not saas_context:
        return

    if "internet_facing_saas" not in matched_ids:
        mapping = CONTROL_MAP["internet_facing_saas"]
        matched_signals.append(
            RiskSignal(
                signal_id="internet_facing_saas",
                label="Internet-facing SaaS footprint",
                category="Infrastructure / Cloud",
                weight=14,
                matched_phrases=["saas/startup footprint implies external exposure"],
                why_it_matters=mapping["why_it_matters"],
                framework_refs=[],
            )
        )
        matched_ids.add("internet_facing_saas")

    has_identity_signal = bool(
        re.search(r"\bmfa\b|\bsso\b|\bleast\s+privilege\b", normalized_text, flags=re.IGNORECASE)
    )
    has_detection_signal = bool(
        re.search(r"\blog(?:ging)?\b|\bmonitor(?:ing)?\b|\balert(?:ing|s)?\b", normalized_text, flags=re.IGNORECASE)
    )
    has_resilience_signal = bool(
        re.search(r"\bbackup(?:s)?\b|\bincident\s+response\b|\brecovery\b", normalized_text, flags=re.IGNORECASE)
    )
    if not (has_identity_signal and has_detection_signal and has_resilience_signal):
        if "baseline_controls_unspecified" not in matched_ids:
            mapping = CONTROL_MAP["baseline_controls_unspecified"]
            matched_signals.append(
                RiskSignal(
                    signal_id="baseline_controls_unspecified",
                    label="Baseline controls not explicitly stated",
                    category="Security Governance",
                    weight=10,
                    matched_phrases=["missing explicit evidence for baseline controls"],
                    why_it_matters=mapping["why_it_matters"],
                    framework_refs=[],
                )
            )


def _find_matches(text: str, patterns: tuple[str, ...]) -> list[str]:
    matches: list[str] = []
    for pattern in patterns:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            found = match.group(0).strip()
            if found and found not in matches:
                matches.append(found)
    return matches


def _matches_negative(text: str, negative_patterns: tuple[str, ...]) -> bool:
    for pattern in negative_patterns:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return True
    return False


def _risk_level(score: int) -> str:
    if score <= 20:
        return "Low"
    if score <= 45:
        return "Moderate"
    if score <= 70:
        return "High"
    return "Critical"


def assess_company_risk(company_description: str) -> RiskAssessment:
    """Run deterministic keyword-based risk assessment for SME narratives."""
    text = (company_description or "").strip()
    normalized = text.lower()

    matched_signals: list[RiskSignal] = []
    for rule in _SIGNAL_RULES:
        matched_phrases = _find_matches(normalized, rule.patterns)
        if not matched_phrases:
            continue
        if rule.negative_patterns and _matches_negative(normalized, rule.negative_patterns):
            continue

        mapping = CONTROL_MAP[rule.signal_id]
        matched_signals.append(
            RiskSignal(
                signal_id=rule.signal_id,
                label=rule.label,
                category=rule.category,
                weight=rule.weight,
                matched_phrases=matched_phrases,
                why_it_matters=mapping["why_it_matters"],
                framework_refs=framework_refs_for_signal(rule.signal_id),
            )
        )

    _append_inferred_baseline_signals(normalized, matched_signals)
    matched_signals.sort(key=lambda item: item.weight, reverse=True)
    total_score = max(0, min(100, sum(signal.weight for signal in matched_signals)))

    top_risks = [
        f"{signal.label} ({signal.category}, +{signal.weight})"
        for signal in matched_signals[:3]
    ]

    recommendations: list[Recommendation] = []
    control_gaps: list[str] = []
    for signal in matched_signals:
        mapping = CONTROL_MAP[signal.signal_id]
        recommendations.append(
            Recommendation(
                signal_id=signal.signal_id,
                category=mapping["category"],
                recommendation=mapping["recommendation"],
                first_action=mapping["first_action"],
                seven_day_action=mapping["seven_day_action"],
            )
        )
        control_gaps.append(f"{mapping['category']}: {signal.label}")

    seen_actions: set[str] = set()
    seven_day_plan: list[str] = []
    for recommendation in recommendations:
        action = recommendation.seven_day_action
        if action not in seen_actions:
            seen_actions.add(action)
            seven_day_plan.append(action)

    bucket_totals: dict[str, InvestmentPriority] = {}
    for signal in matched_signals:
        mapping = CONTROL_MAP[signal.signal_id]
        bucket = mapping["investment_bucket"]
        priority = bucket_totals.get(bucket)
        if priority is None:
            priority = InvestmentPriority(
                bucket=bucket,
                rationale=f"Signals indicate gaps in {bucket.lower()} controls.",
                related_signals=[],
                score_contribution=0,
            )
            bucket_totals[bucket] = priority

        priority.related_signals.append(signal.signal_id)
        priority.score_contribution += signal.weight

    investment_priorities = sorted(
        bucket_totals.values(),
        key=lambda item: item.score_contribution,
        reverse=True,
    )

    return RiskAssessment(
        company_input=text,
        overall_score=total_score,
        risk_level=_risk_level(total_score),
        matched_signals=matched_signals,
        top_risks=top_risks,
        control_gaps=control_gaps,
        recommendations=recommendations,
        seven_day_plan=seven_day_plan,
        investment_priorities=investment_priorities,
        framework_references={
            signal.signal_id: signal.framework_refs
            for signal in matched_signals
            if signal.framework_refs
        },
    )
