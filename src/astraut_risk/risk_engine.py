"""Deterministic SME risk scoring engine."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from .control_map import CONTROL_MAP
from .framework_mapping import framework_refs_for_signal
from .models import InvestmentPriority, Recommendation, RiskAssessment, RiskSignal
from .questionnaire import default_questionnaire, to_signal_hints


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


_DEFAULT_FACTOR_CONFIG: dict[str, dict[str, float]] = {
    "likelihood_weights": {
        "exposure": 0.28,
        "exploitability_proxy": 0.22,
        "threat_relevance_proxy": 0.20,
        "identity_exposure": 0.18,
        "precondition_complexity": 0.12,
    },
    "impact_weights": {
        "business_criticality": 0.15,
        "data_sensitivity": 0.24,
        "privilege_level": 0.16,
        "blast_radius": 0.20,
        "regulatory_consequence": 0.12,
        "customer_impact": 0.13,
    },
    "control_effectiveness_weights": {
        "design": 0.30,
        "operating_evidence": 0.35,
        "coverage": 0.20,
        "freshness": 0.10,
        "exception_rate": 0.05,
    },
    "control_strengths": {
        "mfa": 0.30,
        "segmentation": 0.25,
        "logging_detection": 0.18,
        "backup_recovery": 0.15,
        "incident_response": 0.12,
    },
    "confidence_weights": {
        "questionnaire_completeness": 0.35,
        "signal_coverage": 0.25,
        "control_evidence_quality": 0.20,
        "input_specificity": 0.20,
    },
}


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


def _clamp(value: float, lower: float = 0.0, upper: float = 1.0) -> float:
    return max(lower, min(upper, value))


def _weighted_sum(weights: dict[str, float], values: dict[str, float]) -> float:
    total = 0.0
    for key, weight in weights.items():
        total += weight * values.get(key, 0.0)
    return _clamp(total)


def _questionnaire_value(questionnaire: dict[str, dict[str, str]], domain: str, field: str) -> str:
    return questionnaire.get(domain, {}).get(field, "unknown")


def _signal_set(matched_signals: list[RiskSignal]) -> set[str]:
    return {signal.signal_id for signal in matched_signals}


@lru_cache(maxsize=1)
def _load_factor_config() -> dict[str, dict[str, float]]:
    config = {section: values.copy() for section, values in _DEFAULT_FACTOR_CONFIG.items()}
    path = Path(__file__).resolve().parent / "frameworks" / "risk_factors.yaml"
    if not path.exists():
        return config

    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return config

    if not isinstance(loaded, dict):
        return config

    for section, defaults in _DEFAULT_FACTOR_CONFIG.items():
        override = loaded.get(section)
        if not isinstance(override, dict):
            continue
        for key, value in override.items():
            if key in defaults and isinstance(value, (int, float)):
                config[section][key] = float(value)

    return config


def _compute_likelihood_factors(
    questionnaire: dict[str, dict[str, str]],
    signal_ids: set[str],
    signal_weight_total: int,
) -> dict[str, float]:
    exposure = 0.20
    if _questionnaire_value(questionnaire, "technical_architecture", "internet_exposed") == "yes":
        exposure += 0.25
    if _questionnaire_value(questionnaire, "technical_architecture", "public_api") == "yes" or "public_api" in signal_ids:
        exposure += 0.35
    if "internet_facing_saas" in signal_ids or "exposed_admin" in signal_ids:
        exposure += 0.20
    if "no_segmentation" in signal_ids or "flat_network" in signal_ids:
        exposure += 0.10

    exploitability_proxy = 0.20
    for signal_id, delta in (
        ("no_mfa", 0.20),
        ("weak_passwords", 0.10),
        ("shared_accounts", 0.12),
        ("unpatched_dependencies", 0.14),
        ("weak_cicd_controls", 0.08),
    ):
        if signal_id in signal_ids:
            exploitability_proxy += delta
    exploitability_proxy += _clamp(signal_weight_total / 180.0) * 0.16

    threat_relevance_proxy = 0.25
    if "public_api" in signal_ids or "internet_facing_saas" in signal_ids:
        threat_relevance_proxy += 0.25
    if _questionnaire_value(questionnaire, "compliance", "regulatory_profile") == "regulated":
        threat_relevance_proxy += 0.10
    if _questionnaire_value(questionnaire, "business", "data_sensitivity") == "high":
        threat_relevance_proxy += 0.12
    if "unpatched_dependencies" in signal_ids or "no_dependency_scanning" in signal_ids:
        threat_relevance_proxy += 0.10

    identity_exposure = 0.22
    if _questionnaire_value(questionnaire, "technical_architecture", "mfa_enforced") == "no" or "no_mfa" in signal_ids:
        identity_exposure += 0.38
    if "shared_accounts" in signal_ids or "no_least_privilege" in signal_ids:
        identity_exposure += 0.20
    if "stale_users" in signal_ids:
        identity_exposure += 0.10
    if _questionnaire_value(questionnaire, "technical_architecture", "mfa_enforced") == "yes":
        identity_exposure -= 0.16

    complexity = 0.35
    if _questionnaire_value(questionnaire, "technical_architecture", "mfa_enforced") == "yes":
        complexity += 0.20
    if _questionnaire_value(questionnaire, "technical_architecture", "network_segmentation") == "yes":
        complexity += 0.20
    if _questionnaire_value(questionnaire, "technical_architecture", "logging_monitoring") == "yes":
        complexity += 0.08
    if "no_mfa" in signal_ids:
        complexity -= 0.20
    if "no_segmentation" in signal_ids or "flat_network" in signal_ids:
        complexity -= 0.20
    if "weak_passwords" in signal_ids:
        complexity -= 0.05

    return {
        "exposure": _clamp(exposure),
        "exploitability_proxy": _clamp(exploitability_proxy),
        "threat_relevance_proxy": _clamp(threat_relevance_proxy),
        "identity_exposure": _clamp(identity_exposure),
        "precondition_complexity": _clamp(1.0 - _clamp(complexity)),
    }


def _compute_impact_factors(
    questionnaire: dict[str, dict[str, str]],
    signal_ids: set[str],
) -> dict[str, float]:
    size = _questionnaire_value(questionnaire, "business", "company_size")
    business_criticality = {
        "sme": 0.45,
        "mid_market": 0.65,
        "enterprise": 0.80,
    }.get(size, 0.50)

    sensitivity = _questionnaire_value(questionnaire, "business", "data_sensitivity")
    data_sensitivity = {
        "low": 0.25,
        "medium": 0.55,
        "high": 0.85,
    }.get(sensitivity, 0.50)
    if _questionnaire_value(questionnaire, "compliance", "regulatory_profile") == "regulated":
        data_sensitivity = max(data_sensitivity, 0.75)

    privilege_level = 0.35
    if "no_least_privilege" in signal_ids or "shared_accounts" in signal_ids:
        privilege_level += 0.25
    if "exposed_admin" in signal_ids:
        privilege_level += 0.20
    if _questionnaire_value(questionnaire, "technical_architecture", "mfa_enforced") == "no":
        privilege_level += 0.08

    blast_radius = 0.30
    if "no_segmentation" in signal_ids or "flat_network" in signal_ids:
        blast_radius += 0.35
    if "shared_accounts" in signal_ids:
        blast_radius += 0.12
    if "backups_not_isolated" in signal_ids:
        blast_radius += 0.12
    if "no_incident_plan" in signal_ids:
        blast_radius += 0.08
    if _questionnaire_value(questionnaire, "technical_architecture", "network_segmentation") == "yes":
        blast_radius -= 0.12

    regulatory_consequence = {
        "regulated": 0.80,
        "unregulated": 0.25,
    }.get(_questionnaire_value(questionnaire, "compliance", "regulatory_profile"), 0.50)
    if data_sensitivity >= 0.75:
        regulatory_consequence += 0.08

    customer_impact = 0.30
    if _questionnaire_value(questionnaire, "technical_architecture", "public_api") == "yes" or "public_api" in signal_ids:
        customer_impact += 0.30
    if _questionnaire_value(questionnaire, "technical_architecture", "internet_exposed") == "yes":
        customer_impact += 0.12
    if data_sensitivity >= 0.75:
        customer_impact += 0.18
    if "no_incident_plan" in signal_ids:
        customer_impact += 0.08
    if "no_tested_backups" in signal_ids:
        customer_impact += 0.06
    if _questionnaire_value(questionnaire, "maturity", "incident_response_plan") == "no":
        customer_impact += 0.10

    return {
        "business_criticality": _clamp(business_criticality),
        "data_sensitivity": _clamp(data_sensitivity),
        "privilege_level": _clamp(privilege_level),
        "blast_radius": _clamp(blast_radius),
        "regulatory_consequence": _clamp(regulatory_consequence),
        "customer_impact": _clamp(customer_impact),
    }


def _control_profile(answer: str) -> dict[str, float]:
    if answer == "yes":
        return {
            "design": 0.85,
            "operating_evidence": 0.80,
            "coverage": 0.75,
            "freshness": 0.70,
            "exception_rate": 0.90,
        }
    if answer == "no":
        return {
            "design": 0.15,
            "operating_evidence": 0.10,
            "coverage": 0.20,
            "freshness": 0.20,
            "exception_rate": 0.20,
        }
    return {
        "design": 0.45,
        "operating_evidence": 0.35,
        "coverage": 0.35,
        "freshness": 0.30,
        "exception_rate": 0.45,
    }


def _adjust_profile(profile: dict[str, float], penalty_count: int, bonus: float = 0.0) -> dict[str, float]:
    penalty = min(0.35, 0.08 * penalty_count)
    adjusted: dict[str, float] = {}
    for key, value in profile.items():
        adjusted[key] = _clamp(value - penalty + bonus)
    return adjusted


def _compute_control_reduction(
    questionnaire: dict[str, dict[str, str]],
    signal_ids: set[str],
    config: dict[str, dict[str, float]],
) -> tuple[float, dict[str, object], float]:
    weights = config["control_effectiveness_weights"]
    strengths = config["control_strengths"]

    control_specs = [
        (
            "mfa",
            _questionnaire_value(questionnaire, "technical_architecture", "mfa_enforced"),
            {"no_mfa", "shared_accounts", "weak_passwords"},
            True,
        ),
        (
            "segmentation",
            _questionnaire_value(questionnaire, "technical_architecture", "network_segmentation"),
            {"no_segmentation", "flat_network", "exposed_admin"},
            True,
        ),
        (
            "logging_detection",
            _questionnaire_value(questionnaire, "technical_architecture", "logging_monitoring"),
            {"no_logging", "no_alerting", "no_centralized_monitoring"},
            True,
        ),
        (
            "backup_recovery",
            _questionnaire_value(questionnaire, "technical_architecture", "backup_restore_tested"),
            {"no_tested_backups", "no_recovery_testing", "backups_not_isolated"},
            True,
        ),
        (
            "incident_response",
            _questionnaire_value(questionnaire, "maturity", "incident_response_plan"),
            {"no_incident_plan"},
            True,
        ),
    ]

    reduction_product = 1.0
    control_items: list[dict[str, object]] = []
    effective_controls: list[float] = []

    for name, answer, penalty_signals, applicable in control_specs:
        profile = _control_profile(answer)
        penalty_count = len(signal_ids.intersection(penalty_signals))
        bonus = 0.0
        if name == "mfa" and _questionnaire_value(questionnaire, "maturity", "identity_maturity") == "advanced":
            bonus = 0.05

        adjusted_profile = _adjust_profile(profile, penalty_count=penalty_count, bonus=bonus)
        effectiveness = _weighted_sum(weights, adjusted_profile)
        effective = _clamp(effectiveness * strengths.get(name, 0.0)) if applicable else 0.0
        if applicable:
            reduction_product *= 1.0 - effective
            effective_controls.append(effective)

        control_items.append(
            {
                "name": name,
                "applicable": applicable,
                "answer": answer,
                "effectiveness": round(effectiveness, 4),
                "effective_reduction": round(effective, 4),
            }
        )

    control_reduction_adjusted = _clamp(1.0 - reduction_product)
    avg_effective = sum(effective_controls) / len(effective_controls) if effective_controls else 0.0
    snapshot = {
        "weights": weights,
        "controls": control_items,
        "reduction_adjusted": round(control_reduction_adjusted, 4),
    }
    return control_reduction_adjusted, snapshot, _clamp(avg_effective)


def _count_known_questionnaire_answers(questionnaire: dict[str, dict[str, str]]) -> tuple[int, int]:
    base = default_questionnaire()
    known = 0
    total = 0
    for domain, fields in base.items():
        answers = questionnaire.get(domain, {})
        for field in fields.keys():
            total += 1
            if answers.get(field, "unknown") != "unknown":
                known += 1
    return known, total


def _compute_input_specificity(company_description: str, signal_ids: set[str]) -> float:
    text = (company_description or "").strip().lower()
    if not text:
        return 0.0

    tokens = re.findall(r"[a-z0-9]+", text)
    token_count = len(tokens)
    unique_ratio = len(set(tokens)) / max(1, token_count)
    detail_score = min(1.0, token_count / 40.0)
    keyword_score = 0.0
    for pattern in (
        r"\baws\b|\bazure\b|\bgcp\b",
        r"\bmfa\b|\bsso\b|\biam\b",
        r"\bbackup\b|\brestore\b",
        r"\blog(?:ging)?\b|\bmonitor(?:ing)?\b|\balert(?:ing|s)?\b",
        r"\bapi\b|\binternet\b|\bpublic\b",
    ):
        if re.search(pattern, text, flags=re.IGNORECASE):
            keyword_score += 0.15

    signal_bonus = min(0.3, 0.05 * len(signal_ids))
    return _clamp(0.45 * detail_score + 0.25 * unique_ratio + 0.20 * min(1.0, keyword_score) + 0.10 * signal_bonus)


def _compute_confidence(
    questionnaire: dict[str, dict[str, str]],
    matched_signals: list[RiskSignal],
    control_evidence_quality: float,
    company_description: str,
    config: dict[str, dict[str, float]],
) -> tuple[float, dict[str, float]]:
    weights = config["confidence_weights"]

    known, total = _count_known_questionnaire_answers(questionnaire)
    questionnaire_completeness = known / max(1, total)

    signal_coverage = _clamp(len(matched_signals) / 6.0)
    input_specificity = _compute_input_specificity(company_description, _signal_set(matched_signals))

    factors = {
        "questionnaire_completeness": _clamp(questionnaire_completeness),
        "signal_coverage": signal_coverage,
        "control_evidence_quality": _clamp(control_evidence_quality),
        "input_specificity": input_specificity,
    }
    return _weighted_sum(weights, factors), factors


def _risk_level(score: int) -> str:
    if score <= 20:
        return "Low"
    if score <= 45:
        return "Moderate"
    if score <= 70:
        return "High"
    return "Critical"


def assess_company_risk(
    company_description: str,
    questionnaire_context: dict[str, dict[str, str]] | None = None,
) -> RiskAssessment:
    """Run deterministic keyword-based risk assessment for SME narratives."""
    text = (company_description or "").strip()
    questionnaire = questionnaire_context or {}

    signal_hints = to_signal_hints(questionnaire)
    normalized = f"{text} {signal_hints}".strip().lower()

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

    signal_ids = _signal_set(matched_signals)
    signal_weight_total = sum(signal.weight for signal in matched_signals)
    factor_config = _load_factor_config()

    likelihood_factors = _compute_likelihood_factors(questionnaire, signal_ids, signal_weight_total)
    impact_factors = _compute_impact_factors(questionnaire, signal_ids)

    likelihood = _weighted_sum(factor_config["likelihood_weights"], likelihood_factors)
    impact = _weighted_sum(factor_config["impact_weights"], impact_factors)

    inherent_risk = int(round(_clamp(likelihood * impact * 100.0, 0.0, 100.0)))

    control_reduction_adjusted, control_snapshot, control_evidence_quality = _compute_control_reduction(
        questionnaire,
        signal_ids,
        factor_config,
    )
    residual_risk = int(
        round(_clamp(inherent_risk * (1.0 - control_reduction_adjusted), 0.0, 100.0))
    )

    confidence, confidence_factors = _compute_confidence(
        questionnaire,
        matched_signals,
        control_evidence_quality,
        text,
        factor_config,
    )

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

    factor_snapshot: dict[str, object] = {
        "likelihood_weights": factor_config["likelihood_weights"],
        "likelihood_factors": {k: round(v, 4) for k, v in likelihood_factors.items()},
        "impact_weights": factor_config["impact_weights"],
        "impact_factors": {k: round(v, 4) for k, v in impact_factors.items()},
        "control": control_snapshot,
        "confidence_weights": factor_config["confidence_weights"],
        "confidence_factors": {k: round(v, 4) for k, v in confidence_factors.items()},
        "signal_weight_total": signal_weight_total,
    }

    return RiskAssessment(
        company_input=text,
        overall_score=residual_risk,
        risk_level=_risk_level(residual_risk),
        likelihood=round(likelihood, 4),
        impact=round(impact, 4),
        inherent_risk=inherent_risk,
        residual_risk=residual_risk,
        control_reduction=round(control_reduction_adjusted, 4),
        confidence=round(confidence, 4),
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
        questionnaire=questionnaire,
        factor_snapshot=factor_snapshot,
        questionnaire_context=questionnaire,
    )
