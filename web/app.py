"""Streamlit web app for Astraut Risk Reasoner."""

from __future__ import annotations

import re
import sys
import math
import json
import copy
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st
from groq import Groq

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from astraut_risk.checklist import CHECKLIST_ITEMS, CHECKLIST_ROWS
from astraut_risk.assessment_formatter import compose_assessment_markdown
from astraut_risk.assessment_store import save_cached_result
from astraut_risk.config import (
    DEFAULT_MODEL,
    MissingApiKeyError,
    get_groq_api_key,
    load_environment,
)
from astraut_risk.matrix import MATRIX_ROWS
from astraut_risk.questionnaire import (
    default_questionnaire,
    infer_questionnaire_from_text,
    merge_questionnaire,
    normalize_questionnaire_mode,
    questionnaire_override_from_template_answers,
    questionnaire_templates,
)
from astraut_risk.risk_engine import assess_company_risk
from astraut_risk.reasoning import (
    InvalidInputError,
    LLMAPIError,
    NetworkError,
    build_assessment_messages,
    request_completion,
    validate_company_description,
)
from astraut_risk.scenarios import SCENARIOS

load_environment()

_YN_UNKNOWN = ["unknown", "yes", "no"]
_SIZE_OPTIONS = ["sme", "mid_market", "enterprise"]
_SENSITIVITY_OPTIONS = ["unknown", "low", "medium", "high"]
_REGULATORY_OPTIONS = ["unknown", "unregulated", "regulated"]
_IDENTITY_OPTIONS = ["unknown", "basic", "advanced"]
_DEFAULT_REQUIREMENTS_INDEX = PROJECT_ROOT / "assessments" / "security_requirements_index.json"
_DEFAULT_RADAR_SCORING_CONFIG = PROJECT_ROOT / "assessments" / "radar_scoring_config.json"
_WORST_CASE_TEST_DESCRIPTION = (
    "SaaS platform with public API and internet-facing services on AWS. "
    "No MFA on admin accounts, shared logins in use, weak passwords, no least privilege, "
    "flat network with no segmentation, unmanaged cloud resources, no incident response plan, "
    "backups not tested, no recovery testing, weak CI/CD controls, unpatched dependencies, "
    "and no dependency scanning."
)

_RADAR_SCORING_DEFAULTS: dict[str, object] = {
    "core_risk": {
        "data_sensitivity_bonus": {"high": 18.0, "medium": 8.0, "default": 0.0},
        "public_api_confidentiality_bonus": 8.0,
        "integrity_signal_factor": 0.9,
        "availability_signal_factor": 1.2,
        "external_surface": {
            "internet_exposed": {"yes": 92.0, "no": 30.0, "unknown": 50.0},
            "public_api": {"yes": 90.0, "no": 35.0, "unknown": 50.0},
        },
        "exploitability_signal_factor": 1.1,
        "detectability": {
            "logging_monitoring": {"yes": 25.0, "no": 88.0, "unknown": 50.0},
            "incident_response_plan": {"yes": 30.0, "no": 86.0, "unknown": 50.0},
        },
        "recovery": {
            "backup_restore_tested": {"yes": 25.0, "no": 92.0, "unknown": 50.0},
            "incident_response_plan": {"yes": 30.0, "no": 88.0, "unknown": 50.0},
        },
        "data_sensitivity_score": {"high": 90.0, "medium": 65.0, "low": 40.0, "unknown": 55.0},
        "privilege_exposure_signal_factor": 1.5,
        "identity_maturity_bonus": {"basic": 20.0, "advanced": 10.0, "unknown": 15.0},
        "residual_control_factor": 0.9,
    },
    "vulnerability": {
        "cvss_weight_factor": 6.5,
        "patch_status": {"unpatched": 90.0, "scan_missing": 55.0, "default": 35.0},
        "asset_criticality_company_size_bonus": 10.0,
        "attack_vector": {
            "internet_exposed": {"yes": 92.0, "no": 30.0, "unknown": 50.0},
            "public_api": {"yes": 90.0, "no": 35.0, "unknown": 50.0},
        },
        "authentication_requirement": {"mfa_yes": 20.0, "mfa_no": 90.0, "unknown": 50.0},
        "known_active_exploitation": {"hot": 88.0, "default": 55.0},
        "configuration_weakness_signal_factor": 1.6,
        "dependency_risk_signal_factor": 1.8,
        "age_of_vulnerability": {"unpatched": 82.0, "scan_missing": 58.0, "default": 42.0},
        "compensating_controls_multiplier": 100.0,
    },
    "controls": {
        "preventive": {
            "mfa": {"yes": 25.0, "no": 90.0, "unknown": 50.0},
            "segmentation": {"yes": 30.0, "no": 88.0, "unknown": 50.0},
        },
        "detective": {"logging": {"yes": 25.0, "no": 88.0, "unknown": 50.0}},
        "response": {"ir_plan": {"yes": 30.0, "no": 90.0, "unknown": 50.0}},
        "patch_mgmt": {"unpatched": 90.0, "scan_missing": 62.0, "default": 35.0},
        "segmentation_maturity": {"yes": 25.0, "no": 90.0, "unknown": 50.0},
        "iam_signal_factor": 1.4,
        "encryption": {"low_confidence": 48.0, "default": 35.0},
        "backup_recovery": {"yes": 25.0, "no": 92.0, "unknown": 50.0},
        "awareness": {"weak": 86.0, "default": 46.0},
        "compliance_alignment": {"with_standards": 35.0, "without_standards": 85.0},
    },
}


def _strip_rich_box(line: str) -> str:
    stripped = line.strip()
    if not stripped:
        return ""
    if stripped.startswith("╭") or stripped.startswith("╰"):
        return ""
    if stripped.startswith("│") and stripped.endswith("│"):
        inner = stripped.strip("│").strip()
        return inner
    return line


def _merge_nested_dict(base: dict[str, object], override: dict[str, object]) -> dict[str, object]:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if (
            key in merged
            and isinstance(merged[key], dict)
            and isinstance(value, dict)
        ):
            merged[key] = _merge_nested_dict(merged[key], value)
        else:
            merged[key] = value
    return merged


def _cfg_value(config: dict[str, object], path: str, default: float) -> float:
    current: object = config
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return float(default)
        current = current[part]
    try:
        return float(current)
    except (TypeError, ValueError):
        return float(default)


def _load_radar_scoring_config(path_text: str) -> tuple[dict[str, object], str | None]:
    path = Path(path_text).expanduser()
    if not path.exists():
        return copy.deepcopy(_RADAR_SCORING_DEFAULTS), f"Radar scoring config not found: {path}"
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return copy.deepcopy(_RADAR_SCORING_DEFAULTS), f"Radar scoring config parse error: {exc}"
    if not isinstance(parsed, dict):
        return copy.deepcopy(_RADAR_SCORING_DEFAULTS), "Radar scoring config must be a JSON object."
    return _merge_nested_dict(_RADAR_SCORING_DEFAULTS, parsed), None


def _extract_sections(raw_text: str) -> dict[str, str]:
    cleaned_lines = [_strip_rich_box(line) for line in raw_text.splitlines()]
    cleaned_text = "\n".join(line for line in cleaned_lines if line.strip())

    sections: dict[str, str] = {}
    current = "_full"
    buffer: list[str] = []

    for line in cleaned_text.splitlines():
        if line.strip().startswith("## "):
            sections[current] = "\n".join(buffer).strip()
            current = line.strip()[3:].strip()
            buffer = []
        else:
            buffer.append(line)

    sections[current] = "\n".join(buffer).strip()
    sections = {k: v for k, v in sections.items() if v}
    if len(sections) > 1:
        return sections

    # Fallback for non-markdown model outputs (e.g., "Top 3 Risks:").
    heading_re = re.compile(
        r"^(overall risk score|top 3 risks|top risks|personalized recommendations|"
        r"recommendations|7-day action checklist|7 day action checklist|7-day action plan|"
        r"action plan|suggested investment priorities(?:\s*\([^)]*\))?|"
        r"investment priorities)\s*:\s*(.*)$",
        flags=re.IGNORECASE,
    )
    plain_sections: dict[str, str] = {}
    current_plain = "_full"
    plain_buffer: list[str] = []
    for line in cleaned_text.splitlines():
        match = heading_re.match(line.strip())
        if match:
            plain_sections[current_plain] = "\n".join(plain_buffer).strip()
            current_plain = match.group(1).strip()
            plain_buffer = []
            inline_value = match.group(2).strip()
            if inline_value:
                plain_buffer.append(inline_value)
        else:
            plain_buffer.append(line)
    plain_sections[current_plain] = "\n".join(plain_buffer).strip()
    plain_sections = {k: v for k, v in plain_sections.items() if v}
    if len(plain_sections) > 1:
        return plain_sections

    # Final fallback: detect heading blocks even with markdown decoration.
    block_heading_re = re.compile(
        r"(?:^|\n)\s*(?:[#>*\-\s]*)\*{0,2}"
        r"(overall risk score|top 3 risks|top risks|personalized recommendations|"
        r"recommendations|7-day action checklist|7 day action checklist|"
        r"7-day action plan|action plan|"
        r"suggested investment priorities(?:\s*\([^)]*\))?|investment priorities)"
        r"\*{0,2}\s*:\s*",
        flags=re.IGNORECASE,
    )
    matches = list(block_heading_re.finditer(cleaned_text))
    if not matches:
        return plain_sections

    extracted: dict[str, str] = {}
    for idx, match in enumerate(matches):
        heading = match.group(1).strip()
        content_start = match.end()
        content_end = matches[idx + 1].start() if idx + 1 < len(matches) else len(
            cleaned_text
        )
        body = cleaned_text[content_start:content_end].strip()
        if body:
            extracted[heading] = body
    return extracted or plain_sections


def _normalize_heading(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", text.strip().lower()).strip()


def _get_section(sections: dict[str, str], aliases: list[str]) -> str:
    normalized_sections = {_normalize_heading(k): v for k, v in sections.items()}
    for alias in aliases:
        match = normalized_sections.get(_normalize_heading(alias))
        if match:
            return match
    for alias in aliases:
        alias_norm = _normalize_heading(alias)
        for key_norm, value in normalized_sections.items():
            if alias_norm and alias_norm in key_norm:
                return value
            if key_norm and key_norm in alias_norm:
                return value
    return "Not available"


def _risk_score_from_text(text: str, full_text: str = "") -> str:
    match = re.search(r"\b(\d{1,2})\s*/\s*10\b", text)
    if match:
        return match.group(0)
    match_100 = re.search(r"\b(\d{1,3})\s*/\s*100\b", text)
    if match_100:
        return match_100.group(0)
    num_match = re.search(r"\boverall risk score\s*:\s*(\d{1,2})\b", full_text, re.I)
    if num_match:
        return f"{num_match.group(1)}/10"
    return text


def _table_from_list_text(text: str) -> list[dict[str, str]]:
    items: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if re.match(r"^\d+\.\s+", line):
            items.append(re.sub(r"^\d+\.\s+", "", line))
        elif re.match(r"^\d+\s+", line):
            items.append(re.sub(r"^\d+\s+", "", line))
        elif line.startswith("- "):
            items.append(line[2:].strip())

    if not items:
        # Fallback: preserve line-by-line content for plain-text outputs.
        items = [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.strip().endswith(":")
        ]

    if not items and text.strip():
        items = [text.strip()]

    return [{"Item": item} for item in items]


def _risk_band_from_score(score_100: float) -> str:
    if score_100 >= 80:
        return "Critical"
    if score_100 >= 60:
        return "High"
    if score_100 >= 30:
        return "Medium"
    return "Low"


def _risk_band_from_signal_weight(weight: int) -> str:
    if weight >= 14:
        return "High"
    if weight >= 10:
        return "Medium"
    return "Low"


def _framework_reference_counts(framework_references: dict[str, list[object]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    seen: set[tuple[str, str]] = set()
    for refs in framework_references.values():
        for ref in refs:
            key = (ref.framework, ref.control_id)
            if key in seen:
                continue
            seen.add(key)
            counts[ref.framework] = counts.get(ref.framework, 0) + 1
    return counts


def _nist_control_counts(framework_references: dict[str, list[object]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    seen: set[tuple[str, str]] = set()
    for refs in framework_references.values():
        for ref in refs:
            if ref.framework != "NIST":
                continue
            key = (ref.framework, ref.control_id)
            if key in seen:
                continue
            seen.add(key)
            counts[ref.control_id] = counts.get(ref.control_id, 0) + 1
    return counts


def _framework_counts_from_mapped_requirements(mapped_requirements: list[object]) -> dict[str, int]:
    counts: dict[str, int] = {}
    seen: set[tuple[str, str]] = set()
    for control in mapped_requirements:
        for ref in control.framework_refs:
            key = (ref.framework, ref.control_id)
            if key in seen:
                continue
            seen.add(key)
            counts[ref.framework] = counts.get(ref.framework, 0) + 1
    return counts


def _radar_points(dimensions: list[tuple[str, float]]) -> tuple[pd.DataFrame, float]:
    """Return closed polygon points for a radar chart in cartesian coordinates."""
    if not dimensions:
        return pd.DataFrame(columns=["dimension", "value", "x", "y", "order"]), 1.0

    max_value = max(float(value) for _, value in dimensions)
    radius_max = max(1.0, max_value)
    total = len(dimensions)
    points: list[dict[str, float | str | int]] = []
    for idx, (name, value) in enumerate(dimensions):
        angle = (2.0 * math.pi * idx / total) - (math.pi / 2.0)
        r = float(value)
        points.append(
            {
                "dimension": name,
                "value": r,
                "x": r * math.cos(angle),
                "y": r * math.sin(angle),
                "order": idx,
            }
        )
    # close polygon by repeating first point
    first = points[0]
    points.append({**first, "order": total})
    return pd.DataFrame(points), radius_max


def _clamp_score(value: float, *, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, float(value)))


def _yn_value(raw: str) -> float:
    value = (raw or "").strip().lower()
    if value == "yes":
        return 100.0
    if value == "no":
        return 0.0
    return 50.0


def _risk_yes_no(raw: str, *, yes_risk: float, no_risk: float, unknown_risk: float = 50.0) -> float:
    value = (raw or "").strip().lower()
    if value == "yes":
        return yes_risk
    if value == "no":
        return no_risk
    return unknown_risk


def _signal_weight(assessment, signal_ids: set[str]) -> int:
    return sum(s.weight for s in assessment.matched_signals if s.signal_id in signal_ids)


def _build_core_risk_axes(assessment, scoring_cfg: dict[str, object]) -> list[tuple[str, float]]:
    questionnaire = assessment.questionnaire_context or {}
    tech = questionnaire.get("technical_architecture", {})
    business = questionnaire.get("business", {})
    maturity = questionnaire.get("maturity", {})
    c = lambda p, d: _cfg_value(scoring_cfg, p, d)

    base_likelihood = float(assessment.likelihood) * 100.0
    base_impact = float(assessment.impact) * 100.0

    conf_impact = base_impact + (
        c("core_risk.data_sensitivity_bonus.high", 18.0)
        if business.get("data_sensitivity") == "high"
        else c("core_risk.data_sensitivity_bonus.medium", 8.0)
        if business.get("data_sensitivity") == "medium"
        else c("core_risk.data_sensitivity_bonus.default", 0.0)
    )
    if tech.get("public_api") == "yes":
        conf_impact += c("core_risk.public_api_confidentiality_bonus", 8.0)

    integrity_impact = base_impact + (
        _signal_weight(assessment, {"weak_cicd_controls", "no_dependency_scanning", "unpatched_dependencies"})
        * c("core_risk.integrity_signal_factor", 0.9)
    )
    availability_impact = base_impact + (
        _signal_weight(assessment, {"no_tested_backups", "no_recovery_testing", "no_incident_plan"})
        * c("core_risk.availability_signal_factor", 1.2)
    )

    external_surface = (
        _risk_yes_no(
            tech.get("internet_exposed", "unknown"),
            yes_risk=c("core_risk.external_surface.internet_exposed.yes", 92.0),
            no_risk=c("core_risk.external_surface.internet_exposed.no", 30.0),
            unknown_risk=c("core_risk.external_surface.internet_exposed.unknown", 50.0),
        )
        + _risk_yes_no(
            tech.get("public_api", "unknown"),
            yes_risk=c("core_risk.external_surface.public_api.yes", 90.0),
            no_risk=c("core_risk.external_surface.public_api.no", 35.0),
            unknown_risk=c("core_risk.external_surface.public_api.unknown", 50.0),
        )
    ) / 2.0

    exploitability = base_likelihood + (
        _signal_weight(assessment, {"no_mfa", "weak_passwords", "shared_accounts", "public_api"})
        * c("core_risk.exploitability_signal_factor", 1.1)
    )

    detectability = (
        _risk_yes_no(
            tech.get("logging_monitoring", "unknown"),
            yes_risk=c("core_risk.detectability.logging_monitoring.yes", 25.0),
            no_risk=c("core_risk.detectability.logging_monitoring.no", 88.0),
            unknown_risk=c("core_risk.detectability.logging_monitoring.unknown", 50.0),
        )
        + _risk_yes_no(
            maturity.get("incident_response_plan", "unknown"),
            yes_risk=c("core_risk.detectability.incident_response_plan.yes", 30.0),
            no_risk=c("core_risk.detectability.incident_response_plan.no", 86.0),
            unknown_risk=c("core_risk.detectability.incident_response_plan.unknown", 50.0),
        )
    ) / 2.0

    recovery_capability = (
        _risk_yes_no(
            tech.get("backup_restore_tested", "unknown"),
            yes_risk=c("core_risk.recovery.backup_restore_tested.yes", 25.0),
            no_risk=c("core_risk.recovery.backup_restore_tested.no", 92.0),
            unknown_risk=c("core_risk.recovery.backup_restore_tested.unknown", 50.0),
        )
        + _risk_yes_no(
            maturity.get("incident_response_plan", "unknown"),
            yes_risk=c("core_risk.recovery.incident_response_plan.yes", 30.0),
            no_risk=c("core_risk.recovery.incident_response_plan.no", 88.0),
            unknown_risk=c("core_risk.recovery.incident_response_plan.unknown", 50.0),
        )
    ) / 2.0

    data_sensitivity = (
        c("core_risk.data_sensitivity_score.high", 90.0)
        if business.get("data_sensitivity") == "high"
        else c("core_risk.data_sensitivity_score.medium", 65.0)
        if business.get("data_sensitivity") == "medium"
        else c("core_risk.data_sensitivity_score.low", 40.0)
        if business.get("data_sensitivity") == "low"
        else c("core_risk.data_sensitivity_score.unknown", 55.0)
    )
    privilege_exposure = (
        _signal_weight(assessment, {"no_mfa", "shared_accounts", "no_least_privilege", "weak_passwords"})
        * c("core_risk.privilege_exposure_signal_factor", 1.5)
    ) + (
        c("core_risk.identity_maturity_bonus.basic", 20.0)
        if maturity.get("identity_maturity") == "basic"
        else c("core_risk.identity_maturity_bonus.advanced", 10.0)
        if maturity.get("identity_maturity") == "advanced"
        else c("core_risk.identity_maturity_bonus.unknown", 15.0)
    )

    return [
        ("Likelihood of exploitation", _clamp_score(base_likelihood)),
        ("Impact on confidentiality", _clamp_score(conf_impact)),
        ("Impact on integrity", _clamp_score(integrity_impact)),
        ("Impact on availability", _clamp_score(availability_impact)),
        ("Exposure surface", _clamp_score(external_surface)),
        ("Exploitability", _clamp_score(exploitability)),
        ("Detectability", _clamp_score(detectability)),
        ("Recovery capability", _clamp_score(recovery_capability)),
        ("Data sensitivity", _clamp_score(data_sensitivity)),
        ("User privilege exposure", _clamp_score(privilege_exposure)),
    ]


def _build_vulnerability_variables(
    assessment, scoring_cfg: dict[str, object]
) -> list[tuple[str, float]]:
    questionnaire = assessment.questionnaire_context or {}
    tech = questionnaire.get("technical_architecture", {})
    business = questionnaire.get("business", {})
    signals = {s.signal_id for s in assessment.matched_signals}
    c = lambda p, d: _cfg_value(scoring_cfg, p, d)
    avg_weight = (
        (sum(float(s.weight) for s in assessment.matched_signals) / len(assessment.matched_signals))
        if assessment.matched_signals
        else 0.0
    )

    return [
        ("CVSS base score (equiv)", _clamp_score(avg_weight * c("vulnerability.cvss_weight_factor", 6.5))),
        (
            "Patch status",
            _clamp_score(
                c("vulnerability.patch_status.unpatched", 90.0)
                if "unpatched_dependencies" in signals
                else c("vulnerability.patch_status.scan_missing", 55.0)
                if "no_dependency_scanning" in signals
                else c("vulnerability.patch_status.default", 35.0)
            ),
        ),
        (
            "Asset criticality",
            _clamp_score(
                float(assessment.impact) * 100.0
                + (
                    c("vulnerability.asset_criticality_company_size_bonus", 10.0)
                    if business.get("company_size") in {"mid_market", "enterprise"}
                    else 0.0
                )
            ),
        ),
        (
            "Attack vector",
            _clamp_score(
                (
                    _risk_yes_no(
                        tech.get("internet_exposed", "unknown"),
                        yes_risk=c("vulnerability.attack_vector.internet_exposed.yes", 92.0),
                        no_risk=c("vulnerability.attack_vector.internet_exposed.no", 30.0),
                        unknown_risk=c("vulnerability.attack_vector.internet_exposed.unknown", 50.0),
                    )
                    + _risk_yes_no(
                        tech.get("public_api", "unknown"),
                        yes_risk=c("vulnerability.attack_vector.public_api.yes", 90.0),
                        no_risk=c("vulnerability.attack_vector.public_api.no", 35.0),
                        unknown_risk=c("vulnerability.attack_vector.public_api.unknown", 50.0),
                    )
                ) / 2.0
            ),
        ),
        (
            "Authentication requirement",
            _clamp_score(
                _risk_yes_no(
                    tech.get("mfa_enforced", "unknown"),
                    yes_risk=c("vulnerability.authentication_requirement.mfa_yes", 20.0),
                    no_risk=c("vulnerability.authentication_requirement.mfa_no", 90.0),
                    unknown_risk=c("vulnerability.authentication_requirement.unknown", 50.0),
                )
            ),
        ),
        (
            "Known active exploitation",
            _clamp_score(
                c("vulnerability.known_active_exploitation.hot", 88.0)
                if "unpatched_dependencies" in signals and tech.get("public_api") == "yes"
                else c("vulnerability.known_active_exploitation.default", 55.0)
            ),
        ),
        (
            "Configuration weakness",
            _clamp_score(
                _signal_weight(assessment, {"no_segmentation", "flat_network", "unmanaged_cloud", "public_api"})
                * c("vulnerability.configuration_weakness_signal_factor", 1.6)
            ),
        ),
        (
            "Dependency risk",
            _clamp_score(
                _signal_weight(assessment, {"unpatched_dependencies", "no_dependency_scanning", "weak_cicd_controls"})
                * c("vulnerability.dependency_risk_signal_factor", 1.8)
            ),
        ),
        (
            "Age of vulnerability",
            _clamp_score(
                c("vulnerability.age_of_vulnerability.unpatched", 82.0)
                if "unpatched_dependencies" in signals
                else c("vulnerability.age_of_vulnerability.scan_missing", 58.0)
                if "no_dependency_scanning" in signals
                else c("vulnerability.age_of_vulnerability.default", 42.0)
            ),
        ),
        (
            "Compensating controls",
            _clamp_score(
                c("vulnerability.compensating_controls_multiplier", 100.0)
                - (float(assessment.control_reduction) * 100.0)
            ),
        ),
    ]


def _build_control_effectiveness_variables(
    assessment, scoring_cfg: dict[str, object]
) -> list[tuple[str, float]]:
    questionnaire = assessment.questionnaire_context or {}
    tech = questionnaire.get("technical_architecture", {})
    maturity = questionnaire.get("maturity", {})
    standards = set(assessment.applicable_standards)
    signals = {s.signal_id for s in assessment.matched_signals}
    c = lambda p, d: _cfg_value(scoring_cfg, p, d)

    return [
        (
            "Preventive control strength",
            _clamp_score((
                _risk_yes_no(
                    tech.get("mfa_enforced", "unknown"),
                    yes_risk=c("controls.preventive.mfa.yes", 25.0),
                    no_risk=c("controls.preventive.mfa.no", 90.0),
                    unknown_risk=c("controls.preventive.mfa.unknown", 50.0),
                )
                + _risk_yes_no(
                    tech.get("network_segmentation", "unknown"),
                    yes_risk=c("controls.preventive.segmentation.yes", 30.0),
                    no_risk=c("controls.preventive.segmentation.no", 88.0),
                    unknown_risk=c("controls.preventive.segmentation.unknown", 50.0),
                )
            ) / 2.0),
        ),
        (
            "Detective control coverage",
            _clamp_score(
                _risk_yes_no(
                    tech.get("logging_monitoring", "unknown"),
                    yes_risk=c("controls.detective.logging.yes", 25.0),
                    no_risk=c("controls.detective.logging.no", 88.0),
                    unknown_risk=c("controls.detective.logging.unknown", 50.0),
                )
            ),
        ),
        (
            "Response capability",
            _clamp_score(
                _risk_yes_no(
                    maturity.get("incident_response_plan", "unknown"),
                    yes_risk=c("controls.response.ir_plan.yes", 30.0),
                    no_risk=c("controls.response.ir_plan.no", 90.0),
                    unknown_risk=c("controls.response.ir_plan.unknown", 50.0),
                )
            ),
        ),
        (
            "Patch management effectiveness",
            _clamp_score(
                c("controls.patch_mgmt.unpatched", 90.0)
                if "unpatched_dependencies" in signals
                else c("controls.patch_mgmt.scan_missing", 62.0)
                if "no_dependency_scanning" in signals
                else c("controls.patch_mgmt.default", 35.0)
            ),
        ),
        (
            "Network segmentation maturity",
            _clamp_score(
                _risk_yes_no(
                    tech.get("network_segmentation", "unknown"),
                    yes_risk=c("controls.segmentation_maturity.yes", 25.0),
                    no_risk=c("controls.segmentation_maturity.no", 90.0),
                    unknown_risk=c("controls.segmentation_maturity.unknown", 50.0),
                )
            ),
        ),
        (
            "Identity and access management robustness",
            _clamp_score(
                _signal_weight(assessment, {"no_mfa", "no_least_privilege", "shared_accounts", "weak_passwords"})
                * c("controls.iam_signal_factor", 1.4)
            ),
        ),
        (
            "Encryption coverage",
            _clamp_score(
                c("controls.encryption.low_confidence", 48.0)
                if assessment.confidence < 0.6
                else c("controls.encryption.default", 35.0)
            ),
        ),
        (
            "Backup and recovery resilience",
            _clamp_score(
                _risk_yes_no(
                    tech.get("backup_restore_tested", "unknown"),
                    yes_risk=c("controls.backup_recovery.yes", 25.0),
                    no_risk=c("controls.backup_recovery.no", 92.0),
                    unknown_risk=c("controls.backup_recovery.unknown", 50.0),
                )
            ),
        ),
        (
            "Security awareness and human factor controls",
            _clamp_score(
                c("controls.awareness.weak", 86.0)
                if "weak_passwords" in signals or "shared_accounts" in signals
                else c("controls.awareness.default", 46.0)
            ),
        ),
        (
            "Compliance alignment",
            _clamp_score(
                c("controls.compliance_alignment.with_standards", 35.0)
                if standards
                else c("controls.compliance_alignment.without_standards", 85.0)
            ),
        ),
    ]


def _compose_web_assessment_markdown(
    company_assessment, llm_explanation: str
) -> str:
    return compose_assessment_markdown(
        company_assessment,
        llm_explanation,
        full_detail=True,
    )


def _run_assessment(
    company_description: str,
    *,
    use_cache: bool,
    refresh_cache: bool,
    questionnaire_context: dict[str, dict[str, str]],
    requirements_index: str = "",
) -> tuple[str, int, str, bool, object]:
    validate_company_description(company_description)
    deterministic = assess_company_risk(
        company_description,
        questionnaire_context=questionnaire_context,
        requirements_index=requirements_index,
    )
    from_cache = False
    api_key = get_groq_api_key(required=True)
    client = Groq(api_key=api_key)
    llm_explanation = request_completion(
        client=client,
        messages=build_assessment_messages(
            company_description, assessment=deterministic
        ),
        model=DEFAULT_MODEL,
    )
    if use_cache or refresh_cache:
        save_cached_result(
            company_description=company_description,
            model=DEFAULT_MODEL,
            assessment=deterministic,
            llm_explanation=llm_explanation,
            assessment_markdown=_compose_web_assessment_markdown(
                deterministic,
                llm_explanation,
            ),
        )

    content = _compose_web_assessment_markdown(
        deterministic,
        llm_explanation,
    )
    return content, deterministic.overall_score, deterministic.risk_level, from_cache, deterministic


def _mode_help_text(mode: str) -> str:
    if mode == "general":
        return "Minimal intake with broad headings and fewer answer choices."
    if mode == "medium":
        return "Balanced intake with operational security questions."
    return "Full detailed intake with controls-level fields and subheadings."


def _normalize_none_answers(questionnaire: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    normalized: dict[str, dict[str, str]] = {}
    for domain, fields in questionnaire.items():
        normalized[domain] = {}
        for field, value in fields.items():
            lowered = value.strip().lower() if isinstance(value, str) else ""
            normalized[domain][field] = "unknown" if lowered == "none" else value
    return normalized


def _worst_case_questionnaire_context() -> dict[str, dict[str, str]]:
    """Temporary helper for stress-testing report generation with high-risk defaults."""
    questionnaire = default_questionnaire()
    questionnaire["business"].update(
        {
            "industry": "other",
            "company_size": "enterprise",
            "data_sensitivity": "high",
        }
    )
    questionnaire["compliance"].update({"regulatory_profile": "regulated"})
    questionnaire["technical_architecture"].update(
        {
            "internet_exposed": "yes",
            "public_api": "yes",
            "mfa_enforced": "no",
            "network_segmentation": "no",
            "logging_monitoring": "no",
            "backup_restore_tested": "no",
        }
    )
    questionnaire["maturity"].update(
        {
            "incident_response_plan": "no",
            "identity_maturity": "basic",
        }
    )
    return questionnaire


st.set_page_config(page_title="Astraut Risk Reasoner", layout="wide")

st.title("Astraut Risk Reasoner")
st.markdown("AI-assisted cyber risk reasoning for small and medium businesses.")

st.sidebar.header("Project Info")
st.sidebar.markdown(
    "Astraut Risk Reasoner translates practical cybersecurity research into "
    "clear SME risk decisions."
)
st.sidebar.markdown(
    "GitHub repo: [astraut-risk-reasoner](https://github.com/astraut-solutions/astraut-risk-reasoner)"
)
show_raw_output = st.sidebar.checkbox("Show raw model output (debug)", value=False)
use_cached_assessments = st.sidebar.checkbox(
    "Save assessment snapshots",
    value=False,
)
refresh_cached_assessment = st.sidebar.checkbox(
    "Compatibility mode: --refresh-cache",
    value=False,
    help="Kept for parity with CLI flags. Runs fresh assessment and saves snapshot.",
)
use_requirements_index = st.sidebar.checkbox(
    "Enable internal requirements calibration (optional)",
    value=False,
    help=(
        "Optional internal calibration tooling. Enables local requirements retrieval "
        "for domains, mapped controls, and coverage."
    ),
)
requirements_index_path = st.sidebar.text_input(
    "Requirements index path",
    value=str(_DEFAULT_REQUIREMENTS_INDEX),
)
radar_scoring_config_path = st.sidebar.text_input(
    "Radar scoring config path",
    value=str(_DEFAULT_RADAR_SCORING_CONFIG),
    help="JSON file for radar variable weights and scoring thresholds.",
)
radar_scoring_cfg, radar_scoring_err = _load_radar_scoring_config(radar_scoring_config_path)
if radar_scoring_err:
    st.sidebar.warning(f"{radar_scoring_err}. Using built-in defaults.")

risk_tab, checklist_tab, matrix_tab = st.tabs(
    ["Risk Assessment", "Security Checklist", "Investment Matrix"]
)

with risk_tab:
    scenario_options = ["Custom"] + sorted(SCENARIOS.keys())
    selected_scenario = st.selectbox("Example scenario", scenario_options, index=0)
    default_description = (
        SCENARIOS[selected_scenario]["description"]
        if selected_scenario != "Custom"
        else ""
    )
    description = st.text_area(
        "Describe your company environment",
        placeholder="12-person SaaS startup on AWS using Gmail, Stripe, and a public API",
        value=default_description,
        height=120,
    )

    inferred_questionnaire = infer_questionnaire_from_text(description)
    st.subheader("Structured Questionnaire")

    mode_label = st.radio(
        "Input detail level",
        ["General (minimal)", "Medium", "Full Detailed"],
        horizontal=True,
    )
    selected_mode = normalize_questionnaire_mode(mode_label)
    st.caption(_mode_help_text(selected_mode))

    templates = questionnaire_templates()
    template_answers: dict[str, str | list[str]] = {}
    detailed_multi_select_headings = {
        "Architecture",
        "Cloud & IAM",
        "Data Security",
        "Infrastructure",
        "Application Security",
        "Operations",
        "Compliance",
    }
    st.markdown("### Mode Questions")
    for idx, item in enumerate(templates[selected_mode]):
        heading = str(item["heading"])
        question = str(item["question"])
        options = [str(option) for option in item.get("options", [])]
        widget_label = f"**{heading}**  \n{question}"
        widget_key = f"questionnaire_{selected_mode}_{idx}"
        use_multiselect = (
            (selected_mode == "medium" and heading == "Architecture")
            or (selected_mode == "detailed" and heading in detailed_multi_select_headings)
        )
        if use_multiselect:
            template_answers[heading] = st.multiselect(
                widget_label,
                options,
                key=widget_key,
            )
        else:
            template_answers[heading] = st.selectbox(
                widget_label,
                options,
                key=widget_key,
            )

    template_override = questionnaire_override_from_template_answers(
        selected_mode, template_answers
    )

    company_size = st.selectbox(
        "Company size",
        _SIZE_OPTIONS,
        index=_SIZE_OPTIONS.index(
            inferred_questionnaire["business"].get("company_size", "sme")
        )
        if inferred_questionnaire["business"].get("company_size", "sme")
        in _SIZE_OPTIONS
        else 0,
    )

    user_questionnaire: dict[str, dict[str, str]] = {"business": {"company_size": company_size}}

    if selected_mode in {"medium", "detailed"}:
        business_col, compliance_col = st.columns(2)
        with business_col:
            data_sensitivity = st.selectbox(
                "Data sensitivity",
                _SENSITIVITY_OPTIONS,
                index=_SENSITIVITY_OPTIONS.index(
                    inferred_questionnaire["business"].get("data_sensitivity", "unknown")
                )
                if inferred_questionnaire["business"].get("data_sensitivity", "unknown")
                in _SENSITIVITY_OPTIONS
                else 0,
            )
            user_questionnaire.setdefault("business", {})["data_sensitivity"] = data_sensitivity
        with compliance_col:
            regulatory_profile = st.selectbox(
                "Regulatory profile",
                _REGULATORY_OPTIONS,
                index=_REGULATORY_OPTIONS.index(
                    inferred_questionnaire["compliance"].get("regulatory_profile", "unknown")
                )
                if inferred_questionnaire["compliance"].get("regulatory_profile", "unknown")
                in _REGULATORY_OPTIONS
                else 0,
            )
            user_questionnaire.setdefault("compliance", {})[
                "regulatory_profile"
            ] = regulatory_profile

    if selected_mode == "detailed":
        st.markdown("### Full Detailed Fields")
        col1, col2 = st.columns(2)
        with col1:
            internet_exposed = st.selectbox(
                "Internet exposed workload",
                _YN_UNKNOWN,
                index=_YN_UNKNOWN.index(
                    inferred_questionnaire["technical_architecture"].get(
                        "internet_exposed", "unknown"
                    )
                )
                if inferred_questionnaire["technical_architecture"].get(
                    "internet_exposed", "unknown"
                )
                in _YN_UNKNOWN
                else 0,
            )
            public_api = st.selectbox(
                "Public API exposed",
                _YN_UNKNOWN,
                index=_YN_UNKNOWN.index(
                    inferred_questionnaire["technical_architecture"].get(
                        "public_api", "unknown"
                    )
                )
                if inferred_questionnaire["technical_architecture"].get("public_api", "unknown")
                in _YN_UNKNOWN
                else 0,
            )
            mfa_enforced = st.selectbox(
                "MFA enforced (admin/privileged)",
                _YN_UNKNOWN,
                index=_YN_UNKNOWN.index(
                    inferred_questionnaire["technical_architecture"].get(
                        "mfa_enforced", "unknown"
                    )
                )
                if inferred_questionnaire["technical_architecture"].get(
                    "mfa_enforced", "unknown"
                )
                in _YN_UNKNOWN
                else 0,
            )
            network_segmentation = st.selectbox(
                "Network segmentation",
                _YN_UNKNOWN,
                index=_YN_UNKNOWN.index(
                    inferred_questionnaire["technical_architecture"].get(
                        "network_segmentation", "unknown"
                    )
                )
                if inferred_questionnaire["technical_architecture"].get(
                    "network_segmentation", "unknown"
                )
                in _YN_UNKNOWN
                else 0,
            )

        with col2:
            logging_monitoring = st.selectbox(
                "Centralized logging and alerting",
                _YN_UNKNOWN,
                index=_YN_UNKNOWN.index(
                    inferred_questionnaire["technical_architecture"].get(
                        "logging_monitoring", "unknown"
                    )
                )
                if inferred_questionnaire["technical_architecture"].get(
                    "logging_monitoring", "unknown"
                )
                in _YN_UNKNOWN
                else 0,
            )
            backup_restore_tested = st.selectbox(
                "Backup restore tests",
                _YN_UNKNOWN,
                index=_YN_UNKNOWN.index(
                    inferred_questionnaire["technical_architecture"].get(
                        "backup_restore_tested", "unknown"
                    )
                )
                if inferred_questionnaire["technical_architecture"].get(
                    "backup_restore_tested", "unknown"
                )
                in _YN_UNKNOWN
                else 0,
            )
            incident_response_plan = st.selectbox(
                "Incident response plan",
                _YN_UNKNOWN,
                index=_YN_UNKNOWN.index(
                    inferred_questionnaire["maturity"].get("incident_response_plan", "unknown")
                )
                if inferred_questionnaire["maturity"].get("incident_response_plan", "unknown")
                in _YN_UNKNOWN
                else 0,
            )
            identity_maturity = st.selectbox(
                "Identity maturity",
                _IDENTITY_OPTIONS,
                index=_IDENTITY_OPTIONS.index(
                    inferred_questionnaire["maturity"].get("identity_maturity", "unknown")
                )
                if inferred_questionnaire["maturity"].get("identity_maturity", "unknown")
                in _IDENTITY_OPTIONS
                else 0,
            )

        user_questionnaire.setdefault("technical_architecture", {}).update(
            {
                "internet_exposed": internet_exposed,
                "public_api": public_api,
                "mfa_enforced": mfa_enforced,
                "network_segmentation": network_segmentation,
                "logging_monitoring": logging_monitoring,
                "backup_restore_tested": backup_restore_tested,
            }
        )
        user_questionnaire.setdefault("maturity", {}).update(
            {
                "incident_response_plan": incident_response_plan,
                "identity_maturity": identity_maturity,
            }
        )

    mode_context = merge_questionnaire(inferred_questionnaire, template_override)
    questionnaire_context = merge_questionnaire(mode_context, user_questionnaire)
    questionnaire_context = _normalize_none_answers(questionnaire_context)

    action_col_assess, action_col_worst = st.columns(2)
    run_assess = action_col_assess.button("Assess Risk", type="primary")
    run_worst_case = action_col_worst.button(
        "Run Worst-Case Test",
        help="Temporary test button: runs a predefined high-risk scenario.",
    )

    if run_assess or run_worst_case:
        run_description = description
        run_questionnaire_context = questionnaire_context
        if run_worst_case:
            run_description = _WORST_CASE_TEST_DESCRIPTION
            run_questionnaire_context = _worst_case_questionnaire_context()
            st.info("Running temporary predefined worst-case scenario.")

        try:
            with st.spinner("Analyzing environment..."):
                content, overall_score, risk_level, from_cache, deterministic = _run_assessment(
                    run_description,
                    use_cache=use_cached_assessments,
                    refresh_cache=refresh_cached_assessment,
                    questionnaire_context=run_questionnaire_context,
                    requirements_index=(
                        requirements_index_path
                        if use_requirements_index and Path(requirements_index_path).expanduser().exists()
                        else ""
                    ),
                )
            st.caption("Result source: fresh LLM run.")

            sections = _extract_sections(content)

            st.header("Full Assessment Report")
            st.markdown(content)

            st.header("Risk Visual Summary")
            overall_col, likelihood_col, impact_col, residual_col, confidence_col = st.columns(5)
            with overall_col:
                st.metric("Overall", f"{overall_score}/100")
                st.progress(min(100, max(0, overall_score)) / 100.0)
                st.caption(f"Band: {_risk_band_from_score(float(overall_score))}")
            with likelihood_col:
                likelihood_score = int(round(float(deterministic.likelihood) * 100))
                st.metric("Likelihood", f"{likelihood_score}/100")
                st.progress(min(100, max(0, likelihood_score)) / 100.0)
                st.caption(f"Band: {_risk_band_from_score(float(likelihood_score))}")
            with impact_col:
                impact_score = int(round(float(deterministic.impact) * 100))
                st.metric("Impact", f"{impact_score}/100")
                st.progress(min(100, max(0, impact_score)) / 100.0)
                st.caption(f"Band: {_risk_band_from_score(float(impact_score))}")
            with residual_col:
                residual_score = int(round(float(deterministic.residual_risk)))
                st.metric("Residual", f"{residual_score}/100")
                st.progress(min(100, max(0, residual_score)) / 100.0)
                st.caption(f"Band: {_risk_band_from_score(float(residual_score))}")
            with confidence_col:
                confidence_score = int(round(float(deterministic.confidence) * 100))
                st.metric("Confidence", f"{confidence_score}%")
                st.progress(min(100, max(0, confidence_score)) / 100.0)
                st.caption(f"Band: {_risk_band_from_score(float(confidence_score))}")

            st.subheader("Risk Signal Severity (High/Low)")
            if deterministic.matched_signals:
                sorted_signals = sorted(
                    deterministic.matched_signals,
                    key=lambda signal: signal.weight,
                    reverse=True,
                )
                band_counts = {"High": 0, "Medium": 0, "Low": 0}
                for signal in sorted_signals:
                    band_counts[_risk_band_from_signal_weight(signal.weight)] += 1

                count_cols = st.columns(3)
                count_cols[0].metric("High Signals", band_counts["High"])
                count_cols[1].metric("Medium Signals", band_counts["Medium"])
                count_cols[2].metric("Low Signals", band_counts["Low"])

                max_weight = max(signal.weight for signal in sorted_signals) or 1
                for signal in sorted_signals[:10]:
                    band = _risk_band_from_signal_weight(signal.weight)
                    st.markdown(
                        f"**{signal.label}** ({signal.category})  \n"
                        f"Weight: +{signal.weight} | Band: {band}"
                    )
                    st.progress(float(signal.weight) / float(max_weight))
            else:
                st.caption("No matched runtime signals to visualize.")

            st.subheader("Charts")
            chart_tab_overview, chart_tab_standards, chart_tab_vulns, chart_tab_controls = st.tabs(
                ["Overview", "Standards", "Vulnerabilities", "Controls"]
            )

            with chart_tab_overview:
                dimensions = [
                    ("Likelihood", int(round(float(deterministic.likelihood) * 100))),
                    ("Impact", int(round(float(deterministic.impact) * 100))),
                    ("Inherent", int(round(float(deterministic.inherent_risk)))),
                    ("Residual", int(round(float(deterministic.residual_risk)))),
                    ("Confidence", int(round(float(deterministic.confidence) * 100))),
                ]

                dim_df = pd.DataFrame(dimensions, columns=["dimension", "value"])
                dim_cols = st.columns(2)

                with dim_cols[0]:
                    pie = (
                        alt.Chart(dim_df)
                        .mark_arc(innerRadius=45)
                        .encode(
                            theta=alt.Theta(field="value", type="quantitative"),
                            color=alt.Color(field="dimension", type="nominal"),
                            tooltip=["dimension", "value"],
                        )
                        .properties(height=320)
                    )
                    st.altair_chart(pie, width='stretch')

                with dim_cols[1]:
                    radar_df, radar_radius = _radar_points(
                        [(str(row["dimension"]), float(row["value"])) for _, row in dim_df.iterrows()]
                    )
                    radar_base = alt.Chart(radar_df).encode(
                        x=alt.X(
                            field="x",
                            type="quantitative",
                            axis=None,
                            scale=alt.Scale(domain=[-radar_radius, radar_radius]),
                        ),
                        y=alt.Y(
                            field="y",
                            type="quantitative",
                            axis=None,
                            scale=alt.Scale(domain=[-radar_radius, radar_radius]),
                        ),
                    )
                    radar = alt.layer(
                        radar_base.mark_area(opacity=0.15),
                        radar_base.mark_line(point=True).encode(
                            order=alt.Order(field="order", type="quantitative"),
                            tooltip=["dimension", "value"],
                        ),
                    ).properties(height=320)
                    st.altair_chart(radar, width='stretch')

                st.markdown("**Core Risk Radar (Inherent vs Residual)**")
                core_axes = _build_core_risk_axes(deterministic, radar_scoring_cfg)
                residual_factor = _cfg_value(
                    radar_scoring_cfg,
                    "core_risk.residual_control_factor",
                    0.9,
                )
                control_factor = max(0.0, min(0.9, float(deterministic.control_reduction)))
                core_rows = []
                for axis, inherent in core_axes:
                    residual = _clamp_score(inherent * (1.0 - (control_factor * residual_factor)))
                    core_rows.append(
                        {
                            "axis": axis,
                            "inherent": round(inherent, 1),
                            "residual": round(residual, 1),
                        }
                    )
                core_df = pd.DataFrame(core_rows)
                mapping_by_axis = {
                    "Exploitability": "Vulnerability management, patching",
                    "Exposure surface": "Network controls, firewalls, segmentation",
                    "Detectability": "Logging, SIEM, alerting",
                    "Recovery capability": "Backup, disaster recovery planning",
                    "Data sensitivity": "Encryption, data classification policies",
                    "User privilege exposure": "IAM, least privilege, MFA",
                }
                core_df["control_mapping"] = core_df["axis"].map(mapping_by_axis).fillna("Cross-domain controls")
                st.dataframe(core_df, width='stretch', hide_index=True)

                inherent_points, inherent_radius = _radar_points(
                    [(row["axis"], float(row["inherent"])) for _, row in core_df.iterrows()]
                )
                inherent_points["layer"] = "Inherent"
                residual_points, residual_radius = _radar_points(
                    [(row["axis"], float(row["residual"])) for _, row in core_df.iterrows()]
                )
                residual_points["layer"] = "Residual"
                layered_radar_df = pd.concat([inherent_points, residual_points], ignore_index=True)
                layered_radius = max(inherent_radius, residual_radius, 100.0)

                layered_base = alt.Chart(layered_radar_df).encode(
                    x=alt.X(
                        field="x",
                        type="quantitative",
                        axis=None,
                        scale=alt.Scale(domain=[-layered_radius, layered_radius]),
                    ),
                    y=alt.Y(
                        field="y",
                        type="quantitative",
                        axis=None,
                        scale=alt.Scale(domain=[-layered_radius, layered_radius]),
                    ),
                    color=alt.Color(field="layer", type="nominal"),
                )
                layered_radar = alt.layer(
                    layered_base.mark_area(opacity=0.12).encode(
                        detail=alt.Detail(field="layer", type="nominal")
                    ),
                    layered_base.mark_line(point=True).encode(
                        detail=alt.Detail(field="layer", type="nominal"),
                        order=alt.Order(field="order", type="quantitative"),
                        tooltip=["layer", "dimension", "value"],
                    ),
                ).properties(height=460)
                st.altair_chart(layered_radar, width='stretch')
                st.caption(
                    "Scale: 0 = negligible/controlled, 50 = partial control/moderate risk, 100 = critical exposure/no effective control."
                )

            with chart_tab_standards:
                framework_counts = _framework_reference_counts(deterministic.framework_references)
                if framework_counts:
                    std_df = pd.DataFrame(
                        [{"standard": key, "controls": value} for key, value in framework_counts.items()]
                    )
                    std_cols = st.columns(2)
                    with std_cols[0]:
                        std_pie = (
                            alt.Chart(std_df)
                            .mark_arc(innerRadius=45)
                            .encode(
                                theta=alt.Theta(field="controls", type="quantitative"),
                                color=alt.Color(field="standard", type="nominal"),
                                tooltip=["standard", "controls"],
                            )
                            .properties(height=320)
                        )
                        st.altair_chart(std_pie, width='stretch')
                    with std_cols[1]:
                        std_bar = (
                            alt.Chart(std_df)
                            .mark_bar()
                            .encode(
                                x=alt.X(field="standard", type="nominal", sort="-y"),
                                y=alt.Y(field="controls", type="quantitative"),
                                tooltip=["standard", "controls"],
                            )
                            .properties(height=320)
                        )
                        st.altair_chart(std_bar, width='stretch')
                else:
                    st.caption("No framework mappings available for charting.")

                nist_counts = _nist_control_counts(deterministic.framework_references)
                st.markdown("**NIST Control Mappings**")
                if nist_counts:
                    nist_df = (
                        pd.DataFrame(
                            [{"control_id": key, "count": value} for key, value in nist_counts.items()]
                        )
                        .sort_values("control_id")
                        .head(12)
                    )
                    nist_bar = (
                        alt.Chart(nist_df)
                        .mark_bar()
                        .encode(
                            x=alt.X(field="control_id", type="nominal", title="NIST Control"),
                            y=alt.Y(field="count", type="quantitative", title="References"),
                            tooltip=["control_id", "count"],
                        )
                        .properties(height=320)
                    )
                    st.altair_chart(nist_bar, width='stretch')
                else:
                    st.caption("No NIST controls mapped in this run.")

            with chart_tab_vulns:
                if deterministic.matched_signals:
                    vuln_rows = []
                    for signal in deterministic.matched_signals:
                        vuln_rows.append(
                            {
                                "signal": signal.label,
                                "category": signal.category,
                                "weight": signal.weight,
                                "severity": _risk_band_from_signal_weight(signal.weight),
                            }
                        )
                    vuln_df = pd.DataFrame(vuln_rows).sort_values("weight", ascending=False)
                    st.markdown("**Vulnerability Register (chart source)**")
                    st.dataframe(vuln_df, width='stretch', hide_index=True)

                    severity_df = (
                        vuln_df.groupby("severity", as_index=False)
                        .agg(count=("signal", "count"), total_weight=("weight", "sum"))
                    )
                    severity_order = ["High", "Medium", "Low"]
                    severity_df["severity"] = pd.Categorical(
                        severity_df["severity"],
                        categories=severity_order,
                        ordered=True,
                    )
                    severity_df = severity_df.sort_values("severity")

                    vuln_cols = st.columns(2)
                    with vuln_cols[0]:
                        sev_pie = (
                            alt.Chart(severity_df)
                            .mark_arc(innerRadius=45)
                            .encode(
                                theta=alt.Theta(field="count", type="quantitative"),
                                color=alt.Color(field="severity", type="nominal"),
                                tooltip=["severity", "count", "total_weight"],
                            )
                            .properties(height=320)
                        )
                        st.altair_chart(sev_pie, width='stretch')
                    with vuln_cols[1]:
                        cat_df = (
                            vuln_df.groupby("category", as_index=False)
                            .agg(count=("signal", "count"), total_weight=("weight", "sum"))
                            .sort_values("total_weight", ascending=False)
                            .head(10)
                        )
                        cat_bar = (
                            alt.Chart(cat_df)
                            .mark_bar()
                            .encode(
                                x=alt.X(field="category", type="nominal", sort="-y"),
                                y=alt.Y(field="total_weight", type="quantitative", title="Total Weight"),
                                tooltip=["category", "count", "total_weight"],
                            )
                            .properties(height=320)
                        )
                        st.altair_chart(cat_bar, width='stretch')

                    radar_source = (
                        vuln_df.groupby("category", as_index=False)
                        .agg(value=("weight", "sum"))
                        .sort_values("value", ascending=False)
                    )
                    if not radar_source.empty:
                        vuln_radar_df, vuln_radius = _radar_points(
                            [
                                (str(row["category"]), float(row["value"]))
                                for _, row in radar_source.iterrows()
                            ]
                        )
                        vuln_base = alt.Chart(vuln_radar_df).encode(
                            x=alt.X(
                                field="x",
                                type="quantitative",
                                axis=None,
                                scale=alt.Scale(domain=[-vuln_radius, vuln_radius]),
                            ),
                            y=alt.Y(
                                field="y",
                                type="quantitative",
                                axis=None,
                                scale=alt.Scale(domain=[-vuln_radius, vuln_radius]),
                            ),
                        )
                        vuln_radar = alt.layer(
                            vuln_base.mark_area(opacity=0.15),
                            vuln_base.mark_line(point=True).encode(
                                order=alt.Order(field="order", type="quantitative"),
                                tooltip=["dimension", "value"],
                            ),
                        ).properties(height=360, title="Radar: Vulnerability Weight by Category")
                        st.altair_chart(vuln_radar, width='stretch')
                        st.caption(
                            "Radar axes: vulnerability categories; polygon radius: aggregated risk weight."
                        )

                    st.markdown("**Vulnerability Assessment Variables**")
                    vuln_var_df = pd.DataFrame(
                        [
                            {"variable": name, "score": round(score, 1)}
                            for name, score in _build_vulnerability_variables(
                                deterministic,
                                radar_scoring_cfg,
                            )
                        ]
                    )
                    st.dataframe(vuln_var_df, width='stretch', hide_index=True)
                    vuln_var_bar = (
                        alt.Chart(vuln_var_df)
                        .mark_bar()
                        .encode(
                            x=alt.X(field="score", type="quantitative", scale=alt.Scale(domain=[0, 100])),
                            y=alt.Y(field="variable", type="nominal", sort="-x"),
                            tooltip=["variable", "score"],
                        )
                        .properties(height=360)
                    )
                    st.altair_chart(vuln_var_bar, width='stretch')
                else:
                    st.caption("No matched signals available for vulnerability charts.")

            with chart_tab_controls:
                control_var_df = pd.DataFrame(
                    [
                        {"variable": name, "score": round(score, 1)}
                        for name, score in _build_control_effectiveness_variables(
                            deterministic,
                            radar_scoring_cfg,
                        )
                    ]
                )
                st.markdown("**Control Effectiveness Variables (Mitigation Scoring)**")
                st.dataframe(control_var_df, width='stretch', hide_index=True)
                control_bar = (
                    alt.Chart(control_var_df)
                    .mark_bar()
                    .encode(
                        x=alt.X(field="score", type="quantitative", scale=alt.Scale(domain=[0, 100])),
                        y=alt.Y(field="variable", type="nominal", sort="-x"),
                        tooltip=["variable", "score"],
                    )
                    .properties(height=400)
                )
                st.altair_chart(control_bar, width='stretch')

            st.header("Control Requirements")
            if deterministic.mapped_requirements:
                requirement_rows = []
                for control in deterministic.mapped_requirements:
                    frameworks = ", ".join(
                        sorted({f"{ref.framework} {ref.control_id}" for ref in control.framework_refs})
                    )
                    requirement_rows.append(
                        {
                            "Rank": control.retrieval_rank,
                            "Domain": control.mapped_layer,
                            "Severity": control.severity,
                            "Retrieval": round(control.retrieval_score, 4),
                            "Control": control.control_text_en[:220],
                            "Source": f"{control.document_title} v{control.document_version}",
                            "Frameworks": frameworks or "none",
                        }
                    )
                req_df = pd.DataFrame(requirement_rows).sort_values(
                    by=["Rank", "Retrieval"],
                    ascending=[True, False],
                )
                st.dataframe(req_df, width='stretch', hide_index=True)

                req_chart_col1, req_chart_col2 = st.columns(2)

                with req_chart_col1:
                    domain_df = (
                        req_df.groupby("Domain", as_index=False)
                        .agg(controls=("Control", "count"))
                        .sort_values("controls", ascending=False)
                    )
                    if not domain_df.empty:
                        domain_radar_df, domain_radius = _radar_points(
                            [
                                (str(row["Domain"]), float(row["controls"]))
                                for _, row in domain_df.iterrows()
                            ]
                        )
                        domain_base = alt.Chart(domain_radar_df).encode(
                            x=alt.X(
                                field="x",
                                type="quantitative",
                                axis=None,
                                scale=alt.Scale(domain=[-domain_radius, domain_radius]),
                            ),
                            y=alt.Y(
                                field="y",
                                type="quantitative",
                                axis=None,
                                scale=alt.Scale(domain=[-domain_radius, domain_radius]),
                            ),
                        )
                        domain_radar = alt.layer(
                            domain_base.mark_area(opacity=0.15),
                            domain_base.mark_line(point=True).encode(
                                order=alt.Order(field="order", type="quantitative"),
                                tooltip=["dimension", "value"],
                            ),
                        ).properties(height=360, title="Radar: Controls by Domain")
                        st.altair_chart(domain_radar, width='stretch')
                    else:
                        st.caption("No domain data for radar chart.")

                with req_chart_col2:
                    framework_counts = _framework_counts_from_mapped_requirements(
                        deterministic.mapped_requirements
                    )
                    if framework_counts:
                        framework_df = pd.DataFrame(
                            [{"framework": key, "controls": value} for key, value in framework_counts.items()]
                        ).sort_values("controls", ascending=False)
                        framework_radar_df, framework_radius = _radar_points(
                            [
                                (str(row["framework"]), float(row["controls"]))
                                for _, row in framework_df.iterrows()
                            ]
                        )
                        framework_base = alt.Chart(framework_radar_df).encode(
                            x=alt.X(
                                field="x",
                                type="quantitative",
                                axis=None,
                                scale=alt.Scale(domain=[-framework_radius, framework_radius]),
                            ),
                            y=alt.Y(
                                field="y",
                                type="quantitative",
                                axis=None,
                                scale=alt.Scale(domain=[-framework_radius, framework_radius]),
                            ),
                        )
                        framework_radar = alt.layer(
                            framework_base.mark_area(opacity=0.15),
                            framework_base.mark_line(point=True).encode(
                                order=alt.Order(field="order", type="quantitative"),
                                tooltip=["dimension", "value"],
                            ),
                        ).properties(height=360, title="Radar: Controls by Framework")
                        st.altair_chart(framework_radar, width='stretch')
                    else:
                        st.caption("No framework mappings found for control radar chart.")
            else:
                st.caption(
                    "No mapped requirement controls available. Enable requirements calibration to populate control tables and radar charts."
                )
                framework_counts = _framework_reference_counts(deterministic.framework_references)
                if framework_counts:
                    fallback_df = pd.DataFrame(
                        [{"framework": key, "controls": value} for key, value in framework_counts.items()]
                    ).sort_values("controls", ascending=False)
                    fallback_radar_df, fallback_radius = _radar_points(
                        [
                            (str(row["framework"]), float(row["controls"]))
                            for _, row in fallback_df.iterrows()
                        ]
                    )
                    fallback_base = alt.Chart(fallback_radar_df).encode(
                        x=alt.X(
                            field="x",
                            type="quantitative",
                            axis=None,
                            scale=alt.Scale(domain=[-fallback_radius, fallback_radius]),
                        ),
                        y=alt.Y(
                            field="y",
                            type="quantitative",
                            axis=None,
                            scale=alt.Scale(domain=[-fallback_radius, fallback_radius]),
                        ),
                    )
                    fallback_radar = alt.layer(
                        fallback_base.mark_area(opacity=0.15),
                        fallback_base.mark_line(point=True).encode(
                            order=alt.Order(field="order", type="quantitative"),
                            tooltip=["dimension", "value"],
                        ),
                    ).properties(height=360, title="Radar: Signal-linked Framework References")
                    st.altair_chart(fallback_radar, width='stretch')

            show_structured_dashboard = st.checkbox(
                "Show structured dashboard",
                value=False,
                help="Optional sectioned view of key report data.",
            )
            if show_structured_dashboard:
                st.header("Structured Dashboard")
                st.markdown(f"**Risk Score:** {overall_score}/100 ({risk_level})")

                st.subheader("Top Risks")
                top_risks = _get_section(sections, ["Top 3 Risks", "Top Risks"])
                st.markdown(top_risks)

                st.subheader("Framework Mapping")
                framework_mapping = _get_section(sections, ["Framework Mapping"])
                st.markdown(framework_mapping)

                st.subheader("Standard-Specific Outputs")
                cis_output = _get_section(sections, ["CIS Output"])
                nist_output = _get_section(sections, ["NIST Output"])
                owasp_output = _get_section(sections, ["OWASP Output"])
                standards_tab_cis, standards_tab_nist, standards_tab_owasp = st.tabs(
                    ["CIS", "NIST", "OWASP"]
                )
                with standards_tab_cis:
                    st.markdown(cis_output)
                with standards_tab_nist:
                    st.markdown(nist_output)
                with standards_tab_owasp:
                    st.markdown(owasp_output)

                st.subheader("Detailed Risk Register (Full)")
                detailed_risk_register = _get_section(sections, ["Detailed Risk Register (Full)"])
                st.markdown(detailed_risk_register)

                st.subheader("Runtime Panels")
                domains_panel, mapped_requirements_panel, coverage_panel = st.tabs(
                    ["Domains", "Mapped Requirements", "Coverage"]
                )

                with domains_panel:
                    if deterministic.detected_security_domains:
                        st.table(
                            [{"Domain": domain} for domain in deterministic.detected_security_domains]
                        )
                    else:
                        st.caption("No explicit domains detected from current input.")

                    if deterministic.runtime_category_layers:
                        st.subheader("Category to Layer Mapper")
                        st.table(
                            [
                                {
                                    "Layer": row["layer"],
                                    "Signal weight": row["signal_weight_total"],
                                    "Signals": row["signal_count"],
                                    "Mapped controls": row["mapped_control_count"],
                                    "Categories": ", ".join(row["categories"]),
                                }
                                for row in deterministic.runtime_category_layers
                            ]
                        )

                with mapped_requirements_panel:
                    if deterministic.mapped_requirements:
                        st.table(
                            [
                                {
                                    "Rank": control.retrieval_rank,
                                    "Domain": control.mapped_layer,
                                    "Severity": control.severity,
                                    "Retrieval score": round(control.retrieval_score, 4),
                                    "Reason": control.retrieval_reason or "baseline retrieval match",
                                    "Control": control.control_text_en[:180],
                                    "Source": f"{control.document_title} v{control.document_version}",
                                }
                                for control in deterministic.mapped_requirements[:30]
                            ]
                        )
                    else:
                        st.caption(
                            "No mapped controls available. Enable internal requirements calibration with a valid index."
                        )

                with coverage_panel:
                    if deterministic.requirements_calibration_enabled:
                        st.markdown(f"Coverage: **{deterministic.control_coverage_percent:.2f}%**")
                        st.caption(
                            "Coverage formula: retrieved controls / mapped applicable controls."
                        )
                        st.progress(
                            min(100, max(0, int(round(deterministic.control_coverage_percent)))) / 100
                        )
                        st.table(
                            [
                                {
                                    "Mapped applicable controls": deterministic.mapped_controls_count,
                                    "Retrieved controls": deterministic.retrieved_controls_count,
                                    "Controls in index": deterministic.requirements_controls_total,
                                }
                            ]
                        )
                        if deterministic.mapped_requirements:
                            domain_totals: dict[str, int] = {}
                            for control in deterministic.mapped_requirements:
                                domain_totals[control.mapped_layer] = (
                                    domain_totals.get(control.mapped_layer, 0) + 1
                                )
                            total_mapped = max(1, len(deterministic.mapped_requirements))
                            st.table(
                                [
                                    {
                                        "Domain": domain,
                                        "Mapped controls": count,
                                        "Share %": round((count / total_mapped) * 100.0, 2),
                                    }
                                    for domain, count in sorted(
                                        domain_totals.items(),
                                        key=lambda item: item[1],
                                        reverse=True,
                                    )
                                ]
                            )
                    else:
                        st.info(
                            "Requirements calibration is disabled. Enable it in the sidebar to compute mapped controls and coverage."
                        )

                st.subheader("Recommendations")
                recommendations = _get_section(
                    sections,
                    [
                        "Personalized Recommendations (Zero Trust first)",
                        "Personalized Recommendations",
                        "Recommendations",
                    ],
                )
                st.markdown(recommendations)

                st.subheader("7-Day Action Plan")
                action_plan = _get_section(
                    sections,
                    ["7-day Action Checklist", "7-Day Action Plan", "Action Plan"],
                )
                st.markdown(action_plan)

                st.subheader("Investment Matrix")
                priorities = _get_section(
                    sections,
                    [
                        "Suggested investment priorities (2025 matrix)",
                        "Suggested Investment Priorities",
                        "Investment Priorities",
                    ],
                )
                st.markdown(priorities)

                st.subheader("Method")
                method = _get_section(sections, ["Method"])
                st.markdown(method)

            if show_raw_output:
                with st.expander("Raw model output"):
                    st.markdown(content)

        except MissingApiKeyError:
            st.error("LLM API key not configured.")
        except InvalidInputError as exc:
            st.error(str(exc))
        except (LLMAPIError, NetworkError) as exc:
            st.error(f"LLM request failed: {exc}")
        except Exception as exc:  # pragma: no cover
            st.error(f"Unexpected error: {exc}")

with checklist_tab:
    st.header("Security Checklist")
    st.table(
        [
            {
                "Priority": row["priority"],
                "Control": row["control"],
                "Domain": row["domain"],
                "Target Outcome": row["target"],
                "Evidence": row["evidence"],
                "Cadence": row["cadence"],
            }
            for row in CHECKLIST_ROWS
        ]
    )
    with st.expander("Checklist Narrative"):
        st.table([{"Checklist Item": item} for item in CHECKLIST_ITEMS])

with matrix_tab:
    st.header("Investment Matrix")
    st.table(
        [
            {
                "Priority": row["priority"],
                "Investment Focus": row["focus"],
                "Why Now": row["why"],
                "SME Examples": row["examples"],
                "Effort": row["effort"],
                "Budget Band": row["investment_band"],
                "Time to Value": row["time_to_value"],
                "Expected Reduction": row["expected_risk_reduction"],
            }
            for row in MATRIX_ROWS
        ]
    )
