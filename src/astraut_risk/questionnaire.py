"""Structured questionnaire utilities for hybrid input collection."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Literal

QuestionValue = Literal["yes", "no", "unknown", "low", "medium", "high", "sme", "mid_market", "enterprise", "none", "basic", "advanced", "regulated", "unregulated", "other"]


def default_questionnaire() -> dict[str, dict[str, str]]:
    """Return a default four-domain questionnaire payload."""
    return {
        "business": {
            "industry": "other",
            "company_size": "sme",
            "data_sensitivity": "unknown",
        },
        "technical_architecture": {
            "internet_exposed": "unknown",
            "public_api": "unknown",
            "mfa_enforced": "unknown",
            "network_segmentation": "unknown",
            "logging_monitoring": "unknown",
            "backup_restore_tested": "unknown",
        },
        "compliance": {
            "regulatory_profile": "unknown",
        },
        "maturity": {
            "incident_response_plan": "unknown",
            "identity_maturity": "unknown",
        },
    }


def _detect_yes_no(text: str, yes_patterns: tuple[str, ...], no_patterns: tuple[str, ...]) -> str:
    if any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in no_patterns):
        return "no"
    if any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in yes_patterns):
        return "yes"
    return "unknown"


def infer_questionnaire_from_text(company_description: str) -> dict[str, dict[str, str]]:
    """Infer questionnaire defaults from free-text customer input."""
    text = (company_description or "").strip()
    lowered = text.lower()
    payload = default_questionnaire()

    payload["technical_architecture"]["public_api"] = _detect_yes_no(
        lowered,
        yes_patterns=(r"\bpublic\s+api\b", r"\binternet[\s-]*facing\s+api\b"),
        no_patterns=(r"\bprivate\s+api\b",),
    )
    payload["technical_architecture"]["mfa_enforced"] = _detect_yes_no(
        lowered,
        yes_patterns=(r"\bmfa\s+(enabled|enforced|required)\b",),
        no_patterns=(r"\bno\s+mfa\b", r"\bwithout\s+mfa\b"),
    )
    payload["technical_architecture"]["network_segmentation"] = _detect_yes_no(
        lowered,
        yes_patterns=(r"\bnetwork\s+segmentation\b", r"\bsegmented\s+network\b"),
        no_patterns=(r"\bno\s+segmentation\b", r"\bflat\s+network\b"),
    )
    payload["technical_architecture"]["logging_monitoring"] = _detect_yes_no(
        lowered,
        yes_patterns=(r"\bcentralized\s+logging\b", r"\bmonitoring\b", r"\balerting\b"),
        no_patterns=(r"\bno\s+logging\b", r"\bno\s+alerting\b", r"\bwithout\s+logs\b"),
    )
    payload["technical_architecture"]["backup_restore_tested"] = _detect_yes_no(
        lowered,
        yes_patterns=(r"\btested\s+backups\b", r"\brestore\s+test\b"),
        no_patterns=(r"\bbackups?\s+not\s+tested\b", r"\bno\s+tested\s+backups\b"),
    )
    payload["maturity"]["incident_response_plan"] = _detect_yes_no(
        lowered,
        yes_patterns=(r"\bincident\s+response\s+plan\b", r"\bincident\s+plan\b"),
        no_patterns=(r"\bno\s+incident\s+plan\b", r"\bundocumented\s+incident\b"),
    )

    if re.search(r"\bpublic\b|\binternet[\s-]*facing\b|\bsaas\b", lowered):
        payload["technical_architecture"]["internet_exposed"] = "yes"
    elif re.search(r"\binternal\s+only\b|\bprivate\s+network\b", lowered):
        payload["technical_architecture"]["internet_exposed"] = "no"

    if re.search(r"\bhealth\b|\bclinic\b|\bpatient\b|\behr\b|\bphi\b", lowered):
        payload["compliance"]["regulatory_profile"] = "regulated"
        payload["business"]["data_sensitivity"] = "high"
    elif re.search(r"\bfinance\b|\bpayment\b|\bcard\b|\bpii\b", lowered):
        payload["compliance"]["regulatory_profile"] = "regulated"
        payload["business"]["data_sensitivity"] = "high"
    elif re.search(r"\bmarketing\b|\bblog\b|\bpublic\s+content\b", lowered):
        payload["business"]["data_sensitivity"] = "low"

    if re.search(r"\b([1-9]|[1-4][0-9])[-\s]?person\b", lowered):
        payload["business"]["company_size"] = "sme"
    elif re.search(r"\b([5-9][0-9]|[1-9][0-9]{2,})[-\s]?person\b", lowered):
        payload["business"]["company_size"] = "mid_market"

    if re.search(r"\bleast\s+privilege\b|\brole[-\s]*based\s+access\b", lowered):
        payload["maturity"]["identity_maturity"] = "advanced"
    elif re.search(r"\bshared\s+accounts?\b|\boverprivileged\b", lowered):
        payload["maturity"]["identity_maturity"] = "basic"

    return payload


def merge_questionnaire(
    base: dict[str, dict[str, str]],
    override: dict[str, dict[str, str]] | None,
) -> dict[str, dict[str, str]]:
    """Deep-merge questionnaire payloads using known domains/fields only."""
    merged = default_questionnaire()
    for domain, fields in base.items():
        if domain not in merged:
            continue
        for field, value in fields.items():
            if field in merged[domain] and isinstance(value, str):
                merged[domain][field] = value
    if not override:
        return merged
    for domain, fields in override.items():
        if domain not in merged or not isinstance(fields, dict):
            continue
        for field, value in fields.items():
            if field in merged[domain] and isinstance(value, str):
                merged[domain][field] = value
    return merged


def high_impact_missing_fields(questionnaire: dict[str, dict[str, str]]) -> list[tuple[str, str]]:
    """Return missing high-impact fields that should be prompted."""
    required = (
        ("technical_architecture", "public_api"),
        ("technical_architecture", "mfa_enforced"),
        ("technical_architecture", "network_segmentation"),
        ("technical_architecture", "logging_monitoring"),
        ("technical_architecture", "backup_restore_tested"),
        ("maturity", "incident_response_plan"),
    )
    missing: list[tuple[str, str]] = []
    for domain, field in required:
        if questionnaire.get(domain, {}).get(field, "unknown") == "unknown":
            missing.append((domain, field))
    return missing


def load_questionnaire_file(path: str) -> dict[str, dict[str, str]]:
    """Load questionnaire JSON file from disk."""
    raw = Path(path).read_text(encoding="utf-8")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Questionnaire file must contain a JSON object.")
    base = default_questionnaire()
    return merge_questionnaire(base, data)  # type: ignore[arg-type]


def to_signal_hints(questionnaire: dict[str, dict[str, str]]) -> str:
    """Convert questionnaire answers into deterministic signal hints."""
    hints: list[str] = []
    tech = questionnaire.get("technical_architecture", {})
    maturity = questionnaire.get("maturity", {})

    if tech.get("public_api") == "yes":
        hints.append("public api")
    if tech.get("mfa_enforced") == "no":
        hints.append("no mfa")
    if tech.get("network_segmentation") == "no":
        hints.append("no segmentation")
    if tech.get("logging_monitoring") == "no":
        hints.append("no logging")
    if tech.get("backup_restore_tested") == "no":
        hints.append("backups not tested")
    if maturity.get("incident_response_plan") == "no":
        hints.append("no incident response")
    if tech.get("internet_exposed") == "yes":
        hints.append("internet facing")
    return " ".join(hints)
