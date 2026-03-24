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


def questionnaire_templates() -> dict[str, list[dict[str, object]]]:
    """Return three questionnaire depth options for user input collection."""
    return {
        "general": [
            {
                "heading": "Business Profile",
                "question": "What best describes your environment?",
                "options": ["Cloud/SaaS", "On-prem", "Hybrid", "None"],
            },
            {
                "heading": "Core Exposure",
                "question": "Do you run internet-facing systems?",
                "options": ["Yes", "No", "Not sure", "None"],
            },
            {
                "heading": "Critical Data",
                "question": "Do you process sensitive data (PII/financial/health)?",
                "options": ["Yes", "No", "Not sure", "None"],
            },
        ],
        "medium": [
            {
                "heading": "Architecture",
                "question": "Which components are in use?",
                "options": ["Web app", "API", "Database", "Cloud services", "Mobile app", "None"],
            },
            {
                "heading": "Access Security",
                "question": "How are privileged accounts protected?",
                "options": ["MFA enforced", "Partially enforced", "Not enforced", "None"],
            },
            {
                "heading": "Network Security",
                "question": "Is network segmentation implemented?",
                "options": ["Yes", "No", "Partially", "None"],
            },
            {
                "heading": "Detection",
                "question": "How mature are logging and alerting controls?",
                "options": ["Centralized + alerting", "Basic logs only", "Not implemented", "None"],
            },
            {
                "heading": "Resilience",
                "question": "Are backup restore tests performed?",
                "options": ["Regularly", "Occasionally", "Never", "None"],
            },
        ],
        "detailed": [
            {
                "heading": "Business Profile",
                "question": "What best describes your environment?",
                "options": ["Cloud/SaaS", "On-prem", "Hybrid", "None"],
            },
            {
                "heading": "Core Exposure",
                "question": "Do you run internet-facing systems?",
                "options": ["Yes", "No", "Not sure", "None"],
            },
            {
                "heading": "Critical Data",
                "question": "Do you process sensitive data (PII/financial/health)?",
                "options": ["Yes", "No", "Not sure", "None"],
            },
            {
                "heading": "Architecture",
                "question": "Which components are in use?",
                "options": ["Web app", "API", "Database", "Cloud services", "Mobile app", "None"],
            },
            {
                "heading": "Access Security",
                "question": "How are privileged accounts protected?",
                "options": ["MFA enforced", "Partially enforced", "Not enforced", "None"],
            },
            {
                "heading": "Network Security",
                "question": "Is network segmentation implemented?",
                "options": ["Yes", "No", "Partially", "None"],
            },
            {
                "heading": "Detection",
                "question": "How mature are logging and alerting controls?",
                "options": ["Centralized + alerting", "Basic logs only", "Not implemented", "None"],
            },
            {
                "heading": "Resilience",
                "question": "Are backup restore tests performed?",
                "options": ["Regularly", "Occasionally", "Never", "None"],
            },
            {
                "heading": "Cloud & IAM",
                "question": "Select all identity controls implemented.",
                "options": ["MFA", "SSO", "Least privilege/RBAC", "Privileged session control", "None"],
            },
            {
                "heading": "Data Security",
                "question": "Select data protection controls in place.",
                "options": ["Encryption at rest", "Encryption in transit", "Key rotation", "DLP", "None"],
            },
            {
                "heading": "Infrastructure",
                "question": "Select infrastructure hardening coverage.",
                "options": ["Segmented network", "Hardened images", "Vulnerability scanning", "Patch SLA", "None"],
            },
            {
                "heading": "Application Security",
                "question": "Select application security practices.",
                "options": ["SAST/DAST", "Dependency scanning", "Secrets scanning", "API gateway controls", "None"],
            },
            {
                "heading": "Operations",
                "question": "Select operational security maturity controls.",
                "options": ["IR playbooks", "Tabletop testing", "Centralized SIEM", "24x7 monitoring", "None"],
            },
            {
                "heading": "Compliance",
                "question": "Select applicable compliance regimes.",
                "options": ["ISO 27001", "NIST", "OWASP", "Internal policy only", "None"],
            },
        ],
    }


def normalize_questionnaire_mode(mode: str) -> str:
    """Normalize user-facing questionnaire mode labels to internal keys."""
    normalized = (mode or "").strip().lower().replace("-", " ").replace("_", " ")
    normalized = re.sub(r"\s+", " ", normalized)
    aliases = {
        "general": "general",
        "minimal": "general",
        "medium": "medium",
        "detailed": "detailed",
        "full detailed": "detailed",
        "full": "detailed",
    }
    return aliases.get(normalized, "medium")


def questionnaire_override_from_template_answers(
    mode: str, answers: dict[str, str | list[str]]
) -> dict[str, dict[str, str]]:
    """Map template answers into deterministic questionnaire override fields."""
    normalized_mode = normalize_questionnaire_mode(mode)
    lowered_answers: dict[str, str | list[str]] = {
        key.strip().lower(): value for key, value in answers.items()
    }
    override: dict[str, dict[str, str]] = {}

    def put(domain: str, field: str, value: str) -> None:
        override.setdefault(domain, {})[field] = value

    if normalized_mode == "general":
        profile = str(lowered_answers.get("business profile", "")).strip().lower()
        if profile in {"cloud/saas", "hybrid"}:
            put("technical_architecture", "internet_exposed", "yes")
        elif profile == "on-prem":
            put("technical_architecture", "internet_exposed", "no")
        elif profile == "none":
            put("technical_architecture", "internet_exposed", "unknown")

        exposure = str(lowered_answers.get("core exposure", "")).strip().lower()
        exposure_map = {"yes": "yes", "no": "no", "not sure": "unknown", "none": "unknown"}
        if exposure in exposure_map:
            mapped = exposure_map[exposure]
            put("technical_architecture", "internet_exposed", mapped)
            put("technical_architecture", "public_api", mapped)

        critical = str(lowered_answers.get("critical data", "")).strip().lower()
        if critical == "yes":
            put("business", "data_sensitivity", "high")
            put("compliance", "regulatory_profile", "regulated")
        elif critical == "no":
            put("business", "data_sensitivity", "low")
            put("compliance", "regulatory_profile", "unregulated")
        elif critical == "not sure":
            put("business", "data_sensitivity", "unknown")
        elif critical == "none":
            put("business", "data_sensitivity", "unknown")
            put("compliance", "regulatory_profile", "unknown")

        return override

    if normalized_mode == "medium":
        components_raw = lowered_answers.get("architecture", [])
        components = (
            {item.strip().lower() for item in components_raw if isinstance(item, str)}
            if isinstance(components_raw, list)
            else set()
        )
        if "none" in components:
            put("technical_architecture", "public_api", "unknown")
            put("technical_architecture", "internet_exposed", "unknown")
        elif components:
            public = "yes" if "api" in components else "no"
            internet_exposed = (
                "yes"
                if components.intersection({"web app", "api", "mobile app"})
                else "no"
            )
            put("technical_architecture", "public_api", public)
            put("technical_architecture", "internet_exposed", internet_exposed)

        access = str(lowered_answers.get("access security", "")).strip().lower()
        access_map = {
            "mfa enforced": "yes",
            "partially enforced": "unknown",
            "not enforced": "no",
            "none": "no",
        }
        if access in access_map:
            put("technical_architecture", "mfa_enforced", access_map[access])

        network = str(lowered_answers.get("network security", "")).strip().lower()
        network_map = {"yes": "yes", "no": "no", "partially": "unknown", "none": "no"}
        if network in network_map:
            put("technical_architecture", "network_segmentation", network_map[network])

        detection = str(lowered_answers.get("detection", "")).strip().lower()
        detection_map = {
            "centralized + alerting": "yes",
            "basic logs only": "unknown",
            "not implemented": "no",
            "none": "no",
        }
        if detection in detection_map:
            put("technical_architecture", "logging_monitoring", detection_map[detection])

        resilience = str(lowered_answers.get("resilience", "")).strip().lower()
        resilience_map = {"regularly": "yes", "occasionally": "unknown", "never": "no", "none": "no"}
        if resilience in resilience_map:
            put("technical_architecture", "backup_restore_tested", resilience_map[resilience])

        return override

    profile = str(lowered_answers.get("business profile", "")).strip().lower()
    if profile in {"cloud/saas", "hybrid"}:
        put("technical_architecture", "internet_exposed", "yes")
    elif profile == "on-prem":
        put("technical_architecture", "internet_exposed", "no")
    elif profile == "none":
        put("technical_architecture", "internet_exposed", "unknown")

    exposure = str(lowered_answers.get("core exposure", "")).strip().lower()
    exposure_map = {"yes": "yes", "no": "no", "not sure": "unknown", "none": "unknown"}
    if exposure in exposure_map:
        mapped = exposure_map[exposure]
        put("technical_architecture", "internet_exposed", mapped)
        put("technical_architecture", "public_api", mapped)

    critical = str(lowered_answers.get("critical data", "")).strip().lower()
    if critical == "yes":
        put("business", "data_sensitivity", "high")
        put("compliance", "regulatory_profile", "regulated")
    elif critical == "no":
        put("business", "data_sensitivity", "low")
        put("compliance", "regulatory_profile", "unregulated")
    elif critical in {"not sure", "none"}:
        put("business", "data_sensitivity", "unknown")
        if critical == "none":
            put("compliance", "regulatory_profile", "unknown")

    architecture_raw = lowered_answers.get("architecture", [])
    architecture_components = (
        {item.strip().lower() for item in architecture_raw if isinstance(item, str)}
        if isinstance(architecture_raw, list)
        else set()
    )
    if "none" in architecture_components:
        put("technical_architecture", "public_api", "unknown")
        put("technical_architecture", "internet_exposed", "unknown")
    elif architecture_components:
        public = "yes" if "api" in architecture_components else "no"
        internet_exposed = (
            "yes"
            if architecture_components.intersection({"web app", "api", "mobile app"})
            else "no"
        )
        put("technical_architecture", "public_api", public)
        put("technical_architecture", "internet_exposed", internet_exposed)

    access = str(lowered_answers.get("access security", "")).strip().lower()
    access_map = {
        "mfa enforced": "yes",
        "partially enforced": "unknown",
        "not enforced": "no",
        "none": "no",
    }
    if access in access_map:
        put("technical_architecture", "mfa_enforced", access_map[access])

    network = str(lowered_answers.get("network security", "")).strip().lower()
    network_map = {"yes": "yes", "no": "no", "partially": "unknown", "none": "no"}
    if network in network_map:
        put("technical_architecture", "network_segmentation", network_map[network])

    detection = str(lowered_answers.get("detection", "")).strip().lower()
    detection_map = {
        "centralized + alerting": "yes",
        "basic logs only": "unknown",
        "not implemented": "no",
        "none": "no",
    }
    if detection in detection_map:
        put("technical_architecture", "logging_monitoring", detection_map[detection])

    resilience = str(lowered_answers.get("resilience", "")).strip().lower()
    resilience_map = {"regularly": "yes", "occasionally": "unknown", "never": "no", "none": "no"}
    if resilience in resilience_map:
        put("technical_architecture", "backup_restore_tested", resilience_map[resilience])

    iam = lowered_answers.get("cloud & iam", [])
    iam_controls = (
        {item.strip().lower() for item in iam if isinstance(item, str)}
        if isinstance(iam, list)
        else set()
    )
    if "mfa" in iam_controls:
        put("technical_architecture", "mfa_enforced", "yes")
    if "none" in iam_controls:
        put("technical_architecture", "mfa_enforced", "no")
        put("maturity", "identity_maturity", "basic")
    elif "least privilege/rbac" in iam_controls or "privileged session control" in iam_controls:
        put("maturity", "identity_maturity", "advanced")
    elif iam_controls:
        put("maturity", "identity_maturity", "basic")

    infra = lowered_answers.get("infrastructure", [])
    infra_controls = (
        {item.strip().lower() for item in infra if isinstance(item, str)}
        if isinstance(infra, list)
        else set()
    )
    if "none" in infra_controls:
        put("technical_architecture", "network_segmentation", "no")
    elif "segmented network" in infra_controls:
        put("technical_architecture", "network_segmentation", "yes")

    appsec = lowered_answers.get("application security", [])
    appsec_controls = (
        {item.strip().lower() for item in appsec if isinstance(item, str)}
        if isinstance(appsec, list)
        else set()
    )
    if "none" in appsec_controls:
        put("technical_architecture", "public_api", "unknown")
        put("technical_architecture", "internet_exposed", "unknown")
    elif "api gateway controls" in appsec_controls:
        put("technical_architecture", "public_api", "yes")
        put("technical_architecture", "internet_exposed", "yes")

    ops = lowered_answers.get("operations", [])
    ops_controls = (
        {item.strip().lower() for item in ops if isinstance(item, str)}
        if isinstance(ops, list)
        else set()
    )
    if "none" in ops_controls:
        put("technical_architecture", "logging_monitoring", "no")
        put("maturity", "incident_response_plan", "no")
    elif ops_controls.intersection({"centralized siem", "24x7 monitoring"}):
        put("technical_architecture", "logging_monitoring", "yes")
    if ops_controls.intersection({"ir playbooks", "tabletop testing"}):
        put("maturity", "incident_response_plan", "yes")

    compliance = lowered_answers.get("compliance", [])
    compliance_controls = (
        [item for item in compliance if isinstance(item, str)]
        if isinstance(compliance, list)
        else []
    )
    if "none" in {item.strip().lower() for item in compliance_controls}:
        put("compliance", "regulatory_profile", "unknown")
    elif compliance_controls:
        put("compliance", "regulatory_profile", "regulated")

    data = lowered_answers.get("data security", [])
    data_controls = (
        [item for item in data if isinstance(item, str)] if isinstance(data, list) else []
    )
    if data_controls:
        put("business", "data_sensitivity", "medium")

    return override
