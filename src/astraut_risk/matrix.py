"""Cybersecurity investment matrix data."""

from __future__ import annotations

MATRIX_ROWS: list[dict[str, str]] = [
    {
        "priority": "1",
        "focus": "MFA + Segmentation",
        "why": "Highest risk reduction per dollar for SMEs.",
        "examples": "MFA for admin/email/cloud; network and role segmentation.",
        "effort": "Medium",
        "investment_band": "$",
        "time_to_value": "1-2 weeks",
        "expected_risk_reduction": "High (20-35%)",
    },
    {
        "priority": "2",
        "focus": "Detection & Response Basics",
        "why": "Catch account abuse and unusual behavior early.",
        "examples": "Cloud audit logs, SIEM-lite alerts, incident runbooks.",
        "effort": "Medium",
        "investment_band": "$$",
        "time_to_value": "2-4 weeks",
        "expected_risk_reduction": "High (15-25%)",
    },
    {
        "priority": "3",
        "focus": "Zero Trust Access",
        "why": "Limit lateral movement and credential blast radius.",
        "examples": "Context-aware access, device checks, least privilege.",
        "effort": "High",
        "investment_band": "$$",
        "time_to_value": "3-6 weeks",
        "expected_risk_reduction": "Medium-High (10-20%)",
    },
    {
        "priority": "4",
        "focus": "Supply Chain Hardening",
        "why": "Third-party and CI/CD compromise is rising.",
        "examples": "Dependency scanning, signed artifacts, vendor reviews.",
        "effort": "Medium",
        "investment_band": "$$",
        "time_to_value": "2-6 weeks",
        "expected_risk_reduction": "Medium (8-15%)",
    },
    {
        "priority": "5",
        "focus": "Advanced AI Detection",
        "why": "High value but comes after baseline controls.",
        "examples": "Behavior analytics, anomaly triage copilots.",
        "effort": "High",
        "investment_band": "$$$",
        "time_to_value": "6-12 weeks",
        "expected_risk_reduction": "Variable (5-12%)",
    },
]
