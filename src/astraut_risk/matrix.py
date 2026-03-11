"""Cybersecurity investment matrix data."""

from __future__ import annotations

MATRIX_ROWS: list[dict[str, str]] = [
    {
        "priority": "1",
        "focus": "MFA + Segmentation",
        "why": "Highest risk reduction per dollar for SMEs.",
        "examples": "MFA for admin/email/cloud; network and role segmentation.",
    },
    {
        "priority": "2",
        "focus": "Detection & Response Basics",
        "why": "Catch account abuse and unusual behavior early.",
        "examples": "Cloud audit logs, SIEM-lite alerts, incident runbooks.",
    },
    {
        "priority": "3",
        "focus": "Zero Trust Access",
        "why": "Limit lateral movement and credential blast radius.",
        "examples": "Context-aware access, device checks, least privilege.",
    },
    {
        "priority": "4",
        "focus": "Supply Chain Hardening",
        "why": "Third-party and CI/CD compromise is rising.",
        "examples": "Dependency scanning, signed artifacts, vendor reviews.",
    },
    {
        "priority": "5",
        "focus": "Advanced AI Detection",
        "why": "High value but comes after baseline controls.",
        "examples": "Behavior analytics, anomaly triage copilots.",
    },
]
