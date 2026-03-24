"""SME security checklist data and helpers."""

from __future__ import annotations

CHECKLIST_ROWS: list[dict[str, str]] = [
    {
        "control": "MFA coverage",
        "domain": "Identity & Access",
        "priority": "P1",
        "target": "Admin, cloud, email, finance, and code-repo accounts",
        "evidence": "Policy + enrollment export",
        "cadence": "Weekly",
    },
    {
        "control": "Least privilege + stale access review",
        "domain": "Identity & Access",
        "priority": "P1",
        "target": "No standing excess admin rights",
        "evidence": "Access review log",
        "cadence": "Monthly",
    },
    {
        "control": "Network segmentation baseline",
        "domain": "Infrastructure",
        "priority": "P1",
        "target": "Production, staging, and admin zones segmented",
        "evidence": "Firewall / SG ruleset snapshot",
        "cadence": "Monthly",
    },
    {
        "control": "Credential hygiene",
        "domain": "Identity & Access",
        "priority": "P1",
        "target": "Password manager enforced, shared credentials removed",
        "evidence": "Vault policy + shared account inventory",
        "cadence": "Monthly",
    },
    {
        "control": "Backup + restore validation",
        "domain": "Resilience",
        "priority": "P1",
        "target": "Critical systems backed up and restore-tested",
        "evidence": "Restore test report (RTO/RPO)",
        "cadence": "Quarterly",
    },
    {
        "control": "Public API protection",
        "domain": "Application Security",
        "priority": "P1",
        "target": "Auth, rate-limit, schema validation, logging",
        "evidence": "Gateway policy + alert rules",
        "cadence": "Weekly",
    },
    {
        "control": "Patch management",
        "domain": "Vulnerability Management",
        "priority": "P1",
        "target": "OS, dependencies, and containers patched on SLA",
        "evidence": "Patch SLA report",
        "cadence": "Weekly",
    },
    {
        "control": "Centralized monitoring",
        "domain": "Detection",
        "priority": "P2",
        "target": "Central logs and high-signal auth alerts",
        "evidence": "SIEM queries + alert routing",
        "cadence": "Daily",
    },
    {
        "control": "Incident response ownership",
        "domain": "Resilience",
        "priority": "P2",
        "target": "Named decision/comms/technical owners",
        "evidence": "IR runbook + tabletop notes",
        "cadence": "Quarterly",
    },
    {
        "control": "Vendor/supply chain review",
        "domain": "Third-party Risk",
        "priority": "P2",
        "target": "Critical suppliers risk-assessed",
        "evidence": "Vendor assessment register",
        "cadence": "Quarterly",
    },
]

CHECKLIST_ITEMS: list[str] = [
    (
        f"{row['control']} ({row['domain']}, {row['priority']}): "
        f"{row['target']} | Evidence: {row['evidence']} | Cadence: {row['cadence']}"
    )
    for row in CHECKLIST_ROWS
]


def format_checklist_markdown() -> str:
    """Return checklist in markdown task-list format."""
    return "\n".join(f"- [ ] {item}" for item in CHECKLIST_ITEMS)
