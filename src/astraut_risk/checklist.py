"""SME security checklist data and helpers."""

from __future__ import annotations

CHECKLIST_ITEMS: list[str] = [
    "Enable MFA for all admin, cloud, email, finance, and code-repo accounts.",
    "Define least-privilege access and remove stale users every month.",
    "Segment production, staging, and internal admin networks.",
    "Enforce strong password manager use and disable shared credentials.",
    "Back up critical systems daily and test restore quarterly.",
    "Protect public APIs with auth, rate limits, schema validation, and logging.",
    "Patch operating systems, dependencies, and containers on a fixed schedule.",
    "Turn on centralized monitoring and alerting for suspicious auth activity.",
    "Create a simple incident owner map: who decides, who communicates, who fixes.",
    "Review vendor and supply-chain risk for payment, auth, and CI/CD services.",
]


def format_checklist_markdown() -> str:
    """Return checklist in markdown task-list format."""
    return "\n".join(f"- [ ] {item}" for item in CHECKLIST_ITEMS)
