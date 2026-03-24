"""Built-in SME scenario library for quick risk assessments."""

from __future__ import annotations

SCENARIOS: dict[str, dict[str, str]] = {
    "saas_startup": {
        "label": "SaaS Startup",
        "description": (
            "We are a 12-person SaaS startup on AWS using Google Workspace, Stripe, "
            "GitHub, and a public API for customer integrations. No MFA on admin yet, "
            "and backups exist but are not regularly tested."
        ),
    },
    "online_store": {
        "label": "Online Store",
        "description": (
            "We run a 20-person e-commerce business with Shopify, payment processors, "
            "warehouse systems, and marketing tools. Some shared accounts are still in "
            "use, and there is no formal incident response plan."
        ),
    },
    "manufacturing_firm": {
        "label": "Manufacturing Firm",
        "description": (
            "We are a 35-person manufacturer with cloud ERP, on-prem production systems, "
            "and remote vendor access. The network is mostly flat, logging is limited, "
            "and backup recovery tests are infrequent."
        ),
    },
    "consulting_agency": {
        "label": "Consulting Agency",
        "description": (
            "We are a 15-person consulting agency using Microsoft 365, shared client "
            "folders, and contractor laptops. Least-privilege access is inconsistent and "
            "offboarding of old users is manual."
        ),
    },
    "healthcare_clinic": {
        "label": "Healthcare Clinic",
        "description": (
            "We are a 25-person clinic using cloud scheduling, EHR access, email, and "
            "billing vendors. Centralized monitoring is missing, vendor security reviews "
            "are ad hoc, and incident procedures are undocumented."
        ),
    },
}


def list_scenarios() -> list[tuple[str, str]]:
    """Return sorted scenario id and label pairs."""
    return sorted((key, value["label"]) for key, value in SCENARIOS.items())


def get_scenario_description(name: str) -> str | None:
    """Return scenario description by id."""
    scenario = SCENARIOS.get(name)
    return scenario["description"] if scenario else None
