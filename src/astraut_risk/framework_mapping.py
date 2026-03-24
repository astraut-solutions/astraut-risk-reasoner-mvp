"""Framework control mapping loader for deterministic risk signals."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
import re

import yaml

from .models import FrameworkReference

_FRAMEWORK_SPECS = {
    "CIS": {
        "display_name": "CIS Critical Security Controls",
        "filename": "cis_controls.yaml",
        "aliases": {"cis", "csc", "cis_controls"},
    },
    "NIST": {
        "display_name": "NIST Cybersecurity Framework",
        "filename": "nist_csf.yaml",
        "aliases": {"nist", "nist_csf", "csf"},
    },
    "OWASP": {
        "display_name": "OWASP Top 10",
        "filename": "owasp_top10.yaml",
        "aliases": {"owasp", "owasp_top10"},
    },
}


def _frameworks_dir() -> Path:
    return Path(__file__).resolve().parent / "frameworks"


def resolve_framework_selector(selector: str) -> str | None:
    """Resolve a framework selector like cis/nist/owasp to a canonical code."""
    token = (selector or "").strip().lower()
    if not token:
        return None
    for code, spec in _FRAMEWORK_SPECS.items():
        if token == code.lower() or token in spec["aliases"]:
            return code
    return None


def _normalize_control_id(framework: str, raw_control: str) -> str:
    control = raw_control.strip()
    if framework in {"CIS", "OWASP"}:
        control = re.sub(rf"^{framework}\s+", "", control, flags=re.IGNORECASE)
    return control


def _reference_from_mapping(
    framework: str,
    data: dict[str, object],
) -> FrameworkReference | None:
    raw_control = str(data.get("control", "")).strip()
    if not raw_control:
        return None

    control_id = _normalize_control_id(framework, raw_control)
    title = str(data.get("title", "")).strip()
    description = str(data.get("description", "")).strip()
    return FrameworkReference(
        framework=framework,
        control_id=control_id,
        title=title,
        description=description,
    )


@lru_cache(maxsize=1)
def load_framework_mappings() -> dict[str, list[FrameworkReference]]:
    """Load framework mappings keyed by risk signal id."""
    signal_map: dict[str, list[FrameworkReference]] = {}

    for framework_code, spec in _FRAMEWORK_SPECS.items():
        path = _frameworks_dir() / str(spec["filename"])
        if not path.exists():
            continue

        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict):
            continue

        for signal_id, data in raw.items():
            if not isinstance(data, dict):
                continue
            ref = _reference_from_mapping(framework_code, data)
            if ref is None:
                continue
            signal_map.setdefault(str(signal_id), []).append(ref)

    return signal_map


def framework_refs_for_signal(signal_id: str) -> list[FrameworkReference]:
    """Get framework references for a given risk signal id."""
    return list(load_framework_mappings().get(signal_id, []))


def list_framework_names() -> list[str]:
    """List supported framework names."""
    return [
        f"{code} ({spec['display_name']})"
        for code, spec in _FRAMEWORK_SPECS.items()
    ]


def list_framework_codes() -> list[str]:
    """List supported framework codes."""
    return list(_FRAMEWORK_SPECS.keys())
