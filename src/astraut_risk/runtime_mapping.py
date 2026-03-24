"""Runtime category-to-layer mapping used during deterministic scoring and reporting."""

from __future__ import annotations

from collections import defaultdict

from .models import RequirementControl, RiskSignal

_CATEGORY_LAYER_MAP: dict[str, str] = {
    "identity & access": "Identity Layer",
    "infrastructure / cloud": "Infrastructure Layer",
    "backups / resilience": "Resilience Layer",
    "monitoring / detection": "Detection Layer",
    "software / supply chain": "Application Layer",
    "security governance": "Governance Layer",
    "general requirements": "Governance Layer",
    "architecture": "Architecture Layer",
    "operating systems": "Platform Layer",
    "virtualization": "Platform Layer",
    "databases": "Data Layer",
    "server applications": "Application Layer",
    "application servers": "Application Layer",
    "web servers": "Web Layer",
    "endpoints": "Endpoint Layer",
    "network components": "Network Layer",
    "third-party access": "Third-Party Layer",
    "mobile apps": "Mobile Layer",
    "operational security": "Operations Layer",
    "web services": "API Layer",
    "cloud & saas": "Cloud Layer",
}


def _normalize_category(category: str) -> str:
    return (category or "").strip().lower()


def map_category_to_layer(category: str) -> str:
    """Map a signal/control category to a stable runtime layer."""
    normalized = _normalize_category(category)
    if not normalized:
        return "Unmapped Layer"

    if normalized in _CATEGORY_LAYER_MAP:
        return _CATEGORY_LAYER_MAP[normalized]

    for key, layer in _CATEGORY_LAYER_MAP.items():
        if key in normalized or normalized in key:
            return layer
    return "Unmapped Layer"


def build_runtime_category_layers(
    matched_signals: list[RiskSignal],
    mapped_requirements: list[RequirementControl],
) -> list[dict[str, object]]:
    """Aggregate runtime layer evidence from deterministic signals and mapped controls."""
    layer_rollup: dict[str, dict[str, object]] = defaultdict(
        lambda: {
            "layer": "",
            "signal_count": 0,
            "signal_weight_total": 0,
            "mapped_control_count": 0,
            "categories": set(),
        }
    )

    for signal in matched_signals:
        layer = map_category_to_layer(signal.category)
        item = layer_rollup[layer]
        item["layer"] = layer
        item["signal_count"] = int(item["signal_count"]) + 1
        item["signal_weight_total"] = int(item["signal_weight_total"]) + int(signal.weight)
        categories = item["categories"]
        assert isinstance(categories, set)
        categories.add(signal.category)

    for control in mapped_requirements:
        layer = control.mapped_layer or map_category_to_layer(control.category)
        item = layer_rollup[layer]
        item["layer"] = layer
        item["mapped_control_count"] = int(item["mapped_control_count"]) + 1
        categories = item["categories"]
        assert isinstance(categories, set)
        if control.category:
            categories.add(control.category)

    output: list[dict[str, object]] = []
    for layer, row in layer_rollup.items():
        categories = sorted(str(category) for category in row["categories"])
        output.append(
            {
                "layer": layer,
                "signal_count": int(row["signal_count"]),
                "signal_weight_total": int(row["signal_weight_total"]),
                "mapped_control_count": int(row["mapped_control_count"]),
                "categories": categories,
            }
        )

    output.sort(
        key=lambda item: (
            int(item["signal_weight_total"]),
            int(item["mapped_control_count"]),
            str(item["layer"]),
        ),
        reverse=True,
    )
    return output
