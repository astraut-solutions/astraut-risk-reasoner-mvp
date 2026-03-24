"""Persistent storage for deterministic + LLM assessment results."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import RiskAssessment

ENGINE_VERSION = "2"
DEFAULT_CACHE_DIR = "assessments"


def _normalize_text(text: str) -> str:
    return " ".join((text or "").strip().split())


def cache_key_for_assessment(
    company_description: str,
    model: str,
    assessment: RiskAssessment,
) -> str:
    """Compute stable cache key for a deterministic baseline and model."""
    payload = {
        "engine_version": ENGINE_VERSION,
        "model": model,
        "company_input": _normalize_text(company_description),
        "overall_score": assessment.overall_score,
        "residual_risk": assessment.residual_risk,
        "inherent_risk": assessment.inherent_risk,
        "confidence": assessment.confidence,
        "risk_level": assessment.risk_level,
        "top_risks": assessment.top_risks,
        "control_gaps": assessment.control_gaps,
        "questionnaire": assessment.questionnaire,
        "factor_snapshot": assessment.factor_snapshot,
        "signal_ids": [signal.signal_id for signal in assessment.matched_signals],
    }
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def _cache_file_path(cache_key: str, cache_dir: str = DEFAULT_CACHE_DIR) -> Path:
    return Path(cache_dir) / f"{cache_key}.json"


def load_cached_result(
    company_description: str,
    model: str,
    assessment: RiskAssessment,
    cache_dir: str = DEFAULT_CACHE_DIR,
) -> dict[str, Any] | None:
    """Load cached result for matching deterministic baseline, if available."""
    cache_key = cache_key_for_assessment(company_description, model, assessment)
    path = _cache_file_path(cache_key, cache_dir)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    if data.get("cache_key") != cache_key:
        return None
    return data


def save_cached_result(
    company_description: str,
    model: str,
    assessment: RiskAssessment,
    llm_explanation: str,
    assessment_markdown: str,
    cache_dir: str = DEFAULT_CACHE_DIR,
) -> Path:
    """Persist assessment output using deterministic cache key."""
    cache_key = cache_key_for_assessment(company_description, model, assessment)
    cache_path = _cache_file_path(cache_key, cache_dir)
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    now = datetime.now().isoformat(timespec="seconds")
    payload = {
        "cache_key": cache_key,
        "created_at": now,
        "engine_version": ENGINE_VERSION,
        "model": model,
        "company_input": company_description,
        "deterministic": assessment.to_dict(),
        "llm_explanation": llm_explanation,
        "assessment_markdown": assessment_markdown,
    }
    cache_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    history_dir = cache_path.parent / "history"
    history_dir.mkdir(parents=True, exist_ok=True)
    timestamp = now.replace(":", "-")
    history_path = history_dir / f"{timestamp}_{cache_key}.json"
    history_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    return cache_path
