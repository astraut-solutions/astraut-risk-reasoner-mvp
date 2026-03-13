"""LLM reasoning and prompt construction."""

from __future__ import annotations

import socket
from json import dumps
from typing import Any

from groq import Groq

from .config import SUPPORTED_MODELS
from .models import RiskAssessment

SYSTEM_PROMPT = (
    "You are Astraut Risk Reasoner from Astraut Solutions. You help SMEs think "
    "clearly about digital risk, trust and system design before small weaknesses "
    "become incidents. Core principles: Zero Trust thinking, AI-assisted risk "
    "reasoning, practical NIST/OWASP/CISA advice, tested backups, MFA everywhere, "
    "clear ownership in incidents, cloud resilience. Focus on small teams (5-50 "
    "people). Be practical, never scary. You must never invent or modify numeric "
    "risk scores; scores are provided by a deterministic control-check engine. "
    "Use the structured findings to explain why the top risks matter and provide "
    "practical guidance for SMEs. Do not include headings for Overall Risk Score, "
    "Top 3 Risks, or Detected Control Gaps because those are rendered separately. "
    "Output sections in markdown: Risk Rationale, Personalized Recommendations "
    "(Zero Trust first), 7-day Action Checklist, Suggested investment priorities "
    "(reference the 2025 matrix: start with MFA + segmentation, then detection, "
    "then advanced)."
)

EXPLAINER_PROMPT = (
    "You are a cybersecurity educator for SME teams. Explain topics clearly and "
    "practically in plain language. Include: definition, why it matters for SMEs, "
    "and 3 concrete actions. Keep it concise."
)


class ReasoningError(RuntimeError):
    """Base reasoning error."""


class InvalidInputError(ReasoningError):
    """Raised for invalid user input."""


class LLMAPIError(ReasoningError):
    """Raised when Groq API fails."""


class NetworkError(ReasoningError):
    """Raised for connectivity issues."""


def validate_company_description(company_description: str) -> None:
    """Validate user-provided company description."""
    text = (company_description or "").strip()
    if not text:
        raise InvalidInputError("Company description cannot be empty.")
    if len(text) < 10:
        raise InvalidInputError(
            "Description is too short. Provide at least a few details about your setup."
        )


def validate_model(model: str) -> None:
    """Validate selected model."""
    if model not in SUPPORTED_MODELS:
        allowed = ", ".join(sorted(SUPPORTED_MODELS))
        raise InvalidInputError(f"Invalid model '{model}'. Allowed values: {allowed}")


def build_assessment_messages(
    company_description: str,
    assessment: RiskAssessment | None = None,
) -> list[dict[str, str]]:
    """Build chat messages for assessment."""
    if assessment is None:
        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": company_description.strip()},
        ]

    summary = {
        "company_input": assessment.company_input,
        "overall_score": assessment.overall_score,
        "risk_level": assessment.risk_level,
        "matched_signals": [
            {
                "id": signal.signal_id,
                "label": signal.label,
                "category": signal.category,
                "weight": signal.weight,
                "matched_phrases": signal.matched_phrases,
            }
            for signal in assessment.matched_signals
        ],
        "top_risks": assessment.top_risks,
        "control_gaps": assessment.control_gaps,
        "framework_references": {
            signal_id: [
                {
                    "framework": ref.framework,
                    "control_id": ref.control_id,
                    "title": ref.title,
                    "description": ref.description,
                }
                for ref in refs
            ]
            for signal_id, refs in assessment.framework_references.items()
        },
        "seven_day_plan_seed": assessment.seven_day_plan[:5],
        "investment_priorities_seed": [
            {
                "bucket": priority.bucket,
                "score_contribution": priority.score_contribution,
                "related_signals": priority.related_signals,
            }
            for priority in assessment.investment_priorities
        ],
    }
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                "Company description:\n"
                f"{company_description.strip()}\n\n"
                "Deterministic findings (JSON):\n"
                f"{dumps(summary, ensure_ascii=False, indent=2)}\n\n"
                "Explain these findings in plain English for a small business team. "
                "Do not restate or recompute the numeric score."
            ),
        },
    ]


def build_explain_messages(topic: str) -> list[dict[str, str]]:
    """Build chat messages for concept explanation."""
    return [
        {"role": "system", "content": EXPLAINER_PROMPT},
        {
            "role": "user",
            "content": (
                f"Explain this cybersecurity concept for a small business team: {topic}."
            ),
        },
    ]


def request_completion(
    client: Groq,
    messages: list[dict[str, str]],
    model: str,
    temperature: float = 0.2,
) -> str:
    """Request completion from Groq and normalize errors."""
    try:
        response: Any = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature,
        )
        content = response.choices[0].message.content if response.choices else None
        if not content:
            raise LLMAPIError("No response was generated by the model.")
        return content
    except (socket.timeout, socket.gaierror, ConnectionError, OSError) as exc:
        raise NetworkError(f"Network error while contacting Groq: {exc}") from exc
    except ReasoningError:
        raise
    except Exception as exc:
        raise LLMAPIError(f"Groq API request failed: {exc}") from exc
