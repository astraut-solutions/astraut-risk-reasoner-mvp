"""Streamlit web app for Astraut Risk Reasoner."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import streamlit as st
from groq import Groq

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from astraut_risk.checklist import CHECKLIST_ITEMS
from astraut_risk.config import (
    DEFAULT_MODEL,
    MissingApiKeyError,
    get_groq_api_key,
    load_environment,
)
from astraut_risk.matrix import MATRIX_ROWS
from astraut_risk.reasoning import (
    InvalidInputError,
    LLMAPIError,
    NetworkError,
    build_assessment_messages,
    request_completion,
    validate_company_description,
)

load_environment()


def _strip_rich_box(line: str) -> str:
    stripped = line.strip()
    if not stripped:
        return ""
    if stripped.startswith("╭") or stripped.startswith("╰"):
        return ""
    if stripped.startswith("│") and stripped.endswith("│"):
        inner = stripped.strip("│").strip()
        return inner
    return line


def _extract_sections(raw_text: str) -> dict[str, str]:
    cleaned_lines = [_strip_rich_box(line) for line in raw_text.splitlines()]
    cleaned_text = "\n".join(line for line in cleaned_lines if line.strip())

    sections: dict[str, str] = {}
    current = "_full"
    buffer: list[str] = []

    for line in cleaned_text.splitlines():
        if line.strip().startswith("## "):
            sections[current] = "\n".join(buffer).strip()
            current = line.strip()[3:].strip()
            buffer = []
        else:
            buffer.append(line)

    sections[current] = "\n".join(buffer).strip()
    sections = {k: v for k, v in sections.items() if v}
    if len(sections) > 1:
        return sections

    # Fallback for non-markdown model outputs (e.g., "Top 3 Risks:").
    heading_re = re.compile(
        r"^(overall risk score|top 3 risks|top risks|personalized recommendations|"
        r"recommendations|7-day action checklist|7 day action checklist|7-day action plan|"
        r"action plan|suggested investment priorities(?:\s*\([^)]*\))?|"
        r"investment priorities)\s*:\s*(.*)$",
        flags=re.IGNORECASE,
    )
    plain_sections: dict[str, str] = {}
    current_plain = "_full"
    plain_buffer: list[str] = []
    for line in cleaned_text.splitlines():
        match = heading_re.match(line.strip())
        if match:
            plain_sections[current_plain] = "\n".join(plain_buffer).strip()
            current_plain = match.group(1).strip()
            plain_buffer = []
            inline_value = match.group(2).strip()
            if inline_value:
                plain_buffer.append(inline_value)
        else:
            plain_buffer.append(line)
    plain_sections[current_plain] = "\n".join(plain_buffer).strip()
    plain_sections = {k: v for k, v in plain_sections.items() if v}
    if len(plain_sections) > 1:
        return plain_sections

    # Final fallback: detect heading blocks even with markdown decoration.
    block_heading_re = re.compile(
        r"(?:^|\n)\s*(?:[#>*\-\s]*)\*{0,2}"
        r"(overall risk score|top 3 risks|top risks|personalized recommendations|"
        r"recommendations|7-day action checklist|7 day action checklist|"
        r"7-day action plan|action plan|"
        r"suggested investment priorities(?:\s*\([^)]*\))?|investment priorities)"
        r"\*{0,2}\s*:\s*",
        flags=re.IGNORECASE,
    )
    matches = list(block_heading_re.finditer(cleaned_text))
    if not matches:
        return plain_sections

    extracted: dict[str, str] = {}
    for idx, match in enumerate(matches):
        heading = match.group(1).strip()
        content_start = match.end()
        content_end = matches[idx + 1].start() if idx + 1 < len(matches) else len(
            cleaned_text
        )
        body = cleaned_text[content_start:content_end].strip()
        if body:
            extracted[heading] = body
    return extracted or plain_sections


def _normalize_heading(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", text.strip().lower()).strip()


def _get_section(sections: dict[str, str], aliases: list[str]) -> str:
    normalized_sections = {_normalize_heading(k): v for k, v in sections.items()}
    for alias in aliases:
        match = normalized_sections.get(_normalize_heading(alias))
        if match:
            return match
    for alias in aliases:
        alias_norm = _normalize_heading(alias)
        for key_norm, value in normalized_sections.items():
            if alias_norm and alias_norm in key_norm:
                return value
            if key_norm and key_norm in alias_norm:
                return value
    return "Not available"


def _risk_score_from_text(text: str, full_text: str = "") -> str:
    match = re.search(r"\b(\d{1,2})\s*/\s*10\b", text)
    if match:
        return match.group(0)
    num_match = re.search(r"\boverall risk score\s*:\s*(\d{1,2})\b", full_text, re.I)
    if num_match:
        return f"{num_match.group(1)}/10"
    return text


def _table_from_list_text(text: str) -> list[dict[str, str]]:
    items: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if re.match(r"^\d+\.\s+", line):
            items.append(re.sub(r"^\d+\.\s+", "", line))
        elif re.match(r"^\d+\s+", line):
            items.append(re.sub(r"^\d+\s+", "", line))
        elif line.startswith("- "):
            items.append(line[2:].strip())

    if not items:
        # Fallback: preserve line-by-line content for plain-text outputs.
        items = [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.strip().endswith(":")
        ]

    if not items and text.strip():
        items = [text.strip()]

    return [{"Item": item} for item in items]


def _run_assessment(company_description: str) -> str:
    validate_company_description(company_description)
    api_key = get_groq_api_key(required=True)
    client = Groq(api_key=api_key)
    return request_completion(
        client=client,
        messages=build_assessment_messages(company_description),
        model=DEFAULT_MODEL,
    )


st.set_page_config(page_title="Astraut Risk Reasoner", layout="wide")

st.title("Astraut Risk Reasoner")
st.markdown("AI-assisted cyber risk reasoning for small and medium businesses.")

st.sidebar.header("Project Info")
st.sidebar.markdown(
    "Astraut Risk Reasoner translates practical cybersecurity research into "
    "clear SME risk decisions."
)
st.sidebar.markdown(
    "GitHub repo: [astraut-risk-reasoner](https://github.com/astraut-solutions/astraut-risk-reasoner)"
)
show_raw_output = st.sidebar.checkbox("Show raw model output (debug)", value=False)

risk_tab, checklist_tab, matrix_tab = st.tabs(
    ["Risk Assessment", "Security Checklist", "Investment Matrix"]
)

with risk_tab:
    description = st.text_area(
        "Describe your company environment",
        placeholder="12-person SaaS startup on AWS using Gmail, Stripe, and a public API",
        height=120,
    )

    if st.button("Assess Risk", type="primary"):
        try:
            with st.spinner("Analyzing environment..."):
                content = _run_assessment(description)

            sections = _extract_sections(content)

            risk_score_text = _get_section(
                sections,
                ["Overall Risk Score", "Risk Score"],
            )
            st.header("Risk Score")
            st.markdown(_risk_score_from_text(risk_score_text, content))

            st.header("Top Risks")
            top_risks = _get_section(sections, ["Top 3 Risks", "Top Risks"])
            st.table(_table_from_list_text(top_risks))

            st.header("Recommendations")
            recommendations = _get_section(
                sections,
                [
                    "Personalized Recommendations (Zero Trust first)",
                    "Personalized Recommendations",
                    "Recommendations",
                ],
            )
            st.markdown(recommendations)

            st.header("7-Day Action Plan")
            action_plan = _get_section(
                sections,
                ["7-day Action Checklist", "7-Day Action Plan", "Action Plan"],
            )
            st.table(_table_from_list_text(action_plan))

            st.header("Investment Priorities")
            priorities = _get_section(
                sections,
                [
                    "Suggested investment priorities (2025 matrix)",
                    "Suggested Investment Priorities",
                    "Investment Priorities",
                ],
            )
            st.table(_table_from_list_text(priorities))

            if show_raw_output:
                with st.expander("Raw model output"):
                    st.markdown(content)

        except MissingApiKeyError:
            st.error("Missing GROQ_API_KEY. Set it in your environment or .env file.")
        except InvalidInputError as exc:
            st.error(str(exc))
        except (LLMAPIError, NetworkError) as exc:
            st.error(f"LLM request failed: {exc}")
        except Exception as exc:  # pragma: no cover
            st.error(f"Unexpected error: {exc}")

with checklist_tab:
    st.header("Security Checklist")
    st.table([{"Checklist Item": item} for item in CHECKLIST_ITEMS])

with matrix_tab:
    st.header("Investment Matrix")
    st.table(
        [
            {
                "Priority": row["priority"],
                "Investment Focus": row["focus"],
                "Why Now": row["why"],
                "SME Examples": row["examples"],
            }
            for row in MATRIX_ROWS
        ]
    )
