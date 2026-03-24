"""Minimal Streamlit web app for Astraut Risk Reasoner MVP."""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from astraut_risk.assessment_formatter import compose_assessment_markdown
from astraut_risk.config import load_environment
from astraut_risk.questionnaire import (
    infer_questionnaire_from_text,
    merge_questionnaire,
    normalize_questionnaire_mode,
    questionnaire_override_from_template_answers,
    questionnaire_templates,
)
from astraut_risk.reasoning import (
    InvalidInputError,
    validate_company_description,
)
from astraut_risk.risk_engine import assess_company_risk

load_environment()

_MODE_LABELS = {
    "General (minimal)": "general",
    "Medium": "medium",
    "Full Detailed": "detailed",
}
_MULTI_SELECT_HEADINGS = {
    "Architecture",
    "Cloud & IAM",
    "Data Security",
    "Infrastructure",
    "Application Security",
    "Operations",
    "Compliance",
}

st.set_page_config(page_title="Astraut Risk Reasoner", layout="centered")
st.title("Astraut Risk Reasoner")
st.caption("Basic MVP: enter company context and run a structured risk assessment.")

company_description = st.text_area(
    "Company description",
    value="12-person SaaS startup on AWS with a public API and no MFA for admin accounts.",
    height=120,
)

st.subheader("Structured Questionnaire")
mode_label = st.selectbox(
    "Input detail level",
    ["General (minimal)", "Medium", "Full Detailed"],
    index=1,
)
mode = normalize_questionnaire_mode(_MODE_LABELS[mode_label])

if mode == "medium":
    st.caption("Balanced intake with operational security questions.")

templates = questionnaire_templates()
selected_template = templates[mode]
answers: dict[str, str | list[str]] = {}

st.markdown("**Mode Questions**")
for idx, item in enumerate(selected_template):
    heading = str(item["heading"])
    question = str(item["question"])
    options = [str(opt) for opt in item.get("options", []) if str(opt).strip()]
    key = f"q_{mode}_{idx}_{heading.lower().replace(' ', '_')}"

    st.markdown(f"**{heading}**")
    st.caption(question)

    if heading in _MULTI_SELECT_HEADINGS:
        selected = st.multiselect("Choose options", options, key=key)
        if selected:
            answers[heading] = selected
    else:
        choose_options = ["Not provided"] + options
        selected = st.selectbox("Choose option", choose_options, key=key)
        if selected != "Not provided":
            answers[heading] = selected

company_size = st.selectbox("Company size", ["sme", "mid_market", "enterprise"], index=0)
data_sensitivity = st.selectbox("Data sensitivity", ["unknown", "low", "medium", "high"], index=0)
regulatory_profile = st.selectbox("Regulatory profile", ["unknown", "unregulated", "regulated"], index=0)

if st.button("Run Assessment", type="primary"):
    try:
        validate_company_description(company_description)

        inferred = infer_questionnaire_from_text(company_description)
        template_override = questionnaire_override_from_template_answers(mode, answers)
        merged = merge_questionnaire(inferred, template_override)
        merged.setdefault("business", {})["company_size"] = company_size
        merged.setdefault("business", {})["data_sensitivity"] = data_sensitivity
        merged.setdefault("compliance", {})["regulatory_profile"] = regulatory_profile

        assessment = assess_company_risk(
            company_description,
            questionnaire_context=merged,
        )

        c1, c2, c3 = st.columns(3)
        c1.metric("Overall Risk", f"{assessment.overall_score}/100")
        c2.metric("Residual Risk", f"{assessment.residual_risk}/100")
        c3.metric("Confidence", f"{int(round(assessment.confidence * 100))}%")

        st.subheader("Top Risks")
        for idx, item in enumerate(assessment.top_risks[:3], start=1):
            st.write(f"{idx}. {item}")

        st.subheader("Assessment Report")
        report = compose_assessment_markdown(assessment, None)
        st.markdown(report)

    except InvalidInputError as exc:
        st.error(str(exc))
