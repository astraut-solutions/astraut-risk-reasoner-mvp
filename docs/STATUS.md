# Documentation Status and Alignment

Date: 2026-03-23

## Current implementation in this repository

- Single-process Python application with:
  - CLI (`astraut-risk`)
  - Streamlit web app (`web/app.py`)
  - Deterministic risk engine with optional LLM explanation layer
- Local-file configuration and local cache snapshots under `assessments/`.
- No microservice decomposition, no Kubernetes deployment, no external databases in the current codebase.

## What `PLAN.md` represents

- `PLAN.md` is the implemented MVP enhancement plan for:
  - Hybrid structured questionnaire input
  - Factor-based deterministic scoring (`likelihood`, `impact`, `inherent_risk`, `residual_risk`, `confidence`)
  - Backward-compatible `overall_score` behavior
  - Cache payload/version updates
  - Test coverage for the above

Status: Aligned with current code and tests.

## What `docs/Astraut Risk Reasoner-v2.md` and `v3.md` represent

- These are broader, future-facing architecture design documents.
- They describe a target enterprise platform direction (for example, multi-tenant microservices, event-driven processing, Kubernetes/data-platform components).
- They are not a direct representation of the current repository implementation.

Status: Intent/roadmap reference, not implementation parity.

## Practical reading order

1. `README.md` for how to run and use the current project.
2. `PLAN.md` for implemented MVP scoring/input enhancements.
3. `docs/Astraut Risk Reasoner-v2.md` and `docs/Astraut Risk Reasoner-v3.md` for target-state architecture evolution.
