## MVP Enhancement Plan: Structured Customer Input + Document-Aligned Risk Computation

### Summary
Upgrade only the customer input and calculation layers, keeping the existing CLI/Web + deterministic engine architecture intact and single-Docker friendly (no DB/cloud/external services).  
Primary reference used: `docs/` (repository contains `docs`, not `/doc`).

### Implementation Changes
- [x] **Input layer (hybrid questionnaire, architecture unchanged)**
- [x] Add a local questionnaire model with 4 sections from docs: `business`, `technical_architecture`, `compliance`, `maturity`.
- [x] Keep current free-text input as step 1; add guided follow-up prompts only for missing high-impact fields.
- [x] Implement shared questionnaire schema and defaults in code (plus optional JSON import/export for reproducibility).
- [x] Web UI: render compact questionnaire fields below description box; prefill from scenario text heuristics when possible.
- [x] CLI: keep `assess "..."`; add guided prompt sequence when required fields are missing (non-interactive mode supported via optional `--questionnaire-file`).

- [x] **Calculation layer (replace single-score internals, keep same entrypoints)**
- [x] Introduce deterministic factor engine with YAML-configurable weights (local file, no infra).
- [x] Compute normalized dimensions in this exact order:
- [x] `likelihood` from weighted factors: exposure, exploitability proxy, threat relevance proxy, identity exposure, precondition complexity.
- [x] `impact` from weighted factors: business criticality, data sensitivity, privilege level, blast radius, regulatory consequence, customer impact.
- [x] `inherent_risk = round(clamp(likelihood * impact * 100, 0, 100))`.
- [x] `control_effectiveness` using doc-prescribed formula: design 30%, operating evidence 35%, coverage 20%, freshness 10%, exception rate 5%.
- [x] `control_reduction_adjusted` with diminishing returns: `1 - Π(1 - control_i_effective)` over applicable controls.
- [x] `residual_risk = round(clamp(inherent_risk * (1 - control_reduction_adjusted), 0, 100))`.
- [x] `confidence` from completeness/coverage/recency: questionnaire completeness, signal coverage, control evidence quality, input specificity.
- [x] Keep existing signal matching as one input source; use it to seed factor values rather than direct additive scoring.

- [x] **Public interfaces/types (backward-compatible)**
- [x] Extend `RiskAssessment` to include: `likelihood`, `impact`, `inherent_risk`, `residual_risk`, `control_reduction`, `confidence`, `questionnaire`.
- [x] Preserve `overall_score` as alias to `residual_risk` and keep `risk_level` derived from residual bands, so existing rendering paths keep working.
- [x] Update formatter/output to show all dimensions by default: likelihood, impact, inherent, residual, confidence + existing top risks/recommendations.
- [x] Bump cache engine version and include questionnaire + factor snapshot in cache payload to avoid collisions with old entries.

### Test Plan
- [x] Unit tests for questionnaire parsing, required-field gating, and fallback defaults.
- [x] Unit tests for factor calculations, bounds, and formula correctness (including control-effectiveness weighting and diminishing returns behavior).
- [x] Regression tests ensuring:
- [x] old free-text-only input still runs.
- [x] `overall_score` remains present and equals residual.
- [x] CLI/Web output includes new dimensions.
- [x] export and cache payloads include new fields.
- [x] Edge-case tests: sparse input, contradictory input, no controls, high controls with low evidence, and confidence degradation when questionnaire completeness is low.

### Assumptions and Defaults
- No new persistence or external infra will be introduced; all config is local YAML and runtime memory/filesystem.
- “Formulae set out in docs” is interpreted as the documented weighted reasoning model and explicit control-effectiveness weighting (30/35/20/10/5), with deterministic MVP defaults.
- Core architecture remains unchanged: same app structure, same command/UI entrypoints, no service decomposition in this phase.
