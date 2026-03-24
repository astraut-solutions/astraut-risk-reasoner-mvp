# Risk Formula (Detailed)

This document describes how Astraut Risk Reasoner calculates risk from each input type.

## 1) Input Types

The engine combines three deterministic input types:

1. Company description text (`company_description`)
2. Structured questionnaire (`questionnaire_context`)
3. Optional requirements repository/index (`requirements_root` or `requirements_index`)

The final `overall_score` is the deterministic `residual_risk` (0-100).

## 2) Text Input Calculation (Company Description)

### 2.1 Signal extraction

Text is normalized and enriched with questionnaire-derived hints.

`normalized_text = lower(company_description + " " + to_signal_hints(questionnaire))`

Regex rules map phrases to risk signals (example: `"no mfa"` -> `no_mfa`, weight `16`).
Each matched signal contributes:

- `signal_id`
- `category`
- `weight`
- matched phrases

For SaaS/startup-like context, inferred baseline signals can be added:

- `internet_facing_saas` (weight 14)
- `baseline_controls_unspecified` (weight 10)

Then:

`signal_weight_total = sum(signal.weight for matched_signals)`

### 2.2 Likelihood factors from text + questionnaire

The model computes 5 normalized factors (each clamped to `[0,1]`):

- `exposure`
- `exploitability_proxy`
- `threat_relevance_proxy`
- `identity_exposure`
- `precondition_complexity` (implemented as `1 - complexity`)

Likelihood is weighted sum:

`likelihood = clamp(sum(weight_k * factor_k))`

Default weights:

- exposure: `0.28`
- exploitability_proxy: `0.22`
- threat_relevance_proxy: `0.20`
- identity_exposure: `0.18`
- precondition_complexity: `0.12`

## 3) Questionnaire Input Calculation

The questionnaire fields are used directly and also pessimistically defaulted when unknown (worst-case fallback for key fields).

### 3.1 Impact factors from questionnaire + matched signals

The model computes 6 normalized impact factors:

- `business_criticality`
- `data_sensitivity`
- `privilege_level`
- `blast_radius`
- `regulatory_consequence`
- `customer_impact`

Impact is weighted sum:

`impact = clamp(sum(weight_k * factor_k))`

Default weights:

- business_criticality: `0.15`
- data_sensitivity: `0.24`
- privilege_level: `0.16`
- blast_radius: `0.20`
- regulatory_consequence: `0.12`
- customer_impact: `0.13`

### 3.2 Inherent risk

`inherent_risk = round(clamp(likelihood * impact * 100, 0, 100))`

### 3.3 Control reduction from questionnaire answers

Five control families are evaluated from questionnaire fields:

- `mfa`
- `segmentation`
- `logging_detection`
- `backup_recovery`
- `incident_response`

For each control family:

1. Pick base profile from answer type:
- `yes` -> strong profile
- `no` -> weak profile
- `unknown` -> evidence-weak profile

2. Apply penalties based on related matched negative signals:

`penalty = min(0.35, 0.08 * penalty_count)`

`adjusted_value = clamp(base_value - penalty + bonus)`

3. Compute control effectiveness:

`effectiveness_j = clamp(sum(control_effectiveness_weight_k * adjusted_profile_k))`

4. Convert to risk reduction strength:

`effective_reduction_j = clamp(effectiveness_j * control_strength_j)`

Global control reduction is multiplicative:

`control_reduction = clamp(1 - product(1 - effective_reduction_j))`

Default control strengths:

- mfa: `0.30`
- segmentation: `0.25`
- logging_detection: `0.18`
- backup_recovery: `0.15`
- incident_response: `0.12`

### 3.4 Residual risk + uncertainty penalty for unknowns

Before uncertainty:

`residual_before_uncertainty = clamp(inherent_risk * (1 - control_reduction), 0, 100)`

Questionnaire completeness:

`questionnaire_completeness = known_answers / total_answers`

Unknown-answer penalty multiplier:

`uncertainty_multiplier = 1 + ((1 - questionnaire_completeness) * unknown_answer_penalty)`

Default `unknown_answer_penalty = 0.60`.

Final residual risk:

`residual_risk = round(clamp(residual_before_uncertainty * uncertainty_multiplier, 0, 100))`

Final score and level:

- `overall_score = residual_risk`
- `risk_level`:
  - `Low`: `0..20`
  - `Moderate`: `21..45`
  - `High`: `46..70`
  - `Critical`: `71..100`

### 3.5 Confidence score (input quality metric)

Confidence is separate from risk severity.
It uses questionnaire completeness + signal/data quality:

`confidence = clamp(sum(weight_k * factor_k))`

Factors:

- `questionnaire_completeness`
- `signal_coverage = clamp(len(matched_signals)/6)`
- `control_evidence_quality` (from control effectiveness quality)
- `input_specificity` (token/detail/keyword/signal-based specificity)

Default weights:

- questionnaire_completeness: `0.35`
- signal_coverage: `0.25`
- control_evidence_quality: `0.20`
- input_specificity: `0.20`

## 4) Optional Requirements/Controls Input Calculation

If a requirements index/root is provided, controls are retrieved and requirement-linked risks are computed.
This currently enriches explainability/calibration outputs in `factor_snapshot` and requirement risk sections.

### 4.1 Retrieval score per control

Each candidate control gets:

`retrieval_score = 0.30*taxonomy + 0.30*vector + 0.20*keyword + 0.15*lexical + 0.05*severity_bonus`

Where:

- `taxonomy`: component-category match boost
- `vector`: IDF-weighted cosine token similarity
- `keyword`: overlap of extracted domain keywords
- `lexical`: character n-gram jaccard overlap
- `severity_bonus`: 1.0 for high severity else 0.0

### 4.2 Requirement risk score per retrieved control

For each retrieved control:

`control_risk_factor = control.risk_weight * control_risk_weight`

`sensitivity_factor = data_sensitivity_factor(questionnaire) * data_sensitivity_weight`

`exposure_factor = exposure_level_factor(questionnaire) * exposure_level_weight`

`compliance_gap_factor = compliance_gap_factor(questionnaire) * compliance_gap_weight`

`control_requirement_risk = control_risk_factor * sensitivity_factor * exposure_factor * compliance_gap_factor`

Aggregate and normalize:

`requirement_risk_score = clamp(sum(control_requirement_risk) * normalization_multiplier, 0, 100)`

Default requirement-scoring weights:

- `control_risk_weight = 1.0`
- `data_sensitivity_weight = 1.0`
- `exposure_level_weight = 1.0`
- `compliance_gap_weight = 1.0`
- `normalization_multiplier = 3.5`

## 5) Input-Type Summary (Quick View)

- Text input mainly drives: signal matching, signal weights, exposure/exploitability/threat context.
- Questionnaire input mainly drives: impact factors, control effectiveness, unknown-answer uncertainty penalty, confidence completeness.
- Requirements input mainly drives: retrieved control relevance and requirement-linked risk traceability/calibration metrics.

## 6) Configuration Override

All major weighting blocks are runtime-configurable through `frameworks/risk_factors.yaml`:

- likelihood weights
- impact weights
- control effectiveness weights
- control strengths
- confidence weights
- requirement risk weights
- residual adjustment penalty

If config is missing/invalid, engine defaults are used.
