# Astraut Risk Reasoner MVP

Turn a short description of a company into a cybersecurity risk assessment.

Describe your stack. Get a risk score, top threats, and a 7-day action plan.

⭐ If you find this useful, consider starring the repository.

## 10-second demo

Describe a company:

```bash
astraut-risk assess "We are a 12-person SaaS startup using AWS, Gmail and Stripe"
```

Result:

```text
Risk Score: 24 / 100

Top Risks
- Internet-facing SaaS footprint
- Baseline controls not explicitly stated
```

Output includes:

- Risk score
- Top threats
- Framework mapping (NIST, CIS, OWASP)
- 7-day action plan

## What it does

Astraut Risk Reasoner analyzes a simple company description and produces a structured cybersecurity risk assessment.

It combines:

- deterministic risk signals
- security framework mappings
- AI explanations

![MIT License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![CLI Tool](https://img.shields.io/badge/type-CLI-orange)
![Security](https://img.shields.io/badge/domain-cybersecurity-red)

Astraut Risk Reasoner helps small teams turn practical security signals into actionable priorities.

## Quick Install

```bash
pip install "git+https://github.com/astraut-solutions/astraut-risk-reasoner.git"
```

## Quick Demo

```bash
astraut-risk assess "12-person SaaS company on AWS"
```

Without API keys/network calls:

```bash
astraut-risk demo
```

## Commands

- `astraut-risk assess "..."`: Deterministic baseline scoring + LLM explanations.
- `astraut-risk assess "..." --model llama-3.3-70b-versatile`: Select the supported Groq model.
- `astraut-risk assess "..." --use-cache`: Save assessment snapshots locally (write-only cache).
- `astraut-risk assess "..." --refresh-cache`: Compatibility flag; assessment still runs fresh and saves snapshot.
- `astraut-risk assess "..." --export report.json`: Export full assessment report as JSON.
- `astraut-risk assess "..." --export report.md`: Export final rendered report as Markdown.
- `astraut-risk assess "..." --export report.csv`: Export assessment sections as CSV.
- `astraut-risk assess "..." --export json,md --output reports/assessment`: Export multiple formats with auto-appended extensions.
- `astraut-risk inspect "..."`: Deterministic analysis only (signals, weights, control gaps).
- `astraut-risk controls`: Show enabled CIS/NIST/OWASP framework mappings.
- `astraut-risk controls cis|nist|owasp`: Show mappings filtered to one framework.
- `astraut-risk control-delta <old_index.json> <new_index.json> --output delta.json`: Compare versioned requirement controls.
- `astraut-risk policy-check "..."`: Run policy-as-code checks.
- `astraut-risk policy-check "..." --policy-pack docs/policy_pack.example.yaml`: Run external YAML policy pack checks.
- `astraut-risk policy-check "..." --policy-pack docs/policy_pack.example.yaml --no-default-policies`: Run only custom pack rules.
- `astraut-risk policy-check "..." --questionnaire-file questionnaire.json --hook-output assessments/policy_hook.json`: Evaluate with explicit questionnaire context and export hook payload.
- `astraut-risk governance-submit <assessment_cache.json> --requested-by <user> --approver <a> --approver <b>`: Start approval trail.
- `astraut-risk governance-approve <trail_id> --actor <user> --decision approve|reject`: Record approval/rejection.
- `astraut-risk governance-list`: List governance trails.
- `astraut-risk governance-list --status pending|approved|rejected`: Filter trails by workflow state.
- `astraut-risk checklist`: Show practical SME baseline checklist.
- `astraut-risk matrix`: Show cybersecurity investment matrix.
- `astraut-risk explain <topic>`: Explain a cybersecurity concept (e.g., `mfa`).
- `astraut-risk scenario list`: List built-in SME scenarios.
- `astraut-risk scenario run saas_startup`: Run a built-in scenario assessment.
- `astraut-risk demo`: Show static built-in output with no API key.
- `astraut-risk doctor`: Run environment and connectivity checks.

### Full command examples

```bash
astraut-risk assess "We are a 12-person SaaS startup using AWS, Gmail, Stripe and GitHub"
astraut-risk assess "12-person SaaS on AWS with public API" --use-cache
astraut-risk assess "12-person SaaS on AWS with public API" --refresh-cache
astraut-risk assess "12-person SaaS on AWS with public API" --model llama-3.3-70b-versatile
astraut-risk assess "12-person SaaS on AWS with public API" --export report.json
astraut-risk assess "12-person SaaS on AWS with public API" --export report.md
astraut-risk assess "12-person SaaS on AWS with public API" --export report.csv
astraut-risk assess "12-person SaaS on AWS with public API" --export json,md --output reports/assessment

astraut-risk inspect "We are a 12-person SaaS startup using AWS, Gmail, Stripe and GitHub"
astraut-risk explain mfa
astraut-risk doctor
astraut-risk demo
astraut-risk checklist
astraut-risk matrix
astraut-risk controls
astraut-risk controls cis
astraut-risk controls nist
astraut-risk controls owasp
astraut-risk control-delta assessments/requirements_prev.json assessments/requirements_curr.json --output assessments/control_delta.json
astraut-risk policy-check "12-person SaaS on AWS with public API and no MFA"
astraut-risk policy-check "12-person SaaS on AWS with public API and no MFA" --policy-pack docs/policy_pack.example.yaml
astraut-risk policy-check "12-person SaaS on AWS with public API and no MFA" --policy-pack docs/policy_pack.example.yaml --no-default-policies
astraut-risk policy-check "12-person SaaS on AWS with public API and no MFA" --policy-pack docs/policy_pack.example.yaml --questionnaire-file questionnaire.json --hook-output assessments/policy_hook.json
astraut-risk scenario list
astraut-risk scenario run saas_startup
```

## Configure API Key

```bash
cp .env.example .env
```

Set:

```env
GROQ_API_KEY=your_real_key_here
```

## Why this is different

Astraut Risk Reasoner now combines:

- deterministic SME control scoring
- explainable risk mapping
- AI-assisted plain-English recommendations

This gives SMEs a consistent baseline score while still getting practical narrative guidance.

It also maps detected signals to control frameworks (CIS Controls, NIST CSF, OWASP) for stronger audit-readiness and trust.

## Control Framework Mapping

Detected risks are mapped to widely used security frameworks including:

- CIS Critical Security Controls
- NIST Cybersecurity Framework
- OWASP Top 10

## How scoring works

Base scoring is deterministic and rule-based, with a structured factor model:

1. Parse company description and optional questionnaire context for known SME control-risk signals.
2. Compute normalized `likelihood` and `impact` from weighted factors.
3. Compute `inherent_risk = likelihood * impact * 100` (bounded to 0-100).
4. Compute control effectiveness and adjusted control reduction with diminishing returns.
5. Compute `residual_risk` and use it as `overall_score`.
6. Compute `confidence` from questionnaire completeness, signal coverage, and evidence quality.
7. Map matched signals to explainable control guidance and framework references.

The LLM receives these structured findings and expands them into clear recommendations, priorities, and 7-day actions. The LLM does not generate the base score.

## Consistency across interfaces

The CLI and Web UI share the same deterministic risk engine and assessment renderer.
This guarantees identical baseline findings (risk score, detected gaps, and risk level).
AI is used only to expand and explain these findings in plain language.

Result: consistent security conclusions with flexible narrative explanations.
When caching is enabled, results are stored under `assessments/` (with timestamped history in `assessments/history/`).

## Example scenarios

```bash
astraut-risk scenario list
astraut-risk scenario run saas_startup
astraut-risk inspect "12-person SaaS startup on AWS with no MFA"
```

## Trust & limits

- Useful for early-stage risk thinking and prioritization.
- Not a replacement for a professional cybersecurity audit.
- Deterministic signals improve consistency and transparency.
- LLM output adds explanation and practical guidance, not core scoring.

## How it works

```text
User input
  ↓
Deterministic SME risk engine (signals + questionnaire + factor model)
  ↓
Structured findings (likelihood, impact, inherent, residual, confidence, control gaps)
  ↓
LLM explanation + prioritization
  ↓
CLI / Streamlit output
```

## Architecture status

- Current implementation: single-process CLI + Streamlit app with local files/cache and no external persistence layer.
- `PLAN.md` describes the implemented MVP enhancement scope for structured input and document-aligned risk computation.
- `docs/Astraut Risk Reasoner-v2.md` and `docs/Astraut Risk Reasoner-v3.md` describe broader target-state platform architecture (future-facing reference), not the current deployed repo shape.
- See `docs/STATUS.md` for a concise alignment snapshot.

## Project structure

```text
src/astraut_risk/
  cli.py
  reasoning.py
  risk_engine.py
  control_map.py
  scenarios.py
  models.py
  output.py
  checklist.py
  matrix.py
  config.py
```

## Terminal screenshots

Current docs assets:

- [System Architecture Diagram](docs/18.1%20System%20Architecture%20Diagram.png)
- [Risk Computation Flow Diagram](docs/18.2%20Risk%20Computation%20Flow%20Diagram.png)
- [Deployment Diagram](docs/18.3%20Deployment%20Diagram.png)

## Development

```bash
make install
make lint
make format
make test
```

## Live Web Demo

```bash
pip install -r requirements.txt
streamlit run web/app.py
```

The web interface supports deterministic + LLM-assisted assessment, checklist view, matrix view, and built-in scenario examples.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).
