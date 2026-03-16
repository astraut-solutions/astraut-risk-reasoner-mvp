# Astraut Risk Reasoner

Turn a short description of a company into a cybersecurity risk assessment.

Describe your stack. Get a risk score, top threats, and a 7-day action plan.

## 10-second demo

Describe a company:

```bash
astraut-risk assess "We are a 12-person SaaS startup using AWS, Gmail and Stripe"
```

Result:

```text
Risk Score: 67 / 100

Top Risks
- Missing MFA
- Public API exposure
- Insufficient logging
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
- `astraut-risk assess "..." --use-cache`: Reuse/persist saved results for identical assessments.
- `astraut-risk assess "..." --export report.json`: Export full assessment report as JSON.
- `astraut-risk assess "..." --export report.md`: Export final rendered report as Markdown.
- `astraut-risk inspect "..."`: Deterministic analysis only (signals, weights, control gaps).
- `astraut-risk controls`: Show enabled CIS/NIST/OWASP framework mappings.
- `astraut-risk controls cis|nist|owasp`: Show mappings filtered to one framework.
- `astraut-risk checklist`: Show practical SME baseline checklist.
- `astraut-risk matrix`: Show cybersecurity investment matrix.
- `astraut-risk explain <topic>`: Explain a cybersecurity concept (e.g., `mfa`).
- `astraut-risk scenario list`: List built-in SME scenarios.
- `astraut-risk scenario run saas_startup`: Run a built-in scenario assessment.
- `astraut-risk demo`: Show static built-in output with no API key.
- `astraut-risk doctor`: Run environment and connectivity checks.

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

Base score generation is deterministic and rule-based:

1. Parse company description for known SME control-risk signals (e.g., no MFA, flat network, no logging).
2. Apply fixed signal weights.
3. Compute total score and risk level.
4. Map matched signals to explainable control guidance.

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
Deterministic SME risk engine (rule-based)
  ↓
Structured findings (score, matched signals, control gaps)
  ↓
LLM explanation + prioritization
  ↓
CLI / Streamlit output
```

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

Live terminal capture:

![CLI Demo](docs/demo.gif)

Static screenshot:

![CLI Screenshot](docs/example-output.png)

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
