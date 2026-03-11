# Astraut Risk Reasoner

Astraut Risk Reasoner is the first open-source CLI product from **Astraut Solutions**, an independent research group focused on AI, cybersecurity, and responsible automation for SMEs.

It helps small teams reason clearly about digital risk and practical next steps before minor weaknesses become incidents.

## Mission Fit

This tool reflects Astraut's operating principles:
- Zero Trust thinking by default.
- AI-assisted risk reasoning for practical decision support.
- Actionable NIST/OWASP/CISA-aligned guidance for teams of 5-50 people.
- Resilience basics first: MFA, segmentation, backups, detection, clear ownership.

## Features

- `astraut-risk assess "..."`:
  - Uses Groq LLMs (`llama-3.3-70b-versatile` by default).
  - Applies Astraut's risk system prompt.
  - Produces structured, practical output with Rich formatting.
- `astraut-risk checklist`:
  - Static, practical SME security checklist.
- `astraut-risk matrix`:
  - Cybersecurity Investment Strategy Matrix 2025 in a Rich table.

## Install

### 1) Clone and enter project

```bash
git clone <your-fork-or-repo-url>
cd astraut-risk-reasoner
```

### 2) (Optional) Create a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
```

### 3) Install in editable mode

```bash
pip install -e .
```

## Quick Install (GitHub)

Install directly from GitHub in one command:

```bash
pip install "git+https://github.com/astraut-solutions/astraut-risk-reasoner.git"
```

Then run:

```bash
astraut-risk --help
```

## Configure Groq API Key

Copy the example env file and set your key:

```bash
cp .env.example .env
```

Then edit `.env`:

```env
GROQ_API_KEY=your_real_key_here
```

You can also export it directly:

```bash
export GROQ_API_KEY=your_real_key_here
```

## Usage

### Main assessment command

```bash
astraut-risk assess "We are a 12-person SaaS startup on AWS using Gmail, Stripe, and a custom web app with public API. No MFA on admin yet."
```

Use the lighter model:

```bash
astraut-risk assess "..." --model llama3-8b-8192
```

### Static checklist

```bash
astraut-risk checklist
```

### 2025 investment matrix

```bash
astraut-risk matrix
```

## Python module execution

Also works with:

```bash
python -m astraut_risk assess "Your description"
```

## Output Structure (Assess)

The assistant is prompted to return:
1. Overall Risk Score (1-10 with emoji)
2. Top 3 Risks
3. Personalized Recommendations (Zero Trust first)
4. 7-day Action Checklist
5. Suggested investment priorities aligned with the 2025 matrix

## Disclaimer

This is a **research tool** from Astraut Solutions. It is not legal advice, compliance certification, or a replacement for a full professional security assessment.

## License

MIT. See [LICENSE](./LICENSE).
