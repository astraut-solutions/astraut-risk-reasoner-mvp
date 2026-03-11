# Astraut Risk Reasoner

![MIT License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![CLI Tool](https://img.shields.io/badge/type-CLI-orange)
![Security](https://img.shields.io/badge/domain-cybersecurity-red)

Astraut Risk Reasoner is the first open-source CLI product from **Astraut Solutions**, an independent research group focused on AI, cybersecurity, and responsible automation for SMEs.

See real example outputs below 👇

It helps small teams reason clearly about digital risk and practical next steps before minor weaknesses become incidents.

## 30-Second Demo

```bash
pip install "git+https://github.com/astraut-solutions/astraut-risk-reasoner.git"

astraut-risk demo
```

Example output:

![Demo](docs/demo.png)
Example output from `astraut-risk demo`.  
Runs instantly without API keys or network calls.

## Quick Install (GitHub)

Install directly from GitHub in one command:

```bash
pip install "git+https://github.com/astraut-solutions/astraut-risk-reasoner.git"
```

Then run:

```bash
astraut-risk --help
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

### Demo (no API key required)

```bash
astraut-risk demo
```

## Example Output

Here’s exactly what each command produces (real output with Rich formatting):

### assess

```text
astraut-risk assess "We are a 12-person SaaS startup on AWS using Gmail, Stripe, and a custom web app with public API. No MFA on admin yet."
╭─────────────────────────────────────── Astraut Risk Reasoner ───────────────────────────────────────╮
│ Input: We are a 12-person SaaS startup on AWS using Gmail, Stripe, and a custom web app with public │
│ API. No MFA on admin yet.                                                                           │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────── Risk Assessment Result ───────────────────────────────────────╮
│ Overall Risk Score: 8/10 ⚠️                                                                          │
│                                                                                                     │
│ Top 3 Risks                                                                                         │
│ 1. No MFA on admin paths (AWS, Gmail admin, and app admin consoles).                               │
│ 2. Public API exposure without strict auth, throttling, and token hygiene.                         │
│ 3. Over-broad access increases lateral movement after credential compromise.                        │
│                                                                                                     │
│ Personalized Recommendations                                                                         │
│ • Enforce MFA everywhere first, then block legacy login methods.                                   │
│ • Segment admin, production, and data-plane access with least privilege.                           │
│ • Harden API auth: scoped tokens, rotation, rate limiting, and anomaly alerts.                     │
│ • Define incident ownership and escalation for account takeover and key leakage.                    │
│                                                                                                     │
│ 7-day Action Checklist                                                                              │
│ 1) Day 1-2: Turn on MFA for AWS, Google Workspace admins, and app admins.                          │
│ 2) Day 3: Review and reduce IAM privileges; remove shared admin credentials.                        │
│ 3) Day 4: Add API gateway limits, auth checks, and abuse detection rules.                          │
│ 4) Day 5: Validate backup restore for app data, configs, and infrastructure state.                 │
│ 5) Day 6: Centralize auth and API logs with alerts for suspicious patterns.                        │
│ 6) Day 7: Run a tabletop exercise and confirm owner/contact matrix.                                │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────╯
                            Cybersecurity Investment Strategy Matrix 2025
╭──────────┬─────────────────────────────┬─────────────────────────────┬──────────────────────────────╮
│ Priority │ Investment Focus            │ Why Now                     │ SME Examples                 │
├──────────┼─────────────────────────────┼─────────────────────────────┼──────────────────────────────┤
│ 1        │ MFA + Segmentation          │ Highest risk reduction      │ MFA for admin/email/cloud;  │
│          │                             │ per dollar for SMEs.        │ network and role            │
│          │                             │                             │ segmentation.               │
│ 2        │ Detection & Response Basics │ Catch account abuse early.  │ Cloud audit logs, alerts,   │
│          │                             │                             │ incident runbooks.          │
│ 3        │ Zero Trust Access           │ Reduce lateral movement.    │ Context-aware access, least │
│          │                             │                             │ privilege.                  │
│ 4        │ Supply Chain Hardening      │ Lower third-party risk.     │ Dependency scanning, signed │
│          │                             │                             │ artifacts.                  │
│ 5        │ Advanced AI Detection       │ Add after baseline controls │ Behavior analytics, anomaly │
│          │                             │ are stable.                 │ triage copilots.            │
╰──────────┴─────────────────────────────┴─────────────────────────────┴──────────────────────────────╯
```

### checklist

```text
(.venv) PS D:\workspace\open-source\astraut-risk-reasoner> astraut-risk checklist
╭────────────────────────────────────── SME Security Checklist ───────────────────────────────────────╮
│                                                                                                     │
│                                                                                                     │
│   • [ ] Enable MFA for all admin, cloud, email, finance, and code-repo accounts.                  │
│   • [ ] Define least-privilege access and remove stale users every month.                          │
│   • [ ] Segment production, staging, and internal admin networks.                                  │
│   • [ ] Enforce strong password manager use and disable shared credentials.                        │
│   • [ ] Back up critical systems daily and test restore quarterly.                                 │
│   • [ ] Protect public APIs with auth, rate limits, schema validation, and logging.                │
│   • [ ] Patch operating systems, dependencies, and containers on a fixed schedule.                 │
│   • [ ] Turn on centralized monitoring and alerting for suspicious auth activity.                  │
│   • [ ] Create a simple incident owner map: who decides, who communicates, who fixes.              │
│   • [ ] Review vendor and supply-chain risk for payment, auth, and CI/CD services.                 │
│                                                                                                     │
╰──────────────────────────────────── Practical baseline controls ────────────────────────────────────╯
```

### matrix

```text
(.venv) PS D:\workspace\open-source\astraut-risk-reasoner> astraut-risk matrix
                             Cybersecurity Investment Strategy Matrix 2025
╭──────────┬─────────────────────────────┬─────────────────────────────┬──────────────────────────────╮
│ Priority │ Investment Focus            │ Why Now                     │ SME Examples                 │
├──────────┼─────────────────────────────┼─────────────────────────────┼──────────────────────────────┤
│    1     │ MFA + Segmentation          │ Highest risk reduction per  │ MFA for admin/email/cloud;   │
│          │                             │ dollar for SMEs.            │ network and role             │
│          │                             │                             │ segmentation.                │
├──────────┼─────────────────────────────┼─────────────────────────────┼──────────────────────────────┤
│    2     │ Detection & Response Basics │ Catch account abuse and     │ Cloud audit logs, SIEM-lite  │
│          │                             │ unusual behavior early.     │ alerts, incident runbooks.   │
├──────────┼─────────────────────────────┼─────────────────────────────┼──────────────────────────────┤
│    3     │ Zero Trust Access           │ Limit lateral movement and  │ Context-aware access, device │
│          │                             │ credential blast radius.    │ checks, least privilege.     │
├──────────┼─────────────────────────────┼─────────────────────────────┼──────────────────────────────┤
│    4     │ Supply Chain Hardening      │ Third-party and CI/CD       │ Dependency scanning, signed  │
│          │                             │ compromise is rising.       │ artifacts, vendor reviews.   │
├──────────┼─────────────────────────────┼─────────────────────────────┼──────────────────────────────┤
│    5     │ Advanced AI Detection       │ High value but comes after  │ Behavior analytics, anomaly  │
│          │                             │ baseline controls.          │ triage copilots.             │
╰──────────┴─────────────────────────────┴─────────────────────────────┴──────────────────────────────╯
```

## Why this exists

Small and medium businesses rarely have dedicated security teams.

Most risk frameworks are designed for enterprises and are too complex for small teams.

Astraut Risk Reasoner helps SMEs quickly think through cyber risk using practical Zero Trust principles.

It is part of the Astraut Solutions research project exploring AI-assisted risk reasoning for small organisations.

## Commands

- `astraut-risk assess "..."`: AI-assisted risk assessment via Groq.
- `astraut-risk checklist`: Practical baseline checklist for SMEs.
- `astraut-risk matrix`: Cybersecurity Investment Strategy Matrix 2025.
- `astraut-risk demo`: Full static demo output, no API key needed.

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

## Install (Editable for Development)

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

⭐ If this project is useful, consider starring the repo.
