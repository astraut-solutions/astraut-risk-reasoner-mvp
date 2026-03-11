"""CLI entrypoint for Astraut Risk Reasoner."""

from __future__ import annotations

import os
import socket
import sys
from typing import Dict, List

import typer
from dotenv import load_dotenv
from groq import Groq
from rich import box
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

load_dotenv()

app = typer.Typer(
    help="Astraut Risk Reasoner: practical cybersecurity risk guidance for SMEs."
)
console = Console()

SYSTEM_PROMPT = (
    "You are Astraut Risk Reasoner from Astraut Solutions. You help SMEs think "
    "clearly about digital risk, trust and system design before small weaknesses "
    "become incidents. Core principles: Zero Trust thinking, AI-assisted risk "
    "reasoning, practical NIST/OWASP/CISA advice, tested backups, MFA everywhere, "
    "clear ownership in incidents, cloud resilience. Focus on small teams (5-50 "
    "people). Be practical, never scary. Structure output as: Overall Risk Score "
    "(1-10 with emoji), Top 3 Risks (short), Personalized Recommendations (Zero "
    "Trust steps first), 7-day Action Checklist, Suggested investment priorities "
    "(reference the 2025 matrix: start with MFA + segmentation, then detection, "
    "then advanced)."
)

DEMO_INPUT = (
    "We are a 12-person SaaS startup on AWS using Gmail, Stripe, and a custom "
    "web app with public API. No MFA on admin yet."
)

DEMO_ASSESSMENT = """## Overall Risk Score
8/10 ⚠️

## Top 3 Risks
1. No MFA on privileged/admin paths (AWS, Gmail admin, app admin).
2. Public API abuse risk from weak auth, rate limits, and key exposure.
3. Excessive access scope increases blast radius after credential theft.

## Personalized Recommendations (Zero Trust first)
- Enforce MFA for all privileged accounts in 48 hours; disable legacy auth.
- Segment admin access from production/data-plane access.
- Apply least-privilege IAM and short-lived credentials for humans/services.
- Add centralized auth/API monitoring with high-signal alerting.

## 7-day Action Checklist
1. Day 1-2: Enable MFA for AWS root/admin, Google Workspace admins, app admins.
2. Day 3: Tighten IAM roles and remove shared admin credentials.
3. Day 4: Harden API auth scopes, rotate secrets, and enforce rate limiting.
4. Day 5: Test restore for backups of data, configs, and infra state.
5. Day 6: Configure alerts for impossible travel, privilege escalation, API abuse.
6. Day 7: Run tabletop for account takeover + leaked token scenarios.

## Suggested investment priorities (2025 matrix)
1. MFA + segmentation first.
2. Detection and response second.
3. Advanced controls after baseline maturity.
"""

CHECKLIST_ITEMS: List[str] = [
    "Enable MFA for all admin, cloud, email, finance, and code-repo accounts.",
    "Define least-privilege access and remove stale users every month.",
    "Segment production, staging, and internal admin networks.",
    "Enforce strong password manager use and disable shared credentials.",
    "Back up critical systems daily and test restore quarterly.",
    "Protect public APIs with auth, rate limits, schema validation, and logging.",
    "Patch operating systems, dependencies, and containers on a fixed schedule.",
    "Turn on centralized monitoring and alerting for suspicious auth activity.",
    "Create a simple incident owner map: who decides, who communicates, who fixes.",
    "Review vendor and supply-chain risk for payment, auth, and CI/CD services.",
]

MATRIX_ROWS: List[Dict[str, str]] = [
    {
        "priority": "1",
        "focus": "MFA + Segmentation",
        "why": "Highest risk reduction per dollar for SMEs.",
        "examples": "MFA for admin/email/cloud; network and role segmentation.",
    },
    {
        "priority": "2",
        "focus": "Detection & Response Basics",
        "why": "Catch account abuse and unusual behavior early.",
        "examples": "Cloud audit logs, SIEM-lite alerts, incident runbooks.",
    },
    {
        "priority": "3",
        "focus": "Zero Trust Access",
        "why": "Limit lateral movement and credential blast radius.",
        "examples": "Context-aware access, device checks, least privilege.",
    },
    {
        "priority": "4",
        "focus": "Supply Chain Hardening",
        "why": "Third-party and CI/CD compromise is rising.",
        "examples": "Dependency scanning, signed artifacts, vendor reviews.",
    },
    {
        "priority": "5",
        "focus": "Advanced AI Detection",
        "why": "High value but comes after baseline controls.",
        "examples": "Behavior analytics, anomaly triage copilots.",
    },
]


def _get_client() -> Groq:
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        console.print(
            Panel(
                "[bold red]Missing GROQ_API_KEY[/bold red]\n\n"
                "Set `GROQ_API_KEY` in your environment or `.env` file.\n"
                "You can copy `.env.example` to `.env` and fill in your key.",
                title="Configuration Error",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)
    return Groq(api_key=api_key)


def _check_python_version() -> tuple[bool, str]:
    version = sys.version_info
    ok = version >= (3, 9)
    return ok, f"{version.major}.{version.minor}.{version.micro}"


def _check_groq_api_key() -> tuple[bool, str]:
    key = os.getenv("GROQ_API_KEY", "")
    if not key:
        return False, "Missing"
    masked = f"{key[:6]}...{key[-4:]}" if len(key) > 12 else "Set"
    return True, masked


def _check_internet() -> tuple[bool, str]:
    try:
        with socket.create_connection(("api.groq.com", 443), timeout=3):
            return True, "Reachable (api.groq.com:443)"
    except OSError as exc:
        return False, f"Not reachable ({exc.__class__.__name__})"


def _check_groq_access() -> tuple[bool, str]:
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return False, "Skipped (missing GROQ_API_KEY)"
    try:
        client = Groq(api_key=api_key)
        models = client.models.list()
        count = len(models.data) if hasattr(models, "data") else 0
        return True, f"Authenticated (models visible: {count})"
    except Exception as exc:  # pragma: no cover - network/credential dependent
        return False, f"Failed ({exc.__class__.__name__})"


@app.command()
def assess(
    company_description: str = typer.Argument(
        ...,
        help="Natural-language description of your company setup and current security posture.",
    ),
    model: str = typer.Option(
        "llama-3.3-70b-versatile",
        "--model",
        help="Groq model to use (llama-3.3-70b-versatile or llama3-8b-8192).",
    ),
) -> None:
    """Assess risk based on a natural-language company description."""
    if model not in {"llama-3.3-70b-versatile", "llama3-8b-8192"}:
        console.print(
            "[red]Invalid model.[/red] Use `llama-3.3-70b-versatile` or `llama3-8b-8192`."
        )
        raise typer.Exit(code=1)

    console.print(
        Panel(
            f"[bold cyan]Input:[/bold cyan] {company_description}",
            title="Astraut Risk Reasoner",
            border_style="cyan",
        )
    )

    client = _get_client()
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold yellow]Reasoning about your risk posture...[/bold yellow]"),
        transient=True,
        console=console,
    ) as progress:
        progress.add_task("llm", total=None)
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": company_description},
            ],
            temperature=0.2,
        )

    content = response.choices[0].message.content or "No response generated."
    _render_assessment(content)


def _render_assessment(content: str) -> None:
    console.print(
        Panel.fit(
            Markdown(content),
            title="Risk Assessment Result",
            border_style="green",
            padding=(1, 2),
        )
    )


@app.command()
def doctor() -> None:
    """Run local diagnostics for runtime and Groq connectivity."""
    python_ok, python_details = _check_python_version()
    key_ok, key_details = _check_groq_api_key()
    internet_ok, internet_details = _check_internet()
    api_ok, api_details = _check_groq_access()

    checks = [
        ("Python version", python_ok, python_details),
        ("GROQ_API_KEY", key_ok, key_details),
        ("Internet connectivity", internet_ok, internet_details),
        ("Groq API access", api_ok, api_details),
    ]

    table = Table(
        title="Astraut Risk Reasoner Diagnostics",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("Check", style="bold white")
    table.add_column("Status", justify="center")
    table.add_column("Details", style="yellow")

    all_ok = True
    for name, ok, details in checks:
        status = "✅ PASS" if ok else "❌ FAIL"
        style = "green" if ok else "red"
        table.add_row(name, f"[{style}]{status}[/{style}]", details)
        all_ok = all_ok and ok

    console.print(table)
    if all_ok:
        console.print("[bold green]All checks passed.[/bold green]")
    else:
        if not key_ok:
            console.print(
                "[bold yellow]Some checks failed.[/bold yellow] "
                "Set `GROQ_API_KEY` and re-run `astraut-risk doctor`."
            )
        else:
            console.print(
                "[bold yellow]Some checks failed.[/bold yellow] "
                "Check network/API access and re-run `astraut-risk doctor`."
            )


@app.command()
def demo() -> None:
    """Print a full example assessment output without requiring API keys."""
    console.print(
        Panel(
            f"[bold cyan]Input:[/bold cyan] {DEMO_INPUT}",
            title="Astraut Risk Reasoner",
            border_style="cyan",
        )
    )
    _render_assessment(DEMO_ASSESSMENT)
    matrix()
    console.print(
        "[dim]Demo mode: static example output (no API key or network call required).[/dim]"
    )


@app.command()
def checklist() -> None:
    """Show a practical SME security checklist."""
    checklist_text = "\n".join(f"- [ ] {item}" for item in CHECKLIST_ITEMS)
    console.print(
        Panel.fit(
            Markdown(checklist_text),
            title="SME Security Checklist",
            subtitle="Practical baseline controls",
            border_style="blue",
            padding=(1, 2),
        )
    )


@app.command()
def matrix() -> None:
    """Show the Cybersecurity Investment Strategy Matrix 2025."""
    table = Table(
        title="Cybersecurity Investment Strategy Matrix 2025",
        box=box.ROUNDED,
        header_style="bold magenta",
        show_lines=True,
    )
    table.add_column("Priority", style="bold cyan", justify="center")
    table.add_column("Investment Focus", style="bold white")
    table.add_column("Why Now", style="green")
    table.add_column("SME Examples", style="yellow")

    for row in MATRIX_ROWS:
        table.add_row(row["priority"], row["focus"], row["why"], row["examples"])

    console.print(table)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
