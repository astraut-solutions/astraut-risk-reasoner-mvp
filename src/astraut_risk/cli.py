"""Typer CLI commands for Astraut Risk Reasoner."""

from __future__ import annotations

import csv
import json
import socket
import sys
from datetime import datetime
from pathlib import Path

import typer
from groq import Groq
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .checklist import format_checklist_markdown
from .config import (
    DEFAULT_MODEL,
    MissingApiKeyError,
    get_groq_api_key,
    load_environment,
    mask_key,
)
from .matrix import MATRIX_ROWS
from .output import (
    console,
    render_assessment,
    render_checklist,
    render_error,
    render_explanation,
    render_info,
    render_input_panel,
    render_matrix,
)
from .reasoning import (
    InvalidInputError,
    LLMAPIError,
    NetworkError,
    build_assessment_messages,
    build_explain_messages,
    request_completion,
    validate_company_description,
    validate_model,
)

app = typer.Typer(
    help="Astraut Risk Reasoner: practical cybersecurity risk guidance for SMEs."
)
load_environment()

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

EXPLAINER_FALLBACKS: dict[str, str] = {
    "mfa": """## MFA (Multi-Factor Authentication)
MFA means users must prove identity with two or more factors, not just a password.

### Why it matters for SMEs
Password theft is still one of the most common ways attackers get in. MFA blocks most account takeover attempts even when passwords leak.

### Practical steps
1. Enable MFA first on admin, cloud, email, and finance accounts.
2. Prefer authenticator apps or hardware keys over SMS.
3. Disable legacy login flows that bypass MFA.
""",
    "zero trust": """## Zero Trust
Zero Trust is a security model that treats every access request as untrusted by default.

### Why it matters for SMEs
Small teams usually share tools and move fast. Zero Trust reduces blast radius when one account is compromised.

### Practical steps
1. Enforce least privilege for each role.
2. Separate admin paths from daily user workflows.
3. Continuously log and review access behavior.
""",
    "phishing": """## Phishing
Phishing tricks people into revealing credentials or running malicious actions.

### Why it matters for SMEs
A single compromised mailbox can expose invoices, reset links, and customer data.

### Practical steps
1. Turn on MFA for email and admin users.
2. Run short monthly phishing-awareness drills.
3. Add email protections (SPF, DKIM, DMARC) and alerting.
""",
}


def _get_client() -> Groq:
    key = get_groq_api_key(required=True)
    return Groq(api_key=key)


def _extract_markdown_sections(content: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    current = "full_response"
    lines: list[str] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if line.startswith("## "):
            sections[current] = "\n".join(lines).strip()
            current = line[3:].strip().lower().replace(" ", "_")
            lines = []
        else:
            lines.append(raw_line)
    sections[current] = "\n".join(lines).strip()
    return {k: v for k, v in sections.items() if v}


def _export_assessment_csv(
    company_description: str, model: str, content: str, output_path: str | None = None
) -> str:
    path = output_path or (
        f"astraut_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    )
    rows = [
        ("timestamp", datetime.now().isoformat(timespec="seconds")),
        ("model", model),
        ("company_description", company_description),
        ("assessment_markdown", content),
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["field", "value"])
        writer.writerows(rows)
    return path


def _export_assessment_json(
    company_description: str, model: str, content: str, output_path: str | None = None
) -> str:
    path = output_path or (
        f"astraut_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )
    payload = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "model": model,
        "company_description": company_description,
        "assessment_markdown": content,
        "sections": _extract_markdown_sections(content),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return path


def _parse_export_formats(export: str) -> list[str]:
    if not export.strip():
        return []
    formats = [fmt.strip().lower() for fmt in export.split(",") if fmt.strip()]
    unique: list[str] = []
    for fmt in formats:
        if fmt not in unique:
            unique.append(fmt)
    invalid = [fmt for fmt in unique if fmt not in {"csv", "json"}]
    if invalid:
        bad = ", ".join(invalid)
        raise InvalidInputError(
            f"Invalid export format(s): {bad}. Supported values: csv, json"
        )
    return unique


def _resolve_output_path(output: str, fmt: str, multi: bool) -> str | None:
    if not output:
        return None
    if not multi:
        return output
    path = Path(output)
    stem = path.with_suffix("")
    return f"{stem}.{fmt}"


@app.command()
def assess(
    company_description: str = typer.Argument(
        ...,
        help="Natural-language description of your company setup and security posture.",
    ),
    model: str = typer.Option(
        DEFAULT_MODEL,
        "--model",
        help="Groq model to use (currently supported: llama-3.3-70b-versatile).",
    ),
    export: str = typer.Option(
        "",
        "--export",
        help="Export formats for results. Supported: csv, json, or csv,json",
    ),
    output: str = typer.Option(
        "",
        "--output",
        help="Output path for exported file(s). For multi-format exports, extensions are auto-appended.",
    ),
) -> None:
    """Assess risk from a company description."""
    try:
        validate_company_description(company_description)
        validate_model(model)
        export_formats = _parse_export_formats(export)

        render_input_panel(company_description)
        client = _get_client()

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold yellow]Reasoning about your risk posture...[/bold yellow]"),
            transient=True,
            console=console,
        ) as progress:
            progress.add_task("llm", total=None)
            content = request_completion(
                client=client,
                messages=build_assessment_messages(company_description),
                model=model,
            )

        render_assessment(content)

        if export_formats:
            multi = len(export_formats) > 1
            exported_files: list[str] = []
            for fmt in export_formats:
                out_path = _resolve_output_path(output, fmt, multi)
                if fmt == "csv":
                    exported = _export_assessment_csv(
                        company_description=company_description,
                        model=model,
                        content=content,
                        output_path=out_path,
                    )
                else:
                    exported = _export_assessment_json(
                        company_description=company_description,
                        model=model,
                        content=content,
                        output_path=out_path,
                    )
                exported_files.append(exported)
            render_info(
                "Export Complete",
                "[bold green]Exported assessment files:[/bold green] "
                + ", ".join(exported_files),
            )

    except MissingApiKeyError as exc:
        render_error(
            "Configuration Error",
            str(exc),
            hint="Copy .env.example to .env and set GROQ_API_KEY.",
        )
        raise typer.Exit(code=1)
    except InvalidInputError as exc:
        render_error("Invalid Input", str(exc))
        raise typer.Exit(code=1)
    except NetworkError as exc:
        render_error(
            "Network Error",
            str(exc),
            hint="Check internet connectivity and retry.",
        )
        raise typer.Exit(code=1)
    except LLMAPIError as exc:
        render_error(
            "LLM API Error",
            str(exc),
            hint="Verify GROQ_API_KEY validity and model availability.",
        )
        raise typer.Exit(code=1)


@app.command()
def explain(
    topic: str = typer.Argument(..., help="Cybersecurity topic to explain (e.g. mfa)."),
    model: str = typer.Option(
        DEFAULT_MODEL,
        "--model",
        help="Optional model when calling Groq for a custom explanation.",
    ),
) -> None:
    """Explain a cybersecurity concept for SME teams."""
    normalized = (topic or "").strip().lower()
    if not normalized:
        render_error("Invalid Input", "Topic cannot be empty.")
        raise typer.Exit(code=1)

    # No API key required for common topics.
    if normalized in EXPLAINER_FALLBACKS:
        render_explanation(topic=topic, content=EXPLAINER_FALLBACKS[normalized])
        return

    try:
        validate_model(model)
        client = _get_client()
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold yellow]Preparing concept explanation...[/bold yellow]"),
            transient=True,
            console=console,
        ) as progress:
            progress.add_task("llm", total=None)
            content = request_completion(
                client=client,
                messages=build_explain_messages(topic),
                model=model,
                temperature=0.1,
            )
        render_explanation(topic=topic, content=content)
    except MissingApiKeyError:
        render_explanation(
            topic=topic,
            content=(
                "## Topic not in built-in glossary\n"
                "Set `GROQ_API_KEY` to generate custom explanations, or try built-in "
                "topics like `mfa`, `zero trust`, or `phishing`."
            ),
        )
    except (InvalidInputError, NetworkError, LLMAPIError) as exc:
        render_error("Explain Command Error", str(exc))
        raise typer.Exit(code=1)


@app.command()
def doctor() -> None:
    """Run local diagnostics for runtime and Groq connectivity."""
    load_environment()

    version = sys.version_info
    python_ok = version >= (3, 9)
    python_details = f"{version.major}.{version.minor}.{version.micro}"

    key = get_groq_api_key(required=False)
    key_ok = bool(key)
    key_details = mask_key(key)

    try:
        with socket.create_connection(("api.groq.com", 443), timeout=3):
            internet_ok, internet_details = True, "Reachable (api.groq.com:443)"
    except OSError as exc:
        internet_ok, internet_details = False, f"Not reachable ({exc.__class__.__name__})"

    if key:
        try:
            client = Groq(api_key=key)
            models = client.models.list()
            count = len(models.data) if hasattr(models, "data") else 0
            api_ok, api_details = True, f"Authenticated (models visible: {count})"
        except Exception as exc:
            api_ok, api_details = False, f"Failed ({exc.__class__.__name__})"
    else:
        api_ok, api_details = False, "Skipped (missing GROQ_API_KEY)"

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
    elif not key_ok:
        console.print(
            "[bold yellow]Some checks failed.[/bold yellow] Set `GROQ_API_KEY` and re-run `astraut-risk doctor`."
        )
    else:
        console.print(
            "[bold yellow]Some checks failed.[/bold yellow] Check network/API access and retry."
        )


@app.command()
def demo() -> None:
    """Print a full example assessment output without API keys."""
    render_input_panel(DEMO_INPUT)
    render_assessment(DEMO_ASSESSMENT)
    render_matrix(MATRIX_ROWS)
    console.print(
        "[dim]Demo mode: static example output (no API key or network call required).[/dim]"
    )


@app.command()
def checklist() -> None:
    """Show a practical SME security checklist."""
    render_checklist(format_checklist_markdown())


@app.command()
def matrix() -> None:
    """Show the Cybersecurity Investment Strategy Matrix 2025."""
    render_matrix(MATRIX_ROWS)


def main() -> None:
    """CLI main entrypoint."""
    load_environment()
    app()
