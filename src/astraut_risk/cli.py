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
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .assessment_formatter import (
    compose_assessment_markdown,
    extract_markdown_sections as shared_extract_markdown_sections,
)
from .assessment_store import save_cached_result
from .checklist import format_checklist_markdown
from .config import (
    DEFAULT_MODEL,
    MissingApiKeyError,
    get_groq_api_key,
    load_environment,
    mask_key,
)
from .matrix import MATRIX_ROWS
from .models import RiskAssessment
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
from .enterprise import (
    build_integration_hook_payload,
    create_governance_trail,
    evaluate_policy_checks,
    load_governance_trails,
    policy_gate_status,
    record_governance_decision,
    save_governance_trails,
    write_hook_payload,
)
from .questionnaire import (
    high_impact_missing_fields,
    infer_questionnaire_from_text,
    load_questionnaire_file,
    merge_questionnaire,
    questionnaire_templates,
)
from .risk_engine import assess_company_risk
from .security_requirements import (
    compare_control_versions,
    ingest_requirements_repository,
    load_repository_index,
    repository_version_snapshot,
    save_repository_index,
)
from .framework_mapping import (
    list_framework_names,
    load_framework_mappings,
    resolve_framework_selector,
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
from .scenarios import SCENARIOS, get_scenario_description, list_scenarios

app = typer.Typer(
    help="Astraut Risk Reasoner: practical cybersecurity risk guidance for SMEs."
)
scenario_app = typer.Typer(help="Run built-in SME scenario examples.")
app.add_typer(scenario_app, name="scenario")
load_environment()

DEMO_INPUT = (
    "We are a 12-person SaaS startup on AWS using Gmail, Stripe, and a custom "
    "web app with public API. No MFA on admin yet."
)
DEFAULT_REQUIREMENTS_INDEX = "assessments/security_requirements_index.json"

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
    return shared_extract_markdown_sections(content)


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


def _export_assessment_markdown(content: str, output_path: str | None = None) -> str:
    path = output_path or (
        f"astraut_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    )
    Path(path).write_text(content, encoding="utf-8")
    return path


def _parse_export_request(export: str, output: str) -> tuple[list[str], str]:
    export_value = (export or "").strip()
    output_value = (output or "").strip()
    allowed = {"csv", "json", "md"}

    if not export_value:
        if output_value:
            ext = Path(output_value).suffix.lower().lstrip(".")
            if ext in allowed:
                return [ext], output_value
        return [], output_value

    if (
        "," not in export_value
        and export_value.lower() not in allowed
        and Path(export_value).suffix.lower().lstrip(".") in allowed
    ):
        return [Path(export_value).suffix.lower().lstrip(".")], export_value

    formats = [fmt.strip().lower() for fmt in export_value.split(",") if fmt.strip()]
    unique: list[str] = []
    for fmt in formats:
        if fmt not in unique:
            unique.append(fmt)
    invalid = [fmt for fmt in unique if fmt not in allowed]
    if invalid:
        bad = ", ".join(invalid)
        raise InvalidInputError(
            f"Invalid export format(s): {bad}. Supported values: csv, json, md"
        )
    return unique, output_value


def _resolve_output_path(output: str, fmt: str, multi: bool) -> str | None:
    if not output:
        return None
    if not multi:
        return output
    path = Path(output)
    stem = path.with_suffix("")
    return f"{stem}.{fmt}"




def _format_structured_assessment(
    assessment: RiskAssessment, llm_explanation: str | None = None
) -> str:
    return compose_assessment_markdown(assessment, llm_explanation)


_QUESTION_PROMPTS: dict[tuple[str, str], str] = {
    ("technical_architecture", "public_api"): "Do you expose a public API? (yes/no/unknown)",
    ("technical_architecture", "mfa_enforced"): "Is MFA enforced for privileged/admin access? (yes/no/unknown)",
    ("technical_architecture", "network_segmentation"): "Is network segmentation implemented? (yes/no/unknown)",
    ("technical_architecture", "logging_monitoring"): "Are centralized logging and alerting in place? (yes/no/unknown)",
    ("technical_architecture", "backup_restore_tested"): "Are backup restore tests performed regularly? (yes/no/unknown)",
    ("maturity", "incident_response_plan"): "Do you have a documented incident response plan? (yes/no/unknown)",
}


def _normalize_yes_no_unknown(value: str) -> str:
    normalized = (value or "").strip().lower()
    if normalized in {"yes", "y"}:
        return "yes"
    if normalized in {"no", "n"}:
        return "no"
    return "unknown"


def _collect_questionnaire_context(
    company_description: str,
    questionnaire_file: str,
    prompt_missing: bool,
) -> dict[str, dict[str, str]]:
    inferred = infer_questionnaire_from_text(company_description)
    from_file: dict[str, dict[str, str]] | None = None
    if questionnaire_file.strip():
        from_file = load_questionnaire_file(questionnaire_file.strip())
    questionnaire = merge_questionnaire(inferred, from_file)
    missing = high_impact_missing_fields(questionnaire)
    if not missing:
        return questionnaire

    can_prompt = prompt_missing and sys.stdin.isatty()
    if not can_prompt:
        return questionnaire

    render_info(
        "Questionnaire",
        "Answering a few high-impact context questions improves assessment quality.",
    )
    for domain, field in missing:
        prompt = _QUESTION_PROMPTS.get((domain, field), f"{domain}.{field} (yes/no/unknown)")
        answer = typer.prompt(prompt, default="unknown")
        questionnaire[domain][field] = _normalize_yes_no_unknown(answer)
    return questionnaire


def _run_assessment_flow(
    company_description: str,
    model: str,
    export: str,
    output: str,
    use_cache: bool = False,
    refresh_cache: bool = False,
    questionnaire_file: str = "",
    prompt_missing: bool = True,
    use_requirements_index: bool = False,
    requirements_index: str = "",
) -> None:
    validate_company_description(company_description)
    validate_model(model)
    export_formats, resolved_output = _parse_export_request(export, output)
    questionnaire_context = _collect_questionnaire_context(
        company_description,
        questionnaire_file=questionnaire_file,
        prompt_missing=prompt_missing,
    )
    resolved_requirements_index = ""
    if use_requirements_index and requirements_index.strip():
        candidate = Path(requirements_index.strip()).expanduser()
        if candidate.exists():
            resolved_requirements_index = str(candidate)

    deterministic_assessment = assess_company_risk(
        company_description,
        questionnaire_context=questionnaire_context,
        requirements_index=resolved_requirements_index,
    )

    render_input_panel(company_description)

    llm_explanation: str
    client = _get_client()
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold yellow]Reasoning about your risk posture...[/bold yellow]"),
        transient=True,
        console=console,
    ) as progress:
        progress.add_task("llm", total=None)
        llm_explanation = request_completion(
            client=client,
            messages=build_assessment_messages(
                company_description, assessment=deterministic_assessment
            ),
            model=model,
        )

    content = _format_structured_assessment(deterministic_assessment, llm_explanation)

    if use_cache or refresh_cache:
        saved_path = save_cached_result(
            company_description=company_description,
            model=model,
            assessment=deterministic_assessment,
            llm_explanation=llm_explanation,
            assessment_markdown=content,
        )
        render_info("Cache Saved", f"Saved assessment snapshot at `{saved_path}`.")

    render_assessment(content)

    if not export_formats:
        return

    multi = len(export_formats) > 1
    exported_files: list[str] = []
    for fmt in export_formats:
        out_path = _resolve_output_path(resolved_output, fmt, multi)
        if fmt == "csv":
            exported = _export_assessment_csv(
                company_description=company_description,
                model=model,
                content=content,
                output_path=out_path,
            )
        elif fmt == "json":
            exported = _export_assessment_json(
                company_description=company_description,
                model=model,
                content=content,
                output_path=out_path,
            )
        else:
            exported = _export_assessment_markdown(
                content=content,
                output_path=out_path,
            )
        exported_files.append(exported)
    render_info(
        "Export Complete",
        "[bold green]Exported assessment files:[/bold green] "
        + ", ".join(exported_files),
    )


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
        help="Export format(s) (`csv`, `json`, `md`) or a path like `report.md`.",
    ),
    output: str = typer.Option(
        "",
        "--output",
        help="Output path for exported file(s). For multi-format exports, extensions are auto-appended.",
    ),
    use_cache: bool = typer.Option(
        False,
        "--use-cache",
        help="Persist assessment results in local cache (write-only; does not reuse on next run).",
    ),
    refresh_cache: bool = typer.Option(
        False,
        "--refresh-cache",
        help="Keep compatibility with older scripts; assessment still runs fresh and saves cache.",
    ),
    questionnaire_file: str = typer.Option(
        "",
        "--questionnaire-file",
        help="Optional path to questionnaire JSON for structured context.",
    ),
    prompt_missing_questionnaire: bool = typer.Option(
        False,
        "--prompt-missing-questionnaire/--no-prompt-missing-questionnaire",
        help="Prompt for missing high-impact questionnaire fields when running interactively (default: disabled to match Web behavior).",
    ),
    use_requirements_index: bool = typer.Option(
        False,
        "--use-requirements-index/--no-use-requirements-index",
        help=(
            "Enable optional internal requirements calibration retrieval "
            "(default: disabled, same as Web)."
        ),
    ),
    requirements_index: str = typer.Option(
        DEFAULT_REQUIREMENTS_INDEX,
        "--requirements-index",
        help=(
            "Optional internal calibration index for requirements retrieval. "
            "Assessment still works when this is not provided."
        ),
    ),
) -> None:
    """Assess risk from a company description."""
    try:
        _run_assessment_flow(
            company_description,
            model,
            export,
            output,
            use_cache=use_cache,
            refresh_cache=refresh_cache,
            questionnaire_file=questionnaire_file,
            prompt_missing=prompt_missing_questionnaire,
            use_requirements_index=use_requirements_index,
            requirements_index=requirements_index,
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


@app.command("questionnaire-options")
def questionnaire_options() -> None:
    """Show three input-depth questionnaire options (general/medium/detailed)."""
    templates = questionnaire_templates()
    table = Table(
        title="Questionnaire Input Modes",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("Mode", style="bold white")
    table.add_column("Questions", justify="right", style="yellow")
    table.add_column("Coverage", style="green")
    for mode in ("general", "medium", "detailed"):
        items = templates[mode]
        headings = ", ".join(item["heading"] for item in items[:4])
        if len(items) > 4:
            headings += ", ..."
        table.add_row(mode, str(len(items)), headings)
    console.print(table)


@app.command("ingest-requirements")
def ingest_requirements(
    root: str = typer.Argument(..., help="Root path containing categorized security requirement PDFs."),
    output: str = typer.Option(
        "assessments/security_requirements_index.json",
        "--output",
        help="Output JSON index path.",
    ),
) -> None:
    """Ingest security requirement PDFs as optional internal calibration tooling."""
    repository = ingest_requirements_repository(root)
    output_path = save_repository_index(repository, output)
    render_info(
        "Requirements Ingestion Complete",
        (
            f"Documents: {len(repository.documents)}\n"
            f"Controls: {len(repository.controls)}\n"
            f"Index: {output_path}"
        ),
    )


@app.command("control-delta")
def control_delta(
    previous_index: str = typer.Argument(..., help="Path to previous requirements index JSON."),
    current_index: str = typer.Argument(..., help="Path to current requirements index JSON."),
    output: str = typer.Option(
        "",
        "--output",
        help="Optional JSON output path for full delta payload.",
    ),
) -> None:
    """Compare versioned requirement controls across index snapshots."""
    previous = load_repository_index(previous_index)
    current = load_repository_index(current_index)
    delta = compare_control_versions(previous, current)

    previous_snapshot = repository_version_snapshot(previous)
    current_snapshot = repository_version_snapshot(current)
    summary = delta.get("summary", {})
    render_info(
        "Control Delta Summary",
        (
            f"Previous fingerprint: {previous_snapshot.get('control_fingerprint', '')}\n"
            f"Current fingerprint: {current_snapshot.get('control_fingerprint', '')}\n"
            f"Added controls: {summary.get('added_controls', 0)}\n"
            f"Removed controls: {summary.get('removed_controls', 0)}\n"
            f"Version changed controls: {summary.get('version_changed_controls', 0)}"
        ),
    )

    if output.strip():
        path = Path(output.strip())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(delta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        render_info("Control Delta Export", f"Saved delta payload to `{path}`.")


@app.command("policy-check")
def policy_check(
    company_description: str = typer.Argument(
        ...,
        help="Natural-language description for deterministic policy gate evaluation.",
    ),
    questionnaire_file: str = typer.Option(
        "",
        "--questionnaire-file",
        help="Optional questionnaire JSON path.",
    ),
    requirements_index: str = typer.Option(
        "",
        "--requirements-index",
        help="Optional requirements index to enrich mapped controls and standards.",
    ),
    hook_output: str = typer.Option(
        "",
        "--hook-output",
        help="Optional path to write integration hook payload JSON.",
    ),
    policy_pack: str = typer.Option(
        "",
        "--policy-pack",
        help="Optional YAML policy pack file with custom rules.",
    ),
    default_policies: bool = typer.Option(
        True,
        "--default-policies/--no-default-policies",
        help="Include built-in policy rules when evaluating a custom policy pack.",
    ),
) -> None:
    """Run policy-as-code checks and produce integration-ready payload."""
    validate_company_description(company_description)
    questionnaire: dict[str, dict[str, str]] = {}
    if questionnaire_file.strip():
        questionnaire = load_questionnaire_file(questionnaire_file.strip())

    assessment = assess_company_risk(
        company_description,
        questionnaire_context=questionnaire,
        requirements_index=requirements_index.strip(),
    )
    try:
        results = evaluate_policy_checks(
            assessment,
            questionnaire,
            policy_pack_path=policy_pack.strip(),
            include_default=default_policies,
        )
    except ValueError as exc:
        render_error("Policy Pack Error", str(exc))
        raise typer.Exit(code=1)
    gate = policy_gate_status(results)

    table = Table(
        title="Policy-as-Code Checks",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("Policy", style="bold white")
    table.add_column("Severity", style="yellow")
    table.add_column("Status", style="green")
    table.add_column("Rationale", style="magenta")

    for result in results:
        color = "green" if result.status == "pass" else "red"
        table.add_row(
            f"{result.policy_id} - {result.title}",
            result.severity.upper(),
            f"[{color}]{result.status.upper()}[/{color}]",
            result.rationale,
        )

    console.print(table)
    render_info(
        "Policy Gate",
        f"Gate status: [bold]{gate.upper()}[/bold] (risk: {assessment.risk_level}, residual: {assessment.residual_risk}/100).",
    )

    if hook_output.strip():
        payload = build_integration_hook_payload("policy_check.completed", assessment, results)
        saved = write_hook_payload(hook_output.strip(), payload)
        render_info("Integration Hook Payload", f"Saved hook payload to `{saved}`.")


@app.command("governance-submit")
def governance_submit(
    assessment_file: str = typer.Argument(..., help="Path to cached assessment JSON payload."),
    requested_by: str = typer.Option(..., "--requested-by", help="Requester identity."),
    approver: list[str] = typer.Option(
        ...,
        "--approver",
        help="Approver identity (repeat option for multiple approvers).",
    ),
    trail_file: str = typer.Option(
        "assessments/governance_trails.jsonl",
        "--trail-file",
        help="Governance trail JSONL path.",
    ),
) -> None:
    """Create governance workflow entry and approval trail."""
    path = Path(assessment_file).expanduser().resolve()
    if not path.exists():
        render_error("Assessment Not Found", f"No file at `{path}`.")
        raise typer.Exit(code=1)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        render_error("Assessment Read Error", f"Could not parse `{path}` as JSON.")
        raise typer.Exit(code=1)

    deterministic = payload.get("deterministic", {}) if isinstance(payload, dict) else {}
    if not isinstance(deterministic, dict):
        deterministic = {}

    trail = create_governance_trail(
        requested_by=requested_by,
        approvers=approver,
        assessment_ref=str(payload.get("cache_key", path.name)),
        risk_level=str(deterministic.get("risk_level", "unknown")),
        residual_risk=int(deterministic.get("residual_risk", 0)),
        policy_gate="unknown",
    )
    trails = load_governance_trails(trail_file)
    trails.append(trail)
    saved = save_governance_trails(trail_file, trails)
    render_info(
        "Governance Trail Created",
        (
            f"Trail ID: {trail.trail_id}\n"
            f"Status: {trail.status}\n"
            f"Approvers: {', '.join(trail.approvers) or 'none'}\n"
            f"Stored at: {saved}"
        ),
    )


@app.command("governance-approve")
def governance_approve(
    trail_id: str = typer.Argument(..., help="Governance trail id."),
    actor: str = typer.Option(..., "--actor", help="Approver/reviewer identity."),
    decision: str = typer.Option(
        ...,
        "--decision",
        help="Decision: approve or reject.",
    ),
    comment: str = typer.Option("", "--comment", help="Optional decision note."),
    trail_file: str = typer.Option(
        "assessments/governance_trails.jsonl",
        "--trail-file",
        help="Governance trail JSONL path.",
    ),
) -> None:
    """Record an approval or rejection decision on a governance trail."""
    trails = load_governance_trails(trail_file)
    index = None
    for idx, trail in enumerate(trails):
        if trail.trail_id == trail_id:
            index = idx
            break
    if index is None:
        render_error("Trail Not Found", f"Could not find trail `{trail_id}`.")
        raise typer.Exit(code=1)
    try:
        updated = record_governance_decision(
            trails[index],
            actor=actor,
            decision=decision,
            comment=comment,
        )
    except ValueError as exc:
        render_error(
            "Invalid Decision",
            str(exc),
            hint="Use --decision approve|reject. Finalized trails cannot be modified.",
        )
        raise typer.Exit(code=1)

    trails[index] = updated
    saved = save_governance_trails(trail_file, trails)
    render_info(
        "Governance Decision Recorded",
        (
            f"Trail ID: {updated.trail_id}\n"
            f"New status: {updated.status}\n"
            f"Decisions recorded: {len(updated.decisions)}\n"
            f"Stored at: {saved}"
        ),
    )


@app.command("governance-list")
def governance_list(
    status: str = typer.Option(
        "",
        "--status",
        help="Optional status filter: pending, approved, rejected.",
    ),
    trail_file: str = typer.Option(
        "assessments/governance_trails.jsonl",
        "--trail-file",
        help="Governance trail JSONL path.",
    ),
) -> None:
    """List governance workflow trails and approval states."""
    trails = load_governance_trails(trail_file)
    if status.strip():
        normalized_status = status.strip().lower()
        if normalized_status not in {"pending", "approved", "rejected"}:
            render_error(
                "Invalid Status Filter",
                f"Unsupported status '{status}'.",
                hint="Use --status pending|approved|rejected",
            )
            raise typer.Exit(code=1)
        trails = [trail for trail in trails if trail.status.lower() == normalized_status]

    if not trails:
        render_info("Governance Trails", "No governance trails found.")
        return

    table = Table(
        title="Governance Approval Trails",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("Trail ID", style="bold white")
    table.add_column("Status", style="yellow")
    table.add_column("Risk", style="green")
    table.add_column("Requested By", style="magenta")
    table.add_column("Approvers", style="white")
    table.add_column("Decisions", justify="right", style="cyan")

    for trail in trails:
        table.add_row(
            trail.trail_id,
            trail.status,
            f"{trail.risk_level} ({trail.residual_risk}/100)",
            trail.requested_by,
            ", ".join(trail.approvers) or "-",
            str(len(trail.decisions)),
        )
    console.print(table)


@app.command()
def inspect(
    company_description: str = typer.Argument(
        ...,
        help="Natural-language description of your company setup and security posture.",
    )
) -> None:
    """Inspect deterministic signal matching and score contributions."""
    try:
        validate_company_description(company_description)
        assessment = assess_company_risk(company_description)
        render_input_panel(company_description)

        signal_table = Table(
            title="Deterministic Risk Signals",
            box=box.ROUNDED,
            show_lines=True,
            header_style="bold cyan",
        )
        signal_table.add_column("Signal", style="bold white")
        signal_table.add_column("Category", style="green")
        signal_table.add_column("Weight", justify="right", style="yellow")
        signal_table.add_column("Matched Phrases", style="magenta")

        if assessment.matched_signals:
            for signal in assessment.matched_signals:
                signal_table.add_row(
                    signal.label,
                    signal.category,
                    f"+{signal.weight}",
                    ", ".join(signal.matched_phrases) or "-",
                )
        else:
            signal_table.add_row("No matched signals", "-", "0", "-")

        console.print(signal_table)

        gaps = (
            "\n".join(f"- {gap}" for gap in assessment.control_gaps)
            if assessment.control_gaps
            else "- No control gaps detected from current input."
        )
        console.print(
            Panel.fit(
                (
                    f"[bold]Calculated total score:[/bold] {assessment.overall_score}/100 "
                    f"({assessment.risk_level})\n\n"
                    "[bold]Detected control gaps:[/bold]\n"
                    f"{gaps}"
                ),
                title="Deterministic Summary",
                border_style="cyan",
            )
        )
    except InvalidInputError as exc:
        render_error("Invalid Input", str(exc))
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


@app.command()
def controls(
    framework: str = typer.Argument(
        "",
        help="Optional framework filter: cis, nist, or owasp.",
    ),
) -> None:
    """List enabled control-framework mappings."""
    framework_names = list_framework_names()
    if not framework.strip():
        lines = "\n".join(f"- {name}" for name in framework_names)
        render_info(
            "Framework mappings enabled",
            f"{lines}\n\nTry `astraut-risk controls cis` for a filtered list.",
        )
        return

    selected = resolve_framework_selector(framework)
    if not selected:
        render_error(
            "Invalid Framework",
            f"Unknown framework '{framework}'.",
            hint="Use one of: cis, nist, owasp.",
        )
        raise typer.Exit(code=1)

    signal_map = load_framework_mappings()
    rows: list[str] = []
    for signal_id in sorted(signal_map.keys()):
        refs = [ref for ref in signal_map[signal_id] if ref.framework == selected]
        if not refs:
            continue
        for ref in refs:
            label = ref.control_id
            if ref.title:
                label = f"{label} - {ref.title}"
            detail = f"{label}: {ref.description}" if ref.description else label
            rows.append(f"- {signal_id}: {detail}")

    if not rows:
        render_info("Framework mappings", f"No mappings found for {selected}.")
        return
    render_info(f"{selected} control mappings", "\n".join(rows))


@scenario_app.command("list")
def scenario_list() -> None:
    """List built-in SME scenarios."""
    table = Table(
        title="Built-in SME Scenarios",
        box=box.ROUNDED,
        header_style="bold cyan",
    )
    table.add_column("Scenario ID", style="bold white")
    table.add_column("Label", style="green")
    for scenario_id, label in list_scenarios():
        table.add_row(scenario_id, label)
    console.print(table)


@scenario_app.command("run")
def scenario_run(
    scenario_id: str = typer.Argument(..., help="Scenario id (e.g. saas_startup)."),
    model: str = typer.Option(
        DEFAULT_MODEL,
        "--model",
        help="Groq model to use (currently supported: llama-3.3-70b-versatile).",
    ),
    export: str = typer.Option(
        "",
        "--export",
        help="Export format(s) (`csv`, `json`, `md`) or a path like `report.md`.",
    ),
    output: str = typer.Option(
        "",
        "--output",
        help="Output path for exported file(s). For multi-format exports, extensions are auto-appended.",
    ),
    use_cache: bool = typer.Option(
        False,
        "--use-cache",
        help="Persist assessment results in local cache (write-only; does not reuse on next run).",
    ),
    refresh_cache: bool = typer.Option(
        False,
        "--refresh-cache",
        help="Keep compatibility with older scripts; assessment still runs fresh and saves cache.",
    ),
    questionnaire_file: str = typer.Option(
        "",
        "--questionnaire-file",
        help="Optional path to questionnaire JSON for structured context.",
    ),
    prompt_missing_questionnaire: bool = typer.Option(
        True,
        "--prompt-missing-questionnaire/--no-prompt-missing-questionnaire",
        help="Prompt for missing high-impact questionnaire fields when running interactively.",
    ),
) -> None:
    """Run an assessment against a built-in scenario."""
    description = get_scenario_description(scenario_id)
    if not description:
        known = ", ".join(sorted(SCENARIOS.keys()))
        render_error(
            "Unknown Scenario",
            f"Scenario '{scenario_id}' not found.",
            hint=f"Use `astraut-risk scenario list`. Available: {known}",
        )
        raise typer.Exit(code=1)

    console.print(f"[bold cyan]Scenario:[/bold cyan] {scenario_id}")
    try:
        _run_assessment_flow(
            description,
            model,
            export,
            output,
            use_cache=use_cache,
            refresh_cache=refresh_cache,
            questionnaire_file=questionnaire_file,
            prompt_missing=prompt_missing_questionnaire,
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


def main() -> None:
    """CLI main entrypoint."""
    load_environment()
    app()
