"""Rich rendering utilities for CLI output."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

console = Console()


def render_input_panel(company_description: str) -> None:
    console.print(
        Panel(
            f"[bold cyan]Input:[/bold cyan] {company_description}",
            title="Astraut Risk Reasoner",
            border_style="cyan",
        )
    )


def render_assessment(content: str) -> None:
    console.print(
        Panel.fit(
            Markdown(content),
            title="Risk Assessment Result",
            border_style="green",
            padding=(1, 2),
        )
    )


def render_explanation(topic: str, content: str) -> None:
    console.print(
        Panel.fit(
            Markdown(content),
            title=f"Concept: {topic}",
            border_style="magenta",
            padding=(1, 2),
        )
    )


def render_checklist(checklist_markdown: str) -> None:
    console.print(
        Panel.fit(
            Markdown(checklist_markdown),
            title="SME Security Checklist",
            subtitle="Practical baseline controls",
            border_style="blue",
            padding=(1, 2),
        )
    )


def build_matrix_table(rows: list[dict[str, str]]) -> Table:
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

    for row in rows:
        table.add_row(row["priority"], row["focus"], row["why"], row["examples"])
    return table


def render_matrix(rows: list[dict[str, str]]) -> None:
    console.print(build_matrix_table(rows))


def render_error(title: str, message: str, *, hint: str | None = None) -> None:
    details = f"[bold red]{message}[/bold red]"
    if hint:
        details = f"{details}\n\n[dim]{hint}[/dim]"
    console.print(Panel(details, title=title, border_style="red"))


def render_info(title: str, message: str) -> None:
    console.print(Panel(message, title=title, border_style="cyan"))
