"""Rendering: Rich terminal tables for interactive use, and a static,
self-contained HTML report (no external assets) for `cleanup-crew report`
and GitHub Pages publishing."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from rich.console import Console
from rich.table import Table

from awscleanup.models import Finding, FindingStatus, utcnow

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

_STATUS_STYLE = {
    FindingStatus.NEW: "yellow",
    FindingStatus.APPROVED: "cyan",
    FindingStatus.PENDING_DELETION: "magenta",
    FindingStatus.DECLINED: "grey58",
    FindingStatus.DELETED: "red",
    FindingStatus.SKIPPED_PROTECTED: "grey58",
}


def render_table(console: Console, findings: list[Finding], title: str = "Findings") -> None:
    if not findings:
        console.print(f"[green]No findings for '{title}'.[/green]")
        return

    table = Table(title=title, show_lines=False)
    table.add_column("Type")
    table.add_column("Resource")
    table.add_column("Region")
    table.add_column("Reason")
    table.add_column("Evidence", overflow="fold")
    table.add_column("Est. $/mo", justify="right")
    table.add_column("Status")

    total_cost = 0.0
    for f in sorted(findings, key=lambda x: (x.resource.resource_type, x.resource.region)):
        cost = f.estimated_monthly_cost_usd
        total_cost += cost or 0.0
        style = _STATUS_STYLE.get(f.status, "white")
        table.add_row(
            f.resource.resource_type,
            f.resource.name or f.resource.resource_id,
            f.resource.region,
            f.reason,
            f.evidence,
            f"${cost:.2f}" if cost is not None else "-",
            f"[{style}]{f.status.value}[/{style}]",
        )

    console.print(table)
    console.print(f"[bold]Estimated total: ${total_cost:.2f}/mo[/bold] across {len(findings)} resource(s)")


def render_html_report(findings: list[Finding], out_path: Path) -> None:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html.jinja")

    by_status: dict[str, list[Finding]] = {}
    for f in findings:
        by_status.setdefault(f.status.value, []).append(f)

    total_cost = sum(f.estimated_monthly_cost_usd or 0.0 for f in findings)

    html = template.render(
        findings=findings,
        by_status=by_status,
        total_cost=total_cost,
        generated_at=utcnow().isoformat(timespec="seconds"),
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html)
