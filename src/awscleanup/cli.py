"""Typer CLI: scan, review, sweep, report.

See README.md for the full workflow. Summary: `scan` is read-only,
`review` tags approved findings for deletion (reversible), `sweep` deletes
anything whose grace period has elapsed after re-verifying it's still
unused.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Optional

import typer
from botocore.exceptions import ClientError
from rich.console import Console
from rich.prompt import Confirm

from awscleanup import aws_session
from awscleanup.config import PENDING_TAG_KEY, REASON_TAG_KEY, load_settings
from awscleanup.models import FindingStatus, utcnow
from awscleanup.report import render_html_report, render_table
from awscleanup.scanners.base import all_scanners, get_scanner
from awscleanup.state import StateStore

app = typer.Typer(
    help="Scan AWS for unused resources, review evidence-backed findings, and clean them up safely.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    profile: Optional[str] = typer.Option(None, "--profile", help="AWS named profile."),
    region: Optional[list[str]] = typer.Option(None, "--region", help="Region(s) to scan; repeatable."),
    grace_period_days: Optional[int] = typer.Option(None, "--grace-period-days"),
) -> None:
    """Read-only: scan configured regions for unused resources. Never mutates AWS."""
    settings = load_settings(profile=profile, regions=region or None, grace_period_days=grace_period_days)
    session = aws_session.get_session(settings)
    store = StateStore(settings.state_file)

    try:
        regions = aws_session.enabled_regions(session, settings)
    except ClientError as e:
        console.print(f"[red]Failed to list regions: {e}[/red]")
        raise typer.Exit(1) from e

    scanners = all_scanners()
    console.print(f"Scanning {len(regions)} region(s) with {len(scanners)} scanner(s)...")

    errors: list[str] = []
    found_count = 0
    for region_name in regions:
        for scanner in scanners:
            try:
                findings = scanner.detect(session, region_name, settings)
            except ClientError as e:
                errors.append(f"{scanner.resource_type} in {region_name}: {e}")
                continue
            for finding in findings:
                store.upsert(finding)
                found_count += 1

    store.save()

    if errors:
        console.print(f"[yellow]{len(errors)} scanner call(s) failed (shown below); results are partial.[/yellow]")
        for err in errors:
            console.print(f"  [yellow]- {err}[/yellow]")

    active = store.by_status(
        FindingStatus.NEW, FindingStatus.APPROVED, FindingStatus.PENDING_DELETION
    )
    render_table(console, active, title="Current findings")
    console.print(f"\n[bold]{found_count}[/bold] finding(s) touched this scan. Run 'cleanup-crew review' next.")


@app.command()
def review(
    approve_all: bool = typer.Option(False, "--all", help="Approve every NEW finding without per-item prompts."),
    reconsider: bool = typer.Option(False, "--reconsider", help="Re-include previously declined findings."),
    grace_period_days: Optional[int] = typer.Option(None, "--grace-period-days"),
    profile: Optional[str] = typer.Option(None, "--profile"),
) -> None:
    """Interactively approve or decline findings. Approved findings get
    tagged `cleanup:pending-deletion` in AWS — reversible, and the only
    mutation this command performs."""
    settings = load_settings(profile=profile, grace_period_days=grace_period_days)
    session = aws_session.get_session(settings)
    store = StateStore(settings.state_file)

    statuses = [FindingStatus.NEW]
    if reconsider:
        statuses.append(FindingStatus.DECLINED)
    candidates = store.by_status(*statuses)

    if not candidates:
        console.print("[green]Nothing to review.[/green]")
        return

    render_table(console, candidates, title="Findings to review")

    if approve_all:
        proceed = Confirm.ask(f"Approve all {len(candidates)} finding(s) for deletion (tag only, not delete)?")
        decisions = {f.key: proceed for f in candidates}
    else:
        decisions = {}
        for f in candidates:
            cost_line = (
                f"\n  est. cost: ${f.estimated_monthly_cost_usd:.2f}/mo"
                if f.estimated_monthly_cost_usd is not None
                else ""
            )
            console.print(
                f"\n[bold]{f.resource.resource_type}[/bold] {f.resource.name or f.resource.resource_id} "
                f"({f.resource.region})\n  reason: {f.reason}\n  evidence: {f.evidence}{cost_line}"
            )
            decisions[f.key] = Confirm.ask("  Approve for deletion?", default=False)

    approved_count = declined_count = 0
    pending_at = utcnow() + timedelta(days=settings.grace_period_days)
    for f in candidates:
        if decisions.get(f.key):
            scanner = get_scanner(f.resource.resource_type)
            tags = {
                PENDING_TAG_KEY: pending_at.date().isoformat(),
                REASON_TAG_KEY: f.reason,
            }
            try:
                scanner.tag_pending_deletion(session, f.resource, tags)
            except ClientError as e:
                console.print(f"[red]Failed to tag {f.resource.resource_id}: {e}[/red]")
                continue
            f.status = FindingStatus.PENDING_DELETION
            f.pending_deletion_at = pending_at
            f.reviewed_at = utcnow()
            store.append_audit(
                settings.audit_log_file,
                f"TAGGED {f.resource.resource_type} {f.resource.resource_id} "
                f"({f.resource.region}) pending-deletion={tags[PENDING_TAG_KEY]}",
            )
            approved_count += 1
        else:
            f.status = FindingStatus.DECLINED
            f.reviewed_at = utcnow()
            declined_count += 1

    store.save()
    console.print(
        f"\n[bold]{approved_count}[/bold] approved (tagged pending-deletion, "
        f"grace period {settings.grace_period_days}d), [bold]{declined_count}[/bold] declined."
    )


@app.command()
def sweep(
    yes: bool = typer.Option(False, "--yes", help="Skip per-resource confirmation (for scheduled runs)."),
    profile: Optional[str] = typer.Option(None, "--profile"),
) -> None:
    """Delete resources whose grace period has elapsed, after re-verifying
    each is still unused. Always re-verifies; --yes only skips the
    confirmation prompt, not the safety check."""
    settings = load_settings(profile=profile)
    session = aws_session.get_session(settings)
    store = StateStore(settings.state_file)

    pending = store.by_status(FindingStatus.PENDING_DELETION)
    now = utcnow()
    due = [f for f in pending if f.pending_deletion_at and f.pending_deletion_at <= now]

    if not due:
        console.print("[green]Nothing due for deletion.[/green]")
        return

    deleted_count = skipped_count = 0
    for f in due:
        scanner = get_scanner(f.resource.resource_type)
        try:
            still_unused, detail = scanner.is_still_unused(session, f.resource)
        except ClientError as e:
            console.print(f"[red]Failed to re-verify {f.resource.resource_id}: {e}[/red]")
            continue

        label = f"{f.resource.resource_type} {f.resource.name or f.resource.resource_id} ({f.resource.region})"

        if not still_unused:
            console.print(f"[yellow]Skipping {label}: {detail}[/yellow]")
            try:
                scanner.untag_pending_deletion(session, f.resource)
            except ClientError:
                pass
            f.status = FindingStatus.NEW
            f.pending_deletion_at = None
            store.append_audit(settings.audit_log_file, f"SKIPPED {label}: {detail}")
            skipped_count += 1
            continue

        if not yes and not Confirm.ask(f"Delete {label}? ({f.evidence})"):
            skipped_count += 1
            continue

        try:
            scanner.delete(session, f.resource)
        except ClientError as e:
            console.print(f"[red]Failed to delete {label}: {e}[/red]")
            continue

        f.status = FindingStatus.DELETED
        f.deleted_at = now
        store.append_audit(settings.audit_log_file, f"DELETED {label}")
        console.print(f"[red]Deleted {label}[/red]")
        deleted_count += 1

    store.save()
    console.print(f"\n[bold]{deleted_count}[/bold] deleted, [bold]{skipped_count}[/bold] skipped.")


@app.command()
def report(
    out: Path = typer.Option(Path("reports/latest.html"), "--out", help="Output HTML file path."),
    profile: Optional[str] = typer.Option(None, "--profile"),
) -> None:
    """Render current findings/history to a self-contained static HTML file."""
    settings = load_settings(profile=profile)
    store = StateStore(settings.state_file)
    findings = store.all()

    render_html_report(findings, out)
    console.print(f"[green]Report written to {out}[/green]")


if __name__ == "__main__":
    app()
