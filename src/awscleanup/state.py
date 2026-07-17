"""Local state store: tracks findings across scan/review/sweep runs and an
append-only audit log of every tag/delete action taken against real AWS
resources. Deliberately simple (single JSON file) — this tool is meant to be
run by one operator, not as a shared service."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from awscleanup.models import Finding, FindingStatus, ResourceRef


def _default(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, FindingStatus):
        return obj.value
    raise TypeError(f"Not JSON serializable: {type(obj)!r}")


def _parse_dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class StateStore:
    """Findings keyed by ResourceRef.key, persisted as JSON on disk."""

    def __init__(self, state_file: Path):
        self.state_file = state_file
        self._findings: dict[str, Finding] = {}
        self._load()

    def _load(self) -> None:
        if not self.state_file.exists():
            return
        raw = json.loads(self.state_file.read_text())
        for key, f in raw.get("findings", {}).items():
            resource = ResourceRef(**f["resource"])
            self._findings[key] = Finding(
                resource=resource,
                reason=f["reason"],
                evidence=f["evidence"],
                estimated_monthly_cost_usd=f.get("estimated_monthly_cost_usd"),
                status=FindingStatus(f["status"]),
                scanned_at=_parse_dt(f["scanned_at"]),
                pending_deletion_at=_parse_dt(f.get("pending_deletion_at")),
                reviewed_at=_parse_dt(f.get("reviewed_at")),
                deleted_at=_parse_dt(f.get("deleted_at")),
                extra=f.get("extra", {}),
            )

    def save(self) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "findings": {
                key: {**asdict(f), "resource": asdict(f.resource)}
                for key, f in self._findings.items()
            }
        }
        self.state_file.write_text(json.dumps(payload, default=_default, indent=2))

    def upsert(self, finding: Finding) -> None:
        """Merge a fresh scan finding with any prior state for the same
        resource, preserving review/pending/declined status instead of
        resetting it to NEW on every scan."""
        existing = self._findings.get(finding.key)
        if existing and existing.status != FindingStatus.NEW:
            existing.evidence = finding.evidence
            existing.estimated_monthly_cost_usd = finding.estimated_monthly_cost_usd
            existing.scanned_at = finding.scanned_at
        else:
            self._findings[finding.key] = finding

    def get(self, key: str) -> Finding | None:
        return self._findings.get(key)

    def all(self) -> list[Finding]:
        return list(self._findings.values())

    def by_status(self, *statuses: FindingStatus) -> list[Finding]:
        return [f for f in self._findings.values() if f.status in statuses]

    def append_audit(self, audit_log_file: Path, message: str) -> None:
        audit_log_file.parent.mkdir(parents=True, exist_ok=True)
        from awscleanup.models import utcnow

        with audit_log_file.open("a") as f:
            f.write(f"{utcnow().isoformat()} {message}\n")
