"""Shared tag helpers used by every scanner."""

from __future__ import annotations

from awscleanup.config import PENDING_TAG_KEY, REASON_TAG_KEY, Settings


def tags_to_dict(aws_tags: list[dict] | None) -> dict[str, str]:
    """AWS returns tags as [{"Key": ..., "Value": ...}, ...]; normalize to a dict."""
    if not aws_tags:
        return {}
    return {t["Key"]: t["Value"] for t in aws_tags}


def dict_to_tag_spec(tags: dict[str, str]) -> list[dict]:
    return [{"Key": k, "Value": v} for k, v in tags.items()]


def is_protected(tags: dict[str, str], settings: Settings) -> bool:
    """A resource is protected (never flagged) if it carries the ignore tag
    with a truthy value, e.g. `cleanup:ignore=true`."""
    value = tags.get(settings.protected_tag_key, "").strip().lower()
    return value in ("true", "1", "yes")


def resource_name(tags: dict[str, str]) -> str | None:
    return tags.get("Name")


PENDING_KEY = PENDING_TAG_KEY
REASON_KEY = REASON_TAG_KEY
