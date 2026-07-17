"""Configuration for cleanup-crew.

Defaults are intentionally generic (no account-specific values baked in) —
boto3's normal credential/region resolution applies unless overridden via
CLI flags, environment variables, or a local `.awscleanup.toml`.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_STATE_DIR = Path.home() / ".awscleanup"
DEFAULT_GRACE_PERIOD_DAYS = 7
DEFAULT_STOPPED_INSTANCE_THRESHOLD_DAYS = 14

# Any resource carrying one of these tags (key=value, case-insensitive key)
# is excluded from scanning entirely, no matter what a scanner detects.
PROTECTED_TAG_KEY = "cleanup:ignore"
PENDING_TAG_KEY = "cleanup:pending-deletion"
REASON_TAG_KEY = "cleanup:reason"


class Settings(BaseSettings):
    # NOTE: env-var driven only for v1 (AWSCLEANUP_* env vars, e.g.
    # AWSCLEANUP_GRACE_PERIOD_DAYS=14). TOML file support can be added later
    # via pydantic-settings' TomlConfigSettingsSource if needed.
    model_config = SettingsConfigDict(
        env_prefix="AWSCLEANUP_",
        extra="ignore",
    )

    profile: str | None = Field(default=None, description="AWS named profile; None = default chain")
    regions: list[str] | None = Field(
        default=None,
        description="Regions to scan; None = discover all enabled regions in the account",
    )
    grace_period_days: int = Field(default=DEFAULT_GRACE_PERIOD_DAYS)
    stopped_instance_threshold_days: int = Field(default=DEFAULT_STOPPED_INSTANCE_THRESHOLD_DAYS)
    state_dir: Path = Field(default=DEFAULT_STATE_DIR)
    protected_tag_key: str = Field(default=PROTECTED_TAG_KEY)

    @property
    def state_file(self) -> Path:
        return self.state_dir / "state.json"

    @property
    def audit_log_file(self) -> Path:
        return self.state_dir / "audit.log"


def load_settings(**overrides) -> Settings:
    """Load settings from env/toml, then apply any CLI-provided overrides
    (only non-None overrides take effect, so unset CLI flags don't clobber
    config-file values)."""
    settings = Settings()
    clean_overrides = {k: v for k, v in overrides.items() if v is not None}
    return settings.model_copy(update=clean_overrides)
