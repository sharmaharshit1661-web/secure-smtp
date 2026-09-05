"""
Centralized Configuration & Settings Module — Secure SMTP.

Replaces scattered os.environ.get() calls with a validated, strongly-typed
Pydantic Settings configuration supporting environment variables, .env files,
validation, and sensible security defaults.
"""

from __future__ import annotations

import re
import urllib.parse
from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Central application settings for Secure SMTP.
    Supports environment variables with prefix SECURE_SMTP_ and backward-compatible aliases.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ── Application Metadata ──
    app_name: str = Field(default="Secure SMTP", description="Application display name")
    app_version: str = Field(default="0.1.0", description="Application semantic version")
    debug: bool = Field(default=False, description="Debug mode")

    # ── API Authentication ──
    api_key: str = Field(
        default="securesmtp_live_secret_key",
        validation_alias=AliasChoices("SECURE_SMTP_API_KEY", "API_KEY"),
        description="Master API authentication key",
    )
    auth_required: bool = Field(
        default=True,
        validation_alias=AliasChoices("SECURE_SMTP_AUTH_REQUIRED", "AUTH_REQUIRED"),
        description="Whether API authentication is enforced on sensitive endpoints",
    )

    # ── Alerting & Webhooks ──
    alerts_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices("SECURE_SMTP_ALERTS_ENABLED", "ALERTS_ENABLED"),
        description="Whether real-time security alerts/webhooks are enabled",
    )
    alert_webhook_url: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("SECURE_SMTP_ALERT_WEBHOOK_URL", "ALERT_WEBHOOK_URL"),
        description="Incoming webhook URL for alerts (Slack, Teams, Discord, or generic)",
    )
    alert_webhook_secret: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("SECURE_SMTP_ALERT_WEBHOOK_SECRET", "ALERT_WEBHOOK_SECRET"),
        description="Optional shared secret for HMAC-SHA256 signature on webhook payloads",
    )
    alert_min_severity: str = Field(
        default="HIGH",
        validation_alias=AliasChoices("SECURE_SMTP_ALERT_MIN_SEVERITY", "ALERT_MIN_SEVERITY"),
        description="Minimum finding severity to trigger alert (LOW, MEDIUM, HIGH, CRITICAL)",
    )
    alert_risk_threshold: float = Field(
        default=75.0,
        validation_alias=AliasChoices("SECURE_SMTP_ALERT_RISK_THRESHOLD", "ALERT_RISK_THRESHOLD"),
        description="Minimum session risk score to trigger alert (0-100)",
    )

    # ── CORS Settings ──
    cors_origins: List[str] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
        ],
        validation_alias=AliasChoices("SECURE_SMTP_CORS_ORIGINS", "CORS_ORIGINS"),
        description="Allowed CORS origin URLs",
    )
    cors_headers: List[str] = Field(
        default_factory=lambda: ["*"],
        validation_alias=AliasChoices("SECURE_SMTP_CORS_HEADERS", "CORS_HEADERS"),
        description="Allowed CORS request headers",
    )

    @field_validator("cors_origins", "cors_headers", mode="before")
    @classmethod
    def parse_comma_separated_list(cls, v):
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    # ── Storage & Directories ──
    upload_dir: Path = Field(
        default=Path("/tmp/secure_smtp_uploads"),
        validation_alias=AliasChoices(
            "SECURE_SMTP_UPLOAD_DIR", "SECUREMAILSCOPE_UPLOAD_DIR", "UPLOAD_DIR"
        ),
        description="Directory for temporary uploaded PCAP files",
    )
    reports_dir: Path = Field(
        default=Path("/tmp/secure_smtp_reports"),
        validation_alias=AliasChoices(
            "SECURE_SMTP_REPORTS_DIR", "SECUREMAILSCOPE_REPORTS_DIR", "REPORTS_DIR"
        ),
        description="Directory for generated PDF/HTML/JSON analysis reports",
    )

    # ── MongoDB Settings ──
    mongo_host: str = Field(
        default="localhost",
        validation_alias=AliasChoices("SECURE_SMTP_MONGO_HOST", "MONGO_HOST"),
        description="MongoDB server hostname or IP",
    )
    mongo_port: int = Field(
        default=27017,
        validation_alias=AliasChoices("SECURE_SMTP_MONGO_PORT", "MONGO_PORT"),
        description="MongoDB server port",
    )
    mongo_db: str = Field(
        default="secure_smtp",
        validation_alias=AliasChoices("SECURE_SMTP_MONGO_DB", "MONGO_DB"),
        description="Application database name",
    )
    mongo_user: str = Field(
        default="",
        validation_alias=AliasChoices("SECURE_SMTP_MONGO_USER", "MONGO_USER"),
        description="MongoDB authentication username",
    )
    mongo_password: str = Field(
        default="",
        validation_alias=AliasChoices("SECURE_SMTP_MONGO_PASSWORD", "MONGO_PASSWORD"),
        description="MongoDB authentication password",
    )
    mongo_auth_db: str = Field(
        default="admin",
        validation_alias=AliasChoices("SECURE_SMTP_MONGO_AUTH_DB", "MONGO_AUTH_DB"),
        description="Database to authenticate against (authSource)",
    )
    mongo_auth_mechanism: str = Field(
        default="SCRAM-SHA-256",
        validation_alias=AliasChoices("SECURE_SMTP_MONGO_AUTH_MECHANISM", "MONGO_AUTH_MECHANISM"),
        description="MongoDB authentication mechanism",
    )
    mongo_auth_required: bool = Field(
        default=False,
        validation_alias=AliasChoices("SECURE_SMTP_MONGO_AUTH_REQUIRED", "MONGO_AUTH_REQUIRED"),
        description="Whether MongoDB authentication is strictly required",
    )
    mongo_uri: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("SECURE_SMTP_MONGO_URI", "MONGO_URI"),
        description="Explicit MongoDB connection URI (overrides individual host/user settings)",
    )

    # ── Derived Connection Helpers ──

    def get_mongo_connection_uri(self) -> str:
        """
        Build a well-formed MongoDB connection URI, safely percent-encoding
        special characters in usernames and passwords.
        """
        if self.mongo_uri and self.mongo_uri.strip():
            return self.mongo_uri.strip()

        if self.mongo_user and self.mongo_password:
            user_enc = urllib.parse.quote_plus(self.mongo_user)
            pwd_enc = urllib.parse.quote_plus(self.mongo_password)
            query_params = []
            if self.mongo_auth_db:
                query_params.append(f"authSource={urllib.parse.quote_plus(self.mongo_auth_db)}")
            if self.mongo_auth_mechanism:
                query_params.append(f"authMechanism={urllib.parse.quote_plus(self.mongo_auth_mechanism)}")
            query_str = f"?{'&'.join(query_params)}" if query_params else ""
            return f"mongodb://{user_enc}:{pwd_enc}@{self.mongo_host}:{self.mongo_port}/{self.mongo_db}{query_str}"
        elif self.mongo_user:
            user_enc = urllib.parse.quote_plus(self.mongo_user)
            query_params = []
            if self.mongo_auth_db:
                query_params.append(f"authSource={urllib.parse.quote_plus(self.mongo_auth_db)}")
            query_str = f"?{'&'.join(query_params)}" if query_params else ""
            return f"mongodb://{user_enc}@{self.mongo_host}:{self.mongo_port}/{self.mongo_db}{query_str}"
        else:
            return f"mongodb://{self.mongo_host}:{self.mongo_port}/{self.mongo_db}"

    def get_masked_mongo_uri(self) -> str:
        """Return the connection URI with the password component safely redacted."""
        uri = self.get_mongo_connection_uri()
        return re.sub(r":([^/@]+)@", r":******@", uri)


@lru_cache()
def get_settings() -> Settings:
    """Cached singleton getter for application settings."""
    return Settings()
