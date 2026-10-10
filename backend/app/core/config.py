"""Application settings.

Every value has a safe default so `docker compose up` works without any `.env`.
Secrets are never read from here: see `app.core.secrets`.
"""

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LSX_", extra="ignore")

    env: Literal["development", "production"] = "production"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    public_url: str = "http://localhost:8080"

    # Database
    db_host: str = "db"
    db_port: int = 5432
    db_name: str = "logstash_explorer"
    db_user: str = "lsx"

    # Secrets provider: "file" (default, generated volume), "env" (dev), "vault" (production)
    secrets_backend: Literal["file", "env", "vault"] = "file"
    secrets_dir: str = "/run/lsx-secrets"
    vault_addr: str = ""
    vault_token_file: str = "/run/vault/token"  # noqa: S105 - a path, not a secret
    vault_kv_mount: str = "secret"
    vault_kv_path: str = "logstash-explorer"

    # Logstash runner (isolated container on an internal network)
    runner_url: str = "http://runner:8700"
    runner_timeout_s: int = 180
    runner_queue_wait_s: int = 120  # time a run may wait for a free runner slot
    max_runs_per_user: int = 2  # concurrent Logstash runs / agent sessions per user

    # Sessions & local auth
    cookie_secure: bool = True
    session_idle_minutes: int = 60
    session_absolute_minutes: int = 480
    lockout_threshold: int = 5
    lockout_minutes: int = 15
    login_min_duration_ms: int = 400
    password_min_length: int = 12
    api_token_max_days: int = 365

    # Hygiene & backups
    inactive_account_days: int = 90
    backup_dir: str = "/backups"
    backup_hour_utc: int = 2
    backup_retention_days: int = 14

    # PKI injection (PEM files dropped here are trusted for outbound TLS)
    pki_dir: str = "/pki"

    # OIDC (authorization code + PKCE). Disabled when issuer is empty.
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_scopes: str = "openid profile email"
    oidc_groups_claim: str = "groups"
    oidc_display_name: str = "SSO"

    # LDAPS. Disabled when url is empty. Only ldaps:// is accepted.
    ldap_url: str = ""
    ldap_bind_dn: str = ""
    ldap_user_base: str = ""
    ldap_user_filter: str = "(&(objectClass=person)(sAMAccountName={username}))"
    ldap_group_attribute: str = "memberOf"

    # WebAuthn relying party
    webauthn_rp_id: str = "localhost"
    webauthn_rp_name: str = "Logstash Explorer"

    # Workspace limits
    max_upload_mb: int = 20
    max_evtx_records: int = 5000
    # auditd pre-processing with LAUREL (installed in the backend image).
    laurel_bin: str = "/usr/local/bin/laurel"
    max_laurel_events: int = 5000
    agent_max_iterations: int = 6

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_client_id)

    @property
    def ldap_enabled(self) -> bool:
        return bool(self.ldap_url)


@lru_cache
def get_settings() -> Settings:
    return Settings()
