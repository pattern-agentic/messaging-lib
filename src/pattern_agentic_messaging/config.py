from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Optional

_DEFAULT_TOKEN_DURATION = timedelta(seconds=3600)


@dataclass
class PASlimConfig:
    local_name: str
    endpoint: str
    auth_type: str = "shared_secret"
    auth_secret: Optional[str] = None
    jwt_token_path: Optional[str] = None
    jwt_jwks_url: Optional[str] = None
    jwt_jwks_content: Optional[str] = None
    jwt_issuer: Optional[str] = None
    jwt_audience: Optional[list[str]] = None
    jwt_subject: Optional[str] = None
    tls_insecure: bool = True
    jwt_token_duration: timedelta = field(default_factory=lambda: _DEFAULT_TOKEN_DURATION)
    max_retries: int = 5
    timeout: timedelta = field(default_factory=lambda: timedelta(seconds=5))
    connect_timeout_sec: float = 30.0
    mls_enabled: bool = True
    message_discriminator: Optional[str] = None
    custom_headers: Optional[dict[str, str]] = None
    audit_nats_url: Optional[str] = None
    audit_nats_subject_prefix: str = "pa.audit.messages"
    audit_nats_creds_file: Optional[str] = None
    resubscribe_enabled: bool = True
    resubscribe_interval_sec: float = 60.0

    def with_no_auth(self) -> PASlimConfig:
        self.auth_type = "none"
        self.auth_secret = None
        return self

    def with_shared_secret(self, secret: str) -> PASlimConfig:
        self.auth_type = "shared_secret"
        self.auth_secret = secret
        return self

    def with_jwt_auth(
        self,
        token_path: str,
        *,
        jwks_url: Optional[str] = None,
        jwks_content: Optional[str] = None,
        issuer: Optional[str] = None,
        audience: Optional[list[str]] = None,
        subject: Optional[str] = None,
    ) -> PASlimConfig:
        self.auth_type = "jwt"
        self.jwt_token_path = token_path
        self.jwt_jwks_url = jwks_url
        self.jwt_jwks_content = jwks_content
        self.jwt_issuer = issuer
        self.jwt_audience = audience
        self.jwt_subject = subject
        self.mls_enabled = False
        return self


@dataclass
class PASlimConfigP2P(PASlimConfig):
    peer_name: Optional[str] = None


@dataclass
class PASlimConfigGroup(PASlimConfig):
    channel_name: Optional[str] = None
    invites: list[str] = field(default_factory=list)
