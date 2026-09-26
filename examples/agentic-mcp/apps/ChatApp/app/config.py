"""Runtime configuration, loaded from environment variables.

Docker Compose sets every value; the defaults target local development.
Two base URLs describe the same Issuerd server: the public issuer spelling
(used for browser redirects, DPoP ``htu`` claims and expected ``iss``) and the
internal base used for server-side calls (docker DNS on the compose network).
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = PACKAGE_DIR / "templates"
STATIC_DIR = PACKAGE_DIR / "static"


@dataclass(frozen=True)
class Settings:
    issuer: str  # public IdP base URL
    idp_internal_base: str  # server-side IdP base URL
    realm: str
    client_id: str
    client_secret: str
    public_base: str  # this app's own public origin
    mcp_url: str  # internal streamable-HTTP MCP endpoint
    demo_mode: str  # "scripted" | "llm"
    llm_base_url: str
    llm_api_key: str
    llm_model: str
    dpop_key_path: str
    session_secret: str
    port: int

    @property
    def realm_base_public(self) -> str:
        return f"{self.issuer}/realms/{self.realm}"

    @property
    def realm_base_internal(self) -> str:
        return f"{self.idp_internal_base}/realms/{self.realm}"

    @property
    def authorize_url(self) -> str:
        return f"{self.realm_base_public}/protocol/openid-connect/auth"

    @property
    def token_url_internal(self) -> str:
        return f"{self.realm_base_internal}/protocol/openid-connect/token"

    @property
    def token_url_public(self) -> str:
        """DPoP htu for token requests: always the public issuer spelling."""
        return f"{self.realm_base_public}/protocol/openid-connect/token"

    @property
    def logout_url(self) -> str:
        return f"{self.realm_base_public}/protocol/openid-connect/logout"

    @property
    def ciba_auth_url_internal(self) -> str:
        return f"{self.realm_base_internal}/protocol/openid-connect/ext/ciba/auth"

    @property
    def ciba_approve_url_public(self) -> str:
        return f"{self.realm_base_public}/protocol/openid-connect/ext/ciba/approve"

    @property
    def redirect_uri(self) -> str:
        return f"{self.public_base}/auth/callback"

    @property
    def secure_cookies(self) -> bool:
        return self.public_base.startswith("https://")

    @classmethod
    def from_env(cls) -> "Settings":
        issuer = os.environ.get("ISSUER", "http://localhost:8080").rstrip("/")
        return cls(
            issuer=issuer,
            idp_internal_base=os.environ.get("IDP_INTERNAL_BASE", issuer).rstrip("/"),
            realm=os.environ.get("REALM", "demo"),
            client_id=os.environ.get("CLIENT_ID", "chat-app"),
            client_secret=os.environ.get("CLIENT_SECRET", ""),
            public_base=os.environ.get("PUBLIC_BASE", "http://localhost:5108").rstrip("/"),
            mcp_url=os.environ.get("MCP_URL", "http://localhost:5109/mcp"),
            demo_mode=os.environ.get("DEMO_MODE", "scripted"),
            llm_base_url=os.environ.get("LLM_BASE_URL", "").rstrip("/"),
            llm_api_key=os.environ.get("LLM_API_KEY", ""),
            llm_model=os.environ.get("LLM_MODEL", ""),
            dpop_key_path=os.environ.get("DPOP_KEY_PATH", "./data/dpop_key.pem"),
            session_secret=os.environ.get("SESSION_SECRET") or secrets.token_hex(32),
            port=int(os.environ.get("PORT", "8000")),
        )
