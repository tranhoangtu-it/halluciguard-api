"""Configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class Settings:
    """Application settings — loaded once at startup."""

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False

    # Rate limits (per API key, per minute)
    rate_limit_free: int = 20
    rate_limit_pro: int = 200
    rate_limit_enterprise: int = 2000

    # Usage limits (per month)
    usage_limit_free: int = 1000
    usage_limit_pro: int = 50000
    usage_limit_enterprise: int = -1  # unlimited

    # Demo API keys for MVP (in production, use a database)
    demo_api_keys: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            host=os.getenv("HOST", "0.0.0.0"),
            port=int(os.getenv("PORT", "8000")),
            debug=os.getenv("DEBUG", "false").lower() == "true",
            demo_api_keys={
                "hg_demo_free_key_2026": "free",
                "hg_demo_pro_key_2026": "pro",
                os.getenv("HG_ADMIN_KEY", "hg_admin_secret_2026"): "enterprise",
            },
        )


settings = Settings.from_env()
