"""API key authentication middleware for HalluciGuard."""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

from .config import settings
from .models import Plan

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# ── In-memory stores (replace with Redis/DB in production) ────────

# api_key -> plan tier
_api_keys: dict[str, str] = dict(settings.demo_api_keys)

# api_key -> list of request timestamps (for rate limiting)
_rate_windows: dict[str, list[float]] = defaultdict(list)

# api_key -> monthly request count
_usage_counts: dict[str, int] = defaultdict(int)


def get_plan(api_key: str) -> Plan:
    """Get the plan tier for an API key."""
    tier = _api_keys.get(api_key)
    if tier is None:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "invalid_api_key",
                "message": "Invalid or missing API key. Get one at https://halluciguard-deploy.vercel.app",
            },
        )
    return Plan(tier)


def get_rate_limit(plan: Plan) -> int:
    """Get rate limit per minute for a plan."""
    limits = {
        Plan.FREE: settings.rate_limit_free,
        Plan.PRO: settings.rate_limit_pro,
        Plan.ENTERPRISE: settings.rate_limit_enterprise,
    }
    return limits[plan]


def get_usage_limit(plan: Plan) -> int:
    """Get monthly usage limit for a plan."""
    limits = {
        Plan.FREE: settings.usage_limit_free,
        Plan.PRO: settings.usage_limit_pro,
        Plan.ENTERPRISE: settings.usage_limit_enterprise,
    }
    return limits[plan]


def check_rate_limit(api_key: str, plan: Plan) -> None:
    """Check and enforce rate limiting."""
    now = time.time()
    window = 60.0  # 1 minute
    limit = get_rate_limit(plan)

    # Prune old entries
    _rate_windows[api_key] = [t for t in _rate_windows[api_key] if now - t < window]

    if len(_rate_windows[api_key]) >= limit:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "rate_limit_exceeded",
                "message": f"Rate limit exceeded ({limit} requests/minute for {plan.value} plan)",
                "retry_after_seconds": int(window - (now - _rate_windows[api_key][0])) + 1,
            },
        )
    _rate_windows[api_key].append(now)


def check_usage_limit(api_key: str, plan: Plan) -> None:
    """Check monthly usage limit."""
    limit = get_usage_limit(plan)
    if limit == -1:  # unlimited
        return

    if _usage_counts[api_key] >= limit:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "usage_limit_exceeded",
                "message": f"Monthly usage limit reached ({limit} requests for {plan.value} plan). Upgrade at https://halluciguard-deploy.vercel.app/#pricing",
            },
        )


def record_usage(api_key: str) -> None:
    """Record a request for usage tracking."""
    _usage_counts[api_key] += 1


def get_usage(api_key: str, plan: Plan) -> dict[str, Any]:
    """Get current usage stats."""
    used = _usage_counts.get(api_key, 0)
    limit = get_usage_limit(plan)
    return {
        "plan": plan.value,
        "requests_used": used,
        "requests_limit": limit if limit > 0 else "unlimited",
        "requests_remaining": max(0, limit - used) if limit > 0 else "unlimited",
    }


async def authenticate(api_key: str | None = Security(api_key_header)) -> tuple[str, Plan]:
    """Authenticate request and return (api_key, plan)."""
    if api_key is None:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "missing_api_key",
                "message": "API key required. Pass it as X-API-Key header.",
            },
        )
    plan = get_plan(api_key)
    check_rate_limit(api_key, plan)
    check_usage_limit(api_key, plan)
    return api_key, plan
