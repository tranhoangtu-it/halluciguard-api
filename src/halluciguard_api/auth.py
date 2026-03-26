"""API key authentication middleware for HalluciGuard.

Validates API keys against Supabase (SHA-256 hash lookup).
Falls back to demo keys when Supabase is not configured.
"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from typing import Any

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

from .config import settings
from .models import Plan

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# ── Supabase client (lazy init) ─────────────────────────────────

_supabase_client = None


def _get_supabase():
    """Lazy-initialize Supabase client."""
    global _supabase_client
    if _supabase_client is None and settings.supabase_url and settings.supabase_service_key:
        from supabase import create_client
        _supabase_client = create_client(settings.supabase_url, settings.supabase_service_key)
    return _supabase_client


# ── In-memory stores ────────────────────────────────────────────

# api_key -> plan tier (demo keys only)
_api_keys: dict[str, str] = dict(settings.demo_api_keys)

# api_key -> list of request timestamps (for rate limiting)
_rate_windows: dict[str, list[float]] = defaultdict(list)

# api_key -> monthly request count (in-memory fallback)
_usage_counts: dict[str, int] = defaultdict(int)

# Cache: key_hash -> (plan, key_id, user_id) to avoid repeated DB lookups
_key_cache: dict[str, tuple[str, str, str]] = {}
_cache_ttl: dict[str, float] = {}
CACHE_TTL_SECONDS = 300  # 5 minutes


def _sha256(text: str) -> str:
    """Hash a string with SHA-256."""
    return hashlib.sha256(text.encode()).hexdigest()


def _lookup_key_in_supabase(api_key: str) -> tuple[str, str, str] | None:
    """Look up API key in Supabase by hash. Returns (plan, key_id, user_id) or None."""
    sb = _get_supabase()
    if sb is None:
        return None

    key_hash = _sha256(api_key)

    # Check cache first
    now = time.time()
    if key_hash in _key_cache and now - _cache_ttl.get(key_hash, 0) < CACHE_TTL_SECONDS:
        return _key_cache[key_hash]

    try:
        result = sb.table("api_keys").select("id, user_id, plan, is_active").eq("key_hash", key_hash).execute()
        if result.data and len(result.data) > 0:
            row = result.data[0]
            if not row.get("is_active", False):
                return None
            info = (row["plan"], row["id"], row["user_id"])
            _key_cache[key_hash] = info
            _cache_ttl[key_hash] = now
            return info
    except Exception as e:
        # Log but don't crash — fall back to demo keys
        import logging
        logging.warning(f"Supabase lookup failed: {e}")

    return None


def get_plan(api_key: str) -> Plan:
    """Get the plan tier for an API key."""
    # Try Supabase first
    sb_result = _lookup_key_in_supabase(api_key)
    if sb_result is not None:
        plan_str, _key_id, _user_id = sb_result
        return Plan(plan_str)

    # Fallback to demo keys
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

    # Also record in Supabase if available
    sb_result = _lookup_key_in_supabase(api_key)
    if sb_result is not None:
        _plan, key_id, user_id = sb_result
        sb = _get_supabase()
        if sb:
            try:
                # Insert usage log
                sb.table("usage_logs").insert({
                    "api_key_id": key_id,
                    "user_id": user_id,
                    "endpoint": "/api/v1/validate",
                    "status_code": 200,
                }).execute()

                # Upsert monthly counter
                from datetime import datetime
                month = datetime.utcnow().strftime("%Y-%m-01")
                sb.rpc("increment_usage", {
                    "p_key_id": key_id,
                    "p_user_id": user_id,
                    "p_month": month,
                }).execute()
            except Exception:
                pass  # Don't fail the request if usage tracking fails


def get_usage(api_key: str, plan: Plan) -> dict[str, Any]:
    """Get current usage stats."""
    used = _usage_counts.get(api_key, 0)

    # Try to get from Supabase
    sb_result = _lookup_key_in_supabase(api_key)
    if sb_result is not None:
        _plan, key_id, user_id = sb_result
        sb = _get_supabase()
        if sb:
            try:
                from datetime import datetime
                month = datetime.utcnow().strftime("%Y-%m-01")
                result = sb.table("usage_monthly").select("request_count").eq("api_key_id", key_id).eq("month", month).execute()
                if result.data:
                    used = result.data[0]["request_count"]
            except Exception:
                pass

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
