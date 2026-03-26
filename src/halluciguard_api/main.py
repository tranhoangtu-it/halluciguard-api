"""HalluciGuard API — AI Hallucination Firewall as a Service.

Usage:
    uvicorn halluciguard_api.main:app --host 0.0.0.0 --port 8000

Endpoints:
    POST /api/v1/validate/code   — Validate AI-generated code
    POST /api/v1/validate/text   — Validate AI-generated text
    GET  /api/v1/usage           — Check usage stats
    GET  /health                 — Health check
    GET  /docs                   — Interactive API docs
"""

from __future__ import annotations

import uuid

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .auth import authenticate, get_usage, record_usage
from .models import (
    HealthResponse,
    Plan,
    UsageResponse,
    ValidateCodeRequest,
    ValidateTextRequest,
    ValidationResponse,
)
from .validator import run_validation

# ── App ───────────────────────────────────────────────────────────

app = FastAPI(
    title="HalluciGuard API",
    description="AI Hallucination Firewall — detect and filter factually incorrect LLM outputs in real-time.",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Public Endpoints ──────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health() -> HealthResponse:
    """Health check — no auth required."""
    return HealthResponse()


@app.get("/", tags=["System"])
async def root() -> dict:
    return {
        "name": "HalluciGuard API",
        "version": "0.1.0",
        "docs": "/docs",
        "description": "AI Hallucination Firewall as a Service",
    }


# ── Authenticated Endpoints ──────────────────────────────────────

@app.post("/api/v1/validate/code", response_model=ValidationResponse, tags=["Validation"])
async def validate_code(
    request: ValidateCodeRequest,
    auth: tuple[str, Plan] = Depends(authenticate),
) -> ValidationResponse:
    """Validate AI-generated code for hallucinated APIs, imports, and signatures."""
    api_key, plan = auth
    record_usage(api_key)

    result = run_validation(
        content=request.code,
        content_type="code",
        language=request.language,
    )
    result.request_id = f"req_{uuid.uuid4().hex[:16]}"
    return result


@app.post("/api/v1/validate/text", response_model=ValidationResponse, tags=["Validation"])
async def validate_text(
    request: ValidateTextRequest,
    auth: tuple[str, Plan] = Depends(authenticate),
) -> ValidationResponse:
    """Validate AI-generated text for factual hallucinations."""
    api_key, plan = auth
    record_usage(api_key)

    result = run_validation(
        content=request.text,
        content_type="text",
        domain=request.domain,
    )
    result.request_id = f"req_{uuid.uuid4().hex[:16]}"
    return result


@app.get("/api/v1/usage", response_model=UsageResponse, tags=["Account"])
async def usage(
    auth: tuple[str, Plan] = Depends(authenticate),
) -> UsageResponse:
    """Check current API usage and remaining quota."""
    api_key, plan = auth
    stats = get_usage(api_key, plan)
    return UsageResponse(
        plan=plan,
        requests_used=stats["requests_used"],
        requests_limit=stats["requests_limit"],
        requests_remaining=stats["requests_remaining"],
        period="2026-03",
    )


# ── Run ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
