"""Pydantic models for the HalluciGuard SaaS API."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


# ── Enums ─────────────────────────────────────────────────────────

class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class IssueType(str, Enum):
    HALLUCINATED_FACT = "hallucinated_fact"
    NONEXISTENT_API = "nonexistent_api"
    WRONG_SIGNATURE = "wrong_signature"
    DEPRECATED_API = "deprecated_api"
    INVALID_IMPORT = "invalid_import"
    FABRICATED_REFERENCE = "fabricated_reference"
    INCONSISTENT_CLAIM = "inconsistent_claim"
    UNSUPPORTED_PARAMETER = "unsupported_parameter"


class Plan(str, Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


# ── Request Models ────────────────────────────────────────────────

class ValidateCodeRequest(BaseModel):
    """Validate AI-generated code for hallucinated APIs."""
    code: str = Field(..., min_length=1, max_length=50000, description="Code to validate")
    language: str | None = Field(None, description="Language hint (python, javascript, typescript)")
    context: str | None = Field(None, max_length=5000, description="Optional context for validation")


class ValidateTextRequest(BaseModel):
    """Validate AI-generated text for factual hallucinations."""
    text: str = Field(..., min_length=1, max_length=100000, description="LLM output text to validate")
    domain: str | None = Field(None, description="Domain hint (medical, legal, finance, general)")
    sources: list[str] = Field(default_factory=list, description="Known-good source URLs for fact-checking")


class ValidateProxyRequest(BaseModel):
    """Proxy an LLM API call and validate the response."""
    provider: str = Field(..., description="LLM provider (openai, anthropic, custom)")
    model: str = Field(default="gpt-4o-mini", description="Model name")
    messages: list[dict] = Field(..., description="Messages array (OpenAI format)")
    api_key: str = Field(..., description="Your LLM provider API key")
    validate: bool = Field(default=True, description="Whether to validate the response")


# ── Response Models ───────────────────────────────────────────────

class Issue(BaseModel):
    """A single hallucination issue detected."""
    severity: Severity
    issue_type: IssueType
    message: str
    line: int | None = None
    column: int | None = None
    suggestion: str | None = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.9)


class ValidationResponse(BaseModel):
    """Result of a validation request."""
    safe: bool = Field(description="Whether the content passed validation")
    confidence: float = Field(ge=0.0, le=1.0, description="Overall confidence score")
    issues: list[Issue] = Field(default_factory=list, description="List of detected issues")
    issues_count: int = Field(default=0)
    latency_ms: float = Field(default=0.0, description="Processing time in milliseconds")
    validated_at: str = Field(default="")
    request_id: str = Field(default="")


class ProxyValidationResponse(BaseModel):
    """Result of a proxy + validate request."""
    response: dict = Field(description="Original LLM response")
    validation: ValidationResponse = Field(description="Validation results")


class UsageResponse(BaseModel):
    """Current usage stats for the API key."""
    plan: Plan
    requests_used: int
    requests_limit: int
    requests_remaining: int
    period: str


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "0.1.0"
    engine: str = "halluciguard"
