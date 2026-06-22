"""Pydantic models — structured, validated artifacts (Evidence preservation)."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Literal
from pydantic import BaseModel, Field

IoCType = Literal["ipv4", "domain", "url", "md5", "sha256", "email", "unknown"]
ThreatLevel = Literal["critical", "high", "medium", "low", "unknown"]


class SourceResult(BaseModel):
    """Raw result from one collector for one IoC."""
    source: str
    ok: bool
    skipped: bool = False
    reason: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    fetched_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class IoCResult(BaseModel):
    """Everything known about a single IoC after enrichment + scoring."""
    indicator: str
    type: IoCType
    sources: list[SourceResult] = Field(default_factory=list)
    related: list[dict[str, str]] = Field(default_factory=list)  # graph edges
    threat_level: ThreatLevel = "unknown"
    score: int = 0
    confidence: ThreatLevel = "low"
    reasons: list[str] = Field(default_factory=list)
    mitre: list[dict[str, str]] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class Report(BaseModel):
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    run_dir: str
    inputs: list[str]
    key_status: dict[str, bool]
    results: list[IoCResult]

    @property
    def overall(self) -> ThreatLevel:
        order = ["unknown", "low", "medium", "high", "critical"]
        worst = "unknown"
        for r in self.results:
            if order.index(r.threat_level) > order.index(worst):
                worst = r.threat_level
        return worst  # type: ignore
