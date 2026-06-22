"""Collector base helpers: resilient HTTP + uniform SourceResult."""
from __future__ import annotations
from typing import Any
import requests
from loguru import logger
from ..config import settings
from ..models import SourceResult


def http_get(url: str, *, headers: dict | None = None, params: dict | None = None) -> tuple[bool, Any, str | None]:
    """Returns (ok, json_or_text, error). Never raises."""
    h = {"User-Agent": settings.user_agent}
    if headers:
        h.update(headers)
    try:
        r = requests.get(url, headers=h, params=params, timeout=settings.http_timeout)
        if r.status_code >= 400:
            return False, None, f"HTTP {r.status_code}"
        ctype = r.headers.get("content-type", "")
        return True, (r.json() if "json" in ctype else r.text), None
    except requests.RequestException as e:
        return False, None, str(e)[:160]


def ok(source: str, data: dict) -> SourceResult:
    return SourceResult(source=source, ok=True, data=data)


def fail(source: str, reason: str) -> SourceResult:
    logger.warning(f"[{source}] failed: {reason}")
    return SourceResult(source=source, ok=False, reason=reason)


def skip(source: str, reason: str) -> SourceResult:
    logger.warning(f"[{source}] skipped: {reason}")
    return SourceResult(source=source, ok=False, skipped=True, reason=reason)
