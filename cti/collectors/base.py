"""Collector base helpers: resilient HTTP + uniform SourceResult."""
from __future__ import annotations
import time
from typing import Any
import requests
from loguru import logger
from ..config import settings
from ..models import SourceResult


def http_get(url: str, *, headers: dict | None = None, params: dict | None = None,
             retries: int = 0, backoff: float = 1.5, timeout: int | None = None) -> tuple[bool, Any, str | None]:
    """Returns (ok, json_or_text, error). Never raises.
    Retries on network errors and 5xx (transient); never retries 4xx (client error)."""
    h = {"User-Agent": settings.user_agent}
    if headers:
        h.update(headers)
    to = timeout or settings.http_timeout
    last_err = "no data"
    for attempt in range(retries + 1):
        try:
            r = requests.get(url, headers=h, params=params, timeout=to)
            if r.status_code >= 500:
                last_err = f"HTTP {r.status_code}"
            elif r.status_code >= 400:
                return False, None, f"HTTP {r.status_code}"  # client error — don't retry
            else:
                ctype = r.headers.get("content-type", "")
                return True, (r.json() if "json" in ctype else r.text), None
        except requests.RequestException as e:
            last_err = str(e)[:160]
        if attempt < retries:
            time.sleep(backoff * (attempt + 1))  # linear backoff
    return False, None, last_err


def ok(source: str, data: dict) -> SourceResult:
    return SourceResult(source=source, ok=True, data=data)


def fail(source: str, reason: str) -> SourceResult:
    logger.warning(f"[{source}] failed: {reason}")
    return SourceResult(source=source, ok=False, reason=reason)


def skip(source: str, reason: str) -> SourceResult:
    logger.warning(f"[{source}] skipped: {reason}")
    return SourceResult(source=source, ok=False, skipped=True, reason=reason)
