"""STIX 2.1 bundle + flat machine-readable JSON export of enriched IoCs."""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from .models import IoCResult

_PATTERN = {
    "ipv4": lambda v: f"[ipv4-addr:value = '{v}']",
    "domain": lambda v: f"[domain-name:value = '{v}']",
    "url": lambda v: f"[url:value = '{v}']",
    "md5": lambda v: f"[file:hashes.MD5 = '{v}']",
    "sha256": lambda v: f"[file:hashes.'SHA-256' = '{v}']",
    "email": lambda v: f"[email-addr:value = '{v}']",
}
_CONF = {"critical": 90, "high": 75, "medium": 50, "low": 20, "unknown": 0}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def to_stix_bundle(results: list[IoCResult]) -> dict:
    now = _now()
    objects = []
    for r in results:
        patt = _PATTERN.get(r.type)
        if not patt:
            continue
        labels = ["malicious-activity"] if r.threat_level in ("critical", "high") else \
                 ["anomalous-activity"] if r.threat_level == "medium" else ["benign"]
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "name": f"{r.type}: {r.indicator}",
            "description": "; ".join(r.reasons)[:500],
            "indicator_types": labels,
            "pattern": patt(r.indicator),
            "pattern_type": "stix",
            "valid_from": now,
            "confidence": _CONF.get(r.threat_level, 0),
            "labels": labels,
            "x_threat_level": r.threat_level,
            "x_mitre_attack": [m["id"] for m in r.mitre],
        })
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": objects,
    }


def to_ioc_json(results: list[IoCResult]) -> list[dict]:
    return [{
        "indicator": r.indicator,
        "type": r.type,
        "threat_level": r.threat_level,
        "score": r.score,
        "confidence": r.confidence,
        "resolved_ip": r.resolved_ip,
        "asn": r.asn,
        "network_country": r.network_country,
        "cdn": r.cdn,
        "origin_candidates": r.origin_candidates,
        "mitre_attack": r.mitre,
        "reasons": r.reasons,
        "recommendations": r.recommendations,
    } for r in results]
