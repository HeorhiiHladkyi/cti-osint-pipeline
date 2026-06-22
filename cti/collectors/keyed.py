"""Keyed collectors — used when an API key is present, else skipped with WARNING."""
from __future__ import annotations
from ..config import settings
from ..models import SourceResult
from ..ioc import host_of
from .base import http_get, ok, fail, skip


def virustotal(indicator: str, ioc_type: str) -> SourceResult:
    if not settings.virustotal_key:
        return skip("virustotal", "no VIRUSTOTAL_API_KEY")
    base = "https://www.virustotal.com/api/v3"
    if ioc_type == "ipv4":
        path = f"/ip_addresses/{indicator}"
    elif ioc_type in ("md5", "sha256"):
        path = f"/files/{indicator}"
    elif ioc_type == "url":
        import base64
        uid = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
        path = f"/urls/{uid}"
    else:
        path = f"/domains/{host_of(indicator) if ioc_type == 'url' else indicator}"
    ok_, data, err = http_get(base + path, headers={"x-apikey": settings.virustotal_key})
    if not ok_ or not isinstance(data, dict):
        return fail("virustotal", err or "no data")
    stats = (data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}))
    return ok("virustotal", {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "reputation": data.get("data", {}).get("attributes", {}).get("reputation"),
    })


def abuseipdb(indicator: str, ioc_type: str) -> SourceResult:
    if ioc_type != "ipv4":
        return skip("abuseipdb", "only IPv4")
    if not settings.abuseipdb_key:
        return skip("abuseipdb", "no ABUSEIPDB_API_KEY")
    ok_, data, err = http_get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": settings.abuseipdb_key, "Accept": "application/json"},
        params={"ipAddress": indicator, "maxAgeInDays": 90},
    )
    if not ok_ or not isinstance(data, dict):
        return fail("abuseipdb", err or "no data")
    d = data.get("data", {})
    return ok("abuseipdb", {
        "abuseConfidenceScore": d.get("abuseConfidenceScore", 0),
        "totalReports": d.get("totalReports", 0),
        "countryCode": d.get("countryCode"),
        "isp": d.get("isp"),
        "domain": d.get("domain"),
    })


def shodan(indicator: str, ioc_type: str) -> SourceResult:
    if ioc_type != "ipv4":
        return skip("shodan", "only IPv4")
    if not settings.shodan_key:
        return skip("shodan", "no SHODAN_API_KEY")
    ok_, data, err = http_get(f"https://api.shodan.io/shodan/host/{indicator}", params={"key": settings.shodan_key})
    if not ok_ or not isinstance(data, dict):
        return fail("shodan", err or "no data")
    return ok("shodan", {
        "ports": data.get("ports", []),
        "asn": data.get("asn"),
        "org": data.get("org"),
        "os": data.get("os"),
        "vulns": list(data.get("vulns", []))[:25],
        "hostnames": data.get("hostnames", []),
    })


def otx(indicator: str, ioc_type: str) -> SourceResult:
    if not settings.otx_key:
        return skip("otx", "no OTX_API_KEY")
    seg = {"ipv4": "IPv4", "domain": "domain", "url": "url", "md5": "file", "sha256": "file"}.get(ioc_type)
    if not seg:
        return skip("otx", f"unsupported type {ioc_type}")
    value = host_of(indicator) if ioc_type == "url" and seg == "domain" else indicator
    url = f"https://otx.alienvault.com/api/v1/indicators/{seg}/{value}/general"
    ok_, data, err = http_get(url, headers={"X-OTX-API-KEY": settings.otx_key})
    if not ok_ or not isinstance(data, dict):
        return fail("otx", err or "no data")
    pulses = data.get("pulse_info", {}).get("pulses", [])
    return ok("otx", {
        "pulse_count": data.get("pulse_info", {}).get("count", 0),
        "pulses": [p.get("name") for p in pulses[:10]],
        "tags": sorted({t for p in pulses for t in p.get("tags", [])})[:25],
    })
