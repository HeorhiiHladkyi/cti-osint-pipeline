"""Collector registry — maps IoC types to applicable collectors."""
from __future__ import annotations
from typing import Callable
from ..models import SourceResult
from . import keyless, keyed

# (name, applicable_types, fn)
REGISTRY: list[tuple[str, set[str], Callable[[str, str], SourceResult]]] = [
    ("dns", {"domain", "url", "ipv4"}, keyless.dns_records),
    ("whois", {"domain", "url"}, keyless.whois_lookup),
    ("crtsh", {"domain", "url"}, keyless.crtsh),
    ("rdap", {"ipv4", "domain", "url"}, keyless.rdap),
    ("urlscan", {"domain", "url", "ipv4"}, keyless.urlscan),
    ("virustotal", {"ipv4", "domain", "url", "md5", "sha256"}, keyed.virustotal),
    ("abuseipdb", {"ipv4"}, keyed.abuseipdb),
    ("shodan", {"ipv4"}, keyed.shodan),
    ("otx", {"ipv4", "domain", "url", "md5", "sha256"}, keyed.otx),
]


def collectors_for(ioc_type: str):
    return [(name, fn) for (name, types, fn) in REGISTRY if ioc_type in types]
