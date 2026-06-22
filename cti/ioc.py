"""IoC type detection and normalization."""
from __future__ import annotations
import ipaddress
import re
from urllib.parse import urlparse

_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$")


def detect_type(value: str) -> str:
    v = value.strip()
    if not v:
        return "unknown"
    try:
        ip = ipaddress.ip_address(v)
        return "ipv4" if ip.version == 4 else "ipv6"
    except ValueError:
        pass
    if v.startswith("http://") or v.startswith("https://"):
        return "url"
    if _MD5.match(v):
        return "md5"
    if _SHA256.match(v):
        return "sha256"
    if _EMAIL.match(v):
        return "email"
    if _DOMAIN.match(v):
        return "domain"
    return "unknown"


def host_of(url: str) -> str:
    return urlparse(url).hostname or ""


def parse_file(path: str) -> list[str]:
    out: list[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if s and not s.startswith("#"):
                out.append(s)
    return out
