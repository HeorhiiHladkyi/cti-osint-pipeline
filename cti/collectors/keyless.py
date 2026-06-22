"""Keyless collectors — work with no API keys (so the pipeline always runs)."""
from __future__ import annotations
from ..models import SourceResult
from ..ioc import host_of
from .base import http_get, ok, fail


def dns_records(indicator: str, ioc_type: str) -> SourceResult:
    try:
        import dns.resolver
        import dns.reversename
    except Exception as e:  # pragma: no cover
        return fail("dns", f"dnspython missing: {e}")

    res = dns.resolver.Resolver()
    res.lifetime = 8
    res.timeout = 8
    try:
        if ioc_type == "ipv4":
            rev = dns.reversename.from_address(indicator)
            ptr = [str(r) for r in res.resolve(rev, "PTR")]
            return ok("dns", {"ptr": ptr})
        host = host_of(indicator) if ioc_type == "url" else indicator
        out: dict[str, list[str]] = {}
        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            try:
                out[rtype] = [r.to_text().strip('"') for r in res.resolve(host, rtype)]
            except Exception:
                out[rtype] = []
        return ok("dns", out)
    except Exception as e:
        return fail("dns", str(e)[:160])


def whois_lookup(indicator: str, ioc_type: str) -> SourceResult:
    try:
        import whois  # python-whois
    except Exception as e:  # pragma: no cover
        return fail("whois", f"python-whois missing: {e}")
    host = host_of(indicator) if ioc_type == "url" else indicator
    try:
        w = whois.whois(host)
        def norm(v):
            if isinstance(v, list):
                return [str(x) for x in v]
            return str(v) if v is not None else None
        return ok("whois", {
            "registrar": norm(w.registrar),
            "creation_date": norm(w.creation_date),
            "expiration_date": norm(w.expiration_date),
            "name_servers": norm(w.name_servers),
            "country": norm(getattr(w, "country", None)),
            "org": norm(getattr(w, "org", None)),
        })
    except Exception as e:
        return fail("whois", str(e)[:160])


def crtsh(indicator: str, ioc_type: str) -> SourceResult:
    host = host_of(indicator) if ioc_type == "url" else indicator
    # crt.sh is publicly flaky (5xx / timeouts) — retry with backoff and a longer timeout.
    ok_, data, err = http_get("https://crt.sh/", params={"q": host, "output": "json"},
                              retries=2, backoff=2.0, timeout=25)
    if not ok_:
        return fail("crtsh", err or "no data")
    if not isinstance(data, list):
        return ok("crtsh", {"certificates": [], "count": 0})
    certs = []
    seen = set()
    for row in data[:200]:
        name = row.get("name_value", "")
        issuer = row.get("issuer_name", "")
        key = (name, issuer)
        if key in seen:
            continue
        seen.add(key)
        certs.append({"name_value": name, "issuer": issuer, "not_before": row.get("not_before")})
    subdomains = sorted({n for c in certs for n in c["name_value"].split("\n") if host in n})
    return ok("crtsh", {"count": len(certs), "certificates": certs[:50], "subdomains": subdomains[:100]})


def rdap(indicator: str, ioc_type: str) -> SourceResult:
    if ioc_type == "ipv4":
        url = f"https://rdap.org/ip/{indicator}"
    else:
        host = host_of(indicator) if ioc_type == "url" else indicator
        url = f"https://rdap.org/domain/{host}"
    ok_, data, err = http_get(url)
    if not ok_ or not isinstance(data, dict):
        return fail("rdap", err or "no data")
    out = {
        "handle": data.get("handle"),
        "name": data.get("name"),
        "country": data.get("country"),
        "asn": None,
        "events": [{e.get("eventAction"): e.get("eventDate")} for e in data.get("events", [])],
    }
    # ASN often in 'arin_originas0_originautnums' or remarks; try cidr/startAddress
    for k in ("startAddress", "endAddress", "ipVersion", "type"):
        if k in data:
            out[k] = data[k]
    return ok("rdap", out)


# Known CDN / reverse-proxy networks — if the target IP belongs here, it is an
# edge node and the true origin server is hidden behind it.
# Only true reverse-proxy CDNs that HIDE the origin. General cloud (AWS/GCP/Azure)
# is intentionally excluded — there the IP is usually the real host, not an edge proxy.
CDN_ASN = {
    13335: "Cloudflare", 209242: "Cloudflare", 54113: "Fastly",
    20940: "Akamai", 16625: "Akamai", 32787: "Akamai",
    19551: "Incapsula/Imperva", 12989: "Incapsula", 54994: "Sucuri",
    60068: "CDN77", 393234: "StackPath", 200325: "BunnyCDN", 22822: "Limelight",
}
CDN_KEYWORDS = ("cloudflare", "fastly", "akamai", "cloudfront", "incapsula", "imperva",
                "sucuri", "stackpath", "bunny", "edgecast", "limelight", "cdn77", "keycdn")


def _cymru_asn(ip: str):
    """Keyless ASN lookup via Team Cymru DNS (origin.asn.cymru.com). IPv4 only."""
    try:
        import dns.resolver
    except Exception:
        return None
    try:
        rev = ".".join(reversed(ip.split(".")))
        r = dns.resolver.Resolver(); r.lifetime = 6; r.timeout = 6
        txt = str(r.resolve(f"{rev}.origin.asn.cymru.com", "TXT")[0]).strip('"')
        # "13335 | 104.16.0.0/12 | US | arin | 2014-03-28"
        asn, prefix, cc, *_ = [p.strip() for p in txt.split("|")]
        as_name = None
        try:
            t2 = str(r.resolve(f"AS{asn.split()[0]}.asn.cymru.com", "TXT")[0]).strip('"')
            as_name = t2.split("|")[-1].strip()
        except Exception:
            pass
        return {"asn": asn.split()[0], "prefix": prefix, "country": cc, "as_name": as_name}
    except Exception:
        return None


def network(indicator: str, ioc_type: str) -> SourceResult:
    """Establish the target IP + its ASN/owner, and flag CDN (origin-hidden) edges."""
    if ioc_type == "ipv4":
        ip = indicator
    elif ioc_type in ("domain", "url"):
        try:
            import dns.resolver
            host = host_of(indicator) if ioc_type == "url" else indicator
            r = dns.resolver.Resolver(); r.lifetime = 6; r.timeout = 6
            ip = str(r.resolve(host, "A")[0])
        except Exception as e:
            return fail("network", f"no A record: {str(e)[:80]}")
    else:
        return fail("network", f"unsupported type {ioc_type}")

    cymru = _cymru_asn(ip) or {}
    asn = cymru.get("asn")
    as_name = cymru.get("as_name") or ""
    cdn = None
    if asn and asn.isdigit() and int(asn) in CDN_ASN:
        cdn = CDN_ASN[int(asn)]
    elif any(kw in as_name.lower() for kw in CDN_KEYWORDS):
        cdn = next(kw.capitalize() for kw in CDN_KEYWORDS if kw in as_name.lower())
    return ok("network", {
        "ip": ip, "asn": f"AS{asn}" if asn else None, "as_name": as_name or None,
        "country": cymru.get("country"), "prefix": cymru.get("prefix"),
        "is_cdn": bool(cdn), "cdn": cdn,
    })


def urlscan(indicator: str, ioc_type: str) -> SourceResult:
    host = host_of(indicator) if ioc_type == "url" else indicator
    q = f"page.domain:{host}" if ioc_type in ("domain", "url") else f"page.ip:{indicator}"
    ok_, data, err = http_get("https://urlscan.io/api/v1/search/", params={"q": q, "size": 10})
    if not ok_ or not isinstance(data, dict):
        return fail("urlscan", err or "no data")
    results = []
    for r in data.get("results", [])[:10]:
        page = r.get("page", {})
        results.append({"url": page.get("url"), "ip": page.get("ip"), "server": page.get("server")})
    return ok("urlscan", {"total": data.get("total", 0), "results": results})
