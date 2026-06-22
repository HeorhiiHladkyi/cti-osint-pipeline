"""Origin-hunting: when a domain is CDN-fronted, its subdomains often bypass the
proxy and resolve straight to the real origin server. We enumerate subdomains from
crt.sh (already collected), resolve them, and flag those that land on a NON-CDN IP —
candidate origin servers behind the CDN. Runs as a post-collection analysis step."""
from __future__ import annotations
from .models import SourceResult
from .collectors import keyless as kl
from .collectors.base import ok, skip

MAX_SUBS = 20      # bound the number of subdomains we resolve
MAX_CANDIDATES = 8


def _src(result, name: str) -> dict:
    for s in result.sources:
        if s.source == name and s.ok:
            return s.data
    return {}


def origin_hunt(result) -> SourceResult:
    if result.type not in ("domain", "url"):
        return skip("origin_hunt", "only domain/url")

    net = _src(result, "network")
    crt = _src(result, "crtsh")
    main_ip = net.get("ip")
    cdn_fronted = bool(net.get("cdn"))
    subs = [s for s in crt.get("subdomains", []) if "*" not in s][:MAX_SUBS]
    if not subs:
        return ok("origin_hunt", {"checked": 0, "cdn_fronted": cdn_fronted, "candidates": []})

    try:
        import dns.resolver
    except Exception as e:
        return skip("origin_hunt", f"dnspython missing: {e}")
    r = dns.resolver.Resolver()
    r.lifetime = 4
    r.timeout = 4

    ip_meta: dict[str, dict] = {}
    candidates: dict[str, dict] = {}  # keyed by ip
    for sub in subs:
        try:
            ip = str(r.resolve(sub, "A")[0])
        except Exception:
            continue
        if ip == main_ip:
            continue
        if ip not in ip_meta:
            info = kl._cymru_asn(ip) or {}
            ip_meta[ip] = {"asn": info.get("asn"), "as_name": info.get("as_name"),
                           "cdn": kl.cdn_for(info.get("asn"), info.get("as_name", ""))}
        meta = ip_meta[ip]
        if not meta["cdn"] and ip not in candidates:        # bypasses CDN → candidate origin
            candidates[ip] = {"subdomain": sub, "ip": ip,
                              "asn": f"AS{meta['asn']}" if meta["asn"] else None,
                              "as_name": meta["as_name"]}

    return ok("origin_hunt", {
        "checked": len(subs),
        "cdn_fronted": cdn_fronted,
        "candidates": list(candidates.values())[:MAX_CANDIDATES],
    })
