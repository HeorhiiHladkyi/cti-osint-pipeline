"""Threat scoring, confidence, MITRE ATT&CK mapping and response recommendations."""
from __future__ import annotations
from .models import IoCResult, SourceResult

SUSP_KEYWORDS = ("login", "secure", "verify", "account", "update", "phish", "wallet", "bonus")
RISKY_VULN_PORTS = {3389: "RDP", 445: "SMB", 23: "Telnet", 21: "FTP", 5900: "VNC"}


def _data(sources: list[SourceResult], name: str) -> dict:
    for s in sources:
        if s.source == name and s.ok:
            return s.data
    return {}


def score_ioc(r: IoCResult) -> IoCResult:
    score = 0
    reasons: list[str] = []
    mitre: list[dict[str, str]] = []
    corroborations = 0

    vt = _data(r.sources, "virustotal")
    if vt:
        mal = int(vt.get("malicious", 0) or 0)
        if mal:
            score += min(60, mal * 12)
            reasons.append(f"VirusTotal: {mal} рушіїв позначили як шкідливе")
            corroborations += 1
            mitre.append({"id": "T1204", "name": "User Execution"} if r.type in ("md5", "sha256")
                         else {"id": "T1071", "name": "Application Layer Protocol"})

    abuse = _data(r.sources, "abuseipdb")
    if abuse:
        conf = int(abuse.get("abuseConfidenceScore", 0) or 0)
        if conf:
            score += int(conf * 0.5)
            reasons.append(f"AbuseIPDB: достовірність зловживань {conf}% ({abuse.get('totalReports', 0)} звітів)")
            corroborations += 1 if conf >= 25 else 0
            if conf >= 25:
                mitre.append({"id": "T1190", "name": "Exploit Public-Facing Application"})

    otx = _data(r.sources, "otx")
    if otx and otx.get("pulse_count"):
        pc = int(otx["pulse_count"])
        score += min(25, pc * 5)
        reasons.append(f"AlienVault OTX: {pc} threat-пульсів (згадок у кампаніях)")
        corroborations += 1

    shodan = _data(r.sources, "shodan")
    if shodan:
        vulns = shodan.get("vulns", [])
        if vulns:
            score += min(30, len(vulns) * 6)
            reasons.append(f"Shodan: відкрито {len(vulns)} відомих CVE")
            mitre.append({"id": "T1190", "name": "Exploit Public-Facing Application"})
        risky = [RISKY_VULN_PORTS[p] for p in shodan.get("ports", []) if p in RISKY_VULN_PORTS]
        if risky:
            score += 8
            reasons.append(f"Відкриті ризиковані сервіси: {', '.join(sorted(set(risky)))}")
            mitre.append({"id": "T1133", "name": "External Remote Services"})

    # keyless heuristics
    host = r.indicator.lower()
    if r.type in ("domain", "url") and any(k in host for k in SUSP_KEYWORDS):
        score += 10
        reasons.append("Домен містить ключове слово, типове для фішингу")
        mitre.append({"id": "T1566", "name": "Phishing"})
    crt = _data(r.sources, "crtsh")
    if crt and crt.get("count", 0) == 0 and r.type in ("domain", "url"):
        reasons.append("Немає сертифікатів у CT-логах (дуже новий або непублічний хост)")

    # network attribution of the established target IP (+ CDN origin-hidden flag)
    net = _data(r.sources, "network")
    if net and net.get("ip"):
        r.resolved_ip = net["ip"]
        r.network_country = net.get("country")
        if net.get("asn"):
            r.asn = f"{net['asn']} {net.get('as_name') or ''}".strip()
        if net.get("is_cdn"):
            r.cdn = net["cdn"]
            reasons.append(f"IP {net['ip']} належить CDN «{net['cdn']}» — реальний origin приховано")

    # crypto wallet on-chain enrichment (informational; threat signal needs a paid feed)
    chain = _data(r.sources, "blockchain")
    if chain and chain.get("chain"):
        r.crypto = chain
        cur = chain.get("currency", "")
        bits = [f"Гаманець {chain['chain']}: баланс {chain.get('balance')} {cur}",
                f"транзакцій {chain.get('tx_count')}"]
        if chain.get("last_seen"):
            bits.append(f"остання активність {chain['last_seen']}")
        reasons.append("; ".join(bits))
        # threat verdict for a wallet requires a paid reputation feed (Arkham/Chainalysis);
        # keyless on-chain data is attribution/context, not a maliciousness signal.

    oh = _data(r.sources, "origin_hunt")
    if oh and oh.get("candidates"):
        r.origin_candidates = oh["candidates"]
        ips = ", ".join(c["ip"] for c in r.origin_candidates[:3])
        note = "ймовірний origin за CDN" if oh.get("cdn_fronted") else "субдомени з власним хостингом"
        reasons.append(f"Origin-hunting ({note}): {ips}")

    score = max(0, min(100, score))
    has_data = any(s.ok and s.data for s in r.sources)
    level = (
        "critical" if score >= 70 else
        "high" if score >= 45 else
        "medium" if score >= 20 else
        "low" if has_data else "unknown"
    )
    confidence = "high" if corroborations >= 2 else "medium" if corroborations == 1 else "low"

    r.score = score
    r.threat_level = level  # type: ignore
    r.confidence = confidence  # type: ignore
    r.reasons = reasons or (["Жодних шкідливих сигналів від опитаних джерел"] if has_data else ["Джерела не повернули даних"])
    # dedupe mitre
    seen = set()
    r.mitre = [m for m in mitre if not (m["id"] in seen or seen.add(m["id"]))]
    r.recommendations = _recommend(level, r.type)
    return r


def _recommend(level: str, ioc_type: str) -> list[str]:
    if level in ("critical", "high"):
        base = ["ЗАБЛОКУВАТИ на периметрі (firewall / proxy / EDR).",
                "Ескалювати до групи реагування на інциденти.",
                "Провести пошук індикатора в логах (останні 90 днів)."]
    elif level == "medium":
        base = ["Моніторити та додати до списку спостереження.",
                "Зіставити з внутрішньою телеметрією перед блокуванням."]
    elif level == "low":
        base = ["Дій не потрібно; зафіксувати для контексту."]
    else:
        base = ["Недостатньо даних — повторіть запуск із налаштованими API-ключами."]
    if ioc_type in ("md5", "sha256") and level in ("critical", "high"):
        base.append("Додати хеш до блок-листа EDR; помістити відповідні файли в карантин.")
    return base
