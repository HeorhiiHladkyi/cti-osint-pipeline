"""Demo: prove the analysis+report tier yields HIGH/CRITICAL with MITRE when keyed
sources return malicious data. Uses synthetic fixtures (no live API key needed) so
you can see exactly what the report looks like once you add a real key to .env."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from cti.models import IoCResult, SourceResult, Report
from cti.scoring import score_ioc
from cti import graph as graphmod, stix as stixmod, report as reportmod, storage

# Synthetic "malicious IP" enrichment as the real APIs would return it
mal = IoCResult(indicator="185.220.101.44", type="ipv4")
mal.sources = [
    SourceResult(source="abuseipdb", ok=True, data={"abuseConfidenceScore": 100, "totalReports": 842, "countryCode": "DE", "isp": "Tor Exit"}),
    SourceResult(source="virustotal", ok=True, data={"malicious": 11, "suspicious": 2, "harmless": 50, "reputation": -40}),
    SourceResult(source="shodan", ok=True, data={"ports": [22, 3389], "asn": "AS208294", "vulns": ["CVE-2026-49777"], "hostnames": ["exit.tor.example"]}),
    SourceResult(source="otx", ok=True, data={"pulse_count": 7, "pulses": ["Ransomware C2 infra"], "tags": ["ransomware", "c2"]}),
    SourceResult(source="dns", ok=True, data={"ptr": ["exit.tor.example."]}),
]
phish = IoCResult(indicator="secure-login-verify.test", type="domain")
phish.sources = [SourceResult(source="virustotal", ok=True, data={"malicious": 4, "harmless": 60})]

results = [score_ioc(mal), score_ioc(phish)]
run = storage.make_run_dir("output")
g = graphmod.build_graph(results)
rep = Report(run_dir=str(run), inputs=[r.indicator for r in results],
             key_status={"virustotal": True, "abuseipdb": True, "shodan": True, "otx": True, "urlscan": True},
             results=results)
storage.save_json(run / "iocs.json", stixmod.to_ioc_json(results))
storage.save_json(run / "stix_bundle.json", stixmod.to_stix_bundle(results))
reportmod.render_html(rep, run / "report.html")

for r in results:
    print(f"{r.indicator:32} -> {r.threat_level.upper():8} score={r.score:3} conf={r.confidence} mitre={[m['id'] for m in r.mitre]}")
print("overall:", rep.overall.upper(), "| report:", run / "report.html")
