"""IoC pivot graph: IP -> domains -> certs -> other IPs (networkx + interactive pyvis)."""
from __future__ import annotations
import networkx as nx
from .models import IoCResult
from .ioc import host_of

TYPE_COLOR = {
    "ioc": "#ef4444", "ip": "#60a5fa", "domain": "#4ade80",
    "subdomain": "#a78bfa", "asn": "#fbbf24", "host": "#f472b6",
}


def _data(r: IoCResult, name: str) -> dict:
    for s in r.sources:
        if s.source == name and s.ok:
            return s.data
    return {}


def build_graph(results: list[IoCResult]) -> nx.Graph:
    g = nx.Graph()
    for r in results:
        node = r.indicator
        g.add_node(node, kind="ioc", level=r.threat_level)
        edges: list[dict[str, str]] = []

        def link(target: str, kind: str, rel: str):
            if not target or target == node:
                return
            if not g.has_node(target):
                g.add_node(target, kind=kind, level="unknown")
            g.add_edge(node, target, rel=rel)
            edges.append({"target": target, "rel": rel, "kind": kind})

        host = host_of(node) if r.type == "url" else node
        dns = _data(r, "dns")
        for ip in dns.get("A", []):
            link(ip, "ip", "resolves_to")
        for ptr in dns.get("ptr", []):
            link(ptr.rstrip("."), "host", "ptr")
        for mx in dns.get("MX", [])[:3]:
            link(mx.split()[-1].rstrip("."), "host", "mx")

        for sub in _data(r, "crtsh").get("subdomains", [])[:15]:
            if sub != host:
                link(sub, "subdomain", "ct_cert")

        for res in _data(r, "urlscan").get("results", [])[:8]:
            link(res.get("ip"), "ip", "urlscan_observed")

        sh = _data(r, "shodan")
        for hn in sh.get("hostnames", [])[:5]:
            link(hn, "host", "shodan_hostname")
        if sh.get("asn"):
            link(str(sh["asn"]), "asn", "in_asn")

        ab = _data(r, "abuseipdb")
        if ab.get("domain"):
            link(ab["domain"], "domain", "abuse_domain")

        r.related = edges
    return g


def export_json(g: nx.Graph) -> dict:
    return {
        "nodes": [{"id": n, **g.nodes[n]} for n in g.nodes],
        "edges": [{"source": u, "target": v, **g.edges[u, v]} for u, v in g.edges],
    }


def render_pyvis(g: nx.Graph, path: str) -> None:
    from pyvis.network import Network
    # cdn_resources='remote' -> single self-contained HTML (no local lib/ folder)
    net = Network(height="720px", width="100%", bgcolor="#0f1729", font_color="#d7def0",
                  directed=False, cdn_resources="remote")
    net.barnes_hut(gravity=-8000, spring_length=120)
    for n in g.nodes:
        kind = g.nodes[n].get("kind", "host")
        size = 28 if kind == "ioc" else 14
        net.add_node(n, label=n, color=TYPE_COLOR.get(kind, "#94a3b8"), size=size,
                     title=f"{kind} · {g.nodes[n].get('level', '')}")
    for u, v in g.edges:
        net.add_edge(u, v, title=g.edges[u, v].get("rel", ""))
    net.write_html(path, notebook=False, open_browser=False)
