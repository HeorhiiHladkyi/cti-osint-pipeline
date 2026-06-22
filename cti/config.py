"""Configuration — API keys read from environment / .env (no hardcoded secrets)."""
from __future__ import annotations
import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()  # loads .env from CWD if present


@dataclass
class Settings:
    virustotal_key: str = field(default_factory=lambda: os.getenv("VIRUSTOTAL_API_KEY", ""))
    abuseipdb_key: str = field(default_factory=lambda: os.getenv("ABUSEIPDB_API_KEY", ""))
    shodan_key: str = field(default_factory=lambda: os.getenv("SHODAN_API_KEY", ""))
    otx_key: str = field(default_factory=lambda: os.getenv("OTX_API_KEY", ""))
    urlscan_key: str = field(default_factory=lambda: os.getenv("URLSCAN_API_KEY", ""))
    chainabuse_key: str = field(default_factory=lambda: os.getenv("CHAINABUSE_API_KEY", ""))
    http_timeout: int = field(default_factory=lambda: int(os.getenv("HTTP_TIMEOUT", "15")))
    user_agent: str = "cti-osint-pipeline/1.0 (+coursework)"

    def key_status(self) -> dict[str, bool]:
        return {
            "virustotal": bool(self.virustotal_key),
            "abuseipdb": bool(self.abuseipdb_key),
            "shodan": bool(self.shodan_key),
            "otx": bool(self.otx_key),
            "urlscan": True,  # public search works without a key
            "wallet_rep": True,  # bundled known-bad list works keyless; Chainabuse if keyed
        }


settings = Settings()
