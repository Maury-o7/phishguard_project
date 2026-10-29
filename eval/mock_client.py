"""OFFLINE STAND-IN for Gemini, only to smoke-test the harness without an API key. Its outputs are NOT
evidence about real LLM performance - never report numbers produced with --mock."""
import re
from phishguard.heuristics import BRANDS, registered_domain


class MockClient:
    def generate_json(self, prompt, images=(), search=False, system=None):
        brand = None
        for im in images:
            brand = getattr(im, "info", {}).get("brand") or brand
        low = prompt.lower()
        brand = brand or next((b for b in BRANDS if b in low.split("<<<untrusted>>>")[-1]), None)
        if "brand under test" in low or "webpage url domain" in low:
            b = re.search(r'brand(?: under test)?: "([^"]+)"', prompt, re.I).group(1).lower()
            off = BRANDS.get(b, [])
            if "webpage url domain" in low:
                dom = re.search(r'domain: "([^"]+)"', prompt).group(1)
                return {"is_official": dom in off, "official_domains": off}, []
            doms = re.search(r"Domains: (.*)", prompt).group(1).split(", ")
            return {"per_domain": {d.strip(): ("official" if d.strip() in off else "not_official") for d in doms}}, \
                   [{"title": "mock", "uri": "https://example.invalid"}]
        urgent = any(k in low for k in ("urgent", "suspend", "verify", "password", "login"))
        return {"brand": brand, "brand_confidence": 0.8 if brand else 0.0, "claimed_domain_candidates": [],
                "red_flags": ["urgent/credential language"] if urgent else [], "llm_risk": 0.6 if (brand and urgent) else 0.15,
                "verdict": "suspicious" if urgent else "legitimate", "explanation": "MOCK response"}, []
