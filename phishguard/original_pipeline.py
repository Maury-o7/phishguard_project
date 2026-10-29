"""Re-implementation of the two-phase pipeline described in Lee et al. (eCrime 2024) so it can be compared
fairly: phase 1 = brand identification from screenshot (+page text); phase 2 = domain verification from the
LLM's own knowledge (NO search, NO heuristics, single modality at a time). Swap in the repo's own scripts by
replacing `detect` if you prefer exact numbers."""
from urllib.parse import urlparse

from . import prompts
from .heuristics import registered_domain


def detect(client, url, image=None, text="") -> dict:
    host = urlparse(url if "://" in url else "http://" + url).hostname or ""
    dom = registered_domain(host)
    d1, _ = client.generate_json(prompts.ORIG_P1.format(text=text or f"(URL: {url})"),
                                 images=[image] if image is not None else [], system=prompts.SYSTEM)
    brand = d1.get("brand")
    if not brand:
        return {"verdict": "legitimate", "risk_score": 0.1, "brand": None, "calls": 1}
    d2, _ = client.generate_json(prompts.ORIG_P2.format(brand=brand, domain=dom), system=prompts.SYSTEM)
    official = bool(d2.get("is_official"))
    return {"verdict": "legitimate" if official else "phishing", "risk_score": 0.1 if official else 0.9,
            "brand": brand, "calls": 2}
