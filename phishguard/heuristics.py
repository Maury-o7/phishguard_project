"""Deterministic URL heuristics. Never fetches or opens a URL: analysis is string-only (safe by design)."""
import difflib
import ipaddress
import math
import re
from urllib.parse import urlparse

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at"}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "ga", "cf", "work",
                   "support", "rest", "fit", "cam", "icu", "buzz", "monster", "sbs"}
MULTI_SUFFIX = {"co.uk", "com.au", "co.in", "com.br", "co.jp", "org.uk", "com.sg", "co.nz", "com.mx"}
KEYWORDS = ["login", "signin", "verify", "secure", "account", "update", "confirm", "password",
            "wallet", "invoice", "billing", "suspend", "unlock", "recover"]
BRANDS = {
    "paypal": ["paypal.com"], "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"],
    "apple": ["apple.com", "icloud.com"], "google": ["google.com", "gmail.com", "youtube.com"],
    "amazon": ["amazon.com", "amazon.co.uk"], "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"], "instagram": ["instagram.com"],
    "dhl": ["dhl.com"], "fedex": ["fedex.com"], "usps": ["usps.com"], "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"], "bankofamerica": ["bankofamerica.com"],
    "docusign": ["docusign.com", "docusign.net"], "dropbox": ["dropbox.com"],
    "linkedin": ["linkedin.com"], "coinbase": ["coinbase.com"], "irs": ["irs.gov"],
}
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s", "7": "t"})


def registered_domain(host: str) -> str:
    host = host.lower().strip(".")
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _normalize(url: str) -> str:
    url = url.strip().strip("<>\"'")
    return url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url) else "http://" + url


def entropy(s: str) -> float:
    if not s:
        return 0.0
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return bool(re.fullmatch(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}", host, re.I))


def analyze_url(url: str) -> dict:
    """Return {'url', 'domain', 'signals': [(name, weight, detail)], 'score'} where score uses noisy-OR."""
    raw = url
    url = _normalize(url)
    p = urlparse(url)
    host = (p.hostname or "").lower()
    reg = registered_domain(host)
    label = reg.split(".")[0] if reg else ""
    tld = reg.split(".")[-1] if "." in reg else ""
    sig = []

    def add(name, w, detail=""):
        sig.append((name, w, detail))

    if _is_ip(host):
        add("ip_address_host", 0.35, host)
    if "xn--" in host:
        add("punycode_domain", 0.25, host)
    if any(ord(c) > 127 for c in host):
        add("non_ascii_domain", 0.25, host)
    if "@" in (p.netloc or ""):
        add("at_symbol_in_authority", 0.25, "credentials-style trick hides real host")
    if reg in SHORTENERS:
        add("url_shortener", 0.15, reg)
    if tld in SUSPICIOUS_TLDS:
        add("suspicious_tld", 0.15, "." + tld)
    sub_labels = max(0, len(host.split(".")) - len(reg.split(".")))
    if sub_labels >= 3:
        add("many_subdomains", 0.15, f"{sub_labels} subdomain labels")
    if host.count("-") >= 3:
        add("many_hyphens", 0.10, host)
    if len(raw) > 100:
        add("long_url", 0.05, f"{len(raw)} chars")
    if p.scheme == "http":
        add("no_https", 0.10)
    if p.port and p.port not in (80, 443):
        add("nonstandard_port", 0.05, str(p.port))
    kw = [k for k in KEYWORDS if k in (host + p.path).lower()]
    if kw:
        add("sensitive_keywords", min(0.05 * len(kw) + 0.05, 0.15), ",".join(kw))
    if len(re.findall(r"%[0-9a-fA-F]{2}", url)) >= 5:
        add("heavy_percent_encoding", 0.05)

    # Brand impersonation (token-level, so 'pineapple.com' does not match 'apple')
    flagged_brand = None
    toks = [t for t in re.split(r"[-.]", host) if t]
    for brand, official in BRANDS.items():
        if reg in official:
            flagged_brand = None
            break
        for t in toks:
            tn = t.translate(_LEET).replace("rn", "m").replace("vv", "w")
            if t == brand or (len(brand) >= 4 and t.startswith(brand)):
                flagged_brand = flagged_brand or (brand, "brand_in_unofficial_domain", 0.40)
            elif tn == brand or (len(brand) >= 4 and tn.startswith(brand)) or \
                    (len(brand) >= 5 and difflib.SequenceMatcher(None, tn, brand).ratio() >= 0.88):
                flagged_brand = (brand, "lookalike_domain", 0.45)
        if flagged_brand:
            break
    if flagged_brand:
        add(flagged_brand[1], flagged_brand[2], f"resembles '{flagged_brand[0]}' but is {reg}")

    score = 1.0
    for _, w, _ in sig:
        score *= (1 - w)
    return {"url": raw, "domain": reg, "host": host, "signals": sig, "score": round(1 - score, 3),
            "impersonated_brand": flagged_brand[0] if flagged_brand else None}


URL_RE = re.compile(r"https?://[^\s<>\"')\]]+|www\.[^\s<>\"')\]]+", re.I)


def extract_urls(text: str) -> list:
    seen, out = set(), []
    for u in URL_RE.findall(text or ""):
        u = u.rstrip(".,;:!?")
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out
