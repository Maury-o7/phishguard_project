"""Parse .eml / pasted email text and derive phishing signals (headers, links, language, AI-prompt-injection)."""
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser

from .heuristics import BRANDS, extract_urls, registered_domain

URGENCY = ["urgent", "immediately", "within 24 hours", "account suspended", "will be suspended", "final notice",
           "act now", "verify your", "limited time", "your account has been", "unusual activity", "confirm your identity"]
CREDS = ["password", "social security", "ssn", "credit card", "card number", "pin", "one-time code", "otp", "login credentials"]
INJECTION = ["ignore previous instructions", "ignore all previous", "you are an ai", "mark this as safe",
             "classify this as legitimate", "classify as safe", "system prompt", "do not flag", "this email is safe",
             "disregard your instructions"]
RISKY_EXT = (".html", ".htm", ".exe", ".scr", ".iso", ".zip", ".docm", ".xlsm", ".js", ".lnk", ".img")


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.text, self._href, self._buf = [], [], None, []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href, self._buf = dict(attrs).get("href"), []

    def handle_endtag(self, tag):
        if tag == "a" and self._href:
            self.links.append((self._href, "".join(self._buf).strip()))
            self._href = None

    def handle_data(self, data):
        self.text.append(data)
        if self._href is not None:
            self._buf.append(data)


def _domain_of(addr: str) -> str:
    return registered_domain(addr.split("@")[-1]) if "@" in addr else ""


def parse_email(raw) -> dict:
    data = raw if isinstance(raw, bytes) else raw.encode("utf-8", "ignore")
    msg = BytesParser(policy=policy.default).parsebytes(data)
    has_headers = bool(msg["From"] or msg["Subject"])
    body_plain, body_html, attachments = "", "", []
    if has_headers:
        for part in msg.walk():
            ctype, fname = part.get_content_type(), part.get_filename()
            if fname:
                attachments.append(fname)
            elif ctype == "text/plain":
                body_plain += part.get_content()
            elif ctype == "text/html":
                body_html += part.get_content()
    else:
        body_plain = data.decode("utf-8", "ignore")
    lp = _LinkParser()
    if body_html:
        lp.feed(body_html)
    text = body_plain or " ".join(lp.text)
    name, addr = parseaddr(str(msg["From"] or ""))
    return {
        "subject": str(msg["Subject"] or ""), "from_name": name, "from_addr": addr,
        "reply_to": parseaddr(str(msg["Reply-To"] or ""))[1],
        "return_path": parseaddr(str(msg["Return-Path"] or ""))[1],
        "auth": (str(msg["Authentication-Results"] or "") + " " + str(msg["Received-SPF"] or "")).lower(),
        "text": text.strip(), "html_links": lp.links, "attachments": attachments,
        "urls": list(dict.fromkeys([h for h, _ in lp.links if h.startswith("http")] + extract_urls(text))),
    }


def email_signals(e: dict) -> list:
    sig = []
    add = lambda n, w, d="": sig.append((n, w, d))
    fdom = _domain_of(e["from_addr"])
    if e["reply_to"] and _domain_of(e["reply_to"]) != fdom:
        add("reply_to_mismatch", 0.20, f"{fdom} vs {_domain_of(e['reply_to'])}")
    if e["return_path"] and _domain_of(e["return_path"]) != fdom:
        add("return_path_mismatch", 0.10)
    for proto in ("spf", "dkim", "dmarc"):
        if re.search(rf"{proto}=(fail|softfail|none|permerror)", e["auth"]):
            add(f"{proto}_failed", 0.25, "from Authentication-Results/Received-SPF")
    disp = (e["from_name"] or "").lower().replace(" ", "")
    for brand, official in BRANDS.items():
        if brand in disp and fdom and fdom not in official:
            add("display_name_brand_spoof", 0.40, f"name mentions {brand}, sender domain is {fdom}")
            break
    for href, shown in e["html_links"]:
        m = re.search(r"(?:https?://)?([\w.-]+\.[a-z]{2,})", shown.lower())
        if m and href.startswith("http"):
            hd = registered_domain(re.sub(r"^https?://", "", href).split("/")[0].split(":")[0])
            if registered_domain(m.group(1)) != hd:
                add("link_text_href_mismatch", 0.35, f"shows {m.group(1)} -> goes to {hd}")
                break
    low = (e["subject"] + " " + e["text"]).lower()
    u = [k for k in URGENCY if k in low]
    if u:
        add("urgency_language", min(0.07 * len(u) + 0.05, 0.2), "; ".join(u[:3]))
    c = [k for k in CREDS if re.search(rf"\b{re.escape(k)}\b", low)]
    if c:
        add("credential_request", 0.20, "; ".join(c[:3]))
    inj = [k for k in INJECTION if k in low]
    if inj:
        add("ai_prompt_injection_attempt", 0.35, "; ".join(inj))
    risky = [a for a in e["attachments"] if a.lower().endswith(RISKY_EXT)]
    if risky:
        add("risky_attachment", 0.20, ", ".join(risky))
    return sig


def noisy_or(weights):
    p = 1.0
    for w in weights:
        p *= (1 - w)
    return round(1 - p, 3)
