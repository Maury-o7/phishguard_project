"""Orchestrates heuristics + Gemini (multimodal brand ID -> search-grounded domain verification) + score fusion."""
from dataclasses import dataclass, field

from . import prompts
from .email_parser import email_signals, noisy_or, parse_email, _domain_of
from .heuristics import analyze_url, registered_domain


@dataclass
class Report:
    verdict: str = "unknown"
    risk_score: float = 0.0
    heuristic_score: float = 0.0
    llm_risk: float | None = None
    brand: str | None = None
    domain_check: dict = field(default_factory=dict)
    red_flags: list = field(default_factory=list)
    signals: list = field(default_factory=list)
    sources: list = field(default_factory=list)
    explanation: str = ""
    recommendation: str = ""
    llm_calls: int = 0

    def to_dict(self):
        return self.__dict__.copy()


def _verdict(r):
    return "phishing" if r >= 0.70 else "suspicious" if r >= 0.40 else "likely_legitimate"


RECOMMEND = {
    "phishing": "Do NOT click links, open attachments or reply. Report it (e.g. reportphishing@apwg.org / your IT team) and delete it. "
                "If you already entered credentials, change that password and enable MFA immediately.",
    "suspicious": "Treat with caution. Do not use the provided links - go to the organisation's site by typing the address yourself "
                  "or via its official app, and confirm with the sender through a separate channel.",
    "likely_legitimate": "No strong phishing indicators found, but no tool is perfect. Still avoid entering credentials via links in messages.",
}


def analyze(url=None, email=None, images=(), client=None, use_search=True) -> Report:
    """url: str | email: bytes/str (.eml or pasted text) | images: list of PIL.Image | client: GeminiClient or None."""
    rep = Report()
    sigs, urls, domains = [], [], set()
    artifacts = []

    if url:
        urls.append(url)
        artifacts.append(f"URL: {url}")
    if email:
        e = parse_email(email)
        sigs += [("email:" + n, w, d) for n, w, d in email_signals(e)]
        urls += [u for u in e["urls"] if u not in urls]
        if _domain_of(e["from_addr"]):
            domains.add(_domain_of(e["from_addr"]))
        artifacts.append(f"EMAIL From: {e['from_name']} <{e['from_addr']}> | Reply-To: {e['reply_to']} | Subject: {e['subject']}\n"
                         f"Attachments: {e['attachments']}\nBody:\n{e['text'][:4000]}\nLinks: {e['html_links'][:15] or e['urls'][:15]}")

    url_results = [analyze_url(u) for u in urls[:20]]
    for r in url_results:
        sigs += [(f"url[{r['domain']}]:{n}", w, d) for n, w, d in r["signals"]]
        if r["domain"]:
            domains.add(r["domain"])
    # Per-source maxima so many benign links don't dilute one malicious link
    url_scores = [r["score"] for r in url_results]
    email_score = noisy_or([w for n, w, _ in sigs if n.startswith("email:")])
    rep.heuristic_score = round(max([email_score] + url_scores + [noisy_or(sorted(url_scores + [email_score])[-2:])]), 3)
    rep.signals = sigs
    rep.red_flags = [f"{n} ({d})" if d else n for n, w, d in sorted(sigs, key=lambda x: -x[1])[:8]]
    heur_brands = [r["impersonated_brand"] for r in url_results if r["impersonated_brand"]]

    risk = rep.heuristic_score
    mismatch = False
    if client and (artifacts or images):
        data, _ = client.generate_json(prompts.PHASE1.format(artifacts="\n\n".join(artifacts) or "(screenshot only)"),
                                       images=images, system=prompts.SYSTEM)
        rep.llm_calls += 1
        rep.llm_risk = float(data.get("llm_risk", 0.5) or 0.5)
        rep.brand = data.get("brand") or (heur_brands[0] if heur_brands else None)
        rep.red_flags += [f for f in data.get("red_flags", []) if f not in rep.red_flags]
        rep.explanation = data.get("explanation", "")
        candidates = sorted(domains | {registered_domain(d) for d in data.get("claimed_domain_candidates", []) if "." in d})
        if rep.brand and candidates and use_search:
            d2, src = client.generate_json(prompts.PHASE2.format(brand=rep.brand, domains=", ".join(candidates)),
                                           search=True, system=prompts.SYSTEM)
            rep.llm_calls += 1
            rep.domain_check, rep.sources = d2, src
            per = d2.get("per_domain", {}) or {}
            observed = {registered_domain(r["host"]) for r in url_results} | ({_domain_of(parse_email(email)["from_addr"])} if email else set())
            mismatch = any(per.get(d) == "not_official" for d in observed if d)
            if mismatch:
                rep.red_flags.insert(0, f"domain does not belong to claimed brand '{rep.brand}' (verified via Google Search)")
        llm_risk = rep.llm_risk
        if mismatch:
            llm_risk = max(llm_risk, 0.85)
        risk = 0.35 * rep.heuristic_score + 0.65 * llm_risk
        if rep.heuristic_score >= 0.8 or mismatch:
            risk = max(risk, 0.80)
    rep.risk_score = round(risk, 3)
    rep.verdict = _verdict(rep.risk_score)
    rep.recommendation = RECOMMEND[rep.verdict]
    if not rep.explanation:
        rep.explanation = ("Heuristic-only analysis (no LLM). " + ("Signals: " + "; ".join(rep.red_flags[:4]) if rep.red_flags else "No suspicious signals."))
    return rep
