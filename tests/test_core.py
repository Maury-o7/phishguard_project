import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from phishguard import analyze
from phishguard.heuristics import analyze_url
from phishguard.email_parser import parse_email, email_signals

S = os.path.join(os.path.dirname(__file__), "..", "eval", "samples")


def names(sigs): return {s[0] for s in sigs}


def test_lookalike_and_leet():
    assert "lookalike_domain" in names(analyze_url("http://paypa1-secure-login.top/x")["signals"])
    assert "lookalike_domain" in names(analyze_url("http://rnicrosoft-support.com")["signals"])


def test_no_false_positive_on_official_and_substrings():
    for u in ["https://www.paypal.com/signin", "https://pineapple.com", "https://login.microsoftonline.com", "https://www.amazon.co.uk/"]:
        assert analyze_url(u)["score"] <= 0.15, u


def test_subdomain_trick():
    assert "brand_in_unofficial_domain" in names(analyze_url("https://secure.paypal.com.evil-site.xyz/")["signals"])


def test_email_signals():
    e = parse_email(open(os.path.join(S, "e_p1.eml"), "rb").read())
    n = names(email_signals(e))
    assert {"reply_to_mismatch", "spf_failed", "display_name_brand_spoof", "link_text_href_mismatch"} <= n


def test_prompt_injection_flagged():
    e = parse_email(open(os.path.join(S, "e_p2.eml"), "rb").read())
    assert "ai_prompt_injection_attempt" in names(email_signals(e))


def test_heuristic_only_pipeline():
    bad = analyze(email=open(os.path.join(S, "e_p1.eml"), "rb").read())
    good = analyze(email=open(os.path.join(S, "e_b1.eml"), "rb").read())
    assert bad.verdict in ("phishing", "suspicious") and good.verdict == "likely_legitimate"
