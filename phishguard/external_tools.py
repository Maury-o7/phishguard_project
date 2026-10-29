"""Adapters for comparable real-time URL-reputation services (need network + your own API keys).
  GOOGLE_SAFE_BROWSING_KEY  -> Safe Browsing v4 threatMatches.find (v5 also exists; see developers.google.com/safe-browsing)
  VIRUSTOTAL_KEY            -> VirusTotal v3 (free tier ~4 req/min; lookups of unseen URLs SUBMIT them, making them visible to VT's community)"""
import base64, json, os, time, urllib.error, urllib.parse, urllib.request


def _req(url, data=None, headers=None):
    r = urllib.request.Request(url, data=data, headers=headers or {})
    with urllib.request.urlopen(r, timeout=20) as f:
        return json.loads(f.read() or b"{}")


def safe_browsing(url, key=None):
    key = key or os.environ["GOOGLE_SAFE_BROWSING_KEY"]
    body = {"client": {"clientId": "phishguard-eval", "clientVersion": "0.1"},
            "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                           "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}]}}
    d = _req(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}", json.dumps(body).encode(),
             {"Content-Type": "application/json"})
    return {"risk_score": 0.95 if d.get("matches") else 0.05, "calls": 1}


def virustotal(url, key=None, submit=False):
    key = key or os.environ["VIRUSTOTAL_KEY"]
    h = {"x-apikey": key}
    uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        d = _req(f"https://www.virustotal.com/api/v3/urls/{uid}", headers=h)
    except urllib.error.HTTPError as e:
        if e.code != 404 or not submit:
            return {"risk_score": 0.0, "calls": 1, "note": "not in VT database (not submitted)"}
        a = _req("https://www.virustotal.com/api/v3/urls", ("url=" + urllib.parse.quote(url)).encode(),
                 {**h, "Content-Type": "application/x-www-form-urlencoded"})
        time.sleep(15)
        d = _req(f"https://www.virustotal.com/api/v3/analyses/{a['data']['id']}", headers=h)
        stats = d["data"]["attributes"]["stats"]
    else:
        stats = d["data"]["attributes"]["last_analysis_stats"]
    bad = stats.get("malicious", 0) + stats.get("suspicious", 0)
    tot = max(sum(stats.values()), 1)
    return {"risk_score": min(1.0, bad / 3) if bad else 0.02, "calls": 1, "engines_flagged": bad, "engines_total": tot}
