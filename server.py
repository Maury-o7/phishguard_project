"""Real-time PhishGuard server (stdlib only). Run:  GEMINI_API_KEY=... python server.py  -> http://127.0.0.1:8000
  POST /api/quick   {"text": "...pasted url/email..."}          instant heuristics (call on every keystroke)
  POST /api/analyze {"url","email","images":[b64..],"search":true}  full Gemini analysis (cached, debounced by the UI)
  POST /api/links   {"links":[{"href","text"}]}                  batch scores for the browser extension
Binds to localhost only. The API key stays on the server."""
import base64, hashlib, io, json, os, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from PIL import Image
from phishguard import analyze
from phishguard.email_parser import noisy_or
from phishguard.heuristics import analyze_url, extract_urls, registered_domain
import re

ROOT = os.path.dirname(os.path.abspath(__file__))
MAX_BODY = 15_000_000
_client, _client_err = None, None
_cache, _lock, _hits = {}, threading.Lock(), {}


def get_client():
    global _client, _client_err
    if _client is None and _client_err is None:
        try:
            from phishguard.gemini_client import GeminiClient
            _client = GeminiClient()
        except Exception as ex:
            _client_err = str(ex)
    return _client


def rate_ok(ip, limit=30, window=60):
    now = time.time()
    with _lock:
        h = [t for t in _hits.get(ip, []) if now - t < window]
        h.append(now); _hits[ip] = h
        return len(h) <= limit


def quick(text):
    """Instant, offline: classify whatever is in the box (email-looking text or bare URL)."""
    text = (text or "").strip()
    if not text:
        return {"risk_score": 0, "verdict": "likely_legitimate", "red_flags": [], "mode": "empty"}
    is_email = bool(re.search(r"^(from|subject|reply-to):", text, re.I | re.M)) or "\n" in text or len(text) > 200
    rep = analyze(email=text.encode()) if is_email else analyze(url=text)
    d = rep.to_dict(); d.pop("signals", None); d["mode"] = "heuristic"
    return d


def link_scores(links):
    out = []
    for l in links[:200]:
        href, shown = l.get("href", ""), l.get("text", "")
        r = analyze_url(href)
        w = [s[1] for s in r["signals"]]; why = [s[0] for s in r["signals"]]
        m = re.search(r"(?:https?://)?([\w-]+(?:\.[\w-]+)+)", shown.lower())
        if m and registered_domain(m.group(1)) != r["domain"]:
            w.append(0.35); why.append(f"text shows {m.group(1)} but goes to {r['domain']}")
        out.append({"href": href, "score": noisy_or(w), "reasons": sorted(why, key=lambda x: "text shows" not in x)[:4]})
    return out


class H(BaseHTTPRequestHandler):
    def _send(self, code, obj, ctype="application/json"):
        body = obj if isinstance(obj, bytes) else json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers(); self.wfile.write(body)

    def do_OPTIONS(self): self._send(204, b"")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, open(os.path.join(ROOT, "static", "index.html"), "rb").read(), "text/html; charset=utf-8")
        elif self.path == "/api/status":
            self._send(200, {"gemini": get_client() is not None, "error": _client_err})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if not rate_ok(self.client_address[0], 600 if self.path != "/api/analyze" else 20):
            return self._send(429, {"error": "rate limit"})
        n = int(self.headers.get("Content-Length", 0))
        if n > MAX_BODY:
            return self._send(413, {"error": "too large"})
        try:
            data = json.loads(self.rfile.read(n) or b"{}")
            if self.path == "/api/quick":
                return self._send(200, quick(data.get("text", "")))
            if self.path == "/api/links":
                return self._send(200, {"results": link_scores(data.get("links", []))})
            if self.path == "/api/analyze":
                imgs = [Image.open(io.BytesIO(base64.b64decode(b))).convert("RGB") for b in data.get("images", [])[:4]]
                email = (data.get("email") or "").encode() or None
                url = data.get("url") or None
                key = hashlib.sha256(json.dumps([url, email and email.decode(), data.get("images", []), data.get("search", True)]).encode()).hexdigest()
                if key in _cache:
                    return self._send(200, _cache[key])
                client = get_client()
                rep = analyze(url=url, email=email, images=imgs, client=client, use_search=data.get("search", True))
                d = rep.to_dict(); d.pop("signals", None)
                d["mode"] = "gemini" if client else "heuristic"
                if not client:
                    d["note"] = "Gemini not configured (" + (_client_err or "") + "): heuristics only."
                _cache[key] = d
                return self._send(200, d)
            self._send(404, {"error": "not found"})
        except Exception as ex:
            self._send(500, {"error": str(ex)[:300]})

    def log_message(self, *a): pass


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    print(f"PhishGuard on http://127.0.0.1:{port}  (Gemini: {'on' if get_client() else 'off - ' + str(_client_err)})")
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
