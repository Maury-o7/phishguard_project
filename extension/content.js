// Scores every link on the page via the local PhishGuard server and marks risky ones; warns before clicking a likely-phishing link.
const API = "http://127.0.0.1:8000/api/links";
const seen = new WeakSet();
async function scan() {
  const links = [...document.querySelectorAll("a[href^='http']")].filter(a => !seen.has(a)).slice(0, 150);
  if (!links.length) return;
  links.forEach(a => seen.add(a));
  try {
    const r = await fetch(API, {method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({links: links.map(a => ({href: a.href, text: a.innerText.slice(0, 200)}))})});
    const {results} = await r.json();
    results.forEach((res, i) => {
      const a = links[i];
      if (res.score >= 0.4) {
        a.style.outline = `2px solid ${res.score >= 0.7 ? "#c62828" : "#c27a00"}`;
        a.title = `PhishGuard: ${Math.round(res.score * 100)}% risk - ${res.reasons.join("; ")}`;
        if (res.score >= 0.7) a.addEventListener("click", e => {
          if (!confirm(`PhishGuard: this link looks like phishing (${res.reasons.join("; ")}).\nOpen anyway?`)) { e.preventDefault(); e.stopPropagation(); }
        }, true);
      }
    });
  } catch (e) { /* server not running: stay silent */ }
}
let t; new MutationObserver(() => { clearTimeout(t); t = setTimeout(scan, 700); }).observe(document.body, {childList: true, subtree: true});
scan();
