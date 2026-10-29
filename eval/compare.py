"""Compare 3 tools on a labelled sample set: (1) Original two-phase MLLM pipeline, (2) URL-lexical ML baseline,
(3) PhishGuard (multi-input + heuristics + search-grounded Gemini). Usage:
  python -m eval.compare --mock                       # offline smoke test (NOT reportable)
  GEMINI_API_KEY=... python -m eval.compare           # real run
  python -m eval.compare --train-csv urls.csv         # train baseline on real data (columns: url,label)"""
import argparse, os, random, sys, time
import pandas as pd
from PIL import Image
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from phishguard import analyze
from phishguard.baseline import URLBaseline
from phishguard.heuristics import extract_urls
from phishguard.email_parser import parse_email
from phishguard import original_pipeline

HERE = os.path.dirname(os.path.abspath(__file__))
S = os.path.join(HERE, "samples")


def synthetic_training(n=600, seed=0):
    """Tiny synthetic URL set to make the baseline runnable offline. Replace with real data for real results."""
    r = random.Random(seed)
    good = ["google.com", "github.com", "wikipedia.org", "nytimes.com", "stackoverflow.com", "amazon.com", "microsoft.com",
            "apple.com", "reddit.com", "bbc.co.uk", "paypal.com", "dropbox.com"]
    paths = ["", "/", "/about", "/search?q=test", "/docs/index.html", "/login", "/account/settings"]
    bad_t = ["top", "xyz", "click", "tk", "work", "icu"]
    words = ["secure", "verify", "login", "update", "account", "support", "billing"]
    urls, y = [], []
    for _ in range(n):
        if r.random() < 0.5:
            urls.append(f"https://www.{r.choice(good)}{r.choice(paths)}"); y.append(0)
        else:
            h = "-".join(r.sample(words, r.randint(2, 3)) + [r.choice(["paypa1", "amaz0n", "dropb0x", "m1crosoft", "bank"])])
            sub = ".".join(r.choice(words) for _ in range(r.randint(0, 3)))
            host = (sub + "." if sub else "") + h + "." + r.choice(bad_t)
            urls.append(f"{r.choice(['http', 'https'])}://{host}/{r.choice(words)}.php?id={r.randint(1000, 99999)}"); y.append(1)
    return urls, y


def first_url(row):
    if row.url:
        return row.url
    e = parse_email(open(os.path.join(S, row.email), "rb").read())
    return (e["urls"] or [""])[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mock", action="store_true")
    ap.add_argument("--samples", default=os.path.join(HERE, "samples.csv"))
    ap.add_argument("--train-csv")
    ap.add_argument("--out", default=os.path.join(HERE, "results"))
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--external", action="store_true", help="also run Google Safe Browsing + VirusTotal (needs keys + network)")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    if a.mock:
        from eval.mock_client import MockClient
        client = MockClient()
    else:
        from phishguard.gemini_client import GeminiClient
        client = GeminiClient()

    if a.train_csv:
        df = pd.read_csv(a.train_csv); urls, y = df["url"].tolist(), df["label"].tolist()
    else:
        urls, y = synthetic_training(); print("[warn] baseline trained on SYNTHETIC data (smoke test only)")
    base = URLBaseline().fit(urls, y)

    rows = []
    for row in pd.read_csv(a.samples, keep_default_na=False).itertuples():
        img = Image.open(os.path.join(S, row.image)) if row.image else None
        eml = open(os.path.join(S, row.email), "rb").read() if row.email else None
        etext = parse_email(eml)["text"] if eml else ""
        u = first_url(row)
        # Tool 1: original pipeline (webpage-centric: needs a URL; screenshot optional)
        t = time.time()
        try:
            o = original_pipeline.detect(client, u, img, etext) if u else {"risk_score": 0.0, "calls": 0}
        except Exception as ex:
            o = {"risk_score": 0.0, "calls": 0, "error": str(ex)}
        rows.append(dict(id=row.id, kind=row.kind, label=row.label, tool="original_2phase_mllm",
                         risk=o["risk_score"], calls=o["calls"], sec=time.time() - t))
        # Tool 2: classical ML baseline (URL only)
        t = time.time()
        rows.append(dict(id=row.id, kind=row.kind, label=row.label, tool="url_ml_baseline",
                         risk=base.predict_risk(u) if u else 0.0, calls=0, sec=time.time() - t))
        # Optional comparables: real-time URL-reputation services
        if a.external and u:
            from phishguard import external_tools as ext
            for name, fn, envk in (("google_safe_browsing", ext.safe_browsing, "GOOGLE_SAFE_BROWSING_KEY"),
                                   ("virustotal", ext.virustotal, "VIRUSTOTAL_KEY")):
                if not os.getenv(envk):
                    continue
                t = time.time()
                try:
                    r_ = fn(u)
                except Exception as ex:
                    r_ = {"risk_score": 0.0, "calls": 0}
                    print(f"[warn] {name} failed on {row.id}: {ex}")
                rows.append(dict(id=row.id, kind=row.kind, label=row.label, tool=name, risk=r_["risk_score"], calls=r_["calls"], sec=time.time() - t))
                if name == "virustotal":
                    time.sleep(16)  # free-tier rate limit
        # Tool 3: PhishGuard (all modalities)
        t = time.time()
        rep = analyze(url=row.url or None, email=eml, images=[img] if img else [], client=client)
        rows.append(dict(id=row.id, kind=row.kind, label=row.label, tool="phishguard",
                         risk=rep.risk_score, calls=rep.llm_calls, sec=time.time() - t))

    df = pd.DataFrame(rows)
    df["pred"] = (df.risk >= a.threshold).astype(int)
    df.to_csv(os.path.join(a.out, "per_sample.csv"), index=False)
    m = []
    for tool, g in df.groupby("tool"):
        tn, fp, fn, tp = confusion_matrix(g.label, g.pred, labels=[0, 1]).ravel()
        m.append(dict(tool=tool, accuracy=accuracy_score(g.label, g.pred), precision=precision_score(g.label, g.pred, zero_division=0),
                      recall=recall_score(g.label, g.pred, zero_division=0), f1=f1_score(g.label, g.pred, zero_division=0),
                      TP=tp, FP=fp, FN=fn, TN=tn, avg_latency_s=g.sec.mean(), avg_llm_calls=g.calls.mean()))
    m = pd.DataFrame(m).round(3)
    m.to_csv(os.path.join(a.out, "metrics.csv"), index=False)
    print(m.to_string(index=False))

    import matplotlib; matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    ax = m.set_index("tool")[["accuracy", "precision", "recall", "f1"]].plot.bar(figsize=(8, 4), ylim=(0, 1.05), rot=15)
    ax.set_title("Tool comparison" + (" (MOCK LLM - smoke test only)" if a.mock else ""))
    plt.tight_layout(); plt.savefig(os.path.join(a.out, "metrics.png"), dpi=150)
    by_kind = df.groupby(["tool", "kind"]).apply(lambda g: accuracy_score(g.label, g.pred), include_groups=False).unstack().round(3)
    by_kind.to_csv(os.path.join(a.out, "accuracy_by_input_type.csv")); print("\nAccuracy by input type:\n", by_kind)


if __name__ == "__main__":
    main()
