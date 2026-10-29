"""Classical-ML baseline (URL lexical features + Random Forest), representative of Sahingoz et al. 2019 / Ma et al. 2009."""
import math
import re
from urllib.parse import urlparse

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from .heuristics import KEYWORDS, SHORTENERS, SUSPICIOUS_TLDS, _is_ip, _normalize, entropy, registered_domain

FEATURES = ["len", "host_len", "dots", "hyphens", "digits_ratio", "specials", "ip", "https", "subdomains",
            "path_len", "query_len", "entropy", "keywords", "at", "bad_tld", "shortener"]


def url_features(url: str) -> list:
    u = _normalize(url)
    p = urlparse(u)
    host = (p.hostname or "").lower()
    reg = registered_domain(host)
    tld = reg.split(".")[-1]
    digits = sum(c.isdigit() for c in u)
    return [len(u), len(host), host.count("."), host.count("-"), digits / max(len(u), 1),
            len(re.findall(r"[^\w./:-]", u)), int(_is_ip(host)), int(p.scheme == "https"),
            max(0, len(host.split(".")) - len(reg.split("."))), len(p.path), len(p.query), entropy(host),
            sum(k in u.lower() for k in KEYWORDS), int("@" in p.netloc), int(tld in SUSPICIOUS_TLDS), int(reg in SHORTENERS)]


class URLBaseline:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=200, random_state=0, class_weight="balanced")

    def fit(self, urls, labels):
        self.model.fit(np.array([url_features(u) for u in urls]), labels)
        return self

    def predict_risk(self, url) -> float:
        return float(self.model.predict_proba(np.array([url_features(url)]))[0][1])

    def save(self, path):
        joblib.dump(self.model, path)

    @classmethod
    def load(cls, path):
        o = cls()
        o.model = joblib.load(path)
        return o
