"""python -m phishguard.cli --url URL [--email msg.eml] [--image shot.png ...] [--no-llm] [--no-search]"""
import argparse, json
from PIL import Image
from . import analyze


def main():
    ap = argparse.ArgumentParser(description="PhishGuard: analyse a URL / email / screenshot (never opens links)")
    ap.add_argument("--url"); ap.add_argument("--email"); ap.add_argument("--image", nargs="*", default=[])
    ap.add_argument("--no-llm", action="store_true"); ap.add_argument("--no-search", action="store_true")
    a = ap.parse_args()
    client = None
    if not a.no_llm:
        from .gemini_client import GeminiClient
        client = GeminiClient()
    eml = open(a.email, "rb").read() if a.email else None
    rep = analyze(url=a.url, email=eml, images=[Image.open(p) for p in a.image], client=client, use_search=not a.no_search)
    print(json.dumps(rep.to_dict(), indent=2, default=str))


if __name__ == "__main__":
    main()
