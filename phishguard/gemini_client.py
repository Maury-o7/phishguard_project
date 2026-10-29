"""Thin Gemini wrapper (google-genai SDK): multimodal input, JSON parsing, optional Google Search grounding."""
import json
import os
import re
import time


def parse_json(text: str) -> dict:
    text = (text or "").strip()
    text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.M).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                pass
    return {"_parse_error": True, "_raw": text[:500]}


class GeminiClient:
    def __init__(self, api_key=None, model=None):
        from google import genai  # lazy import so heuristics/baseline work without the SDK
        from google.genai import types
        key = api_key or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        if not key:
            raise RuntimeError("Set GEMINI_API_KEY (free key: https://aistudio.google.com/apikey)")
        self._types = types
        self.client = genai.Client(api_key=key)
        # Model names change over time: override with GEMINI_MODEL if this one is retired.
        self.model = model or os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

    def generate_json(self, prompt, images=(), search=False, system=None, retries=2):
        """Returns (dict, sources). With search=True, Gemini may ground on Google Search and
        `sources` lists [{'title','uri'}]. (Grounding and forced-JSON mode can't be combined, so JSON is prompted.)"""
        t = self._types
        cfg = dict(system_instruction=system, temperature=0.0)
        if search:
            cfg["tools"] = [t.Tool(google_search=t.GoogleSearch())]
        else:
            cfg["response_mime_type"] = "application/json"
        last = None
        for attempt in range(retries + 1):
            try:
                resp = self.client.models.generate_content(
                    model=self.model, contents=[prompt, *images], config=t.GenerateContentConfig(**cfg))
                return parse_json(resp.text), self._sources(resp)
            except Exception as ex:  # rate limit / transient
                last = ex
                time.sleep(2 ** attempt)
        raise RuntimeError(f"Gemini call failed: {last}")

    @staticmethod
    def _sources(resp):
        out = []
        try:
            for ch in resp.candidates[0].grounding_metadata.grounding_chunks or []:
                out.append({"title": ch.web.title, "uri": ch.web.uri})
        except Exception:
            pass
        return out
