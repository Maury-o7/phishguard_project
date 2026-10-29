"""PhishGuard: multi-input (URL / email / screenshot) phishing analysis with Gemini + search grounding."""
from .analyzer import analyze, Report
__all__ = ["analyze", "Report"]
