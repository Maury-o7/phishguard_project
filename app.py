"""Streamlit UI: streamlit run app.py   (needs GEMINI_API_KEY or paste it in the sidebar)"""
import os
import streamlit as st
from PIL import Image
from phishguard import analyze

st.set_page_config(page_title="PhishGuard", page_icon="🛡️")
st.title("🛡️ PhishGuard")
st.caption("Check a link, email or screenshot for phishing. Links are analysed as text only - never opened.")

with st.sidebar:
    key = st.text_input("Gemini API key", type="password", value=os.getenv("GEMINI_API_KEY", ""))
    use_llm = st.toggle("Use Gemini", value=True)
    use_search = st.toggle("Verify brand domains with Google Search", value=True)
    st.info("Privacy: with Gemini on, the content you submit is sent to Google's Gemini API. Don't submit anything you aren't allowed to share.")

url = st.text_input("Suspicious URL (optional)")
email_text = st.text_area("Paste email (raw source with headers is best)", height=160)
eml_file = st.file_uploader("...or upload a .eml file", type=["eml", "txt"])
shots = st.file_uploader("Screenshots (webpage, SMS, email)", type=["png", "jpg", "jpeg", "webp"], accept_multiple_files=True)

if st.button("Analyze", type="primary"):
    email = eml_file.read() if eml_file else (email_text.encode() if email_text.strip() else None)
    imgs = [Image.open(s) for s in shots]
    if not (url or email or imgs):
        st.warning("Provide at least one input."); st.stop()
    client = None
    if use_llm:
        try:
            from phishguard.gemini_client import GeminiClient
            client = GeminiClient(api_key=key or None)
        except Exception as ex:
            st.error(f"Gemini unavailable ({ex}); falling back to heuristics only.")
    with st.spinner("Analyzing..."):
        rep = analyze(url=url or None, email=email, images=imgs, client=client, use_search=use_search)
    icon = {"phishing": "🚨", "suspicious": "⚠️", "likely_legitimate": "✅"}[rep.verdict]
    st.subheader(f"{icon} {rep.verdict.replace('_', ' ').title()}  -  risk {rep.risk_score:.0%}")
    st.progress(min(rep.risk_score, 1.0))
    st.write(rep.explanation)
    st.warning(rep.recommendation)
    if rep.brand: st.write(f"**Brand claimed/imitated:** {rep.brand}")
    if rep.red_flags:
        st.write("**Red flags**"); [st.write(f"- {f}") for f in rep.red_flags]
    if rep.sources:
        st.write("**Search sources used to verify the domain**")
        for s in rep.sources: st.write(f"- [{s['title']}]({s['uri']})")
    with st.expander("Raw signals"): st.json(rep.to_dict())
