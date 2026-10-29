# PhishGuard - multi-input phishing analysis (extension of Multimodal_LLM_Phishing_Detection)

Accepts **URLs, emails (.eml / pasted) and screenshots**, runs deterministic heuristics, then Gemini:
1. multimodal brand identification + red flags, 2. **Google-Search-grounded** domain-ownership verification,
3. score fusion -> verdict, red flags, cited sources, recommended action. Links are never opened.

## Setup
    pip install -r requirements.txt
    export GEMINI_API_KEY=...        # https://aistudio.google.com/apikey
    export GEMINI_MODEL=gemini-2.5-flash   # optional; change if the model name is retired

## Use
    streamlit run app.py                                   # upload UI
    python -m phishguard.cli --url "http://paypa1-login.top" --image shot.png
    python -m phishguard.cli --email eval/samples/e_p1.eml --no-llm   # heuristics only, no key

## Real-time web app + browser extension
    GEMINI_API_KEY=... python server.py          # http://127.0.0.1:8000 (localhost only)
- Type/paste a link or email: instant heuristic score on every keystroke (`/api/quick`); after a pause, a deep Gemini + Google Search analysis runs (`/api/analyze`, cached). Drop or Ctrl+V screenshots.
- `extension/`: Chrome/Edge -> chrome://extensions -> Developer mode -> Load unpacked. Scores every link on every page (incl. webmail) through the local server, outlines risky links, and asks before you click a likely-phishing one. Keep the server running.

## Compare tools (milestone section 1)
Optional real-time comparables: `export GOOGLE_SAFE_BROWSING_KEY=... VIRUSTOTAL_KEY=...` then `python -m eval.compare --external`.
(VirusTotal submits unseen URLs only if you opt in in code; free tier is rate limited.)

## Compare 3 tools (milestone section 1)
    python eval/make_samples.py                 # synthetic demo set (smoke test only)
    python -m eval.compare --mock               # offline harness check - NOT reportable numbers
    python -m eval.compare                      # real Gemini run -> eval/results/{metrics.csv,metrics.png,...}
    python -m eval.compare --samples my.csv --train-csv urls.csv   # real data (baseline cols: url,label)

For real results use the repo's `data/benign` + `data/phishing` (screenshots + HTML text), PhishTank/OpenPhish URLs
and an email corpus (e.g. Nazario). `phishguard/original_pipeline.py` re-implements the paper's two-phase pipeline;
replace `detect()` with a call into the repo's own scripts for exact reproduction.

## Layout
phishguard/{heuristics,email_parser,gemini_client,prompts,analyzer,original_pipeline,baseline,cli}.py - app.py - eval/ - tests/
