Final Project Student Runbook — Secure RAG & Safe Agent
=======================================================
> Author : Badr TAJINI - LLM Cybersecurity - ECE 2025/2026

This starter contains **both** tracks. Pick both and satisfy the deliverables + CI gates.

---

## 0. Prereqs
- Python 3.9+
- Node.js 18+ (for promptfoo)
- Gemini API key (`.env`)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # set GEMINI_API_KEY and optional MODEL_ID
npm i -g promptfoo@latest
```

---

## 1. Run locally

```bash
# RAG mode
python -m src.app --track rag --question "What is LLM01?"
# Agent mode
python -m src.app --track agent --question "Add 12 and 30; cite the doc id"
```

Both modes share guards and logging under `src/common/`.

---

## 2. Eval + metrics

```bash
promptfoo eval -c promptfooconfig.yaml -o reports/report.html -o reports/results.json
python tools/metrics.py reports/results.json reports/metrics.csv
```

Adjust `promptfooconfig.yaml` (add attacks/questions) and re-run metrics until CI gates (JSON ≥0.95, safety ≥0.85, citations ≥0.80 for RAG) pass.

---

## 3. Automated tests

```bash
python -m unittest discover tests    # or make w05-day from repo root
```

Tests mock Gemini responses and ensure `src.app`, `src/rag/app.py`, and `src/agent/app.py` enforce guards + schema. CI (`.github/workflows/ci.yml`) runs promptfoo+metrics; `.github/workflows/final-project-tests.yml` runs the unit tests.

---

## 4. Publish changes

```bash
git status -sb
git add src/ config/ promptfooconfig.yaml tools/metrics.py reports/*.json reports/metrics.csv README.md README-student.md
# include your replay logs + report in reports/
git commit -m "Final project: tuned rag guardrails and metrics"
git push
```

Deliverables checklist:
- ✅ Unified codebase with both tracks complete
- ✅ `logs.jsonl` replay
- ✅ `reports/report.html`, `reports/results.json`, `reports/metrics.csv`
- ✅ Promptfoo + metrics thresholds met in CI
- ✅ 3–5 page report (threat model, design, eval results, failures/fixes, OWASP/ATLAS mapping)

Good luck finishing strong!
