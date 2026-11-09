# Pixel_Tracking (pixel_scan)

Finds Australian organisations in sensitive sectors (IVF, telehealth, mental health, ...) whose websites fire
ad-tech tracking pixels **before** cookie consent. Output is a triage signal: a *potential issue, not a legal finding*.

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt && .venv/bin/python -m playwright install chromium
export BRAVE_API_KEY=...                      # discover only
.venv/bin/python pixel_scan.py discover       # -> targets.csv
.venv/bin/python pixel_scan.py scan --limit 5 --concurrency 2 [--consent-test] [--screenshots]
.venv/bin/python pixel_scan.py report         # rebuild report.html from results.json
.venv/bin/pip install -r requirements-dev.txt && .venv/bin/python -m pytest -q
```

Honours robots.txt unless `--ignore-robots`. `--consent-test` clicks Accept/Reject on banners (never submits forms).
