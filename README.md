# PDFScan Toolkit — Deployment Guide

## Project File Structure

```
pdf_webapp/
├── app.py                          ← Flask backend (new)
├── pdf_analyzer.py                 ← Real analysis engine (CLI — unchanged)
├── requirements.txt                ← Python dependencies
├── Procfile                        ← For Railway / Render
├── templates/
│   └── index.html                  ← Live web UI (new)
└── static/
    └── pdf_malware_toolkit.html    ← Original demo toolkit
```

## How Files Connect

```
User uploads PDF
      ↓
templates/index.html  (web UI)
      ↓  POST /api/analyze
app.py  (Flask)
      ↓  imports as module
pdf_analyzer.py  (7-step engine)
      ↓
JSON result → rendered in browser
```

## Run Locally on Kali

```bash
# 1. Install dependencies
pip3 install flask werkzeug gunicorn --break-system-packages

# 2. Run the server
cd pdf_webapp
python3 app.py

# 3. Open browser
# Main live UI   → http://localhost:5000
# Original demo  → http://localhost:5000/toolkit
# Health check   → http://localhost:5000/api/health
```

---

## Deployment Link

   `https://pdf-analysis-tool.onrender.com/`

---

## Environment Variables (optional)

| Variable      | Default | Description              |
|---------------|---------|--------------------------|
| PORT          | 5000    | Server port              |
| FLASK_DEBUG   | false   | Enable debug mode        |

---

## Usage After Deploy

| URL                  | Description                          |
|----------------------|--------------------------------------|
| /                    | Live analysis UI (real PDF upload)   |
| /toolkit             | Original demo HTML toolkit           |
| /api/analyze         | POST endpoint (multipart PDF)        |
| /api/health          | Health check JSON                    |
