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

## FREE Deployment Options

### Option A — Railway (Recommended · Easiest)

1. Go to https://railway.app  →  Sign up free (GitHub login)
2. Click "New Project" → "Deploy from GitHub repo"
3. Upload this folder to a GitHub repo first:
   ```bash
   git init
   git add .
   git commit -m "PDFScan Toolkit"
   gh repo create pdfscan --public --push --source=.
   ```
4. Railway auto-detects Procfile → click Deploy
5. Your live URL: https://pdfscan-xxxx.up.railway.app

Free tier: 500 hours/month (enough for a project demo)

---

### Option B — Render (Also Free)

1. Go to https://render.com  →  Sign up free
2. New → Web Service → Connect GitHub repo
3. Settings:
   - Build Command : `pip install -r requirements.txt`
   - Start Command : `gunicorn app:app --bind 0.0.0.0:$PORT`
4. Click Deploy
5. Free tier spins down after 15 min inactivity (wakes on request)

---

### Option C — PythonAnywhere (Free Forever)

1. Go to https://www.pythonanywhere.com  →  Free account
2. Dashboard → Files → Upload all project files
3. Web tab → Add new web app → Flask → Python 3.10
4. Set source directory to /home/yourusername/pdf_webapp
5. WSGI config: point to app.py

Free tier: always-on, 512MB storage, pythonanywhere.com subdomain

---

### Option D — Hugging Face Spaces (Free · Good for demos)

1. Go to https://huggingface.co/spaces  →  Create Space
2. SDK: Gradio or "Static" → choose "Docker"
3. Add a Dockerfile:
   ```dockerfile
   FROM python:3.11-slim
   WORKDIR /app
   COPY . .
   RUN pip install -r requirements.txt
   EXPOSE 7860
   ENV PORT=7860
   CMD ["gunicorn","app:app","--bind","0.0.0.0:7860"]
   ```
4. Push files → Space auto-deploys

---

## Push to GitHub (required for Railway/Render)

```bash
# Install GitHub CLI on Kali
sudo apt install gh -y

# Authenticate
gh auth login

# From inside pdf_webapp folder:
git init
git add .
git commit -m "Initial: PDFScan Malware Analysis Toolkit"
gh repo create pdfscan-toolkit --public --push --source=.
```

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
