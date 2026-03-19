# 🔍 PDFSCAN — Malware Analysis Toolkit
### `v2.4.1 — Kali Edition`

> Real-time static analysis of malicious PDF files. Works from terminal, browser, or both.  
> Built for SOC analysts, incident responders, and cybersecurity students.

---

![Python 3.8+](https://img.shields.io/badge/Python-3.8+-green?style=flat-square&logo=python)
![Flask Web UI](https://img.shields.io/badge/Flask-Web%20UI-blue?style=flat-square&logo=flask)
![Static Analysis](https://img.shields.io/badge/🔍-Static%20Analysis-yellow?style=flat-square)
![Kali Linux](https://img.shields.io/badge/⚡-Kali%20Linux-red?style=flat-square)
![7-Step Pipeline](https://img.shields.io/badge/📄-7--Step%20Pipeline-green?style=flat-square)
![Auto Reports](https://img.shields.io/badge/📊-Auto%20Reports-blue?style=flat-square)

[![Download ZIP](https://img.shields.io/badge/⬇-Download%20ZIP-00ff9d?style=for-the-badge)](https://github.com)
[![Deploy Free](https://img.shields.io/badge/🚀-Deploy%20Free-555?style=for-the-badge)](https://railway.app)
[![VirusTotal](https://img.shields.io/badge/🔗-VirusTotal-555?style=for-the-badge)](https://www.virustotal.com)

---

## 💻 Terminal Demo

```
┌──(kali㉿kali)-[~/pdf_webapp]
└─$ python3 pdf_analyzer.py suspicious.pdf --report --json

╔══════════════════════════════════════════════════════════╗
║        PDF Malware Analysis Toolkit — Kali Edition       ║
╚══════════════════════════════════════════════════════════╝

  [+] File     : suspicious.pdf
  [+] Size     : 247.3 KB
  [+] MD5      : a3f2c1d8e9b047c6a2f1e83d7c5b0924

  [CRITICAL] /JavaScript      found 3x  — JavaScript action
  [CRITICAL] /OpenAction      found 1x  — Executes on document open
  [HIGH    ] eval             found 2x  — Code execution
  [HIGH    ] unescape         found 1x  — Heap spray technique

  [CRITICAL] obj 5 — JS Action — JavaScript, eval(), unescape()
  [URL     ] http://malicious-invoice.ru/payload.exe
  [IP      ] 185.220.101.47

  ──────────────────────────────────────
  RISK SCORE : 82/100  [HIGH RISK]
  VERDICT    : IMMEDIATE ACTION REQUIRED
  ──────────────────────────────────────

  [+] TXT report  : reports/suspicious_20250319_143022_report.txt
  [+] JSON report : reports/suspicious_20250319_143022_report.json

✓ Analysis complete.
```

---

## ✨ Features — What It Does

| Feature | Description |
|---|---|
| 🔍 **Static Analysis** | Parses raw PDF binary structure — no execution, no sandbox needed. Safe to run on any machine. |
| 📜 **JS Extraction** | Extracts embedded JavaScript, decodes fromCharCode chains, detects `eval()`, `unescape()`, heap spray patterns. |
| 🎯 **IOC Extractor** | Pulls URLs, IPs, email addresses, embedded filenames and executable references from every PDF object. |
| ⚖️ **Risk Scoring** | Weighted scoring engine assigns 0–100 severity score based on all detected artifacts and keyword hits. |
| 📊 **Auto Reports** | Saves TXT + JSON reports automatically. Download from browser or from the `reports/` folder in terminal. |
| 👁️ **Watch Mode** | Monitor a folder and auto-analyse every new PDF dropped in — perfect for email attachment scanning. |

---

## ⚙️ 7-Step Analysis Engine

**`1` — Load PDF + Compute Hashes**  
Validates PDF header, reads binary, computes MD5 / SHA-1 / SHA-256.  
`All modes`

**`2` — Metadata Extraction**  
Reads Author, Creator, Producer, CreationDate, ModDate. Flags anomalies like missing author or post-creation edits.  
`Info dictionary`

**`3` — Keyword-Based Detection**  
Scans binary for 16 suspicious keywords: `/JavaScript`, `/OpenAction`, `/EmbeddedFile`, `/Launch`, `eval`, `unescape`, `fromCharCode`, and more.  
`pdfid logic`

**`4` — Object Enumeration + Deep Parsing**  
Finds all PDF objects, decompresses FlateDecode streams with zlib, re-scans decompressed content for hidden indicators.  
`pdf-parser logic`

**`5` — JavaScript Analysis**  
Extracts JS from direct strings and hex streams. Decodes fromCharCode arrays. Detects obfuscation patterns and embedded URLs.  
`12 pattern detectors`

**`6` — IOC Extraction**  
Regex-based extraction of URLs, IPs, email addresses, embedded executable filenames, and URI actions.  
`Network indicators`

**`7` — Risk Score + Report Generation**  
Weighted scoring 0–100. Auto-saves TXT and JSON reports to `reports/` folder with timestamp in filename.  
`SOC-ready output`

---

## 🚀 3 Ways to Use It

### ⚡ Local Mode
Pure terminal. No server, no internet. Runs the full 7-step engine locally on Kali.

```bash
python3 pdf_analyzer.py file.pdf
python3 pdf_analyzer.py file.pdf --report
python3 pdf_analyzer.py file.pdf --report --json
```

### 🌐 Server Mode
Send file from terminal to running web server. Auto-fallback to local if server is down.

```bash
python3 pdf_analyzer.py file.pdf --server
python3 pdf_analyzer.py file.pdf --server --url https://your-app.railway.app --report
```

### 👁 Watch Mode
Monitor a folder. Auto-analyses every new PDF dropped in. Great for email attachments.

```bash
python3 pdf_analyzer.py --watch ~/Downloads --report
python3 pdf_analyzer.py --watch ~/Desktop --server --report
```

### 🖥 Web UI Mode
Upload PDF from browser. Full results rendered live. Reports auto-saved server-side + downloadable.

```bash
python3 app.py
# → open http://localhost:5000
# → upload PDF → view + download report
```

---

## 🛠 Installation on Kali

All dependencies are standard Python stdlib except Flask (needed only for web mode). The CLI works with zero external packages.

```bash
# 1. Unzip and enter folder
unzip pdf_webapp_final.zip && cd pdf_webapp

# 2. Install web dependencies (CLI works without these)
pip3 install flask werkzeug gunicorn --break-system-packages

# 3. Optional — install real Kali tools for deeper analysis
sudo apt install qpdf binutils -y
wget https://didierstevens.com/files/software/pdfid_v0_2_8.zip
unzip pdfid_v0_2_8.zip

# 4. Run (pick your mode)
python3 pdf_analyzer.py suspicious.pdf --report   # terminal only
python3 app.py                                     # start web server
```

---

## 📊 Report Formats

| Mode | TXT Report | JSON Report | Terminal Output | Web Download | Saved to |
|---|---|---|---|---|---|
| Local CLI | ✅ `--report` | ✅ `--json` | ✅ always | — | `reports/` |
| Server CLI | ✅ `--report` | ✅ `--json` | ✅ always | — | `reports/` |
| Web Upload | ✅ auto | ✅ auto | — | ✅ button | `reports/` |
| Watch Mode | ✅ `--report` | ✅ `--json` | ✅ always | — | `reports/` |

**Report filename format:**
```
reports/
  suspicious_20250319_143022_report.txt    # human-readable
  suspicious_20250319_143022_report.json   # machine-readable / SIEM ingest
```

---

## 📁 Project Files

```
pdf_webapp/
├── pdf_analyzer.py              ← CLI engine (works standalone)
├── app.py                       ← Flask web server
├── requirements.txt             ← flask, werkzeug, gunicorn
├── Procfile                     ← for Railway / Render deploy
├── templates/
│   └── index.html               ← live analysis web UI
├── static/
│   └── pdf_malware_toolkit.html ← original demo toolkit (/toolkit)
└── reports/                     ← auto-created, all reports saved here
    ├── sample_20250319_report.txt
    └── sample_20250319_report.json
```

---

## ☁️ Deploy for Free

Push to GitHub first, then deploy to any of these platforms in under 5 minutes.

```bash
# Push to GitHub — Kali terminal
sudo apt install gh -y
gh auth login
cd pdf_webapp
git init && git add . && git commit -m "PDFScan Toolkit"
gh repo create pdfscan-toolkit --public --push --source=.
```

| Platform | Cost | Notes |
|---|---|---|
| 🚂 [**Railway**](https://railway.app) | FREE | Fastest. Auto-detects Procfile. 500 hrs/month free. Deploy in 2 clicks. |
| 🎨 [**Render**](https://render.com) | FREE | Always-on (sleeps 15min). Connect GitHub repo, set start command, done. |
| 🐍 [**PythonAnywhere**](https://www.pythonanywhere.com) | FREE FOREVER | No sleep. Upload files directly. No GitHub needed. Best for always-on. |
| 🤗 [**HuggingFace Spaces**](https://huggingface.co/spaces) | FREE | Good for project demos. Docker-based. Great for sharing with classmates. |

```bash
# After deploy — use CLI against live server
python3 pdf_analyzer.py suspicious.pdf \
  --server --url https://pdfscan-xxxx.up.railway.app \
  --report --json
```

---

## 🔧 Tools & Technologies

| Tool | Role |
|---|---|
| 🐍 **Python 3** | Core engine. Uses only stdlib (`re`, `zlib`, `hashlib`, `http.client`) — no third-party deps for CLI. |
| 🌶 **Flask** | Lightweight web server exposing `/api/analyze` POST endpoint. Web UI served via Jinja2 templates. |
| 🔬 **pdfid / pdf-parser** | Didier Stevens tools auto-detected and invoked if present in the same directory. |
| 🗜 **QPDF + Strings** | `qpdf` decompresses object streams. GNU `strings` extracts printable content for pattern matching. |
| 🛡 **VirusTotal** | File hashes displayed for manual submission. Direct link to VirusTotal upload built into the web UI. |
| 📈 **Chart.js** | Object type distribution charts and IOC breakdown doughnut charts in the web UI dashboard. |

---

## 🔗 Links

- [GitHub](https://github.com)
- [Deploy on Railway](https://railway.app)
- [VirusTotal](https://www.virustotal.com)
- [Didier Stevens Tools](https://didierstevens.com)

---

> ⚠️ *For educational and authorized security research purposes only.*
