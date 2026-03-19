"""
PDF Malware Analysis Toolkit — Flask Web Server
Imports pdf_analyzer.py as a module (CLI script stays 100% intact).

Start via terminal:
  python3 app.py
  python3 pdf_analyzer.py --start-server
  python3 pdf_analyzer.py --start-server --open-browser

Routes:
  /                 → Live analysis web UI
  /toolkit          → Original demo HTML toolkit
  /api/analyze      → POST multipart PDF → JSON result
  /api/health       → Health check
"""

from flask import Flask, request, jsonify, render_template, send_from_directory
from werkzeug.utils import secure_filename
import os, importlib.util, pathlib

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB

# ── Import pdf_analyzer.py as a module (keeps CLI file intact) ──
_here = pathlib.Path(__file__).parent
spec  = importlib.util.spec_from_file_location("pdf_analyzer", _here / "pdf_analyzer.py")
_mod  = importlib.util.module_from_spec(spec)
spec.loader.exec_module(_mod)


# ─────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Live analysis web UI — uploads real PDFs to /api/analyze"""
    return render_template("index.html")


@app.route("/toolkit")
def toolkit():
    """Original demo HTML toolkit (no upload needed — uses sample data)"""
    return send_from_directory("static", "pdf_malware_toolkit.html")


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "engine": "PDFScan v2.4.1",
                    "modes": ["local-cli", "server-cli", "watch-folder", "web-ui"]})


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    POST /api/analyze
    Body : multipart/form-data  field=file  (PDF ≤ 10 MB)
    Returns: full JSON analysis result from pdf_analyzer.py pipeline
    """
    if "file" not in request.files:
        return jsonify({"error": "No file field in request"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "No file selected"}), 400
    if not f.filename.lower().endswith(".pdf"):
        return jsonify({"error": "Only .pdf files accepted"}), 400

    raw = f.read()
    if raw[:4] != b"%PDF":
        return jsonify({"error": "Invalid PDF (bad header)"}), 400

    filename = secure_filename(f.filename)

    # ── Run the full 7-step pipeline from pdf_analyzer.py ─────
    try:
        info = _mod.load_file_from_bytes(raw, filename)
        info = _mod.extract_metadata(info)
        info = _mod.scan_keywords(info)
        info = _mod.enumerate_objects(info)
        info = _mod.extract_javascript(info)
        info = _mod.extract_iocs(info)
        info = _mod.calculate_risk(info)
    except Exception as e:
        return jsonify({"error": f"Analysis error: {str(e)}"}), 500

    # ── Save report server-side into reports/ folder ──────────
    reports_dir = _here / "reports"
    reports_dir.mkdir(exist_ok=True)
    import datetime
    ts   = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    base = filename.replace(".pdf", "")

    # TXT report
    txt_lines = build_txt_report(info)
    txt_path  = reports_dir / f"{base}_{ts}_report.txt"
    txt_path.write_text("\n".join(txt_lines))

    # JSON report
    import json as _json
    json_path = reports_dir / f"{base}_{ts}_report.json"

    # ── Build JSON-safe response ───────────────────────────────
    def safe(b, n=400):
        return b[:n].decode("utf-8", errors="replace") if isinstance(b, (bytes,bytearray)) else str(b)[:n]

    response = {
        "filename":         info["filename"],
        "timestamp":        info["timestamp"],
        "size_kb":          info["size_kb"],
        "version":          info["version"],
        "md5":              info["md5"],
        "sha1":             info["sha1"],
        "sha256":           info["sha256"],
        "metadata":         info.get("metadata", {}),
        "keyword_findings": {k: {"count":v["count"],"severity":v["severity"],"desc":v["desc"]}
                             for k,v in info.get("keyword_findings",{}).items()},
        "objects":          [{"num":o["num"],"type":o["type"],"risk":o["risk"],
                               "flags":o["flags"],"size":o["size"],
                               "preview":safe(o.get("raw",b""))}
                             for o in info.get("objects",[])],
        "js_blocks_count":  len(info.get("js_blocks",[])),
        "js_patterns":      info.get("js_patterns_found",[]),
        "js_previews":      [{"source":b["source"],"preview":safe(b.get("content",b""))}
                             for b in info.get("js_blocks",[])],
        "iocs":             [{"type":i["type"],"value":i["value"],"risk":i["risk"]}
                             for i in info.get("iocs",[])],
        "suspicious_strings": info.get("suspicious_strings",[])[:20],
        "risk_score":       info["risk_score"],
        "risk_label":       info["risk_label"],
        "tools_run":        info.get("tools_run",[]),
        "report_saved":     str(txt_path),
    }

    # Write JSON report
    json_path.write_text(_json.dumps(response, indent=2))

    return jsonify(response)



@app.route("/reports/<path:filename>")
def download_report(filename):
    """Serve a saved report file from the reports/ folder."""
    reports_dir = _here / "reports"
    return send_from_directory(str(reports_dir), filename, as_attachment=True)

# ─────────────────────────────────────────────────────────────
# Helper — build TXT report lines (shared logic)
# ─────────────────────────────────────────────────────────────
def build_txt_report(info):
    score = info["risk_score"]
    label = info["risk_label"]
    net_iocs = [i for i in info.get("iocs",[]) if i["type"] not in ("MD5","SHA1","SHA256")]
    lines = [
        "═"*62, "  PDF MALWARE ANALYSIS REPORT",
        "  PDFScan Toolkit — Kali Edition", "═"*62,
        f"  File     : {info.get('filename', info.get('path','?'))}",
        f"  Size     : {info['size_kb']} KB",
        f"  Analyzed : {info['timestamp']}",
        f"  MD5      : {info['md5']}",
        f"  SHA-1    : {info['sha1']}",
        f"  SHA-256  : {info['sha256']}",
        "", f"  RISK SCORE : {score}/100  [{label}]", "",
        "─"*62, "  METADATA", "─"*62,
    ]
    for k,v in info.get("metadata",{}).items():
        lines.append(f"  {k:<16}: {v}")
    lines += ["","─"*62,"  SUSPICIOUS KEYWORDS","─"*62]
    found = [(k,v) for k,v in info.get("keyword_findings",{}).items() if v["count"]>0]
    lines += [f"  [{v['severity'].upper():<8}] {k:<18} ({v['count']}x) — {v['desc']}" for k,v in found] or ["  None"]
    lines += ["","─"*62,f"  OBJECTS  ({len(info.get('objects',[]))} total)","─"*62]
    for o in info.get("objects",[]):
        if o["risk"] in ("critical","high","medium"):
            lines.append(f"  [{o['risk'].upper():<8}] obj {o['num']} — {o['type']} — {', '.join(o['flags']) or 'none'}")
    lines += ["","─"*62,f"  JAVASCRIPT  ({len(info.get('js_blocks',[]))} block(s))","─"*62]
    for p in info.get("js_patterns_found",[]):
        lines.append(f"  [{p['severity'].upper():<8}] {p['pattern']} ({p['count']}x block {p['block']})")
    if not info.get("js_patterns_found"): lines.append("  No suspicious JS patterns")
    lines += ["","─"*62,"  IOCs","─"*62]
    lines += [f"  [{i['risk'].upper():<8}] {i['type']:<12} {i['value']}" for i in net_iocs] or ["  None"]
    lines += ["","─"*62,"  MITIGATIONS","─"*62]
    if score>=60:
        lines += ["  [HIGH] Quarantine immediately — do not open on production systems",
                  "[HIGH] Block IOC domains/IPs at firewall and DNS",
                  "  [MED]  Disable PDF JavaScript in reader settings",
                  "  [MED]  Submit hash to VirusTotal"]
    elif score>=30:
        lines += ["  [MED] Review in sandboxed environment","  [MED] Scan with VirusTotal"]
    else:
        lines += ["  [INFO] No action required — document appears clean"]
    lines += ["","═"*62,"  Generated by PDFScan Toolkit — For SOC/IR use only","═"*62]
    return lines


# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port  = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG","false").lower() == "true"
    print(f"""
  ╔══════════════════════════════════════════════════╗
  ║      PDFScan Toolkit — Web Server                ║
  ╚══════════════════════════════════════════════════╝
  Live UI   →  http://localhost:{port}
  Demo      →  http://localhost:{port}/toolkit
  API       →  http://localhost:{port}/api/analyze
  Health    →  http://localhost:{port}/api/health
  Reports   →  ./reports/   (auto-saved on every upload)

  CLI also works in parallel:
    python3 pdf_analyzer.py file.pdf --report
    python3 pdf_analyzer.py file.pdf --server --url http://localhost:{port}
    python3 pdf_analyzer.py --watch ~/Downloads --server --report
    """)
    app.run(host="0.0.0.0", port=port, debug=debug)
