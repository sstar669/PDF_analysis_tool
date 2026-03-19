#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║        PDF Malware Analysis Toolkit — Kali Edition       ║
║        Real-time static analysis of PDF files            ║
║        Works standalone OR connected to web server       ║
╚══════════════════════════════════════════════════════════╝

── LOCAL MODE (no server needed) ────────────────────────────
  python3 pdf_analyzer.py suspicious.pdf
  python3 pdf_analyzer.py suspicious.pdf --report
  python3 pdf_analyzer.py suspicious.pdf --report --json
  python3 pdf_analyzer.py suspicious.pdf --verbose

── SERVER MODE (send to running Flask app) ──────────────────
  python3 pdf_analyzer.py suspicious.pdf --server
  python3 pdf_analyzer.py suspicious.pdf --server --url http://localhost:5000
  python3 pdf_analyzer.py suspicious.pdf --server --report
  python3 pdf_analyzer.py suspicious.pdf --server --url https://your-app.railway.app

── WATCH MODE (auto-analyse a folder) ───────────────────────
  python3 pdf_analyzer.py --watch /path/to/folder
  python3 pdf_analyzer.py --watch /path/to/folder --server
  python3 pdf_analyzer.py --watch ~/Downloads --report

── OTHER ─────────────────────────────────────────────────────
  python3 pdf_analyzer.py --install          # install dependencies
  python3 pdf_analyzer.py --start-server     # start the web server
  python3 pdf_analyzer.py --open-browser     # open web UI in browser
"""

import sys
import os
import re
import subprocess
import hashlib
import struct
import zlib
import json
import argparse
import datetime
import time
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path

# ─────────────────────────────────────────────────────────────
# ANSI Colors
# ─────────────────────────────────────────────────────────────
R  = "\033[91m"   # Red    — critical
Y  = "\033[93m"   # Yellow — warning
G  = "\033[92m"   # Green  — safe / info
B  = "\033[94m"   # Blue   — info
C  = "\033[96m"   # Cyan   — heading
M  = "\033[95m"   # Magenta
DIM = "\033[2m"
BOLD = "\033[1m"
NC = "\033[0m"    # Reset

def banner():
    print(f"""
{C}{BOLD}╔══════════════════════════════════════════════════════════╗
║         PDF Malware Analysis Toolkit — Kali Edition      ║
║         Real-time Static PDF Analysis Engine             ║
╚══════════════════════════════════════════════════════════╝{NC}
{DIM}  Tools: pdfid · pdf-parser · qpdf · strings · built-in parser{NC}
""")

# ─────────────────────────────────────────────────────────────
# Dependency Installer
# ─────────────────────────────────────────────────────────────
def install_dependencies():
    print(f"\n{C}[*] Installing dependencies on Kali Linux...{NC}\n")
    cmds = [
        ["sudo", "apt", "update", "-y"],
        ["sudo", "apt", "install", "-y", "qpdf", "binutils"],
        ["sudo", "pip3", "install", "peepdf", "--break-system-packages"],
    ]
    tools = {
        "pdfid.py": "https://didierstevens.com/files/software/pdfid_v0_2_8.zip",
        "pdf-parser.py": "https://didierstevens.com/files/software/pdf-parser_V0_7_8.zip",
    }
    for cmd in cmds:
        print(f"  {DIM}$ {' '.join(cmd)}{NC}")
        subprocess.run(cmd, capture_output=True)

    print(f"\n{G}[+] Base packages installed.{NC}")
    print(f"{Y}[!] Manually download Didier Stevens tools:{NC}")
    for t, u in tools.items():
        print(f"    wget {u} && unzip *.zip")
    print(f"\n{G}[+] Place pdfid.py and pdf-parser.py in the same directory as this script.{NC}\n")
    sys.exit(0)

# ─────────────────────────────────────────────────────────────
# Step 1 — Load PDF & Compute Hashes
# ─────────────────────────────────────────────────────────────
def load_file(path):
    print(f"\n{C}{'─'*58}{NC}")
    print(f"{C}{BOLD}  STEP 1 — Load PDF File{NC}")
    print(f"{C}{'─'*58}{NC}")

    if not os.path.isfile(path):
        print(f"{R}[✗] File not found: {path}{NC}")
        sys.exit(1)

    with open(path, "rb") as f:
        data = f.read()

    # Verify PDF magic bytes
    if data[:4] != b"%PDF":
        print(f"{R}[✗] Not a valid PDF file (bad magic bytes){NC}")
        sys.exit(1)

    size_kb = len(data) / 1024
    md5    = hashlib.md5(data).hexdigest()
    sha1   = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()

    # PDF version from header
    try:
        version = data[:8].decode("ascii", errors="ignore").strip()
    except:
        version = "unknown"

    print(f"  {G}[+]{NC} File     : {BOLD}{path}{NC}")
    print(f"  {G}[+]{NC} Size     : {size_kb:.1f} KB")
    print(f"  {G}[+]{NC} Header   : {version}")
    print(f"  {G}[+]{NC} MD5      : {md5}")
    print(f"  {G}[+]{NC} SHA-1    : {sha1}")
    print(f"  {DIM}[+] SHA-256 : {sha256}{NC}")

    return {
        "path": path,
        "data": data,
        "size_kb": size_kb,
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
        "version": version,
    }

# ─────────────────────────────────────────────────────────────
# Web-compatible loader (used by Flask app.py)
# Accepts raw bytes instead of a file path.
# Does NOT call sys.exit or print — safe for API use.
# ─────────────────────────────────────────────────────────────
def load_file_from_bytes(data: bytes, filename: str) -> dict:
    if data[:4] != b"%PDF":
        raise ValueError("Not a valid PDF file (bad magic bytes)")
    try:
        version = data[:8].decode("ascii", errors="ignore").strip()
    except Exception:
        version = "unknown"
    return {
        "path":     filename,
        "filename": filename,
        "data":     data,
        "size_kb":  round(len(data) / 1024, 1),
        "md5":      hashlib.md5(data).hexdigest(),
        "sha1":     hashlib.sha1(data).hexdigest(),
        "sha256":   hashlib.sha256(data).hexdigest(),
        "version":  version,
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }

# ─────────────────────────────────────────────────────────────
# Step 2 — Extract Metadata
# ─────────────────────────────────────────────────────────────
def extract_metadata(info):
    print(f"\n{C}{'─'*58}{NC}")
    print(f"{C}{BOLD}  STEP 2 — Metadata Extraction{NC}")
    print(f"{C}{'─'*58}{NC}")

    data = info["data"]
    meta = {}

    # Extract metadata from Info dictionary
    patterns = {
        "Author":       rb"/Author\s*\(([^)]+)\)",
        "Creator":      rb"/Creator\s*\(([^)]+)\)",
        "Producer":     rb"/Producer\s*\(([^)]+)\)",
        "Title":        rb"/Title\s*\(([^)]+)\)",
        "Subject":      rb"/Subject\s*\(([^)]+)\)",
        "Keywords":     rb"/Keywords\s*\(([^)]+)\)",
        "CreationDate": rb"/CreationDate\s*\(([^)]+)\)",
        "ModDate":      rb"/ModDate\s*\(([^)]+)\)",
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, data)
        if match:
            try:
                val = match.group(1).decode("utf-8", errors="replace").strip()
            except:
                val = str(match.group(1))
            meta[key] = val
            flag = ""
            # Anomaly detection
            if key in ("CreationDate", "ModDate") and val:
                flag = ""
            if key == "Author" and val.lower() in ("", "unknown", "user"):
                flag = f"  {Y}[!] Suspicious: generic author{NC}"
            print(f"  {G}[+]{NC} {key:<14}: {val}{flag}")
        else:
            meta[key] = "N/A"

    # Page count
    page_match = re.search(rb"/Count\s+(\d+)", data)
    if page_match:
        meta["Pages"] = page_match.group(1).decode()
        print(f"  {G}[+]{NC} Pages         : {meta['Pages']}")

    # Check for metadata anomalies
    anomalies = []
    if meta.get("CreationDate") != "N/A" and meta.get("ModDate") != "N/A":
        if meta["CreationDate"] != meta["ModDate"]:
            anomalies.append("Document was modified after creation")
    if meta.get("Author", "N/A") == "N/A":
        anomalies.append("No author metadata — possible sanitization")

    if anomalies:
        print(f"\n  {Y}[!] Metadata Anomalies:{NC}")
        for a in anomalies:
            print(f"      {Y}→ {a}{NC}")

    info["metadata"] = meta
    return info

# ─────────────────────────────────────────────────────────────
# Step 3 — Keyword-Based Detection (pdfid logic)
# ─────────────────────────────────────────────────────────────
SUSPICIOUS_KEYWORDS = {
    b"/JavaScript":    ("critical", "JavaScript action — primary attack vector"),
    b"/JS":            ("critical", "Shorthand JS reference"),
    b"/OpenAction":    ("high",     "Executes action on document open without user interaction"),
    b"/AA":            ("high",     "Additional Actions — auto-triggers on events"),
    b"/EmbeddedFile":  ("high",     "Contains embedded file — possible dropper"),
    b"/Launch":        ("critical", "Launches external application or file"),
    b"/URI":           ("medium",   "Contains URI action — possible network callback"),
    b"/AcroForm":      ("medium",   "Interactive form — possible data exfiltration"),
    b"/XFA":           ("medium",   "XML Forms Architecture — complex form engine"),
    b"/RichMedia":     ("medium",   "Rich media annotation — Flash/video exploit surface"),
    b"/ObjStm":        ("low",      "Object streams — objects may be hidden inside"),
    b"/XObject":       ("low",      "External object reference"),
    b"/Colors":        ("low",      "May indicate color space manipulation"),
    b"eval":           ("high",     "JavaScript eval() — code execution / obfuscation"),
    b"unescape":       ("high",     "unescape() — classic heap spray / shellcode technique"),
    b"fromCharCode":   ("high",     "String.fromCharCode() — obfuscation of payload strings"),
    b"base64":         ("medium",   "Base64 encoding — possible payload encoding"),
    b"atob":           ("medium",   "atob() — base64 decode in browser JS context"),
    b"submitForm":     ("high",     "Submits form data — possible data exfiltration"),
}

def scan_keywords(info):
    print(f"\n{C}{'─'*58}{NC}")
    print(f"{C}{BOLD}  STEP 3 — Keyword-Based Detection{NC}")
    print(f"{C}{'─'*58}{NC}")

    data = info["data"]
    findings = {}
    score_add = 0

    for kw, (severity, desc) in SUSPICIOUS_KEYWORDS.items():
        count = data.count(kw)
        findings[kw.decode("utf-8", errors="replace")] = {
            "count": count, "severity": severity, "desc": desc
        }
        if count > 0:
            color = R if severity == "critical" else Y if severity == "high" else B if severity == "medium" else DIM
            sev_label = severity.upper().ljust(8)
            print(f"  {color}[{sev_label}]{NC} {kw.decode():<16} found {count}x  — {DIM}{desc}{NC}")
            # Score contribution
            score_add += {"critical": 25, "high": 15, "medium": 8, "low": 3}.get(severity, 0) * min(count, 2)

    found_count = sum(1 for v in findings.values() if v["count"] > 0)
    if found_count == 0:
        print(f"  {G}[✓] No suspicious keywords detected{NC}")

    info["keyword_findings"] = findings
    info["kw_score"] = min(score_add, 60)  # cap keyword contribution
    return info

# ─────────────────────────────────────────────────────────────
# Step 4 — Object Enumeration & Deep Parsing
# ─────────────────────────────────────────────────────────────
def enumerate_objects(info):
    print(f"\n{C}{'─'*58}{NC}")
    print(f"{C}{BOLD}  STEP 4 — Object Enumeration & Deep Parsing{NC}")
    print(f"{C}{'─'*58}{NC}")

    data = info["data"]
    objects = []

    # Find all objects: N G obj ... endobj
    obj_pattern = re.compile(
        rb"(\d+)\s+(\d+)\s+obj\s*(.*?)\s*endobj",
        re.DOTALL
    )

    for m in obj_pattern.finditer(data):
        num = int(m.group(1))
        gen = int(m.group(2))
        body = m.group(3)

        obj_info = {
            "num": num,
            "gen": gen,
            "raw": body[:500],  # first 500 bytes for display
            "size": len(body),
            "flags": [],
            "risk": "clean",
            "type": "Unknown",
            "has_stream": False,
        }

        # Detect object type
        if b"/Type /Catalog" in body:    obj_info["type"] = "Catalog"
        elif b"/Type /Pages" in body:    obj_info["type"] = "Pages"
        elif b"/Type /Page" in body:     obj_info["type"] = "Page"
        elif b"/Type /Font" in body:     obj_info["type"] = "Font"
        elif b"/Type /XObject" in body:  obj_info["type"] = "XObject"
        elif b"/Type /Action" in body:
            obj_info["type"] = "Action"
            if b"/S /JavaScript" in body or b"/S/JavaScript" in body:
                obj_info["type"] = "JS Action"
        elif b"stream" in body:
            obj_info["type"] = "Stream"
            obj_info["has_stream"] = True

        # Detect flags & risk
        risk_score = 0
        if b"/JavaScript" in body or b"/JS" in body:
            obj_info["flags"].append("JavaScript")
            risk_score += 30
        if b"/OpenAction" in body:
            obj_info["flags"].append("OpenAction")
            risk_score += 20
        if b"/AA" in body:
            obj_info["flags"].append("AutoAction")
            risk_score += 15
        if b"eval(" in body:
            obj_info["flags"].append("eval()")
            risk_score += 25
        if b"unescape(" in body:
            obj_info["flags"].append("unescape()")
            risk_score += 25
        if b"fromCharCode" in body:
            obj_info["flags"].append("fromCharCode")
            risk_score += 20
        if b"/EmbeddedFile" in body:
            obj_info["flags"].append("EmbeddedFile")
            risk_score += 20
        if b"/Launch" in body:
            obj_info["flags"].append("Launch")
            risk_score += 30
        if b"/Filter /FlateDecode" in body or b"/Filter/FlateDecode" in body:
            obj_info["flags"].append("Compressed")
        if b"stream" in body:
            obj_info["has_stream"] = True

        # Assign risk level
        if risk_score >= 40:    obj_info["risk"] = "critical"
        elif risk_score >= 20:  obj_info["risk"] = "high"
        elif risk_score >= 8:   obj_info["risk"] = "medium"
        elif risk_score > 0:    obj_info["risk"] = "low"

        # Try to decompress FlateDecode streams
        if b"stream" in body:
            stream_match = re.search(rb"stream\r?\n(.*?)\r?\nendstream", body, re.DOTALL)
            if stream_match:
                raw_stream = stream_match.group(1)
                if b"/FlateDecode" in body or b"/Fl " in body:
                    try:
                        decompressed = zlib.decompress(raw_stream)
                        obj_info["decompressed"] = decompressed[:1000]
                        # Re-scan decompressed content for suspicious patterns
                        for kw in [b"eval", b"unescape", b"fromCharCode", b"http", b"/JavaScript"]:
                            if kw in decompressed and kw.decode() not in [f for f in obj_info["flags"]]:
                                obj_info["flags"].append(f"[decompressed] {kw.decode()}")
                                obj_info["risk"] = "high" if obj_info["risk"] == "clean" else obj_info["risk"]
                    except zlib.error:
                        obj_info["decompressed"] = b"[decompression failed]"

        objects.append(obj_info)

    # Print summary
    print(f"  {G}[+]{NC} Total objects found : {BOLD}{len(objects)}{NC}")
    suspicious = [o for o in objects if o["risk"] in ("critical","high","medium")]
    print(f"  {Y}[!]{NC} Suspicious objects  : {BOLD}{len(suspicious)}{NC}")

    for obj in objects:
        if obj["risk"] in ("critical", "high", "medium"):
            color = R if obj["risk"] == "critical" else Y if obj["risk"] == "high" else B
            flags_str = ", ".join(obj["flags"]) if obj["flags"] else "no flags"
            print(f"\n  {color}[{obj['risk'].upper():<8}]{NC} Object {obj['num']} — {obj['type']}")
            print(f"  {DIM}           Flags : {flags_str}{NC}")
            print(f"  {DIM}           Size  : {obj['size']} bytes{NC}")

    info["objects"] = objects
    info["suspicious_count"] = len(suspicious)
    return info

# ─────────────────────────────────────────────────────────────
# Step 5 — JavaScript Extraction & Analysis
# ─────────────────────────────────────────────────────────────
def extract_javascript(info):
    print(f"\n{C}{'─'*58}{NC}")
    print(f"{C}{BOLD}  STEP 5 — JavaScript Extraction & Analysis{NC}")
    print(f"{C}{'─'*58}{NC}")

    data = info["data"]
    js_blocks = []

    # Method 1: /JS (direct string)
    js_str_pattern = re.compile(rb"/JS\s*\(([^)]{1,4096})\)", re.DOTALL)
    for m in js_str_pattern.finditer(data):
        js_blocks.append({"source": "direct string", "content": m.group(1)})

    # Method 2: /JS with hex string
    js_hex_pattern = re.compile(rb"/JS\s*<([0-9a-fA-F\s]+)>")
    for m in js_hex_pattern.finditer(data):
        try:
            hex_str = re.sub(rb"\s+", b"", m.group(1))
            decoded = bytes.fromhex(hex_str.decode())
            js_blocks.append({"source": "hex string", "content": decoded})
        except:
            pass

    # Method 3: Standalone JS in streams (look for common JS patterns)
    js_patterns_in_streams = [b"eval(", b"unescape(", b"app.alert", b"this.submitForm",
                               b"String.fromCharCode", b"app.launch", b"util.printd"]
    for obj in info.get("objects", []):
        if "decompressed" in obj:
            dc = obj["decompressed"]
            for pat in js_patterns_in_streams:
                if pat in dc:
                    js_blocks.append({"source": f"decompressed obj {obj['num']}", "content": dc})
                    break

    # Analyze each JS block
    obfuscation_patterns = [
        (rb"eval\s*\(",                  "critical", "eval() code execution"),
        (rb"unescape\s*\(",              "critical", "unescape() — heap spray / shellcode"),
        (rb"String\.fromCharCode\s*\(",  "critical", "fromCharCode() — obfuscated string"),
        (rb"atob\s*\(",                  "high",     "atob() — base64 decode"),
        (rb"btoa\s*\(",                  "medium",   "btoa() — base64 encode"),
        (rb"submitForm",                 "high",     "submitForm() — data exfiltration"),
        (rb"this\.open\s*\(",            "critical", "this.open() — opens URL/file"),
        (rb"app\.launch\s*\(",           "critical", "app.launch() — executes external process"),
        (rb"app\.alert\s*\(",            "medium",   "app.alert() — social engineering lure"),
        (rb"\\\\x[0-9a-fA-F]{2}",       "high",     "Hex escape obfuscation"),
        (rb"\\\\u[0-9a-fA-F]{4}",       "high",     "Unicode escape obfuscation"),
        (rb"(https?|ftp)://[^\s\"')]+",  "high",     "Embedded URL"),
    ]

    info["js_blocks"] = js_blocks
    info["js_patterns_found"] = []

    if not js_blocks:
        print(f"  {G}[✓] No JavaScript blocks detected{NC}")
        return info

    print(f"  {Y}[!]{NC} JavaScript blocks found: {BOLD}{len(js_blocks)}{NC}\n")

    for i, block in enumerate(js_blocks):
        content = block["content"]
        print(f"  {B}[JS Block {i+1}]{NC} Source: {block['source']}")
        try:
            preview = content[:200].decode("utf-8", errors="replace").replace("\n", " ")
        except:
            preview = repr(content[:200])
        print(f"  {DIM}  Preview: {preview}...{NC}\n")

        # Scan for patterns
        for pattern, severity, desc in obfuscation_patterns:
            matches = re.findall(pattern, content)
            if matches:
                color = R if severity == "critical" else Y if severity == "high" else B
                print(f"  {color}  [{severity.upper():<8}]{NC} {desc} ({len(matches)}x found)")
                info["js_patterns_found"].append({
                    "pattern": desc, "severity": severity,
                    "count": len(matches), "block": i+1
                })

        # Try to decode fromCharCode
        fcc = re.search(rb"fromCharCode\s*\(([0-9,\s]+)\)", content)
        if fcc:
            try:
                nums = [int(x.strip()) for x in fcc.group(1).split(b",") if x.strip().isdigit()]
                decoded = "".join(chr(n) for n in nums if 0 < n < 128)
                if decoded:
                    print(f"\n  {G}  [DECODED fromCharCode]{NC}: {decoded[:200]}")
            except:
                pass

        # Extract embedded URLs
        urls = re.findall(rb"(https?://[^\s\"')\\\x00-\x1f]+)", content)
        for url in urls:
            try:
                print(f"  {R}  [URL FOUND]{NC} {url.decode('utf-8', errors='replace')}")
                info.setdefault("js_urls", []).append(url.decode("utf-8", errors="replace"))
            except:
                pass

    return info

# ─────────────────────────────────────────────────────────────
# Step 5b — Run External Tools (if available)
# ─────────────────────────────────────────────────────────────
def run_external_tools(info):
    path = info["path"]
    script_dir = os.path.dirname(os.path.abspath(__file__))

    tools_run = []

    # pdfid.py
    pdfid = os.path.join(script_dir, "pdfid.py")
    if os.path.isfile(pdfid):
        print(f"\n  {C}[*] Running pdfid.py...{NC}")
        result = subprocess.run(["python3", pdfid, path], capture_output=True, text=True, timeout=30)
        if result.stdout:
            for line in result.stdout.splitlines():
                print(f"  {DIM}    {line}{NC}")
        tools_run.append("pdfid")

    # pdf-parser.py
    pdfparser = os.path.join(script_dir, "pdf-parser.py")
    if os.path.isfile(pdfparser):
        print(f"\n  {C}[*] Running pdf-parser.py (stats)...{NC}")
        result = subprocess.run(["python3", pdfparser, "-a", path],
                                capture_output=True, text=True, timeout=30)
        if result.stdout:
            for line in result.stdout.splitlines()[:30]:
                print(f"  {DIM}    {line}{NC}")
        tools_run.append("pdf-parser")

    # qpdf — decompress for further analysis
    qpdf_out = path + ".qpdf_decompressed.pdf"
    try:
        result = subprocess.run(
            ["qpdf", "--qdf", "--object-streams=disable", path, qpdf_out],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            print(f"\n  {G}[+] qpdf decompressed output:{NC} {qpdf_out}")
            tools_run.append("qpdf")
            # Optionally clean up
            # os.remove(qpdf_out)
    except FileNotFoundError:
        pass

    # strings (GNU binutils)
    try:
        result = subprocess.run(["strings", path], capture_output=True, text=True, timeout=15)
        strings_out = result.stdout.splitlines()
        suspicious_strings = [
            s for s in strings_out if any(pat in s.lower() for pat in
            ["http", "ftp", "eval(", "unescape(", "fromcharcode", "javascript",
             "cmd.exe", "powershell", "wget", "curl", ".exe", ".dll", "base64"])
        ]
        if suspicious_strings:
            print(f"\n  {Y}[!] Suspicious strings (via `strings` tool):{NC}")
            for s in suspicious_strings[:20]:
                print(f"  {DIM}    {s[:120]}{NC}")
            info["suspicious_strings"] = suspicious_strings
        tools_run.append("strings")
    except FileNotFoundError:
        pass

    info["tools_run"] = tools_run
    return info

# ─────────────────────────────────────────────────────────────
# Step 6 — IOC Extraction
# ─────────────────────────────────────────────────────────────
def extract_iocs(info):
    print(f"\n{C}{'─'*58}{NC}")
    print(f"{C}{BOLD}  STEP 6 — IOC Extraction{NC}")
    print(f"{C}{'─'*58}{NC}")

    data = info["data"]
    iocs = []

    # URLs
    url_pattern = re.compile(rb"(https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{8,})")
    for m in url_pattern.finditer(data):
        url = m.group(1).decode("utf-8", errors="replace")
        if url not in [i["value"] for i in iocs]:
            iocs.append({"type": "URL", "value": url, "risk": "high"})
            print(f"  {R}[URL    ]{NC} {url}")

    # IP Addresses
    ip_pattern = re.compile(rb"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
    for m in ip_pattern.finditer(data):
        ip = m.group(1).decode()
        parts = ip.split(".")
        # Filter out obviously invalid IPs
        if all(0 <= int(p) <= 255 for p in parts) and ip not in ("0.0.0.0", "255.255.255.255", "127.0.0.1"):
            if ip not in [i["value"] for i in iocs]:
                iocs.append({"type": "IP", "value": ip, "risk": "medium"})
                print(f"  {Y}[IP     ]{NC} {ip}")

    # Email addresses
    email_pattern = re.compile(rb"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
    for m in email_pattern.finditer(data):
        email = m.group(0).decode("utf-8", errors="replace")
        if email not in [i["value"] for i in iocs]:
            iocs.append({"type": "EMAIL", "value": email, "risk": "low"})
            print(f"  {B}[EMAIL  ]{NC} {email}")

    # Domains (from URI actions)
    domain_pattern = re.compile(rb"/URI\s*\(([^)]+)\)")
    for m in domain_pattern.finditer(data):
        uri = m.group(1).decode("utf-8", errors="replace")
        if uri not in [i["value"] for i in iocs]:
            iocs.append({"type": "URI", "value": uri, "risk": "high"})
            print(f"  {Y}[URI    ]{NC} {uri}")

    # Embedded filenames
    file_pattern = re.compile(rb"/F\s*\(([^)]{3,100})\)")
    for m in file_pattern.finditer(data):
        fname = m.group(1).decode("utf-8", errors="replace")
        if any(fname.lower().endswith(ext) for ext in [".exe",".dll",".bat",".ps1",".vbs",".sh",".bin"]):
            iocs.append({"type": "FILENAME", "value": fname, "risk": "critical"})
            print(f"  {R}[EXEC   ]{NC} Embedded file reference: {fname}")

    # Add JS URLs
    for url in info.get("js_urls", []):
        if url not in [i["value"] for i in iocs]:
            iocs.append({"type": "JS-URL", "value": url, "risk": "critical"})
            print(f"  {R}[JS-URL ]{NC} {url}")

    # Hashes as IOCs
    iocs.append({"type": "MD5",    "value": info["md5"],    "risk": "info"})
    iocs.append({"type": "SHA1",   "value": info["sha1"],   "risk": "info"})
    iocs.append({"type": "SHA256", "value": info["sha256"], "risk": "info"})

    if len(iocs) == 3:  # only hashes
        print(f"  {G}[✓] No network or file IOCs detected{NC}")

    info["iocs"] = iocs
    return info

# ─────────────────────────────────────────────────────────────
# Step 7 — Risk Scoring Engine
# ─────────────────────────────────────────────────────────────
RISK_WEIGHTS = {
    # Keyword-based (from kw_score)
    "js_patterns":  {"critical": 20, "high": 12, "medium": 6},
    "object_risks": {"critical": 20, "high": 10, "medium": 5},
    "ioc_count":    3,   # per non-hash IOC
    "js_blocks":    8,   # per JS block
}

def calculate_risk(info):
    print(f"\n{C}{'─'*58}{NC}")
    print(f"{C}{BOLD}  STEP 7 — Risk Scoring Engine{NC}")
    print(f"{C}{'─'*58}{NC}")

    score = 0
    breakdown = []

    # Keyword contributions (already calculated)
    kw = info.get("kw_score", 0)
    score += kw
    if kw > 0:
        breakdown.append(f"Keyword detection    : +{kw}")

    # JS patterns
    for pat in info.get("js_patterns_found", []):
        add = RISK_WEIGHTS["js_patterns"].get(pat["severity"], 0)
        score += add
        breakdown.append(f"JS pattern ({pat['severity']:<8}) : +{add}  [{pat['pattern']}]")

    # Object risks
    for obj in info.get("objects", []):
        add = RISK_WEIGHTS["object_risks"].get(obj["risk"], 0)
        score += add

    # IOCs (excluding hashes)
    net_iocs = [i for i in info.get("iocs", []) if i["type"] not in ("MD5","SHA1","SHA256")]
    ioc_add = len(net_iocs) * RISK_WEIGHTS["ioc_count"]
    score += ioc_add
    if ioc_add > 0:
        breakdown.append(f"IOCs extracted       : +{ioc_add}  ({len(net_iocs)} IOCs)")

    # JS blocks
    js_add = len(info.get("js_blocks", [])) * RISK_WEIGHTS["js_blocks"]
    score += js_add
    if js_add > 0:
        breakdown.append(f"JS blocks found      : +{js_add}  ({len(info.get('js_blocks',[]))} blocks)")

    score = min(score, 100)

    # Severity label
    if score >= 80:
        label = f"{R}{BOLD}CRITICAL — IMMEDIATE ACTION REQUIRED{NC}"
        label_plain = "CRITICAL"
    elif score >= 60:
        label = f"{R}HIGH RISK — Likely malicious{NC}"
        label_plain = "HIGH RISK"
    elif score >= 40:
        label = f"{Y}MEDIUM RISK — Suspicious, review recommended{NC}"
        label_plain = "MEDIUM RISK"
    elif score >= 20:
        label = f"{Y}LOW RISK — Minor indicators present{NC}"
        label_plain = "LOW RISK"
    else:
        label = f"{G}CLEAN — No significant indicators{NC}"
        label_plain = "CLEAN"

    print(f"\n  {'─'*40}")
    for line in breakdown:
        print(f"  {DIM}  {line}{NC}")
    print(f"  {'─'*40}")
    print(f"  {BOLD}  RISK SCORE : {score}/100{NC}")
    print(f"  {BOLD}  VERDICT    : {label}{NC}")
    print(f"  {'─'*40}")

    info["risk_score"] = score
    info["risk_label"] = label_plain
    return info

# ─────────────────────────────────────────────────────────────
# Step 8 — Report Generation
# ─────────────────────────────────────────────────────────────
def generate_report(info, save=False, json_out=False):
    print(f"\n{C}{'─'*58}{NC}")
    print(f"{C}{BOLD}  STEP 8 — Final Report{NC}")
    print(f"{C}{'─'*58}{NC}")

    ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    score = info["risk_score"]
    label = info["risk_label"]

    lines = [
        "═" * 62,
        "  PDF MALWARE ANALYSIS REPORT",
        "  PDFScan Toolkit — Kali Edition",
        "═" * 62,
        f"  File     : {info['path']}",
        f"  Size     : {info['size_kb']:.1f} KB",
        f"  Analyzed : {ts}",
        f"  MD5      : {info['md5']}",
        f"  SHA-1    : {info['sha1']}",
        f"  SHA-256  : {info['sha256']}",
        "",
        "  RISK SCORE : {}/100  [{}]".format(score, label),
        "",
        "─" * 62,
        "  METADATA",
        "─" * 62,
    ]
    for k, v in info.get("metadata", {}).items():
        lines.append(f"  {k:<16}: {v}")

    lines += ["", "─" * 62, "  SUSPICIOUS KEYWORDS DETECTED", "─" * 62]
    found_kw = [(k, v) for k, v in info.get("keyword_findings", {}).items() if v["count"] > 0]
    if found_kw:
        for k, v in found_kw:
            lines.append(f"  [{v['severity'].upper():<8}] {k:<18} ({v['count']}x) — {v['desc']}")
    else:
        lines.append("  None detected")

    lines += ["", "─" * 62, "  OBJECT SUMMARY", "─" * 62]
    lines.append(f"  Total objects : {len(info.get('objects', []))}")
    lines.append(f"  Suspicious    : {info.get('suspicious_count', 0)}")
    for obj in info.get("objects", []):
        if obj["risk"] in ("critical", "high", "medium"):
            flags = ", ".join(obj["flags"]) or "none"
            lines.append(f"  [{obj['risk'].upper():<8}] Object {obj['num']} — {obj['type']} — {flags}")

    lines += ["", "─" * 62, "  JAVASCRIPT ANALYSIS", "─" * 62]
    lines.append(f"  JS blocks found : {len(info.get('js_blocks', []))}")
    for p in info.get("js_patterns_found", []):
        lines.append(f"  [{p['severity'].upper():<8}] {p['pattern']} ({p['count']}x in block {p['block']})")
    if not info.get("js_patterns_found"):
        lines.append("  No suspicious JS patterns detected")

    lines += ["", "─" * 62, "  INDICATORS OF COMPROMISE (IOCs)", "─" * 62]
    net_iocs = [i for i in info.get("iocs", []) if i["type"] not in ("MD5","SHA1","SHA256")]
    if net_iocs:
        for ioc in net_iocs:
            lines.append(f"  [{ioc['risk'].upper():<8}] {ioc['type']:<10} {ioc['value']}")
    else:
        lines.append("  No network or file IOCs detected")

    lines += ["", "─" * 62, "  MITIGATIONS", "─" * 62]
    if score >= 60:
        mitigations = [
            "[HIGH] Quarantine file immediately — do not open on production systems",
            "[HIGH] Block identified IOC domains/IPs at perimeter firewall and DNS",
            "[HIGH] Disable JavaScript execution in PDF reader (Adobe: Preferences → JavaScript)",
            "[MED]  Submit file hash to VirusTotal and threat intelligence platforms",
            "[MED]  Check endpoint logs for process spawned by PDF reader (AcroRd32.exe)",
            "[MED]  Conduct user awareness training on malicious PDF identification",
        ]
    elif score >= 30:
        mitigations = [
            "[MED]  Review document carefully before opening on production system",
            "[MED]  Scan with additional AV engines on VirusTotal",
            "[LOW]  Enable Protected View in Adobe Acrobat for untrusted files",
        ]
    else:
        mitigations = [
            "[INFO] Document appears clean — no immediate action required",
            "[INFO] Standard email/web delivery acceptable",
        ]
    for m in mitigations:
        lines.append(f"  {m}")

    lines += [
        "",
        "═" * 62,
        "  Generated by PDFScan Toolkit — For SOC/IR use only",
        "═" * 62,
    ]

    report_text = "\n".join(lines)

    # Print to terminal
    print()
    for line in lines:
        print(f"  {line}")

    # Save to reports/ folder
    if save:
        # Create reports/ folder next to this script if it doesn't exist
        script_dir = os.path.dirname(os.path.abspath(__file__))
        reports_dir = os.path.join(script_dir, "reports")
        os.makedirs(reports_dir, exist_ok=True)

        # Filename: <pdf_name>_<timestamp>_report.txt
        pdf_basename = os.path.splitext(os.path.basename(info["path"]))[0]
        timestamp    = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        report_name  = f"{pdf_basename}_{timestamp}_report.txt"
        report_path  = os.path.join(reports_dir, report_name)

        with open(report_path, "w") as f:
            f.write(report_text)

        print(f"\n  {G}[+] Report folder : {reports_dir}{NC}")
        print(f"  {G}[+] TXT report    : {report_name}{NC}")
        info["report_path"] = report_path

    # Save JSON report
    if json_out:
        script_dir  = os.path.dirname(os.path.abspath(__file__))
        reports_dir = os.path.join(script_dir, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        pdf_basename = os.path.splitext(os.path.basename(info["path"]))[0]
        timestamp    = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        json_name    = f"{pdf_basename}_{timestamp}_report.json"
        json_path    = os.path.join(reports_dir, json_name)
        safe = {
            "filename":  info.get("filename", info["path"]),
            "timestamp": info.get("timestamp",""),
            "size_kb":   info["size_kb"],
            "version":   info["version"],
            "md5":       info["md5"],
            "sha1":      info["sha1"],
            "sha256":    info["sha256"],
            "metadata":  info.get("metadata", {}),
            "keyword_findings": {
                k: {"count": v["count"], "severity": v["severity"], "desc": v["desc"]}
                for k, v in info.get("keyword_findings", {}).items()
            },
            "objects": [
                {"num": o["num"], "type": o["type"], "risk": o["risk"], "flags": o["flags"]}
                for o in info.get("objects", [])
            ],
            "js_patterns": info.get("js_patterns_found", []),
            "iocs": [{"type": i["type"], "value": i["value"], "risk": i["risk"]}
                     for i in info.get("iocs", [])],
            "risk_score":  info["risk_score"],
            "risk_label":  info["risk_label"],
        }
        with open(json_path, "w") as f:
            json.dump(safe, f, indent=2)
        print(f"  {G}[+] JSON report   : {json_name}{NC}")
        info["json_report_path"] = json_path

    return info

# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────
# Server mode — send PDF to Flask API, render result in terminal
# ─────────────────────────────────────────────────────────────
def send_to_server(pdf_path: str, server_url: str) -> dict:
    """
    Upload a PDF to /api/analyze using http.client (stdlib only).
    Returns parsed JSON dict.
    Raises ConnectionError if the server cannot be reached — caller
    decides whether to fall back to local mode or abort.
    """
    import http.client
    from urllib.parse import urlparse

    pdf_path = os.path.abspath(pdf_path)
    parsed   = urlparse(server_url.rstrip("/"))
    host     = parsed.hostname
    port     = parsed.port or (443 if parsed.scheme == "https" else 80)
    api_path = (parsed.path.rstrip("/")) + "/api/analyze"

    print(f"\n{C}{chr(9472)*58}{NC}")
    print(f"{C}{BOLD}  SERVER MODE — {server_url}{NC}")
    print(f"{C}{chr(9472)*58}{NC}")

    with open(pdf_path, "rb") as fh:
        file_bytes = fh.read()

    filename = os.path.basename(pdf_path)
    boundary = b"XPDFScanBnd42Z"
    CRLF     = b"\r\n"

    body = (
        b"--" + boundary + CRLF
        + b'Content-Disposition: form-data; name="file"; filename="' + filename.encode() + b'"' + CRLF
        + b"Content-Type: application/pdf" + CRLF
        + CRLF
        + file_bytes + CRLF
        + b"--" + boundary + b"--" + CRLF
    )

    hdrs = {
        "Content-Type":   "multipart/form-data; boundary=" + boundary.decode(),
        "Content-Length": str(len(body)),
        "Accept":         "application/json",
    }

    print(f"  {B}[*]{NC} Connecting {host}:{port}{api_path} …")

    try:
        conn = http.client.HTTPConnection(host, port, timeout=90)
        conn.request("POST", api_path, body=body, headers=hdrs)
        resp = conn.getresponse()
        raw  = resp.read().decode("utf-8", errors="replace")
        conn.close()
        if resp.status != 200:
            raise ConnectionError(f"HTTP {resp.status}: {raw[:200]}")
        result = json.loads(raw)
        print(f"  {G}[+]{NC} Server responded — analysis complete\n")
        return result
    except (OSError, ConnectionRefusedError, TimeoutError) as exc:
        raise ConnectionError(str(exc)) from exc
    except json.JSONDecodeError as exc:
        raise ConnectionError(f"Bad JSON from server: {exc}") from exc


def render_server_result(data: dict, save: bool = False, json_out: bool = False):
    """Pretty-print the JSON result from the server as a terminal report."""
    score = data.get("risk_score", 0)
    label = data.get("risk_label", "UNKNOWN")

    color = R if score >= 80 else Y if score >= 50 else G

    print(f"\n{C}{'═'*58}{NC}")
    print(f"{C}{BOLD}  PDF MALWARE ANALYSIS REPORT (via server){NC}")
    print(f"{C}{'═'*58}{NC}")
    print(f"  {BOLD}File     :{NC} {data.get('filename','?')}")
    print(f"  {BOLD}Size     :{NC} {data.get('size_kb','?')} KB   |   {data.get('version','')}")
    print(f"  {BOLD}Analyzed :{NC} {data.get('timestamp','')}")
    print(f"\n  {color}{BOLD}RISK SCORE : {score}/100   [{label}]{NC}\n")

    # Hashes
    print(f"  {DIM}MD5    : {data.get('md5','')}")
    print(f"  SHA-1  : {data.get('sha1','')}")
    print(f"  SHA-256: {data.get('sha256','')}{NC}")

    # Metadata
    meta = data.get("metadata", {})
    if meta:
        print(f"\n{C}{'─'*58}{NC}")
        print(f"{C}{BOLD}  METADATA{NC}")
        print(f"{C}{'─'*58}{NC}")
        for k, v in meta.items():
            if v and v != "N/A":
                print(f"  {k:<16}: {v}")

    # Keywords
    print(f"\n{C}{'─'*58}{NC}")
    print(f"{C}{BOLD}  KEYWORD DETECTION{NC}")
    print(f"{C}{'─'*58}{NC}")
    found_kw = [(k, v) for k, v in data.get("keyword_findings", {}).items() if v["count"] > 0]
    if found_kw:
        for k, v in found_kw:
            col = R if v["severity"] == "critical" else Y if v["severity"] == "high" else B
            print(f"  {col}[{v['severity'].upper():<8}]{NC} {k:<18} ({v['count']}x) — {DIM}{v['desc']}{NC}")
    else:
        print(f"  {G}[✓] No suspicious keywords detected{NC}")

    # Objects
    objs = data.get("objects", [])
    susp = [o for o in objs if o["risk"] in ("critical","high","medium")]
    print(f"\n{C}{'─'*58}{NC}")
    print(f"{C}{BOLD}  OBJECTS  ({len(objs)} total · {len(susp)} suspicious){NC}")
    print(f"{C}{'─'*58}{NC}")
    for o in susp:
        col = R if o["risk"] == "critical" else Y if o["risk"] == "high" else B
        flags = ", ".join(o["flags"]) or "none"
        print(f"  {col}[{o['risk'].upper():<8}]{NC} obj {o['num']} — {o['type']} — {flags}")
    if not susp:
        print(f"  {G}[✓] No suspicious objects{NC}")

    # JavaScript
    print(f"\n{C}{'─'*58}{NC}")
    print(f"{C}{BOLD}  JAVASCRIPT  ({data.get('js_blocks_count',0)} block(s)){NC}")
    print(f"{C}{'─'*58}{NC}")
    for p in data.get("js_patterns", []):
        col = R if p["severity"] == "critical" else Y
        print(f"  {col}[{p['severity'].upper():<8}]{NC} {p['pattern']} ({p['count']}x — block {p['block']})")
    if data.get("js_previews"):
        print(f"\n  {DIM}--- JS Preview (block 1) ---")
        print(data["js_previews"][0]["preview"][:400])
        print(f"---{NC}")
    if not data.get("js_patterns"):
        print(f"  {G}[✓] No suspicious JS patterns{NC}")

    # IOCs
    net_iocs = [i for i in data.get("iocs", []) if i["type"] not in ("MD5","SHA1","SHA256")]
    print(f"\n{C}{'─'*58}{NC}")
    print(f"{C}{BOLD}  IOCs  ({len(net_iocs)} network/file indicator(s)){NC}")
    print(f"{C}{'─'*58}{NC}")
    for ioc in net_iocs:
        col = R if ioc["risk"] == "critical" else Y if ioc["risk"] == "high" else B
        print(f"  {col}[{ioc['risk'].upper():<8}]{NC} {ioc['type']:<12} {ioc['value']}")
    if not net_iocs:
        print(f"  {G}[✓] No network or file IOCs{NC}")

    # Mitigations
    print(f"\n{C}{'─'*58}{NC}")
    print(f"{C}{BOLD}  MITIGATIONS{NC}")
    print(f"{C}{'─'*58}{NC}")
    if score >= 60:
        mits = [
            (R,"HIGH","Quarantine file immediately — do not open on production systems"),
            (R,"HIGH","Block IOC domains/IPs at firewall and DNS sinkhole"),
            (Y,"MED ","Disable PDF JavaScript: Adobe → Preferences → JavaScript"),
            (Y,"MED ","Submit hash to VirusTotal and threat intelligence platforms"),
            (B,"INFO","Check endpoint for processes spawned by AcroRd32.exe"),
        ]
    elif score >= 30:
        mits = [
            (Y,"MED ","Review in sandboxed environment before distributing"),
            (Y,"MED ","Scan with additional AV engines on VirusTotal"),
            (B,"INFO","Enable Protected View in Adobe Acrobat for untrusted files"),
        ]
    else:
        mits = [(G,"INFO","Document appears clean — no immediate action required")]
    for col, lbl, txt in mits:
        print(f"  {col}[{lbl}]{NC} {txt}")

    print(f"\n{C}{'═'*58}{NC}")
    print(f"{C}  Tools run on server: {', '.join(data.get('tools_run',[])) or 'built-in engine'}{NC}")
    print(f"{C}{'═'*58}{NC}")

    # Save reports
    if save or json_out:
        script_dir  = os.path.dirname(os.path.abspath(__file__))
        reports_dir = os.path.join(script_dir, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        ts   = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        base = os.path.splitext(data.get("filename", "report"))[0]

        if save:
            # TXT report
            txt_lines = [
                "═"*62, "  PDF MALWARE ANALYSIS REPORT (server mode)",
                "  PDFScan Toolkit — Kali Edition", "═"*62,
                f"  File     : {data.get('filename')}",
                f"  Analyzed : {data.get('timestamp')}",
                f"  Risk     : {score}/100  [{label}]",
                f"  MD5      : {data.get('md5')}",
                f"  SHA-1    : {data.get('sha1')}",
                f"  SHA-256  : {data.get('sha256')}",
                "", "─"*62, "  METADATA", "─"*62,
            ]
            for k, v in data.get("metadata", {}).items():
                txt_lines.append(f"  {k:<16}: {v}")
            txt_lines += ["", "─"*62, "  KEYWORDS", "─"*62]
            for k, v in data.get("keyword_findings", {}).items():
                if v["count"] > 0:
                    txt_lines.append(f"  [{v['severity'].upper():<8}] {k} ({v['count']}x)")
            txt_lines += ["", "─"*62, "  IOCs", "─"*62]
            for ioc in net_iocs:
                txt_lines.append(f"  [{ioc['risk'].upper():<8}] {ioc['type']:<12} {ioc['value']}")
            txt_lines += ["", "═"*62, "  PDFScan Toolkit — For SOC/IR use only", "═"*62]
            txt_path = os.path.join(reports_dir, f"{base}_{ts}_report.txt")
            with open(txt_path, "w") as f:
                f.write("\n".join(txt_lines))
            print(f"\n  {G}[+] TXT report : {txt_path}{NC}")

        if json_out:
            json_path = os.path.join(reports_dir, f"{base}_{ts}_report.json")
            with open(json_path, "w") as f:
                json.dump(data, f, indent=2)
            print(f"  {G}[+] JSON report: {json_path}{NC}")


# ─────────────────────────────────────────────────────────────
# Watch mode — auto-analyse every new PDF dropped in a folder
# ─────────────────────────────────────────────────────────────
def watch_folder(folder: str, server_url: str = None, save: bool = False,
                 json_out: bool = False, verbose: bool = False):
    folder = os.path.abspath(folder)
    if not os.path.isdir(folder):
        print(f"{R}[✗] Folder not found: {folder}{NC}")
        sys.exit(1)

    seen = set(os.listdir(folder))
    mode = f"server ({server_url})" if server_url else "local engine"
    print(f"\n{C}{BOLD}  WATCH MODE — {folder}{NC}")
    print(f"  {DIM}Mode: {mode}   |   Reports: {'yes' if save else 'no'}   |   Ctrl+C to stop{NC}\n")

    try:
        while True:
            current = set(os.listdir(folder))
            new_files = current - seen
            for fname in sorted(new_files):
                if fname.lower().endswith(".pdf"):
                    full_path = os.path.join(folder, fname)
                    print(f"\n{G}[NEW PDF DETECTED]{NC} {fname}")
                    time.sleep(0.5)   # wait for write to finish
                    if server_url:
                        data = send_to_server(full_path, server_url)
                        render_server_result(data, save=save, json_out=json_out)
                    else:
                        run_local(full_path, save=save, json_out=json_out, verbose=verbose)
            seen = current
            time.sleep(1.5)
    except KeyboardInterrupt:
        print(f"\n{Y}[!] Watch mode stopped.{NC}\n")


# ─────────────────────────────────────────────────────────────
# Local analysis pipeline (extracted so watch mode can call it)
# ─────────────────────────────────────────────────────────────
def run_local(pdf_path: str, save: bool = False, json_out: bool = False,
              verbose: bool = False):
    print(f"{DIM}  Analysis started: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}{NC}")
    info = load_file(pdf_path)
    info = extract_metadata(info)
    info = scan_keywords(info)
    info = enumerate_objects(info)
    info = extract_javascript(info)
    info = run_external_tools(info)
    info = extract_iocs(info)
    info = calculate_risk(info)
    info = generate_report(info, save=save, json_out=json_out)
    return info


# ─────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="PDF Malware Analysis Toolkit — Kali Edition",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
EXAMPLES
  Local analysis (no server):
    python3 pdf_analyzer.py suspicious.pdf
    python3 pdf_analyzer.py suspicious.pdf --report
    python3 pdf_analyzer.py suspicious.pdf --report --json

  Server mode (sends file to Flask app):
    python3 pdf_analyzer.py suspicious.pdf --server
    python3 pdf_analyzer.py suspicious.pdf --server --url http://localhost:5000
    python3 pdf_analyzer.py suspicious.pdf --server --report

  Watch a folder for new PDFs:
    python3 pdf_analyzer.py --watch ~/Downloads
    python3 pdf_analyzer.py --watch ~/Downloads --server --report

  Manage the web server:
    python3 pdf_analyzer.py --start-server
    python3 pdf_analyzer.py --open-browser
        """
    )
    # ── File / folder targets ──
    parser.add_argument("file",           nargs="?",  help="PDF file to analyse")
    parser.add_argument("--watch",        metavar="FOLDER", help="Watch folder for new PDFs")

    # ── Mode flags ──
    parser.add_argument("--server",       action="store_true", help="Send to web server instead of local engine")
    parser.add_argument("--url",          default="http://localhost:5000",
                                          help="Server URL (default: http://localhost:5000)")

    # ── Output flags ──
    parser.add_argument("--report",       action="store_true", help="Save TXT report to reports/ folder")
    parser.add_argument("--json",         action="store_true", help="Also save JSON report to reports/ folder")
    parser.add_argument("--verbose",      action="store_true", help="Show all objects (including clean)")

    # ── Utility ──
    parser.add_argument("--install",      action="store_true", help="Install dependencies")
    parser.add_argument("--start-server", action="store_true", help="Start the Flask web server")
    parser.add_argument("--open-browser", action="store_true", help="Open web UI in browser")

    args = parser.parse_args()
    banner()

    # ── Utility actions ──
    if args.install:
        install_dependencies()

    if args.start_server:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        app_path   = os.path.join(script_dir, "app.py")
        if not os.path.isfile(app_path):
            print(f"{R}[✗] app.py not found in {script_dir}{NC}")
            sys.exit(1)
        print(f"{G}[+] Starting web server → http://localhost:5000{NC}")
        print(f"{DIM}    Press Ctrl+C to stop{NC}\n")
        os.execv(sys.executable, [sys.executable, app_path])

    if args.open_browser:
        import webbrowser
        url = args.url
        print(f"{G}[+] Opening {url} in browser…{NC}")
        webbrowser.open(url)
        sys.exit(0)

    # ── Watch mode ──
    if args.watch:
        watch_folder(
            folder     = args.watch,
            server_url = args.url if args.server else None,
            save       = args.report,
            json_out   = args.json,
            verbose    = args.verbose,
        )
        sys.exit(0)

    # ── Need a file for all remaining modes ──
    if not args.file:
        parser.print_help()
        print(f"\n{Y}Quick start:{NC}")
        print(f"  python3 pdf_analyzer.py suspicious.pdf              # local")
        print(f"  python3 pdf_analyzer.py suspicious.pdf --server     # via web app")
        print(f"  python3 pdf_analyzer.py --watch ~/Downloads         # auto-scan folder\n")
        sys.exit(0)

    # ── Server mode (with auto-fallback to local if server is down) ──
    if args.server:
        try:
            data = send_to_server(args.file, args.url)
            render_server_result(data, save=args.report, json_out=args.json)
            print(f"\n{G}[✓] Analysis complete (server mode).{NC}\n")
        except ConnectionError as err:
            print(f"\n  {R}[✗] Cannot reach server: {err}{NC}")
            print(f"  {Y}[→] Auto-falling back to local analysis …{NC}\n")
            try:
                run_local(args.file, save=args.report, json_out=args.json, verbose=args.verbose)
                print(f"\n{G}[✓] Analysis complete (local fallback).{NC}\n")
            except Exception as loc_err:
                print(f"\n{R}[✗] Local analysis also failed: {loc_err}{NC}\n")
                sys.exit(1)
        except KeyboardInterrupt:
            print(f"\n{Y}[!] Interrupted.{NC}\n")
            sys.exit(0)
        sys.exit(0)

    # ── Local mode ──
    try:
        run_local(args.file, save=args.report, json_out=args.json, verbose=args.verbose)
    except KeyboardInterrupt:
        print(f"\n{Y}[!] Analysis interrupted by user.{NC}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{R}[✗] Error during analysis: {e}{NC}")
        import traceback; traceback.print_exc()
        sys.exit(1)

    print(f"\n{G}[✓] Analysis complete (local mode).{NC}\n")


if __name__ == "__main__":
    main()
