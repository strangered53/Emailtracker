#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║          EMAIL SOC TOOLKIT v2.0 — HEADER ANALYSIS + OSINT          ║
║          SOC Analyst Toolkit  |  Kali Linux  |  Python3            ║
╚══════════════════════════════════════════════════════════════════════╝

MODES:
  1. Header Analysis  — analyze .eml file or raw headers for phishing
  2. OSINT            — investigate a sender email address
  3. Full Pipeline    — analyze .eml AND auto-run OSINT on sender

Usage:
  python3 Email_tracker.py --demo
  python3 Email_tracker.py --file suspicious.eml
  python3 Email_tracker.py --file suspicious.eml --osint
  python3 Email_tracker.py --osint -e target@example.com
  python3 Email_tracker.py --demo --osint --json report.json
  python3 Email_tracker.py --demo --vt-key YOUR_API_KEY
⚠️  FOR AUTHORIZED INVESTIGATIONS & UNIVERSITY RESEARCH ONLY
"""

import argparse
import base64
import email
import hashlib
import ipaddress
import json
import re
import sys
import textwrap
import time
from datetime import datetime, timezone
from email import policy
from email.parser import Parser
from urllib.request import urlopen, Request
from urllib.error import HTTPError
from urllib.parse import quote_plus, urlparse


# ══════════════════════════════════════════════════════════════════════════════
#  COLORS
# ══════════════════════════════════════════════════════════════════════════════
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def section(title: str, width: int = 66):
    print(f"\n{C.CYAN}{C.BOLD}{'─'*width}\n  {title}\n{'─'*width}{C.RESET}")

def ok(msg):             print(f"  {C.GREEN}[✔]{C.RESET} {msg}")
def warn(msg):           print(f"  {C.YELLOW}[!]{C.RESET} {msg}")
def info(msg):           print(f"  {C.BLUE}[*]{C.RESET} {msg}")
def fail(msg):           print(f"  {C.RED}[✘]{C.RESET} {msg}")
def found(label, value): print(f"  {C.GREEN}[✔]{C.RESET} {C.BOLD}{label:<24}{C.RESET} {value}")
def notfound(label):     print(f"  {C.DIM}[–] {label:<24} not found{C.RESET}")

def banner():
    print(f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════════════╗
║        EMAIL SOC TOOLKIT v2.0 — HEADER ANALYSIS + OSINT            ║
║        Phishing Detection | IP Tracing | Attachment | OSINT         ║
║        SOC Analyst Toolkit  |  Python3  |  Cross-platform           ║
╚══════════════════════════════════════════════════════════════════════╝
{C.YELLOW}  ⚠  Authorized use only. This tool has known limitations — see output.{C.RESET}
""")


# ══════════════════════════════════════════════════════════════════════════════
#  DEMO EMAIL
# ══════════════════════════════════════════════════════════════════════════════
DEMO_RAW = """\
Delivered-To: victim@example.com
Received: from mail.fakepaypal.xyz (mail.fakepaypal.xyz [198.51.100.77])
        by mx.example.com with ESMTP id abc123
        for <victim@example.com>; Mon, 23 Jun 2025 09:12:04 +0000 (UTC)
Received: from [10.0.0.5] (unknown [10.0.0.5])
        by mail.fakepaypal.xyz with SMTP id xyz456
        Mon, 23 Jun 2025 09:11:58 +0000 (UTC)
Authentication-Results: mx.example.com;
   spf=fail (sender IP is 198.51.100.77) smtp.mailfrom=paypal.com;
   dkim=none;
   dmarc=fail action=none header.from=paypal.com
Received-SPF: fail (mx.example.com: domain of paypal.com does not designate
  198.51.100.77 as permitted sender) client-ip=198.51.100.77
From: "PayPal Security" <security@paypal.com>
Reply-To: support@fakepaypal.xyz
To: victim@example.com
Date: Mon, 23 Jun 2025 09:11:50 +0000
Subject: Urgent: Your account has been limited!
Message-ID: <abc123@fakepaypal.xyz>
X-Mailer: PHPMailer 6.0
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8
X-Originating-IP: 198.51.100.77

<html><body>
Dear Customer,<br>
Your PayPal account has been limited. Click <a href="http://fakepaypal.xyz/login">here</a> to verify.
<form action="http://fakepaypal.xyz/steal" method="post">
  <input type="password" name="pass">
</form>
</body></html>
"""

BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Accept": "application/json, text/html,*/*",
}

def http_get(url: str, timeout: int = 8, json_resp: bool = False,
             extra_headers: dict = None):
    """[FIX-12] Returns (data, status_code, error_type)."""
    hdrs = dict(BROWSER_HEADERS)
    if extra_headers:
        hdrs.update(extra_headers)
    try:
        req = Request(url, headers=hdrs)
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            data = json.loads(raw) if json_resp else raw.decode("utf-8", errors="replace")
            return data, resp.status, None
    except HTTPError as e:
        return None, e.code, "http_error"
    except TimeoutError:
        return None, None, "timeout"
    except Exception as e:
        return None, None, str(type(e).__name__)

def registrable_domain(value: str) -> str:
    """
    Extract registrable domain (e.g. paypal.com from sub.paypal.com).
    Uses tldextract if available, falls back to simple 2-part extraction.
    Prevents paypal.com.evil.xyz bypass.
    """
    host = urlparse(value).hostname or value
    host = host.lower().rstrip(".")
    try:
        import tldextract
        import logging
        # Suppress tldextract network errors (offline environments)
        logging.getLogger("tldextract").setLevel(logging.CRITICAL)
        ext = tldextract.extract(host)
        if ext.suffix and ext.domain:
            return f"{ext.domain}.{ext.suffix}"
    except Exception:
        pass
    # Fallback: take last two parts of hostname
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host

def valid_public_ip(value: str) -> bool:
    """[FIX-02] Validates IP using ipaddress module. Supports IPv4 + IPv6."""
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False

def extract_ips_from_text(text: str) -> list[str]:
    """Extract valid public IPs (IPv4 + IPv6) from text."""
    # IPv4
    ipv4 = re.findall(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', text)
    # IPv6 (simplified)
    ipv6 = re.findall(r'\b([0-9a-fA-F:]{7,39})\b', text)
    candidates = ipv4 + ipv6
    return [ip for ip in candidates if valid_public_ip(ip)]

def parse_email_msg(raw: str) -> email.message.Message:
    return Parser(policy=policy.default).parsestr(raw)

def extract_received_chain(msg: email.message.Message) -> list[dict]:
    hops = []
    received_headers = msg.get_all("Received") or []
    from_re = re.compile(r'from\s+([\w.\-]+)\s', re.IGNORECASE)
    by_re   = re.compile(r'by\s+([\w.\-]+)\s',   re.IGNORECASE)
    for i, hdr in enumerate(reversed(received_headers), 1):
        public_ips = extract_ips_from_text(hdr)   # FIX-02
        fm = from_re.search(hdr)
        by = by_re.search(hdr)
        hops.append({
            "hop":       i,
            "from_host": fm.group(1) if fm else "unknown",
            "by_host":   by.group(1) if by else "unknown",
            "ips":       public_ips,
            "raw":       hdr.strip()[:120],
        })
    return hops

def geolocate_ip(ip: str) -> dict:
    # [FIX-12] Use HTTPS endpoint
    data, status, err = http_get(
        f"https://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,query",
    )
    if data:
        try:
            parsed = json.loads(data) if isinstance(data, str) else data
            if parsed.get("status") == "success":
                return parsed
        except Exception:
            pass
    return {"query": ip, "country": "N/A", "city": "N/A",
            "regionName": "N/A", "isp": "N/A", "org": "N/A",
            "error": err}

KNOWN_ESP_PATTERNS = [
    "sendgrid", "amazonses", "mailchimp", "outbound.protection.outlook",
    "google", "googlemail", "mailgun", "sparkpost", "mandrill",
    "postmarkapp", "smtp.zoho", "mimecast", "proofpoint",
]

def parse_auth_results(msg: email.message.Message) -> dict:
    """
    [FIX-04] Read ALL Authentication-Results headers.
    Use the last one added by the receiving MTA (most trusted).
    Separate none/neutral/temperror/permerror from fail.
    """
    all_auth = msg.get_all("Authentication-Results") or []
    if not all_auth:
        return {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown",
                "trusted_header": False, "raw": ""}

    # Last header = added by our receiving server (most trustworthy)
    hdr = all_auth[-1]
    multiple = len(all_auth) > 1

    def _get(key):
        m = re.search(rf'{key}=([\w]+)', hdr, re.IGNORECASE)
        val = m.group(1).lower() if m else "unknown"
        # Separate error states from fail
        if val in ("temperror", "permerror"):
            return "error"
        return val

    return {
        "spf":            _get("spf"),
        "dkim":           _get("dkim"),
        "dmarc":          _get("dmarc"),
        "trusted_header": True,  # last header assumed from our MTA
        "multiple_headers": multiple,
        "raw":            hdr.strip()[:200],
    }


# ══════════════════════════════════════════════════════════════════════════════
#  FIX-09: PROPER MIME BODY DECODING
# ══════════════════════════════════════════════════════════════════════════════
def decode_part(part) -> tuple[str, str]:
    """Returns (plain_text, html_text) properly decoded with charset."""
    ct = part.get_content_type()
    payload_bytes = part.get_payload(decode=True)
    if not payload_bytes:
        return "", ""
    charset = part.get_content_charset() or "utf-8"
    try:
        text = payload_bytes.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        text = payload_bytes.decode("utf-8", errors="replace")
    if ct == "text/plain":
        return text, ""
    if ct == "text/html":
        return "", text
    return "", ""

def extract_body(msg: email.message.Message) -> tuple[str, str]:
    """Extract full plain + html body with proper charset decoding."""
    plain, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            p, h = decode_part(part)
            plain += p
            html  += h
    else:
        p, h = decode_part(msg)
        plain += p
        html  += h
    return plain, html


# ══════════════════════════════════════════════════════════════════════════════
#  PHISHING ANALYSIS — with all fixes
# ══════════════════════════════════════════════════════════════════════════════
def analyze_phishing(msg: email.message.Message,
                     hops: list, auth: dict,
                     plain_body: str, html_body: str) -> list[dict]:
    findings = []
    body_all = (plain_body + html_body).lower()

    # SPF
    if auth["spf"] in ("fail", "softfail"):
        findings.append({"severity": "HIGH", "category": "auth",
            "indicator": "SPF Failure",
            "detail": f"SPF={auth['spf'].upper()} — sending IP not authorized by domain"})

    # [FIX-05] DKIM none → LOW only; escalate if DMARC also fails
    if auth["dkim"] == "fail":
        findings.append({"severity": "HIGH", "category": "auth",
            "indicator": "DKIM Signature Failed",
            "detail": "DKIM signature invalid — email content may be tampered"})
    elif auth["dkim"] in ("none", "unknown"):
        sev = "MEDIUM" if auth["dmarc"] == "fail" else "LOW"
        findings.append({"severity": sev, "category": "auth",
            "indicator": "DKIM Not Present",
            "detail": "No DKIM signature — informational; not standalone evidence of phishing"})

    # DMARC
    if auth["dmarc"] == "fail":
        findings.append({"severity": "HIGH", "category": "auth",
            "indicator": "DMARC Failure",
            "detail": "DMARC policy failed — From domain spoofing likely"})

    # [FIX-04] Multiple Auth-Results headers warning
    if auth.get("multiple_headers"):
        findings.append({"severity": "LOW", "category": "auth",
            "indicator": "Multiple Authentication-Results Headers",
            "detail": "More than one Auth-Results header — possible header injection attempt"})

    # From / Reply-To mismatch
    from_addr = msg.get("From", "")
    reply_to  = msg.get("Reply-To", "")
    if reply_to:
        # Strip angle brackets and whitespace from domain part
        def _extract_domain(addr):
            m = re.search(r'@([\w.\-]+)', addr)
            return m.group(1).lower() if m else ""
        fd = registrable_domain(_extract_domain(from_addr))
        rd = registrable_domain(_extract_domain(reply_to))
        if fd and rd and fd != rd:
            findings.append({"severity": "HIGH", "category": "identity",
                "indicator": "From/Reply-To Domain Mismatch",
                "detail": f"From domain: {fd} | Reply-To domain: {rd}"})

    # [FIX-06] Sending host check — skip known ESPs
    lfd_match = re.search(r'@([\w.\-]+)', from_addr)
    if lfd_match:
        claimed_domain = lfd_match.group(1).lower()
        for hop in hops:
            hop_host = hop["from_host"].lower()
            is_esp = any(esp in hop_host for esp in KNOWN_ESP_PATTERNS)
            if not is_esp and claimed_domain not in hop_host and hop_host != "unknown":
                findings.append({"severity": "MEDIUM", "category": "routing",
                    "indicator": "Sending Host Doesn't Match From Domain",
                    "detail": f"Claimed: {claimed_domain} | Actual sender host: {hop['from_host']}"})
                break

    # Bulk mailer
    mailer = msg.get("X-Mailer", "") + msg.get("X-Sender", "")
    if any(x in mailer.lower() for x in ["phpmailer", "massmail"]):
        findings.append({"severity": "LOW", "category": "infrastructure",
            "indicator": "Script/Bulk Mailer Detected",
            "detail": f"X-Mailer: {mailer.strip()}"})

    # Urgency keywords
    subject = msg.get("Subject", "")
    urgency = [w for w in ["urgent","limited","suspended","verify","action required",
               "account locked","unusual activity","immediately","warning"]
               if w in subject.lower()]
    if urgency:
        findings.append({"severity": "MEDIUM", "category": "social_engineering",
            "indicator": "Urgency Language in Subject",
            "detail": f"Keywords: {', '.join(urgency)}"})

    urls = re.findall(r'href=["\']?(https?://[^\s"\'<>]+)', html_body, re.IGNORECASE)
    if urls and lfd_match:
        sender_reg = registrable_domain(claimed_domain)
        for url in urls:
            link_reg = registrable_domain(url)
            if link_reg and sender_reg and sender_reg != link_reg:
                findings.append({"severity": "HIGH", "category": "url",
                    "indicator": "Hyperlink Domain Mismatch",
                    "detail": f"Link domain: {link_reg} | Sender domain: {sender_reg}"})
                break

    cred_patterns = ["enter your password","confirm your password","verify your identity",
                     "update your payment","click here to verify","confirm your account",
                     "validate your email","unusual sign-in"]
    found_cred = [p for p in cred_patterns if p in body_all]
    if found_cred:
        findings.append({"severity": "HIGH", "category": "social_engineering",
            "indicator": "Credential Harvesting Language",
            "detail": f"Patterns found: {'; '.join(found_cred[:3])}"})

    hidden = re.findall(
        r'color\s*:\s*(?:white|#fff|#ffffff)|font-size\s*:\s*[01]px',
        html_body, re.IGNORECASE)
    if hidden:
        findings.append({"severity": "HIGH", "category": "evasion",
            "indicator": "Hidden Text Detected",
            "detail": "White/invisible text — spam filter evasion technique"})

    # HTML form
    if "<form" in html_body.lower():
        action = re.search(r'<form[^>]+action=["\']([^"\']+)', html_body, re.IGNORECASE)
        action_url = action.group(1) if action else "unknown"
        findings.append({"severity": "HIGH", "category": "credential_theft",
            "indicator": "HTML Form in Email Body",
            "detail": f"Form submits to: {action_url}"})

    # HTML entity obfuscation
    if "&#" in html_body and "@" in body_all:
        findings.append({"severity": "MEDIUM", "category": "evasion",
            "indicator": "HTML Entity Obfuscation",
            "detail": "HTML-encoded characters detected — spam filter evasion"})

    return findings

def compute_risk_score(findings: list) -> tuple[int, str]:
    """
    [FIX-08] Deduplicate findings by category to avoid double-counting
    same root cause (e.g. SPF+DMARC+host-mismatch all from one spoofed sender).
    [FIX-07] No CLEAN verdict — replaced with INCONCLUSIVE.
    """
    weights = {"HIGH": 30, "MEDIUM": 15, "LOW": 5}
    # Cap contribution per category to avoid inflation
    category_scores = {}
    for f in findings:
        cat   = f.get("category", "misc")
        sev   = f.get("severity", "LOW")
        score = weights.get(sev, 0)
        # Each category can contribute at most its highest-severity finding
        if cat not in category_scores or score > category_scores[cat]:
            category_scores[cat] = score

    score = min(sum(category_scores.values()), 100)

    if score >= 70:
        verdict = f"{C.RED}HIGH RISK — Strong phishing/spoofing indicators{C.RESET}"
    elif score >= 40:
        verdict = f"{C.YELLOW}SUSPICIOUS — Multiple indicators present{C.RESET}"
    elif score >= 15:
        verdict = f"{C.YELLOW}LOW CONFIDENCE — Minor indicators; analyst review needed{C.RESET}"
    else:
        # [FIX-07] Never say CLEAN
        verdict = f"{C.DIM}INCONCLUSIVE — No indicators detected by current rules{C.RESET}"

    return score, verdict

MITRE_MAP = {
    # Evidence → (technique_id, name, requires)
    "Hyperlink Domain Mismatch":        ("T1566.002", "Phishing: Spearphishing Link",       "url_evidence"),
    "HTML Form in Email Body":          ("T1566.002", "Phishing: Spearphishing Link",       "url_evidence"),
    "Credential Harvesting Language":   ("T1598",     "Phishing for Information",           "social_eng"),
    "Urgency Language in Subject":      ("T1598",     "Phishing for Information",           "social_eng"),
    "From/Reply-To Domain Mismatch":    ("T1036.005", "Masquerading: Match Legitimate Name","identity"),
    "DMARC Failure":                    ("T1036.005", "Masquerading: Match Legitimate Name","identity"),
    "SPF Failure":                      ("T1036",     "Masquerading",                       "auth"),
    "Hidden Text Detected":             ("T1027",     "Obfuscated Files or Information",    "evasion"),
    "HTML Entity Obfuscation":          ("T1027",     "Obfuscated Files or Information",    "evasion"),
    "Script/Bulk Mailer Detected":      ("T1586",     "Compromise Accounts",                "infra"),
}

def map_mitre(findings: list, attachments: list) -> list[tuple]:
    seen_ids = set()
    results  = []
    for f in findings:
        entry = MITRE_MAP.get(f["indicator"])
        if entry and entry[0] not in seen_ids:
            seen_ids.add(entry[0])
            results.append(entry)
    # Attachment-based mapping
    if any(a["severity"] == "HIGH" for a in attachments):
        tid = "T1566.001"
        if tid not in seen_ids:
            results.append((tid, "Phishing: Spearphishing Attachment", "attachment_evidence"))
    if not results:
        results.append(("N/A", "No technique mapped — analyst validation required", ""))
    return results


DANGEROUS_EXT = {".exe",".com",".bat",".cmd",".msi",".pif",".scr",".jar",
                 ".js",".jse",".vbs",".vbe",".ps1",".psm1",".sh",
                 ".doc",".dot",".xls",".xlt",".xlam",".ppt",
                 ".zip",".rar",".7z",".iso",".img",
                 ".lnk",".hta",".chm",".reg",".dll"}
MEDIUM_EXT    = {".pdf",".docx",".xlsx",".pptx",".html",".htm"}

def analyze_attachments(msg: email.message.Message) -> list[dict]:
    results = []
    for part in msg.walk():
        disposition = part.get_content_disposition() or ""
        filename    = part.get_filename() or ""
        content_type = part.get_content_type()
        if not filename and "attachment" not in disposition:
            continue

        fn_lower = filename.lower()
        ext = ("." + fn_lower.rsplit(".", 1)[-1]) if "." in fn_lower else ""
        severity, flags = "INFO", []

        # Double extension
        if len(fn_lower.split(".")) > 2 and ext in DANGEROUS_EXT:
            flags.append(f"Double extension: {filename}")
            severity = "HIGH"
        if ext in DANGEROUS_EXT:
            flags.append(f"Dangerous file type: {ext}")
            severity = "HIGH"
        elif ext in MEDIUM_EXT:
            flags.append(f"Potentially exploitable type: {ext}")
            severity = "MEDIUM"

        encoding = part.get("Content-Transfer-Encoding", "").lower()
        if encoding == "base64" and ext in DANGEROUS_EXT:
            flags.append("Base64-encoded dangerous attachment")
            severity = "HIGH"

        if fn_lower.endswith(".pdf") and "pdf" not in content_type:
            flags.append(f"MIME type mismatch: {content_type}")
            severity = "HIGH"

        sha256, size_kb = "N/A", 0
        try:
            payload = part.get_payload(decode=True)
            if payload:
                sha256   = hashlib.sha256(payload).hexdigest()
                size_kb  = round(len(payload) / 1024, 1)
        except Exception:
            pass

        results.append({
            "filename":     filename or "(unnamed)",
            "content_type": content_type,
            "encoding":     encoding,
            "size_kb":      size_kb,
            "sha256":       sha256,
            "severity":     severity,
            "flags":        flags or ["No immediate threat detected"],
        })
    return results


URL_SHORTENERS = {"bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","short.link",
                  "rebrand.ly","cutt.ly","is.gd","buff.ly","tiny.cc"}

def analyze_urls(urls: list[str], sender_domain: str) -> list[dict]:
    results = []
    sender_reg = registrable_domain(sender_domain) if sender_domain else ""
    for url in urls:
        flags, severity = [], "INFO"
        url_domain = urlparse(url).hostname or ""

        if any(s in url_domain for s in URL_SHORTENERS):
            flags.append("URL shortener — hides real destination")
            severity = "HIGH"

        # [FIX-01] Compare registrable domains
        link_reg = registrable_domain(url)
        if sender_reg and link_reg and sender_reg != link_reg:
            flags.append(f"Registrable domain mismatch: {link_reg} vs sender {sender_reg}")
            if severity != "HIGH": severity = "MEDIUM"

        if re.match(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            flags.append("Raw IP address URL — suspicious")
            severity = "HIGH"

        sus = [w for w in ["login","signin","verify","account","secure","update",
                            "confirm","banking","paypal","apple","microsoft"]
               if w in url.lower() and sender_reg not in link_reg]
        if sus:
            flags.append(f"Suspicious keywords in URL: {', '.join(sus)}")
            if severity != "HIGH": severity = "MEDIUM"

        results.append({"url": url[:100], "domain": url_domain,
                         "severity": severity,
                         "flags": flags or ["No immediate threat"]})
    return results


def virustotal_check_url(url: str, api_key: str) -> dict:
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    data, status, err = http_get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        extra_headers={"x-apikey": api_key}
    )
    if data:
        try:
            parsed = json.loads(data) if isinstance(data, str) else data
            stats = parsed["data"]["attributes"]["last_analysis_stats"]
            return {"url": url[:80], "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "clean": stats.get("harmless", 0)}
        except Exception:
            pass
    return {"url": url[:80], "error": err or f"HTTP {status}"}

def virustotal_check_hash(sha256: str, api_key: str) -> dict:
    data, status, err = http_get(
        f"https://www.virustotal.com/api/v3/files/{sha256}",
        extra_headers={"x-apikey": api_key}
    )
    if status == 404:
        return {"sha256": sha256, "error": "Not in VirusTotal database"}
    if data:
        try:
            parsed = json.loads(data) if isinstance(data, str) else data
            stats  = parsed["data"]["attributes"]["last_analysis_stats"]
            name   = parsed["data"]["attributes"].get("meaningful_name", "unknown")
            return {"sha256": sha256, "name": name,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "clean": stats.get("harmless", 0)}
        except Exception:
            pass
    return {"sha256": sha256, "error": err or f"HTTP {status}"}


# ══════════════════════════════════════════════════════════════════════════════
#  HEADER REPORT PRINTER
# ══════════════════════════════════════════════════════════════════════════════
def print_header_report(msg, hops, auth, findings, geo_results,
                        attachments, url_analysis, vt_results, mitre):

    section("📧  EMAIL METADATA")
    for f in ["From","To","Subject","Date","Message-ID","Reply-To","X-Mailer"]:
        val = msg.get(f, f"{C.DIM}(not present){C.RESET}")
        print(f"  {C.BOLD}{f:<15}{C.RESET} {val}")

    section("🔐  AUTHENTICATION  (SPF / DKIM / DMARC)")
    icons = {"pass":     f"{C.GREEN}PASS{C.RESET}",
             "fail":     f"{C.RED}FAIL{C.RESET}",
             "softfail": f"{C.YELLOW}SOFTFAIL{C.RESET}",
             "none":     f"{C.DIM}NONE{C.RESET}",
             "error":    f"{C.YELLOW}ERROR (temperror/permerror){C.RESET}",
             "unknown":  f"{C.DIM}UNKNOWN (header missing){C.RESET}"}
    for key in ("spf","dkim","dmarc"):
        print(f"  {key.upper():<8} {icons.get(auth[key], auth[key])}")
    if auth.get("multiple_headers"):
        warn("Multiple Authentication-Results headers found — possible header injection")

    section("🌐  EMAIL ROUTING  (Received Chain)")
    for hop in hops:
        print(f"\n  {C.BOLD}Hop {hop['hop']}{C.RESET}")
        print(f"  {'From:':<10} {hop['from_host']}")
        print(f"  {'By:':<10} {hop['by_host']}")
        for ip in hop["ips"]:
            print(f"  {'IP:':<10} {ip}")

    if geo_results:
        section("🗺️   IP GEOLOCATION")
        for geo in geo_results:
            print(f"\n  {C.BOLD}{geo.get('query','?')}{C.RESET}")
            print(f"  {'Location:':<12} {geo.get('city','?')}, "
                  f"{geo.get('regionName','?')}, {geo.get('country','?')}")
            print(f"  {'ISP/Org:':<12} {geo.get('isp','?')} / {geo.get('org','?')}")

    if attachments:
        section("📎  ATTACHMENT ANALYSIS")
        for att in attachments:
            sev_color = {
                "HIGH": C.RED, "MEDIUM": C.YELLOW,
                "LOW": C.BLUE, "INFO": C.DIM
            }.get(att["severity"], "")
            print(f"\n  {sev_color}{C.BOLD}[{att['severity']}]{C.RESET}  {att['filename']}")
            print(f"  {'Type:':<12} {att['content_type']}  |  Size: {att['size_kb']} KB")
            print(f"  {'SHA256:':<12} {C.DIM}{att['sha256']}{C.RESET}")
            for flag in att["flags"]:
                print(f"  {C.YELLOW}  ⚑{C.RESET} {flag}")
    else:
        section("📎  ATTACHMENT ANALYSIS")
        ok("No attachments found")

    if url_analysis:
        section("🔗  URL ANALYSIS")
        for u in url_analysis:
            sev_color = {"HIGH": C.RED, "MEDIUM": C.YELLOW}.get(u["severity"], C.DIM)
            print(f"\n  {sev_color}[{u['severity']}]{C.RESET} {u['url']}")
            for flag in u["flags"]:
                print(f"    {C.YELLOW}⚑{C.RESET} {flag}")

    if vt_results:
        section("🦠  VIRUSTOTAL RESULTS")
        for vt in vt_results:
            if "error" in vt:
                warn(f"{vt.get('url', vt.get('sha256','?'))}: {vt['error']}")
            else:
                mal = vt.get("malicious", 0)
                color = C.RED if mal > 0 else C.GREEN
                label = vt.get("url", vt.get("sha256","?"))
                print(f"  {color}Malicious: {mal}{C.RESET}  "
                      f"Suspicious: {vt.get('suspicious',0)}  "
                      f"Clean: {vt.get('clean',0)}  — {label}")

    section("⚠️   PHISHING / SPOOFING INDICATORS")
    if not findings:
        info("No indicators detected by current rules.")
    else:
        colors = {"HIGH": C.RED, "MEDIUM": C.YELLOW, "LOW": C.BLUE}
        for f in findings:
            c = colors.get(f["severity"], "")
            print(f"\n  {c}{C.BOLD}[{f['severity']}]{C.RESET}  {f['indicator']}")
            print(f"  {C.DIM}         {f['detail']}{C.RESET}")

    section("🎯  RISK ASSESSMENT")
    score, verdict = compute_risk_score(findings)
    bar = f"{'█' * int(score/5)}{'░' * (20 - int(score/5))}"
    c   = C.RED if score >= 70 else (C.YELLOW if score >= 15 else C.DIM)
    print(f"\n  Risk Score: {c}{C.BOLD}{score}/100{C.RESET}  [{c}{bar}{C.RESET}]")
    print(f"  Verdict:    {verdict}")
    # [FIX-14] Always note tool limitations
    print(f"\n  {C.DIM}⚠  This is a rule-based scanner. A low score does NOT confirm")
    print(f"     the email is safe. Results require analyst validation.{C.RESET}")

    section("🛡️   MITRE ATT&CK MAPPING  (evidence-based)")
    for tid, name, evidence in mitre:
        if tid == "N/A":
            print(f"  {C.DIM}{name}{C.RESET}")
        else:
            print(f"  {C.CYAN}{tid}{C.RESET}  {name}")
            if evidence:
                print(f"  {C.DIM}         Evidence: {evidence}{C.RESET}")
    print(f"\n  {C.DIM}Reference: https://attack.mitre.org/tactics/TA0001/{C.RESET}")

def validate_email_addr(addr: str) -> dict:
    try:
        from email_validator import validate_email, EmailNotValidError
        result = validate_email(addr, check_deliverability=False)
        parts = result.normalized.split("@")
        return {"valid": True, "username": parts[0], "domain": parts[1],
                "normalized": result.normalized}
    except ImportError:
        pass
    except Exception:
        return {"valid": False, "username": "", "domain": "", "normalized": addr}
    # Fallback regex
    if re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', addr):
        parts = addr.split("@")
        return {"valid": True, "username": parts[0], "domain": parts[1], "normalized": addr}
    return {"valid": False, "username": "", "domain": "", "normalized": addr}

def derive_usernames(username: str) -> list[str]:
    candidates = [username]
    for sep in [".", "_", "-"]:
        if sep in username:
            candidates.append(username.replace(sep, ""))
            parts = username.split(sep)
            if len(parts) >= 2:
                candidates.append(parts[0])
                candidates.append(parts[0] + parts[-1])
    return list(dict.fromkeys(candidates))

def dns_mx_lookup(domain: str) -> list[str]:
    data, _, _ = http_get(f"https://dns.google/resolve?name={domain}&type=MX", json_resp=True)
    if data:
        try:
            parsed = json.loads(data) if isinstance(data, str) else data
            if parsed.get("Answer"):
                return [r["data"] for r in parsed["Answer"] if r.get("type") == 15]
        except Exception:
            pass
    return []

def whois_domain(domain: str) -> dict:
    data, _, _ = http_get(f"https://rdap.org/domain/{domain}", json_resp=True)
    if not data:
        return {}
    try:
        parsed = json.loads(data) if isinstance(data, str) else data
        registrar = next(
            (e["fn"][0] for e in parsed.get("entities", [])
             if "registrar" in e.get("roles", []) and e.get("fn")), "N/A")
        events = {e["eventAction"]: e["eventDate"] for e in parsed.get("events", [])}
        return {"registrar":  registrar,
                "registered": events.get("registration", "N/A")[:10],
                "expires":    events.get("expiration",   "N/A")[:10],
                "status":     ", ".join(parsed.get("status", []))}
    except Exception:
        return {}

def check_gravatar(addr: str) -> dict:
    md5 = hashlib.md5(addr.strip().lower().encode()).hexdigest()
    data, status, _ = http_get(f"https://www.gravatar.com/{md5}.json", json_resp=True)
    if data:
        try:
            parsed = json.loads(data) if isinstance(data, str) else data
            entry  = parsed["entry"][0]
            return {"found": True,
                    "display_name": entry.get("displayName","N/A"),
                    "profile_url":  entry.get("profileUrl","N/A"),
                    "avatar_url":   f"https://www.gravatar.com/avatar/{md5}?s=200",
                    "location":     entry.get("currentLocation","N/A"),
                    "about":        entry.get("aboutMe","N/A")[:120],
                    "accounts":     [a.get("name","") for a in entry.get("accounts",[])],
                    "urls":         [u.get("value","") for u in entry.get("urls",[])]}
        except Exception:
            pass
    # Fallback: avatar image check
    _, avatar_status, _ = http_get(f"https://www.gravatar.com/avatar/{md5}?d=404")
    if avatar_status == 200:
        return {"found": True, "display_name": "N/A (no public profile)",
                "profile_url": f"https://www.gravatar.com/{md5}",
                "avatar_url":  f"https://www.gravatar.com/avatar/{md5}?s=200",
                "location": "N/A", "about": "N/A", "accounts": [], "urls": []}
    return {"found": False}

# [FIX-13] Platform probing with granular status
PLATFORMS = [
    ("GitHub",     "https://github.com/{}"),
    ("GitLab",     "https://gitlab.com/{}"),
    ("Twitter/X",  "https://twitter.com/{}"),
    ("Instagram",  "https://www.instagram.com/{}/"),
    ("TikTok",     "https://www.tiktok.com/@{}"),
    ("Reddit",     "https://www.reddit.com/user/{}/"),
    ("LinkedIn",   "https://www.linkedin.com/in/{}"),
    ("Pinterest",  "https://www.pinterest.com/{}/"),
    ("Tumblr",     "https://{}.tumblr.com"),
    ("Medium",     "https://medium.com/@{}"),
    ("Dev.to",     "https://dev.to/{}"),
    ("Keybase",    "https://keybase.io/{}"),
    ("Pastebin",   "https://pastebin.com/u/{}"),
    ("HackerNews", "https://news.ycombinator.com/user?id={}"),
    ("Steam",      "https://steamcommunity.com/id/{}"),
    ("Twitch",     "https://www.twitch.tv/{}"),
    ("Replit",     "https://replit.com/@{}"),
    ("Fiverr",     "https://www.fiverr.com/{}"),
]

NOT_FOUND_PATTERNS = [
    "user not found", "page not found", "this account doesn't exist",
    "sorry, that page", "no user found", "404", "doesn't exist",
    "profile not found", "account suspended",
]

def probe_platform(name: str, url_tpl: str, username: str) -> dict:
    """[FIX-03] [FIX-13] Returns granular status: FOUND/NOT_FOUND/BLOCKED/RATE_LIMITED/UNKNOWN/NETWORK_ERROR."""
    url = url_tpl.format(username)
    data, status, err = http_get(url)

    if err or status is None:
        return {"platform": name, "username": username, "url": url,
                "status": "NETWORK_ERROR", "found": False, "detail": err}

    if status == 429:
        return {"platform": name, "username": username, "url": url,
                "status": "RATE_LIMITED", "found": False}

    if status in (403, 401):
        return {"platform": name, "username": username, "url": url,
                "status": "BLOCKED", "found": False}

    if status == 404:
        return {"platform": name, "username": username, "url": url,
                "status": "NOT_FOUND", "found": False}

    if status == 200:
        # Secondary check: look for "not found" patterns in page content
        content = (data or "").lower()
        if any(p in content for p in NOT_FOUND_PATTERNS):
            return {"platform": name, "username": username, "url": url,
                    "status": "NOT_FOUND", "found": False}
        return {"platform": name, "username": username, "url": url,
                "status": "FOUND", "found": True}

    return {"platform": name, "username": username, "url": url,
            "status": "UNKNOWN", "found": False, "detail": f"HTTP {status}"}

def resolve_domain_ips(domain: str) -> list[str]:
    data, _, _ = http_get(f"https://dns.google/resolve?name={domain}&type=A", json_resp=True)
    if data:
        try:
            parsed = json.loads(data) if isinstance(data, str) else data
            return list(dict.fromkeys(
                r["data"] for r in parsed.get("Answer", [])
                if r.get("type") == 1 and valid_public_ip(r["data"])
            ))
        except Exception:
            pass
    return []

def generate_dork_links(addr: str, username: str, domain: str) -> list[dict]:
    dorks = [
        ("Email mentions on web",  f'"{addr}"'),
        ("Email on Pastebin",      f'site:pastebin.com "{addr}"'),
        ("Email on GitHub",        f'site:github.com "{addr}"'),
        ("Username on GitHub",     f'site:github.com "{username}"'),
        ("Email in documents",     f'"{addr}" filetype:pdf OR filetype:docx'),
        ("LinkedIn profile",       f'site:linkedin.com "{username}"'),
        ("Email in forums",        f'"{addr}" site:reddit.com OR site:stackoverflow.com'),
        ("Domain + email",         f'"{addr}" site:{domain}'),
    ]
    base = "https://www.google.com/search?q="
    return [{"label": l, "url": base + quote_plus(q)} for l, q in dorks]

def run_osint(addr: str, no_social: bool = False, no_geo: bool = False) -> dict:
    addr   = addr.strip().lower()
    struct = validate_email_addr(addr)
    if not struct["valid"]:
        fail(f"Invalid email address: {addr}")
        return {}

    username  = struct["username"]
    domain    = struct["domain"]
    usernames = derive_usernames(username)

    info(f"OSINT target:        {C.BOLD}{addr}{C.RESET}")
    info(f"Candidate usernames: {', '.join(usernames)}")

    info("Looking up MX / WHOIS...")
    mx    = dns_mx_lookup(domain)
    whois = whois_domain(domain)

    geo_results = []
    if not no_geo:
        info("Resolving domain IPs for geolocation...")
        domain_ips = resolve_domain_ips(domain)
        mx_ips = []
        for mx_rec in mx[:2]:
            mx_host = mx_rec.split()[-1].rstrip(".")
            mx_ips.extend(resolve_domain_ips(mx_host))
        all_ips = list(dict.fromkeys(domain_ips + mx_ips))[:5]
        for ip in all_ips:
            geo = geolocate_ip(ip)
            geo_results.append(geo)
            ok(f"Server IP {ip} → {geo.get('city','?')}, {geo.get('country','?')} ({geo.get('isp','?')})")

    info("Checking Gravatar...")
    gravatar = check_gravatar(addr)

    social_hits, social_other = [], []
    if not no_social:
        info(f"Scanning {len(PLATFORMS)} platforms...")
        checked = {}
        for name, url_tpl in PLATFORMS:
            for uname in usernames:
                if name in checked:
                    break
                result = probe_platform(name, url_tpl, uname)
                time.sleep(0.25)
                if result["found"]:
                    checked[name] = True
                    social_hits.append(result)
                    ok(f"FOUND on {name}: {result['url']}")
                    break
                elif result["status"] in ("RATE_LIMITED", "BLOCKED", "NETWORK_ERROR"):
                    checked[name] = True
                    social_other.append(result)
                    warn(f"{result['status']} on {name}")
                    break
            if name not in checked:
                social_other.append({"platform": name, "status": "NOT_FOUND", "found": False})

    hibp  = {"note": "HIBP requires API key — check manually",
             "manual_url": f"https://haveibeenpwned.com/account/{quote_plus(addr)}"}
    dorks = generate_dork_links(addr, username, domain)

    return {"email": addr, "struct": struct, "mx": mx, "whois": whois,
            "geo": geo_results, "gravatar": gravatar,
            "social_hits": social_hits, "social_other": social_other,
            "hibp": hibp, "dorks": dorks}

def print_osint_report(r: dict):
    addr = r["email"]

    section("📧  EMAIL STRUCTURE")
    ok("Valid email address")
    found("Username",   r["struct"]["username"])
    found("Domain",     r["struct"]["domain"])
    found("Normalized", r["struct"].get("normalized", addr))

    section("🌐  DOMAIN INTELLIGENCE")
    if r["mx"]:
        found("MX Record",  r["mx"][0] + (f" (+{len(r['mx'])-1} more)" if len(r["mx"])>1 else ""))
    else:
        warn("No MX records found")
    if r["whois"]:
        found("Registrar",  r["whois"].get("registrar","N/A"))
        found("Registered", r["whois"].get("registered","N/A"))
        found("Expires",    r["whois"].get("expires","N/A"))
        found("Status",     r["whois"].get("status","N/A"))
    else:
        warn("WHOIS/RDAP data unavailable")

    section("🗺️   MAIL SERVER GEOLOCATION")
    if r.get("geo"):
        for geo in r["geo"]:
            print(f"\n  {C.BOLD}IP: {geo.get('query','?')}{C.RESET}")
            print(f"  {'Location:':<14} {geo.get('city','?')}, {geo.get('regionName','?')}, {geo.get('country','?')}")
            print(f"  {'ISP/Org:':<14} {geo.get('isp','?')} / {geo.get('org','?')}")
        print(f"\n  {C.DIM}Note: Mail SERVER location — not the sender's personal location.{C.RESET}")
    else:
        warn("No geolocation data (large providers like Gmail block IP resolution)")

    section("🖼️   GRAVATAR PROFILE")
    if r["gravatar"].get("found"):
        g = r["gravatar"]
        found("Display Name", g["display_name"])
        found("Profile URL",  g["profile_url"])
        found("Avatar URL",   g["avatar_url"])
        if g["location"] != "N/A": found("Location", g["location"])
        if g["about"]    != "N/A": found("About",    g["about"])
        if g["accounts"]:          found("Linked Accts", ", ".join(g["accounts"]))
        for u in g["urls"]:        found("URL", u)
    else:
        notfound("Gravatar account")
        print(f"  {C.DIM}  Most people don't use Gravatar — this is expected.{C.RESET}")

    section("🔍  SOCIAL MEDIA & PLATFORM SCAN")
    if r["social_hits"]:
        for h in r["social_hits"]:
            found(h["platform"], f"{h['url']}  {C.DIM}(username: {h['username']}){C.RESET}")
    else:
        warn("No accounts confirmed found")

    # [FIX-13] Show granular status for blocked/rate-limited
    blocked = [h for h in r.get("social_other",[]) if h["status"] in ("BLOCKED","RATE_LIMITED")]
    not_found = [h for h in r.get("social_other",[]) if h["status"] == "NOT_FOUND"]
    if blocked:
        print(f"\n  {C.YELLOW}Inconclusive (blocked/rate-limited):{C.RESET} "
              f"{', '.join(h['platform'] for h in blocked)}")
    if not_found:
        print(f"\n  {C.DIM}Not found: {', '.join(h['platform'] for h in not_found)}{C.RESET}")

    section("💥  BREACH CHECK  (HaveIBeenPwned)")
    warn(r["hibp"]["note"])
    info(f"Check manually → {r['hibp']['manual_url']}")

    section("🔎  GOOGLE DORK LINKS")
    for d in r["dorks"]:
        print(f"  {C.CYAN}•{C.RESET} {d['label']}")
        print(f"    {C.DIM}{d['url']}{C.RESET}")

    section("📊  OSINT SUMMARY")
    total = len(r["social_hits"]) + (1 if r["gravatar"].get("found") else 0)
    c = C.GREEN if total > 0 else C.DIM
    print(f"\n  {C.BOLD}Email:          {C.RESET}{addr}")
    print(f"  {C.BOLD}Accounts found: {C.RESET}{c}{total} platform(s){C.RESET}")
    print(f"\n  {C.DIM}Note: HTTP 200 alone does not confirm account existence.")
    print(f"  Results marked BLOCKED/RATE_LIMITED require manual verification.{C.RESET}")


# ══════════════════════════════════════════════════════════════════════════════
#  JSON EXPORT
# ══════════════════════════════════════════════════════════════════════════════
def export_json(path: str, header_data: dict, osint_data: dict):
    payload = {"analyzed_at": datetime.now(timezone.utc).isoformat(),
               "tool_version": "2.0",
               "header_analysis": header_data,
               "osint": osint_data}
    with open(path, "w") as f:
        json.dump(payload, f, indent=2, default=str)
    ok(f"JSON report saved → {path}")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="Email SOC Toolkit v2.0 — Header Analysis + OSINT",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          python3 email_soc_toolkit.py --demo
          python3 email_soc_toolkit.py --file suspicious.eml --osint
          python3 email_soc_toolkit.py --osint -e target@example.com
          python3 email_soc_toolkit.py --demo --vt-key YOUR_KEY --json report.json
        """)
    )
    src = parser.add_mutually_exclusive_group()
    src.add_argument("--file", metavar="FILE",  help="Path to .eml file")
    src.add_argument("--raw",  action="store_true", help="Paste raw headers (stdin)")
    src.add_argument("--demo", action="store_true", help="Built-in demo phishing email")

    parser.add_argument("--osint",     action="store_true", help="Run OSINT on sender")
    parser.add_argument("-e","--email",metavar="EMAIL",      help="Email for OSINT-only mode")
    parser.add_argument("--no-geo",    action="store_true",  help="Skip IP geolocation")
    parser.add_argument("--no-social", action="store_true",  help="Skip social platform scan")
    parser.add_argument("--vt-key",   metavar="KEY",        help="VirusTotal API key")
    parser.add_argument("--json",      metavar="FILE",       help="Export JSON report")
    args = parser.parse_args()

    if not any([args.file, args.raw, args.demo, args.email]):
        parser.print_help()
        sys.exit(1)

    banner()

    header_data, osint_data = {}, {}

    # ── HEADER ANALYSIS ───────────────────────────────────────────────────────
    if args.file or args.raw or args.demo:
        if args.demo:
            info("Loading built-in demo phishing email...\n")
            raw = DEMO_RAW
        elif args.file:
            try:
                with open(args.file, "rb") as f:
                    raw = f.read().decode("utf-8", errors="replace")
                info(f"Loaded: {args.file}\n")
            except FileNotFoundError:
                fail(f"File not found: {args.file}"); sys.exit(1)
        else:
            info("Paste raw email headers. Press Ctrl+D when done:\n")
            raw = sys.stdin.read()

        msg          = parse_email_msg(raw)
        hops         = extract_received_chain(msg)
        auth         = parse_auth_results(msg)
        plain, html  = extract_body(msg)          # FIX-09
        findings     = analyze_phishing(msg, hops, auth, plain, html)
        attachments  = analyze_attachments(msg)
        score, _     = compute_risk_score(findings)

        # URL extraction and analysis
        from_match   = re.search(r'@([\S]+)', msg.get("From",""))
        sender_dom   = from_match.group(1).rstrip(">") if from_match else ""
        raw_urls     = re.findall(r'href=["\']?(https?://[^\s"\'<>]+)', html, re.IGNORECASE)
        raw_urls     = list(dict.fromkeys(raw_urls))[:20]
        url_analysis = analyze_urls(raw_urls, sender_dom)

        # Geolocation
        geo_results = []
        if not args.no_geo:
            all_ips = list(dict.fromkeys(ip for h in hops for ip in h["ips"]))
            for ip in all_ips[:5]:
                geo_results.append(geolocate_ip(ip))

        # VirusTotal
        vt_results = []
        if args.vt_key:
            info("Running VirusTotal checks...")
            for u in [u["url"] for u in url_analysis if u["severity"] == "HIGH"][:3]:
                vt_results.append(virustotal_check_url(u, args.vt_key))
            for att in attachments:
                if att["sha256"] != "N/A" and att["severity"] == "HIGH":
                    vt_results.append(virustotal_check_hash(att["sha256"], args.vt_key))

        mitre = map_mitre(findings, attachments)   # FIX-10
        print_header_report(msg, hops, auth, findings, geo_results,
                            attachments, url_analysis, vt_results, mitre)

        header_data = {
            "from": msg.get("From",""), "to": msg.get("To",""),
            "subject": msg.get("Subject",""), "date": msg.get("Date",""),
            "reply_to": msg.get("Reply-To",""), "auth": auth,
            "hops": hops, "geo": geo_results, "findings": findings,
            "attachments": attachments, "url_analysis": url_analysis,
            "vt_results": vt_results, "mitre": mitre, "risk_score": score,
        }

        # Auto-OSINT on sender
        if args.osint and not args.email:
            m = re.search(r'[\w._%+\-]+@[\w.\-]+\.[a-zA-Z]{2,}', msg.get("From",""))
            if m:
                sender_email = m.group(0).lower()
                section(f"🔬  AUTO-OSINT ON SENDER:  {sender_email}")
                osint_data = run_osint(sender_email,
                                       no_social=args.no_social,
                                       no_geo=args.no_geo)
                if osint_data:
                    print_osint_report(osint_data)
            else:
                warn("Could not extract sender email for OSINT")

    # ── STANDALONE OSINT ──────────────────────────────────────────────────────
    if args.email:
        section(f"🔬  OSINT MODE:  {args.email}")
        osint_data = run_osint(args.email,
                               no_social=args.no_social,
                               no_geo=args.no_geo)
        if osint_data:
            print_osint_report(osint_data)

    # ── FOOTER ────────────────────────────────────────────────────────────────
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"\n{C.DIM}{'─'*66}")
    print(f"  Analysis complete — {ts}  |  Tool version: 2.0")
    print(f"  Findings require analyst validation before any action is taken.")
    print(f"{'─'*66}{C.RESET}\n")

    if args.json:
        export_json(args.json, header_data, osint_data)


if __name__ == "__main__":
    main()
