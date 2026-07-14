# Emailtracker
That's for Educational purpose Email_tracking tool so you should use that for only hands on lab.
# 📧 Email SOC Toolkit v2.0

A Python-based SOC analyst tool for email header analysis, phishing detection, attachment scanning, and sender OSINT. Built for Kali Linux as a university cybersecurity project.

---

## ⚠️ Legal Disclaimer

> This tool is intended **for authorized investigations, academic research, and educational purposes only.**
> Do not use this tool against emails or individuals without explicit written authorization.
> Unauthorized use may violate the Myanmar Computer Science Development Law, GDPR, and other applicable laws.
> The author assumes no responsibility for misuse of this tool.

---

## 📋 Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Modules](#modules)
- [Output Example](#output-example)
- [VirusTotal Integration](#virustotal-integration)
- [JSON Export](#json-export)
- [Limitations](#limitations)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Changelog](#changelog)

---

## ✨ Features

| Module | What It Does |
|---|---|
| **Header Analysis** | Parse `.eml` files or raw headers for routing and metadata |
| **SPF / DKIM / DMARC** | Checks all `Authentication-Results` headers from trusted MTA |
| **Phishing Detection** | 10+ indicators: domain spoofing, urgency language, hidden text, HTML forms |
| **IP Geolocation** | Traces public IPs in Received chain — country, city, ISP |
| **Attachment Analysis** | Flags dangerous extensions, double extensions, MIME mismatches, SHA256 hash |
| **URL Analysis** | Registrable-domain comparison, shortener detection, raw IP URLs |
| **VirusTotal** | Optional — checks suspicious URLs and attachment hashes |
| **OSINT** | Gravatar lookup, 18-platform social scan, WHOIS, MX, Google dorks |
| **Risk Score** | 0–100 score with category deduplication (no double-counting) |
| **MITRE ATT&CK** | Evidence-based mapping to relevant techniques |
| **JSON Export** | SIEM-ready output for integration with dashboards |

---

## 🖥️ Requirements

- Python 3.10 or higher
- Works on: **Kali Linux**, Ubuntu, Debian, macOS, Windows (with Python installed)
- Internet connection (for geolocation, WHOIS, Gravatar, VirusTotal)

### Python Dependencies

| Package | Required | Purpose |
|---|---|---|
| `requests` | ✅ Yes | HTTP requests |
| `tldextract` | ⭐ Recommended | Accurate registrable domain extraction |
| `email-validator` | ⭐ Recommended | Strict email address validation |

> The tool works without `tldextract` and `email-validator` using built-in fallbacks, but installing them improves accuracy.

---

## 🔧 Installation

**Step 1 — Clone or download the tool**

```bash
# Place the file in your home directory
mv email_soc_toolkit.py ~/
cd ~/
```

**Step 2 — Install dependencies**

```bash
pip3 install requests tldextract email-validator --break-system-packages
```

**Step 3 — Make executable (optional)**

```bash
chmod +x email_soc_toolkit.py
```

**Step 4 — Verify installation**

```bash
python3 email_soc_toolkit.py --demo
```

You should see a full analysis of a built-in fake PayPal phishing email.

---

## 🚀 Usage

### Basic Commands

```bash
# Run built-in demo phishing email
python3 email_soc_toolkit.py --demo

# Analyze a real .eml file
python3 email_soc_toolkit.py --file suspicious.eml

# Paste raw email headers manually
python3 email_soc_toolkit.py --raw

# OSINT on a specific email address
python3 email_soc_toolkit.py --osint -e sender@example.com
```

### Full Pipeline (Most Powerful)

```bash
# Analyze headers AND auto-run OSINT on the sender
python3 email_soc_toolkit.py --file suspicious.eml --osint

# Same with demo email
python3 email_soc_toolkit.py --demo --osint
```

### With VirusTotal

```bash
# Get a free API key at https://www.virustotal.com
python3 email_soc_toolkit.py --file suspicious.eml --vt-key YOUR_API_KEY
```

### Export Results

```bash
# Save full report as JSON (for SIEM integration)
python3 email_soc_toolkit.py --file suspicious.eml --osint --json report.json
```

### Speed Options

```bash
# Skip geolocation (faster, offline)
python3 email_soc_toolkit.py --file suspicious.eml --no-geo

# Skip social media platform scan (faster)
python3 email_soc_toolkit.py --osint -e target@example.com --no-social

# Offline mode (skip both)
python3 email_soc_toolkit.py --file suspicious.eml --no-geo --no-social
```

### All Options

```
--demo              Use built-in demo phishing email
--file FILE         Path to .eml file
--raw               Paste raw email headers via stdin
--osint             Run OSINT on the sender email
-e, --email EMAIL   Target email for OSINT-only mode
--no-geo            Skip IP geolocation
--no-social         Skip social media platform scan
--vt-key KEY        VirusTotal API key
--json FILE         Export results to JSON file
```

---

## 📦 Modules

### Module 1 — Header Analysis

Parses the full email routing chain from `Received:` headers.

- Extracts sending hosts, mail servers, and public IPs
- Validates IPs using Python's `ipaddress` module (IPv4 + IPv6)
- Filters private/reserved ranges automatically
- Geolocates public IPs via HTTPS API

### Module 2 — Authentication Checks

Reads all `Authentication-Results` headers and uses the last one (added by the receiving MTA — most trustworthy).

| Result | Meaning |
|---|---|
| `PASS` | Email authenticated successfully |
| `FAIL` | Authentication failed — spoofing likely |
| `SOFTFAIL` | Weak failure — suspicious |
| `NONE` | No record configured — informational |
| `ERROR` | Temporary/permanent DNS error |
| `UNKNOWN` | Header missing entirely |

### Module 3 — Phishing Detection

Checks for 10+ indicators across categories:

- **Auth**: SPF/DKIM/DMARC failures, multiple Auth-Results headers
- **Identity**: From/Reply-To domain mismatch
- **Routing**: Sending host vs claimed domain (skips known ESPs)
- **URL**: Registrable-domain mismatch, shorteners, raw IP links
- **Social Engineering**: Urgency keywords in subject
- **Evasion**: Hidden white text, HTML entity obfuscation
- **Credential Theft**: HTML forms in body, credential-harvesting language
- **Infrastructure**: PHPMailer/bulk mailer signatures

### Module 4 — Attachment Analysis

For each attachment found in the email:

- Checks file extension against dangerous types (`.exe`, `.js`, `.vbs`, `.ps1`, `.bat`, `.zip`, `.iso`, etc.)
- Detects double extensions (e.g. `invoice.pdf.exe`)
- Flags MIME type mismatches
- Detects base64-encoded executables
- Computes SHA256 hash for VirusTotal lookup

### Module 5 — URL Analysis

Extracts all URLs from plain text and HTML body:

- Compares registrable domains (prevents `paypal.com.evil.xyz` bypass)
- Detects URL shorteners (bit.ly, tinyurl, t.co, etc.)
- Flags raw IP address URLs
- Checks for credential-harvesting keywords

### Module 6 — OSINT

Investigates the sender email address:

- **Email validation** — strict format and normalization
- **MX lookup** — via Google DNS-over-HTTPS
- **WHOIS/RDAP** — registrar, registration date, expiry
- **Mail server geolocation** — country, city, ISP of mail servers
- **Gravatar** — profile photo, display name, linked accounts (with avatar fallback)
- **18 platform scan** — GitHub, Reddit, Twitter/X, Instagram, TikTok, LinkedIn, Steam, Twitch, Medium, Dev.to, Keybase, Pastebin, HackerNews, Replit, Fiverr, and more
- **HaveIBeenPwned** — direct link to breach check
- **Google dork links** — 8 pre-built search queries for manual follow-up

Platform scan result statuses:

| Status | Meaning |
|---|---|
| `FOUND` | Profile page confirmed (200 + content verified) |
| `NOT_FOUND` | 404 or "user not found" in page content |
| `BLOCKED` | 403/401 — platform blocked the request |
| `RATE_LIMITED` | 429 — too many requests |
| `NETWORK_ERROR` | Timeout or connection failure |
| `UNKNOWN` | Unexpected HTTP status |

---

## 📊 Output Example

```
╔══════════════════════════════════════════════════════════════════════╗
║        EMAIL SOC TOOLKIT v2.0 — HEADER ANALYSIS + OSINT            ║
╚══════════════════════════════════════════════════════════════════════╝

──────────────────────────────────────────────────────────────────
  📧  EMAIL METADATA
──────────────────────────────────────────────────────────────────
  From            PayPal Security <security@paypal.com>
  Subject         Urgent: Your account has been limited!
  Reply-To        support@fakepaypal.xyz

──────────────────────────────────────────────────────────────────
  🔐  AUTHENTICATION  (SPF / DKIM / DMARC)
──────────────────────────────────────────────────────────────────
  SPF      FAIL
  DKIM     NONE
  DMARC    FAIL

──────────────────────────────────────────────────────────────────
  ⚠️   PHISHING / SPOOFING INDICATORS
──────────────────────────────────────────────────────────────────

  [HIGH]    SPF Failure
            SPF=FAIL — sending IP not authorized by domain

  [HIGH]    DMARC Failure
            DMARC policy failed — From domain spoofing likely

  [HIGH]    From/Reply-To Domain Mismatch
            From domain: paypal.com | Reply-To domain: fakepaypal.xyz

  [HIGH]    HTML Form in Email Body
            Form submits to: http://fakepaypal.xyz/steal

──────────────────────────────────────────────────────────────────
  🎯  RISK ASSESSMENT
──────────────────────────────────────────────────────────────────
  Risk Score: 100/100  [████████████████████]
  Verdict:    HIGH RISK — Strong phishing/spoofing indicators

  ⚠  This is a rule-based scanner. A low score does NOT confirm
     the email is safe. Results require analyst validation.
```

---

## 🦠 VirusTotal Integration

Get a free API key (500 requests/day) at [virustotal.com](https://www.virustotal.com).

The tool will automatically:
- Submit HIGH-severity URLs for reputation check
- Submit attachment SHA256 hashes for malware detection

```bash
python3 email_soc_toolkit.py --file suspicious.eml --vt-key YOUR_KEY
```

---

## 📁 JSON Export

The `--json` flag exports a SIEM-ready JSON report containing all analysis results.

```bash
python3 email_soc_toolkit.py --demo --osint --json report.json
```

Output structure:

```json
{
  "analyzed_at": "2025-06-23T09:15:00Z",
  "tool_version": "2.0",
  "header_analysis": {
    "from": "...",
    "auth": { "spf": "fail", "dkim": "none", "dmarc": "fail" },
    "findings": [...],
    "risk_score": 100,
    "mitre": [...],
    "attachments": [...],
    "url_analysis": [...]
  },
  "osint": {
    "email": "...",
    "whois": {...},
    "geo": [...],
    "social_hits": [...],
    "gravatar": {...}
  }
}
```

This JSON output can be fed directly into Elasticsearch, Splunk, Wazuh, or your own SIEM dashboard.

---

## ⚠️ Limitations

This tool is a **rule-based static analyzer**. You must be aware of its limitations:

1. **A low risk score does not mean the email is safe.** New or unknown phishing techniques may not be detected.
2. **Social platform scan uses HTTP 200 + content heuristics.** Some platforms return 200 for non-existent users. Results marked `BLOCKED` or `RATE_LIMITED` require manual verification.
3. **Geolocation shows mail SERVER location**, not the sender's physical location. Large providers (Gmail, Outlook) do not expose server IPs.
4. **Gravatar results depend on whether the sender created an account.** Most people do not use Gravatar — a "not found" result is normal.
5. **VirusTotal results reflect known threats only.** A clean result does not guarantee the file is safe.
6. **MIME-type analysis is static only.** Files are never executed or sandboxed.
7. **All findings require analyst validation** before any action is taken.

---

## 🛡️ MITRE ATT&CK Coverage

| Technique ID | Name | Triggered By |
|---|---|---|
| T1566.001 | Phishing: Spearphishing Attachment | Dangerous attachment detected |
| T1566.002 | Phishing: Spearphishing Link | Malicious/mismatched URL in body |
| T1598 | Phishing for Information | Urgency language, credential harvesting |
| T1036 | Masquerading | SPF failure |
| T1036.005 | Masquerading: Match Legitimate Name | DMARC failure, From/Reply-To mismatch |
| T1027 | Obfuscated Files or Information | Hidden text, HTML entity obfuscation |
| T1586 | Compromise Accounts | Bulk/script mailer detected |

Reference: [MITRE ATT&CK — Initial Access](https://attack.mitre.org/tactics/TA0001/)

---

## 📝 Changelog

### v2.0 (Code Review Update)
- `[FIX-01]` URL domain comparison uses registrable domain — stops `paypal.com.evil.xyz` bypass
- `[FIX-02]` IP validation uses `ipaddress` module — rejects invalid IPs, supports IPv6
- `[FIX-03]` Network errors separated from "not found" in platform probing
- `[FIX-04]` Reads all `Authentication-Results` headers; uses last (most trusted)
- `[FIX-05]` `dkim=none` → LOW severity only; escalates only if DMARC also fails
- `[FIX-06]` Sending-host check skips known ESPs (SendGrid, SES, Outlook, etc.)
- `[FIX-07]` "CLEAN" verdict removed — replaced with "INCONCLUSIVE"
- `[FIX-08]` Risk score deduplicates same-root-cause findings by category
- `[FIX-09]` MIME body decoded with proper charset instead of raw `str(bytes)`
- `[FIX-10]` MITRE mappings based on evidence, not header failures alone
- `[FIX-11]` Email validation uses `email-validator` library with regex fallback
- `[FIX-12]` Geolocation uses HTTPS endpoint
- `[FIX-13]` Platform scan returns: `FOUND / NOT_FOUND / BLOCKED / RATE_LIMITED / UNKNOWN / NETWORK_ERROR`
- `[FIX-14]` Tool limitations printed in every output

### v1.0 (Initial Release)
- Email header parsing and phishing detection
- IP geolocation via Received chain
- Gravatar and social media OSINT
- VirusTotal URL and hash checking
- JSON export for SIEM integration

---

## 👤 Author

**John** — Cybersecurity Student | Junior SOC Analyst  
University Project — Email Forensics & Phishing Analysis  
Built on Kali Linux | Python 3.12

---

## 📄 License

This project is for **educational and authorized research purposes only**.  
Do not use against systems or individuals without explicit written permission.
