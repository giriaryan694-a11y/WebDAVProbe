# WebDAVProbe

**IIS Fingerprinting & WebDAV Active Exploitation Testing**

Made By **Aryan Giri** | giriaryan694

---

## Overview

WebDAVProbe is a Python-based reconnaissance and exploitation testing tool designed for:

- **IIS Fingerprinting** — Detect Microsoft-IIS version, ASP.NET stack, and underlying Windows Server version
- **WebDAV Enumeration** — Discover WebDAV-enabled endpoints and enumerate allowed HTTP methods
- **Active Exploitation Testing** — Actually test if advertised methods work (not just listed in `Allow:` header)

The tool distinguishes between **methods advertised** vs **methods that actually work** — critical because many servers list dangerous methods but block them at the application layer or require authentication.

---

## Features

| Feature | Description |
|---------|-------------|
| IIS Version Detection | Maps `Server: Microsoft-IIS/X.X` to Windows Server versions |
| WebDAV Discovery | Probes `/`, `/webdav`, `/dav`, `/public`, `/share`, `/files` |
| Method Analysis | Explains risk level, description, and attack impact for each method |
| Active Testing | Actually executes PUT, DELETE, MOVE, COPY, MKCOL, PROPFIND, TRACE |
| Auth Support | Basic authentication via `--auth user:pass` |
| Report Export | Save clean output to text file via `-o report.txt` |
| 401 Detection | Distinguishes "blocked by controls" vs "requires authentication" |

---

## Installation

```bash
pip install requests colorama
```

---

## Usage

### Basic Scan
```bash
python3 webdavprobe.py -u http://target.com
```

### With Authentication
```bash
python3 webdavprobe.py -u http://target.com --auth admin:password
```

### Save Report to File
```bash
python3 webdavprobe.py -u http://target.com -o report.txt
```

### Full Example
```bash
python3 webdavprobe.py -u http://10.48.172.90 --auth admin:password -o webdav_report.txt --timeout 15
```

---

## Command Line Options

| Option | Description |
|--------|-------------|
| `-u, --url` | Target URL (required) |
| `--auth` | Basic auth credentials as `user:pass` |
| `-o, --output` | Save report to text file |
| `--timeout` | Request timeout in seconds (default: 10) |

---

## How It Works

### Phase 1: IIS Fingerprinting
- Sends `HEAD` request to target
- Extracts `Server` and `X-Powered-By` headers
- Detects `Microsoft-IIS/*` and `ASP.NET`
- Maps IIS version to Windows Server version
- **Always continues** to Phase 2 regardless of IIS match

### Phase 2: WebDAV Enumeration
- Probes 6 common WebDAV endpoints
- Sends `OPTIONS` to extract `Allow:` and `DAV:` headers
- Analyzes each allowed method with risk level and impact
- Lists attack scenarios for dangerous methods

### Phase 3: Active Exploitation Testing
For each dangerous method found, the tool actually tests it:

| Method | Test Performed | Verification |
|--------|---------------|--------------|
| **PUT** | Uploads ASPX webshell (`1+1`) | GET file → checks response contains `2` |
| **DELETE** | Deletes the uploaded PUT file | GET deleted file → expects `404` |
| **MOVE** | Upload `.txt` → MOVE to `.aspx` | GET `.aspx` → checks execution |
| **COPY** | Upload file → COPY to new name | GET copy → verifies content matches |
| **MKCOL** | Creates a directory | PROPFIND → confirms `200/207` |
| **PROPFIND** | Sends XML body for listing | Checks XML response with item count |
| **TRACE** | Sends TRACE request | Checks if server echoes request |

### Final Report
- IIS fingerprint summary
- WebDAV status per endpoint
- **Active Test Results** table showing:
  - Method advertised? (YES/NO)
  - Actually worked? (WORKED / AUTH REQ / FAILED)
  - Details and payload URLs

---

## Method Risk Reference

| Method | Risk | Attack Impact |
|--------|------|---------------|
| `PUT` | **CRITICAL** | Upload webshells → RCE |
| `DELETE` | **HIGH** | Delete configs, deface, disrupt |
| `MOVE` | **HIGH** | Bypass filters: `.txt` → `.aspx` |
| `COPY` | **HIGH** | Duplicate shells |
| `PROPFIND` | **MEDIUM** | Enumerate hidden files |
| `MKCOL` | **MEDIUM** | Create directories for malware |
| `TRACE` | **MEDIUM** | XST attacks, steal cookies |

---

## Example Output

```
============================================================
  ACTIVE TEST RESULTS - WHAT ACTUALLY WORKED
============================================================

Endpoint: http://10.48.172.90/webdav
  Method       Advertised   Worked       Details
  ------------------------------------------------------------
  PUT          YES          AUTH REQ     AUTH REQUIRED
  DELETE       YES          FAILED       No file to delete
  MOVE         YES          AUTH REQ     PUT blocked: AUTH REQUIRED
  COPY         YES          AUTH REQ     PUT blocked: AUTH REQUIRED
  MKCOL        YES          AUTH REQ     AUTH REQUIRED
  PROPFIND     YES          AUTH REQ     AUTH REQUIRED
  TRACE        YES          FAILED       HTTP 501

[!] Methods advertised but require authentication (HTTP 401).
    Try --auth user:pass
```

---

## Why Active Testing Matters

Many security scanners only check the `Allow:` header and report "PUT enabled" — but the server may return **401 Unauthorized** or **403 Forbidden** on actual execution. WebDAVProbe **actually performs** each operation and verifies the result, giving you actionable intelligence instead of false positives.

---

## Requirements

- Python 3.7+
- `requests`
- `colorama`

---

## Disclaimer

This tool is for **authorized security testing and educational purposes only**. Always obtain explicit permission before testing systems you do not own. The author assumes no liability for misuse.

---

## Author

**Aryan Giri** | giriaryan694
