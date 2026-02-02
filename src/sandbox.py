# src/sandbox.py
#It is an application-level sandbox that isolates execution, removes persistence, and allows controlled observation, which is sufficient and standard for web security analysis.

from selenium import webdriver
#from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
#from webdriver_manager.chrome import ChromeDriverManager
import time
from cookie_analyzer import analyze_cookies
from risk_engine import calculate_risk
from zero_trust import zero_trust_decision
from honeypot import inject_honeypot_cookie, check_honeypot_tamper  # <-- Added honeypot import

## Initialize headless Chrome browser for sandboxed environment
#chrome_options = Options()
#chrome_options.add_argument("--headless=new")
#chrome_options.add_argument("--disable-gpu")
#chrome_options.add_argument("--no-sandbox")
#chrome_options.add_argument("--disable-dev-shm-usage")

options = Options()
options.add_argument("--headless") 
options.add_argument("--disable-gpu")
options.add_argument("--window-size=1280,720")
options.add_argument("--incognito")              # sandbox hardening
options.add_argument("--disable-extensions")     # sandbox hardening

driver = webdriver.Chrome(options=options)

#user_input = input("Enter payment page URLs separated by commas: ")
#payment_pages = [url.strip() for url in user_input.split(",") if url.strip()]

payment_pages = [
    "http://localhost:3000/#/basket",         # Juice Shop
    "https://www.emirates.com/payment"        # Emirates (read-only, safe)
]

# Removed this line because payment_page_url was undefined
# driver.get(payment_page_url)
# time.sleep(2)

if not payment_pages:
    print("[Sandbox] No URLs provided. Exiting.")
    driver.quit()
    exit()

print("[Sandbox] Headless browser initialized")

def monitor_cookies_realtime(driver, main_domain, baseline_cookies, duration=5, interval=0.5):
    """Monitor cookie changes and flag anomalies in real-time."""
    elapsed = 0
    while elapsed < duration:
        current_cookies = {c['name']: c for c in driver.get_cookies()}

        for name, cookie in current_cookies.items():
            prev = baseline_cookies.get(name)

            if not prev:
                issues = []
                if main_domain not in cookie.get("domain", ""):
                    issues.append("New third-party cookie detected")
                if not cookie.get("secure"):
                    issues.append("New cookie missing Secure flag")
                if not cookie.get("httpOnly"):
                    issues.append("New cookie missing HttpOnly flag")
                if issues:
                    print(f"[Real-Time ALERT] {name}: {', '.join(issues)}")

            else:
                issues = []
                if cookie.get("secure") != prev.get("secure"):
                    issues.append("Secure flag changed")
                if cookie.get("httpOnly") != prev.get("httpOnly"):
                    issues.append("HttpOnly flag changed")
                if cookie.get("domain") != prev.get("domain"):
                    issues.append("Cookie domain changed")
                if issues:
                    print(f"[Real-Time ALERT] {name}: {', '.join(issues)}")

        baseline_cookies = current_cookies
        time.sleep(interval)
        elapsed += interval

for url in payment_pages:
    print(f"[Sandbox] Loading payment page: {url}")

    try:
        driver.get(url)
        time.sleep(2)
    except Exception as e:
        print(f"[Sandbox] ERROR loading page: {url}")
        print(f"[Sandbox] Reason: {e}")
        print("[Sandbox] Skipping page and continuing...\n")
        continue

    # # Robust domain extraction
# #   parsed = urlparse(url)
# # main_domain = parsed.netloc if parsed.netloc else parsed.path

# # --- Honeypot injection & real-time check ---
# # print(f"[Sandbox] Injecting honeypot cookie for {url}")
# # token = inject_honeypot_cookie(driver, main_domain)
# print(f"[Honeypot] Injected token: {token}")

# # Real-time honeypot monitoring for 5 seconds
# for i in range(5):
#     tampered, details = check_honeypot_tamper(driver, token)
#     if tampered:
#         print(f"[Honeypot ALERT] Tampering detected! Details: {details}")
#         # Optionally, append a synthetic finding to increase risk here
#         break
#     time.sleep(1)
# else:
#     print("[Honeypot] No tampering detected")

    if "localhost" in url:
        main_domain = "localhost"
    else:
        main_domain = url.split("/")[2]  # extract domain dynamically

    # Capture baseline cookies before honeypot
    baseline_cookies = {c['name']: c for c in driver.get_cookies()}

    #Honeypot injection and check
    print(f"[Sandbox] Injecting honeypot cookie for {url}")
    token = inject_honeypot_cookie(driver, url)  # pass full URL to match original honeypot.py
    print(f"[Sandbox] Honeypot cookie token: {token}")

    monitor_cookies_realtime(driver, main_domain, baseline_cookies)

    tampered, details = check_honeypot_tamper(driver, token)
    if tampered:
        print(f"[Honeypot] ALERT: Tampering detected! Details: {details}")
        baseline_cookies["__hp_token"] = {
            "name": "__hp_token",
            "domain": main_domain,
            "issues": ["Honeypot tampering detected"]
        }
    else:
        print("[Honeypot] No tampering detected")

    cookies = driver.get_cookies()

    print(f"[Sandbox] Cookie security analysis for {url}:")
    findings = analyze_cookies(cookies, main_domain)

    if "__hp_token" in baseline_cookies:
        findings.append(baseline_cookies["__hp_token"])

    risk_score, risk_level = calculate_risk(findings)

    print(f"[Sandbox] Risk Score: {risk_score}")
    print(f"[Sandbox] Risk Level: {risk_level}")

    if not findings:
        print("No obvious cookie security issues detected")
    else:
        for f in findings:
            print(f"{f['name']} → {', '.join(f['issues'])}")

    decision = zero_trust_decision(risk_level)
    print(f"[Zero Trust] Decision: {decision}")

    if decision == "DENY":
        print("[User Alert]  High risk detected. Credential entry blocked (simulated).")
    elif decision == "WARN":
        print("[User Alert]  Medium risk detected. Proceed at your own risk.")
    else:
        print("[User Alert]  Low risk. Page allowed.")

    print(f"[Sandbox] Page loaded safely. Zero Trust decision enforced.\n")

driver.quit()
print("[Sandbox] All pages processed. Sandbox session terminated safely.")

if __name__ == "__main__":
    pass
