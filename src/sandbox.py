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

payment_pages = [
    "http://localhost:3000/#/basket",         # Juice Shop
    "https://www.emirates.com/payment"        # Emirates (read-only, safe)
]

# Removed this line because payment_page_url was undefined
# driver.get(payment_page_url)
# time.sleep(2)

print("[Sandbox] Headless browser initialized")

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

    cookies = driver.get_cookies()

    # Decide main domain based on URL
    if "localhost" in url:
        main_domain = "localhost"
    else:
        main_domain = "emirates.com"

    print(f"[Sandbox] Cookie security analysis for {url}:")
    findings = analyze_cookies(cookies, main_domain)
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
        print("[User Alert] ❌ High risk detected. Credential entry blocked (simulated).")
    elif decision == "WARN":
        print("[User Alert] ⚠️ Medium risk detected. Proceed at your own risk.")
    else:
        print("[User Alert] ✅ Low risk. Page allowed.")

    print(f"[Sandbox] Page loaded safely. Zero Trust decision enforced.\n")

driver.quit()
print("[Sandbox] All pages processed. Sandbox session terminated safely.")


if __name__ == "__main__":
    # The script runs exactly as above when executed directly.
    pass