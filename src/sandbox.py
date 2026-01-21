# src/sandbox.py

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
import time

# Initialize headless Chrome browser for sandboxed environment
chrome_options = Options()
chrome_options.add_argument("--headless=new")
chrome_options.add_argument("--disable-gpu")
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument("--disable-dev-shm-usage")

driver = webdriver.Chrome(
    service=Service(ChromeDriverManager().install()),
    options=chrome_options
)

print("[Sandbox] Headless browser initialized")

payment_url = "http://localhost:3000"
driver.get(payment_url)

print(f"[Sandbox] Payment page loaded in isolated environment: {payment_url}")

# Allow page scripts to execute
time.sleep(5)

driver.quit()
print("[Sandbox] Sandbox session terminated safely")
