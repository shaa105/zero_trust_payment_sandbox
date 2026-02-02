# src/honeypot.py
"""
Honeypot cookie injection and tamper detection module.
Injects a canary cookie that should never be touched, and detects unauthorized access/modification.
"""

import random
import string

def generate_honeypot_token():
    """Generate a random token for the honeypot cookie."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

def inject_honeypot_cookie(driver, url):
    """
    Injects a honeypot cookie into the browser session.
    
    Args:
        driver: Selenium WebDriver instance
        url: The URL string to extract domain from
    
    Returns:
        token: The injected token for later verification
    """
    # Extract domain consistently (like in sandbox.py)
    if "localhost" in url:
        domain = "localhost"
    else:
        domain = url.split("/")[2]  # extract domain dynamically
    
    token = generate_honeypot_token()
    
    honeypot_cookie = {
        "name": "__hp_token",
        "value": token,
        #"domain": domain,  # Commented out to avoid domain issues for example emirates, not localhost
        "path": "/",
        "secure": True,
        "httpOnly": True
    }
    
    driver.add_cookie(honeypot_cookie)
    print(f"[Honeypot] Injected honeypot cookie with token {token} for domain {domain}")
    return token

def check_honeypot_tamper(driver, original_token):
    """
    Checks if the honeypot cookie has been tampered with.
    
    Args:
        driver: Selenium WebDriver instance
        original_token: The original token value
    
    Returns:
        tampered: Boolean indicating if tampering was detected
        details: String describing the issue
    """
    try:
        cookies = driver.get_cookies()
        honeypot_cookie = next((c for c in cookies if c.get("name") == "__hp_token"), None)

        if honeypot_cookie is None:
            return True, "Honeypot cookie missing (possibly deleted)"

        if honeypot_cookie.get("value") != original_token:
            return True, "Honeypot cookie value modified"

        return False, "No tampering detected"
    except Exception as e:
        return True, f"Error checking honeypot: {str(e)}"