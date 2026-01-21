# src/cookie_analyzer.py

def analyze_cookies(cookies, main_domain):
    """
    Analyzes cookies for common security issues.
    Returns a list of findings.
    """

    findings = []

    for cookie in cookies:
        issues = []

        if not cookie.get("secure"):
            issues.append("Missing Secure flag")

        if not cookie.get("httpOnly"):
            issues.append("Missing HttpOnly flag")

        if main_domain not in cookie.get("domain", ""):
            issues.append("Third-party cookie")

        if issues:
            findings.append({
                "name": cookie.get("name"),
                "domain": cookie.get("domain"),
                "issues": issues
            })

    return findings
