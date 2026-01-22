#Translate cookie security issues into a numeric risk score and risk level that can be enforced by Zero Trust.
# src/risk_engine.py

def calculate_risk(findings):
    """
    findings: list of dicts from cookie_analyzer
    returns: (risk_score, risk_level)
    """

    risk_score = 0

    for f in findings:
        issues = f.get("issues", [])

        for issue in issues:
            if issue == "Missing Secure flag":
                risk_score += 2
            elif issue == "Missing HttpOnly flag":
                risk_score += 1
            elif issue == "Third-party cookie":
                risk_score += 2
            elif issue == "Insecure session cookie":
                risk_score += 3

    # Risk thresholds
    if risk_score >= 8:
        level = "HIGH"
    elif risk_score >= 4:
        level = "MEDIUM"
    else:
        level = "LOW"

    return risk_score, level
