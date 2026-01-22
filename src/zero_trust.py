# src/zero_trust.py

def zero_trust_decision(risk_level):
    """
    Decide whether to ALLOW, WARN, or DENY based on risk_level
    """
    if risk_level == "HIGH":
        return "DENY"
    elif risk_level == "MEDIUM":
        return "WARN"
    else:
        return "ALLOW"
