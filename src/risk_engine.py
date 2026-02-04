#Translate cookie security issues into a numeric risk score and risk level that can be enforced by Zero Trust.
# src/risk_engine.py

import os
import joblib
import pandas as pd
import warnings
from sklearn.exceptions import InconsistentVersionWarning

# Suppress the scikit-learn version mismatch warning
warnings.filterwarnings("ignore", category=InconsistentVersionWarning)

MODEL_PATH = os.path.join(os.path.dirname(__file__), "ml_risk_model.pkl")

def calculate_risk(findings):
    """
    findings: list of dicts from cookie_analyzer
    returns: (risk_score, risk_level)
    """
    # Numeric risk score (1-10 integer scale)
    risk_score = 1  # Base score

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
            elif issue == "Honeypot tampering detected":
                risk_score += 4

    # Cap at 10
    risk_score = min(10, risk_score)

    # Determine risk level based on score
    if risk_score <= 4:
        risk_level = "LOW"
    elif risk_score <= 7:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    return risk_score, risk_level


def extract_features(findings):
    return {
        "missing_secure": sum("Missing Secure flag" in f.get("issues", []) for f in findings),
        "missing_httponly": sum("Missing HttpOnly flag" in f.get("issues", []) for f in findings),
        "third_party": sum("Third-party cookie" in f.get("issues", []) for f in findings),
        "insecure_session": sum("Insecure session cookie" in f.get("issues", []) for f in findings),
        "total_cookies": len(findings),
    }

#def calculate_risk(findings):
 #   """
  #  findings: list of dicts from cookie_analyzer
   # returns: (risk_score, risk_level)
    #"""

    #risk_score = 0

    #for f in findings:
     #   issues = f.get("issues", [])

      #  for issue in issues:
       #     if issue == "Missing Secure flag":
        #        risk_score += 2
         #   elif issue == "Missing HttpOnly flag":
          #      risk_score += 1
           # elif issue == "Third-party cookie":
            #    risk_score += 2
            #elif issue == "Insecure session cookie":
              #  risk_score += 3

    # Risk thresholds
    #if risk_score >= 8:
     #   level = "HIGH"
    #elif risk_score >= 4:
     #   level = "MEDIUM"
    #else:
     #   level = "LOW"

#    return risk_score, levels