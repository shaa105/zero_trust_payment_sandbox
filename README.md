# Zero Trust Payment Sandbox: ML-Enhanced Cookie & Behavioral Risk Analyzer

A security sandbox environment for analyzing payment pages using cookie security analysis, honeypot-based behavioral detection, machine learning risk scoring, and Zero Trust access control decisions.

## Overview

This project provides a security analysis framework that:

1. **Sandbox Execution** - Uses headless Chrome browser to safely analyze payment pages
2. **Cookie Security Analysis** - Detects missing Secure/HttpOnly flags, third-party cookies
3. **Honeypot Detection** - Injects canary cookies to detect tampering or unauthorized access
4. **ML Risk Scoring** - Uses a trained machine learning model to calculate risk scores
5. **Zero Trust Decision Engine** - Enforces ALLOW/WARN/DENY policies based on risk levels

### Risk Levels

- **LOW** (Score ≤ 4): Page allowed, no intervention
- **MEDIUM** (Score 5-7): Warn user, proceed with caution
- **HIGH** (Score > 7): Block access, simulate credential entry prevention

## Installation

1. Clone the repository:
```
bash
git clone <repository-url>
cd zero_trust_payment_sandbox
```

2. Create a virtual environment (recommended):
```
bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```
bash
pip install -r requirements.txt
```

4. Install ChromeDriver:
   - Ensure Chrome browser is installed
   - Download matching ChromeDriver version
   - Add to PATH or place in project directory

## Usage

Run the sandbox with payment page URLs:
```
bash
cd src
python sandbox.py
```

Enter URLs when prompted (comma-separated):
```
Enter payment page URLs separated by commas: http://localhost:3000/#/basket, https://www.emirates.com/payment
```

### Example URLs for Testing

**LOW Risk:**
- https://example.com
- https://example.org
- https://iana.org
- https://wikipedia.org

**MEDIUM Risk:**
- https://shopify.com
- https://etsy.com
- https://github.com

**HIGH Risk:**
- https://www.paypal.com
- https://checkout.stripe.com
- https://squareup.com

## Output Example

```
[Sandbox] Headless browser initialized
[Sandbox] Loading payment page: http://localhost:3000/#/basket
[Sandbox] Injecting honeypot cookie for http://localhost:3000/#/basket
[Sandbox] Honeypot cookie token: aB3xK9mP2qR5tY7z
[Honeypot] No tampering detected
[Sandbox] Cookie security analysis for http://localhost:3000/#/basket:
[Sandbox] Risk Score: 6
[Sandbox] Risk Level: MEDIUM
session → Missing Secure flag, Missing HttpOnly flag
[Zero Trust] Decision: WARN
[User Alert]  Medium risk detected. Proceed at your own risk.
[Sandbox] Page loaded safely. Zero Trust decision enforced.
```

## Integration with Juice-Shop

This project includes integration with OWASP Juice Shop for security testing:
- Run Juice Shop locally: `cd juice-shop-repo && npm start`
- Access at: http://localhost:3000
- Test the basket page: http://localhost:3000/#/basket

## Technical Details

- **Browser**: Chrome headless with incognito mode
- **Sandbox Hardening**: No-sandbox mode, disabled extensions
- **Real-time Monitoring**: 5-second cookie change detection
- **ML Model**: scikit-learn based classifier (RandomForest)
- **Python Version**: 3.8+

## License
MIT 
