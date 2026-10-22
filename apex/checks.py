import requests
import jwt
import warnings
warnings.filterwarnings("ignore")

HEADERS = {"User-Agent": "apix/1.0"}


def run_all_checks(base_url, output_file=None):
    session = requests.Session()
    session.headers.update(HEADERS)
    findings = []

    checks = [
        check_auth_bypass, check_broken_object_auth, check_jwt_weak_secret,
        check_mass_assignment, check_sqli, check_excessive_data,
        check_rate_limiting, check_security_misconfig
    ]

    for check in checks:
        results = check(session, base_url)
        for r in results:
            findings.append(r)
            entry = f"[{r['severity']}] {r['vuln']} — {r['detail']}"
            print(entry)
            if output_file:
                output_file.write(entry + "\n")

    return findings


def _finding(vuln, severity, detail):
    return {"vuln": vuln, "severity": severity, "detail": detail}


# API1:2023 - Broken Object Level Authorization (BOLA/IDOR)
def check_broken_object_auth(session, url):
    out = []
    for oid in ["1", "2", "100"]:
        try:
            r = session.get(f"{url.rstrip('/')}/{oid}", timeout=8)
            if r.status_code == 200:
                out.append(_finding("Broken Object Level Auth (IDOR)", "HIGH",
                    f"Accessed object id={oid} without proper authorization"))
        except Exception:
            continue
    return out


# API2:2023 - Broken Authentication
def check_auth_bypass(session, url):
    out = []
    bad_headers = [{"Authorization": "Bearer null"}, {"Authorization": "Bearer undefined"}]
    for h in bad_headers:
        try:
            r = session.get(url, headers=h, timeout=8)
            if r.status_code == 200:
                out.append(_finding("Broken Authentication", "CRITICAL",
                    f"Accepted invalid token: {h['Authorization']}"))
        except Exception:
            continue
    return out


# JWT weak secret (supports API2)
def check_jwt_weak_secret(session, url):
    out = []
    for secret in ["secret", "password", "123456", "admin"]:
        try:
            token = jwt.encode({"user": "admin", "role": "admin"}, secret, algorithm="HS256")
            r = session.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=8)
            if r.status_code == 200:
                out.append(_finding("Weak JWT Secret", "CRITICAL",
                    f"Server accepted JWT signed with weak secret '{secret}'"))
        except Exception:
            continue
    return out


# API3:2023 - Broken Object Property Level Authorization (mass assignment)
def check_mass_assignment(session, url):
    out = []
    payload = {"role": "admin", "isAdmin": True, "is_admin": True}
    try:
        r = session.post(url, json=payload, timeout=8)
        if r.status_code in [200, 201] and any(k in r.text for k in ["admin", "isAdmin"]):
            out.append(_finding("Mass Assignment", "HIGH",
                "Server accepted unexpected privileged fields in request body"))
    except Exception:
        pass
    return out


# API8:2023-adjacent - Injection
def check_sqli(session, url):
    out = []
    payloads = ["'", "' OR '1'='1"]
    errors = ["sql", "syntax", "mysql", "sqlite", "postgresql"]
    for p in payloads:
        try:
            r = session.get(url, params={"id": p}, timeout=8)
            if any(e in r.text.lower() for e in errors):
                out.append(_finding("Injection (SQLi)", "CRITICAL",
                    f"SQL error triggered with payload: {p}"))
        except Exception:
            continue
    return out


# API3:2023 - Excessive Data Exposure
def check_excessive_data(session, url):
    out = []
    keywords = ["password", "secret", "api_key", "token", "ssn", "credit_card"]
    try:
        r = session.get(url, timeout=8)
        found = [k for k in keywords if k in r.text.lower()]
        if found:
            out.append(_finding("Excessive Data Exposure", "HIGH",
                f"Sensitive fields in response: {', '.join(found)}"))
    except Exception:
        pass
    return out


# API4:2023 - Unrestricted Resource Consumption (rate limiting)
def check_rate_limiting(session, url):
    out = []
    try:
        codes = [session.get(url, timeout=8).status_code for _ in range(10)]
        if 429 not in codes:
            out.append(_finding("No Rate Limiting", "MEDIUM",
                "No HTTP 429 after 10 rapid requests"))
    except Exception:
        pass
    return out


# API8:2023 - Security Misconfiguration
def check_security_misconfig(session, url):
    out = []
    try:
        r = session.get(url, timeout=8)
        required = ["X-Content-Type-Options", "Strict-Transport-Security"]
        missing = [h for h in required if h not in r.headers]
        if missing:
            out.append(_finding("Security Misconfiguration", "LOW",
                f"Missing headers: {', '.join(missing)}"))
        if url.startswith("http://"):
            out.append(_finding("Security Misconfiguration", "MEDIUM", "API served over HTTP, not HTTPS"))
    except Exception:
        pass
    return out
