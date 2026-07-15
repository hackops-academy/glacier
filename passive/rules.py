"""
rules.py
Passive scan rules.

Each rule takes a traffic dict (one row from the `traffic` table, same
shape as storage.get_message()) and returns a list of finding dicts:
    {"risk": ..., "name": ..., "description": ..., "evidence": ...}

Passive rules only *inspect* traffic that already flowed through the
proxy - they never send additional requests to the target. That's what
makes them safe to run continuously on everything, unlike the active
scanner (phase 6), which will actually send test payloads.

risk is one of: "High", "Medium", "Low", "Informational"
"""

import re

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Generic JWT", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}")),
    ("Private Key Block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]

ERROR_SIGNATURES = [
    ("SQL error disclosure", re.compile(r"(SQL syntax|mysql_fetch|ORA-\d{5}|SQLSTATE|PostgreSQL.*ERROR)", re.I)),
    ("Stack trace disclosure", re.compile(r"(Traceback \(most recent call last\)|at java\.lang\.|Exception in thread)", re.I)),
    ("PHP error disclosure", re.compile(r"(Fatal error:|Warning:.*on line \d+)", re.I)),
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": ("Missing HSTS header", "Low"),
    "X-Content-Type-Options": ("Missing X-Content-Type-Options header", "Low"),
    "X-Frame-Options": ("Missing X-Frame-Options / clickjacking protection", "Medium"),
    "Content-Security-Policy": ("Missing Content-Security-Policy header", "Medium"),
}


def _headers_dict(header_text):
    """Parse the stored 'Key: Value\\n' header blob into a dict, case-insensitive."""
    out = {}
    for line in (header_text or "").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip().lower()] = v.strip()
    return out


def rule_missing_security_headers(traffic):
    findings = []
    # Only meaningful for actual page/API responses, not every asset -
    # skip obvious static files to cut noise.
    if re.search(r"\.(png|jpg|jpeg|gif|svg|css|woff2?|ico)(\?|$)", traffic["url"]):
        return findings
    headers = _headers_dict(traffic.get("response_headers"))
    for header_name, (desc, risk) in SECURITY_HEADERS.items():
        if header_name.lower() not in headers:
            findings.append({
                "risk": risk,
                "name": desc,
                "description": f"The response did not include a '{header_name}' header.",
                "evidence": f"URL: {traffic['url']}",
            })
    return findings


def rule_insecure_cookies(traffic):
    findings = []
    headers_text = traffic.get("response_headers") or ""
    for line in headers_text.splitlines():
        if line.lower().startswith("set-cookie:"):
            cookie = line.split(":", 1)[1].strip()
            missing = []
            if "secure" not in cookie.lower():
                missing.append("Secure")
            if "httponly" not in cookie.lower():
                missing.append("HttpOnly")
            if "samesite" not in cookie.lower():
                missing.append("SameSite")
            if missing:
                findings.append({
                    "risk": "Medium" if "Secure" in missing else "Low",
                    "name": "Cookie missing security flags",
                    "description": f"Cookie is missing: {', '.join(missing)}.",
                    "evidence": cookie[:200],
                })
    return findings


def rule_server_disclosure(traffic):
    findings = []
    headers = _headers_dict(traffic.get("response_headers"))
    for header_name in ("server", "x-powered-by"):
        if header_name in headers and headers[header_name]:
            value = headers[header_name]
            # A bare "nginx" or "Apache" isn't very interesting; a version
            # number attached is what actually helps an attacker fingerprint.
            if re.search(r"\d", value):
                findings.append({
                    "risk": "Low",
                    "name": "Server/technology version disclosure",
                    "description": f"The '{header_name}' header reveals version information.",
                    "evidence": f"{header_name}: {value}",
                })
    return findings


def rule_error_disclosure(traffic):
    findings = []
    body = traffic.get("response_body") or ""
    for name, pattern in ERROR_SIGNATURES:
        m = pattern.search(body)
        if m:
            findings.append({
                "risk": "Medium",
                "name": name,
                "description": "The response body appears to contain a verbose application error, which can leak implementation details.",
                "evidence": body[max(0, m.start() - 40): m.start() + 120],
            })
    return findings


def rule_exposed_secrets(traffic):
    findings = []
    body = traffic.get("response_body") or ""
    for name, pattern in SECRET_PATTERNS:
        m = pattern.search(body)
        if m:
            findings.append({
                "risk": "High",
                "name": f"Possible exposed secret: {name}",
                "description": f"A pattern matching {name} was found in the response body.",
                "evidence": m.group(0)[:12] + "…(redacted)",
            })
    return findings


ALL_RULES = [
    rule_missing_security_headers,
    rule_insecure_cookies,
    rule_server_disclosure,
    rule_error_disclosure,
    rule_exposed_secrets,
]
