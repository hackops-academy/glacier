"""
scanner.py
Active scanner: unlike the passive scanner, this SENDS test payloads to
the target rather than just inspecting traffic that already happened.

Detection methodology is the same standard, published approach used by
ZAP, sqlmap, and every other mainstream scanner:
  - Reflected XSS: inject a unique marker with HTML-breaking characters,
    check whether the response reflects it back unescaped.
  - SQL injection (error-based): inject a single quote, check whether the
    response leaks a database error signature.

Deliberately NOT included: destructive payloads, anything that writes/
deletes data, anything beyond detecting whether a vulnerability exists.
This confirms presence, it doesn't exploit it further.

Scope: only ever tests the exact URL/parameters explicitly passed in -
never crawls or expands scope on its own. Every call must come from a
deliberate, per-target decision made by the caller (the API layer
requires an explicit confirm=True for this reason).
"""

import difflib
import re
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "auth"))
import manager as auth_manager  # noqa: E402

SQL_ERROR_SIGNATURES = re.compile(
    r"(SQL syntax|mysql_fetch|ORA-\d{5}|SQLSTATE|PostgreSQL.*ERROR|sqlite3\.OperationalError|unrecognized token)",
    re.I,
)

XSS_MARKER_ID = uuid.uuid4().hex[:8]

# Path traversal: a spread of depths and separator styles, since we don't
# know the target's OS or how many directories deep the include actually
# sits. Checked against both a Linux marker file (/etc/passwd, always
# present and harmless to read) and a Windows one (win.ini).
PATH_TRAVERSAL_PAYLOADS = [
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//....//....//etc/passwd",
    "../../../../../../windows/win.ini",
    "..%2f..%2f..%2f..%2f..%2f..%2fwindows%2fwin.ini",
]
LINUX_TRAVERSAL_SIGNATURE = re.compile(r"root:.*:0:0:")
WINDOWS_TRAVERSAL_SIGNATURE = re.compile(r"\[fonts\]", re.I)

# Command injection: covers both Linux (;, &&, |, backticks) and Windows
# (&) shell metacharacters, chained onto a harmless, verifiable command.
#
# Deliberately NOT a literal echoed string (e.g. "echo glacierXYZ"): a
# literal marker can leak into the response just because the app reflects
# unrecognized input back in an error message (e.g. "no such host: <input>")
# WITHOUT the shell ever having executed anything - a classic false-
# positive trap. Using arithmetic instead means the digits that appear in
# the response only exist if a shell genuinely evaluated the expression;
# the raw, unexecuted payload text never contains the product itself.
_CMD_INJECTION_A = 6247
_CMD_INJECTION_B = 8351
CMD_INJECTION_PRODUCT = str(_CMD_INJECTION_A * _CMD_INJECTION_B)
CMD_INJECTION_PAYLOAD_TEMPLATES = [
    "; expr {a} \\* {b}",
    "&& expr {a} \\* {b}",
    "| expr {a} \\* {b}",
    "` expr {a} \\* {b} `",
    "$(expr {a} \\* {b})",
]
# Blind command injection (no output reflected) - same idea as time-based
# blind SQLi, but pausing the shell itself instead of the database.
CMD_INJECTION_TIME_PAYLOAD_TEMPLATES = [
    "; sleep {d}",
    "&& sleep {d}",
    "| sleep {d}",
    "` sleep {d} `",
    "$(sleep {d})",
]

# Open redirect: absolute URLs and a couple of common bypass tricks for
# naive "starts with http" allow-list checks (protocol-relative, and a
# backslash which some URL parsers normalize to a slash).
OPEN_REDIRECT_TARGET = "https://glacier-redirect-test.invalid/"
OPEN_REDIRECT_PAYLOADS = [
    OPEN_REDIRECT_TARGET,
    "//glacier-redirect-test.invalid/",
    "/\\glacier-redirect-test.invalid/",
    "https:glacier-redirect-test.invalid/",
]

# TRUE/FALSE payload pairs covering the common injection contexts
# (bare numeric, single-quoted string, double-quoted string, parenthesised
# numeric). Same idea sqlmap uses for its "boolean-based blind" tests.
BOOLEAN_BLIND_PAYLOAD_PAIRS = [
    ("1 AND 1=1", "1 AND 1=2"),
    ("1' AND '1'='1", "1' AND '1'='2"),
    ('1" AND "1"="1', '1" AND "1"="2'),
    ("1) AND (1=1", "1) AND (1=2"),
]

# {d} is filled in with the delay in seconds. Covers MySQL, MSSQL, and
# Postgres sleep syntax across a couple of common injection contexts.
TIME_BASED_PAYLOAD_TEMPLATES = [
    "1 AND SLEEP({d})",
    "1' AND SLEEP({d})-- -",
    "1 OR SLEEP({d})",
    "1';WAITFOR DELAY '0:0:{d}'--",
    "1' AND pg_sleep({d})-- -",
]


def _build_url(base_url, param, value):
    parsed = urlparse(base_url)
    qs = parse_qs(parsed.query)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _get(session, url, proxy, ca_bundle, timeout=8, allow_redirects=True):
    kwargs = {
        "timeout": timeout,
        "verify": ca_bundle if ca_bundle else False,
        "allow_redirects": allow_redirects,
    }
    if proxy:
        kwargs["proxies"] = {"http": proxy, "https": proxy}
    resp = session.get(url, **kwargs)

    # If this session is authenticated and the response looks like a
    # logout happened (session timeout, CSRF rotation, etc.), try to
    # re-authenticate once and retry the request - otherwise the rest
    # of the scan would silently run unauthenticated and report nothing.
    auth_config = getattr(session, "glacier_auth", None)
    if auth_config and auth_manager.looks_logged_out(resp.text, auth_config):
        ok, _ = auth_manager.reauthenticate(session, proxy=proxy, ca_bundle=ca_bundle)
        if ok:
            resp = session.get(url, **kwargs)
    return resp


def check_reflected_xss(session, base_url, param, proxy=None, ca_bundle=None):
    marker = f'glacier{XSS_MARKER_ID}"\'><svg/onload=alert(1)>'
    test_url = _build_url(base_url, param, marker)
    try:
        resp = _get(session, test_url, proxy, ca_bundle)
    except requests.RequestException as e:
        return None, str(e)

    if marker in resp.text:
        return {
            "risk": "High",
            "name": "Reflected Cross-Site Scripting (XSS)",
            "description": f"Parameter '{param}' reflects attacker-controlled input into the response without encoding, allowing script injection.",
            "evidence": f"Payload was reflected unescaped in response to: {test_url}",
            "url": test_url,
        }, None
    return None, None


def check_sql_injection(session, base_url, param, proxy=None, ca_bundle=None):
    test_url = _build_url(base_url, param, "1'")
    try:
        resp = _get(session, test_url, proxy, ca_bundle)
    except requests.RequestException as e:
        return None, str(e)

    match = SQL_ERROR_SIGNATURES.search(resp.text)
    if match:
        return {
            "risk": "High",
            "name": "Possible SQL Injection",
            "description": f"Parameter '{param}' triggered a database error signature when a quote character was injected, suggesting unsanitized input reaches a SQL query.",
            "evidence": resp.text[max(0, match.start() - 30): match.start() + 100],
            "url": test_url,
        }, None
    return None, None


def _similarity(a, b):
    return difflib.SequenceMatcher(None, a, b).ratio()


def check_boolean_blind_sqli(session, base_url, param, proxy=None, ca_bundle=None):
    """
    Covers the case check_sql_injection() misses: no error message leaks,
    but the application silently behaves differently depending on whether
    the injected condition is true or false (e.g. "found" vs "not found").

    For each payload pair, fetch the TRUE and FALSE variants and compare
    both against a baseline (the page's normal, un-injected response).
    A real vuln looks like: TRUE ~= baseline (query still "works" as
    before), FALSE is meaningfully different (query now returns nothing/
    something else) - with no raw DB error in either response, since
    that's the other check's signal, not this one.

    Caveat: pages with content that changes on every load (timestamps,
    random ads, view counters) can trigger false positives here, since
    this relies on response diffing. Worth a manual look before trusting
    a finding from this check specifically.
    """
    try:
        baseline = _get(session, base_url, proxy, ca_bundle)
    except requests.RequestException as e:
        return None, str(e)

    for true_payload, false_payload in BOOLEAN_BLIND_PAYLOAD_PAIRS:
        true_url = _build_url(base_url, param, true_payload)
        false_url = _build_url(base_url, param, false_payload)
        try:
            true_resp = _get(session, true_url, proxy, ca_bundle)
            false_resp = _get(session, false_url, proxy, ca_bundle)
        except requests.RequestException as e:
            return None, str(e)

        if SQL_ERROR_SIGNATURES.search(true_resp.text) or SQL_ERROR_SIGNATURES.search(false_resp.text):
            continue  # that's check_sql_injection()'s signal, skip here to avoid double-reporting

        true_vs_baseline = _similarity(true_resp.text, baseline.text)
        true_vs_false = _similarity(true_resp.text, false_resp.text)
        len_diff = abs(len(true_resp.text) - len(false_resp.text))

        # Two independent oracles, either one is enough:
        #   - status code: TRUE matches baseline's status, FALSE doesn't
        #     (e.g. 200 vs 404 for found/not-found) - a clean signal that
        #     survives even when the page body is mostly shared template
        #     (nav/footer) around a small differing snippet.
        #   - content similarity: TRUE closely matches normal (baseline)
        #     behavior, FALSE differs meaningfully - catches apps that
        #     stay on the same status code but change the body (e.g. a
        #     "no results" message on a 200).
        # Content similarity alone false-negatived here once a page had a
        # large shared template: a ~30-byte "found"/"not found" swing
        # inside a ~3KB shared nav/footer barely moves the ratio, even
        # though the pages are clearly different. Status code doesn't
        # have that problem, so it catches what similarity alone misses.
        status_differs = (
            true_resp.status_code == baseline.status_code
            and false_resp.status_code != baseline.status_code
        )
        content_differs = true_vs_baseline > 0.90 and true_vs_false < 0.85

        if status_differs or content_differs:
            if status_differs:
                signal = (
                    f"TRUE payload ({true_payload}) returned status {true_resp.status_code} "
                    f"(matching the baseline), FALSE payload ({false_payload}) returned "
                    f"{false_resp.status_code} instead."
                )
            else:
                signal = (
                    f"TRUE payload ({true_payload}) response vs FALSE payload "
                    f"({false_payload}) response: similarity={true_vs_false:.2f}, "
                    f"length difference={len_diff} bytes."
                )
            return {
                "risk": "High",
                "name": "Possible Boolean-Based Blind SQL Injection",
                "description": (
                    f"Parameter '{param}' produces a different response for a true SQL "
                    f"condition than for a false one, with no error message in either "
                    f"case - the response itself leaks whether the injected "
                    f"condition was true, suggesting unsanitized input reaches a query."
                ),
                "evidence": signal,
                "url": true_url,
            }, None

    return None, None


def check_time_based_blind_sqli(session, base_url, param, proxy=None, ca_bundle=None, delay=5):
    """
    Covers the case where the app leaks nothing at all in its response -
    no error, no content difference - but the database itself can still
    be told to pause. Injects a payload that asks the DB to sleep for
    `delay` seconds and checks whether the response actually took that
    long.

    To avoid flagging a target that's just slow, a finding requires ALL of:
      1. The payload's response takes at least `delay` seconds longer
         than baseline.
      2. That delay reproduces on a second, independent request.
      3. A "control" request - same payload syntax, but a 0-second delay -
         comes back fast, ruling out "this endpoint/param is just slow
         no matter what you send it".
    """
    try:
        start = time.time()
        _get(session, base_url, proxy, ca_bundle, timeout=delay + 15)
        baseline_time = time.time() - start
    except requests.RequestException as e:
        return None, str(e)

    for template in TIME_BASED_PAYLOAD_TEMPLATES:
        payload = template.format(d=delay)
        control_payload = template.format(d=0)
        test_url = _build_url(base_url, param, payload)

        try:
            t0 = time.time()
            _get(session, test_url, proxy, ca_bundle, timeout=delay + 15)
            elapsed_1 = time.time() - t0
        except requests.RequestException:
            continue  # this syntax likely broke the query outright, try the next one

        if elapsed_1 < baseline_time + delay - 1:
            continue  # no meaningful delay from this payload syntax

        try:
            t1 = time.time()
            _get(session, test_url, proxy, ca_bundle, timeout=delay + 15)
            elapsed_2 = time.time() - t1
        except requests.RequestException:
            continue
        if elapsed_2 < baseline_time + delay - 1:
            continue  # didn't reproduce - could've been a network blip, not a real signal

        try:
            control_url = _build_url(base_url, param, control_payload)
            t2 = time.time()
            _get(session, control_url, proxy, ca_bundle, timeout=delay + 15)
            control_elapsed = time.time() - t2
        except requests.RequestException:
            control_elapsed = 0.0

        if control_elapsed > baseline_time + (delay / 2):
            continue  # the param/endpoint is just generally slow - not a real signal

        return {
            "risk": "High",
            "name": "Possible Time-Based Blind SQL Injection",
            "description": (
                f"Parameter '{param}' reproducibly delayed the response by ~{delay}s "
                f"when a database sleep condition was injected, while an equivalent "
                f"zero-delay payload returned quickly - indicating unsanitized input "
                f"reaches a SQL query, even though nothing is visible in the response."
            ),
            "evidence": (
                f"Payload '{payload}' delayed responses by {elapsed_1:.1f}s and "
                f"{elapsed_2:.1f}s on repeat (baseline {baseline_time:.1f}s, "
                f"zero-delay control {control_elapsed:.1f}s)."
            ),
            "url": test_url,
        }, None

    return None, None


def check_path_traversal(session, base_url, param, proxy=None, ca_bundle=None):
    """
    Injects classic directory-traversal sequences (in a few depths/
    encodings, since we don't know the target OS or how many directories
    the vulnerable include actually sits under) and checks the response
    for content unique to /etc/passwd or windows/win.ini - files that are
    always present and harmless to read, but should never appear unless
    the app is passing our input straight into a file path.
    """
    for payload in PATH_TRAVERSAL_PAYLOADS:
        test_url = _build_url(base_url, param, payload)
        try:
            resp = _get(session, test_url, proxy, ca_bundle)
        except requests.RequestException as e:
            return None, str(e)

        if LINUX_TRAVERSAL_SIGNATURE.search(resp.text):
            return {
                "risk": "High",
                "name": "Possible Path Traversal / Local File Inclusion",
                "description": (
                    f"Parameter '{param}' returned the contents of /etc/passwd when a "
                    f"directory traversal sequence was injected, indicating the "
                    f"application passes unsanitized input into a file path."
                ),
                "evidence": f"Traversal payload '{payload}' returned /etc/passwd content at: {test_url}",
                "url": test_url,
            }, None

        if WINDOWS_TRAVERSAL_SIGNATURE.search(resp.text):
            return {
                "risk": "High",
                "name": "Possible Path Traversal / Local File Inclusion",
                "description": (
                    f"Parameter '{param}' returned the contents of windows/win.ini when a "
                    f"directory traversal sequence was injected, indicating the "
                    f"application passes unsanitized input into a file path."
                ),
                "evidence": f"Traversal payload '{payload}' returned win.ini content at: {test_url}",
                "url": test_url,
            }, None

    return None, None


def check_command_injection(session, base_url, param, proxy=None, ca_bundle=None):
    """
    First tries to get command output reflected directly into the
    response. Uses an arithmetic marker (multiply two fixed numbers,
    look for the product) rather than a literal echoed string, because a
    literal string can leak into the response just from the app echoing
    back unrecognized input in an error message - with no shell having
    executed anything. The product digits only appear if a shell
    genuinely evaluated the expression. Only falls back to the slower
    time-based check if nothing reflects, the same escalation pattern
    used for SQLi above.
    """
    for template in CMD_INJECTION_PAYLOAD_TEMPLATES:
        payload = template.format(a=_CMD_INJECTION_A, b=_CMD_INJECTION_B)
        test_url = _build_url(base_url, param, payload)
        try:
            resp = _get(session, test_url, proxy, ca_bundle)
        except requests.RequestException:
            continue  # this syntax likely broke the request outright, try the next one

        if CMD_INJECTION_PRODUCT in resp.text:
            return {
                "risk": "High",
                "name": "Possible OS Command Injection",
                "description": (
                    f"Parameter '{param}' caused a shell command's output to appear in "
                    f"the response when a command-chaining payload was injected, "
                    f"indicating unsanitized input reaches a system shell call."
                ),
                "evidence": (
                    f"Payload '{payload}' caused the computed value "
                    f"'{CMD_INJECTION_PRODUCT}' ({_CMD_INJECTION_A} x {_CMD_INJECTION_B}) "
                    f"to appear in the response at: {test_url}"
                ),
                "url": test_url,
            }, None

    return check_blind_command_injection(session, base_url, param, proxy, ca_bundle)


def check_blind_command_injection(session, base_url, param, proxy=None, ca_bundle=None, delay=5):
    """
    Covers command injection that reflects no output at all - same
    reasoning as check_time_based_blind_sqli(): inject a payload that
    tells the shell to sleep, confirm the delay is real (reproduces on a
    second request) and not just target slowness (a zero-delay control
    stays fast).
    """
    try:
        start = time.time()
        _get(session, base_url, proxy, ca_bundle, timeout=delay + 15)
        baseline_time = time.time() - start
    except requests.RequestException as e:
        return None, str(e)

    for template in CMD_INJECTION_TIME_PAYLOAD_TEMPLATES:
        payload = template.format(d=delay)
        control_payload = template.format(d=0)
        test_url = _build_url(base_url, param, payload)

        try:
            t0 = time.time()
            _get(session, test_url, proxy, ca_bundle, timeout=delay + 15)
            elapsed_1 = time.time() - t0
        except requests.RequestException:
            continue

        if elapsed_1 < baseline_time + delay - 1:
            continue

        try:
            t1 = time.time()
            _get(session, test_url, proxy, ca_bundle, timeout=delay + 15)
            elapsed_2 = time.time() - t1
        except requests.RequestException:
            continue
        if elapsed_2 < baseline_time + delay - 1:
            continue

        try:
            control_url = _build_url(base_url, param, control_payload)
            t2 = time.time()
            _get(session, control_url, proxy, ca_bundle, timeout=delay + 15)
            control_elapsed = time.time() - t2
        except requests.RequestException:
            control_elapsed = 0.0

        if control_elapsed > baseline_time + (delay / 2):
            continue

        return {
            "risk": "High",
            "name": "Possible Blind OS Command Injection",
            "description": (
                f"Parameter '{param}' reproducibly delayed the response by ~{delay}s "
                f"when a shell sleep condition was injected, while an equivalent "
                f"zero-delay payload returned quickly - indicating unsanitized input "
                f"reaches a system shell call, even though nothing is visible in the "
                f"response."
            ),
            "evidence": (
                f"Payload '{payload}' delayed responses by {elapsed_1:.1f}s and "
                f"{elapsed_2:.1f}s on repeat (baseline {baseline_time:.1f}s, "
                f"zero-delay control {control_elapsed:.1f}s)."
            ),
            "url": test_url,
        }, None

    return None, None


def check_open_redirect(session, base_url, param, proxy=None, ca_bundle=None):
    """
    Injects an absolute (or bypass-style) URL into the parameter and
    follows the response WITHOUT auto-following redirects, so we can
    inspect the Location header directly. A vulnerable app copies the
    parameter straight into Location; a safe app either ignores it,
    rejects it, or rewrites it to a relative/allow-listed path.
    """
    for payload in OPEN_REDIRECT_PAYLOADS:
        test_url = _build_url(base_url, param, payload)
        try:
            resp = _get(session, test_url, proxy, ca_bundle, allow_redirects=False)
        except requests.RequestException as e:
            return None, str(e)

        if 300 <= resp.status_code < 400:
            location = resp.headers.get("Location", "")
            target_host = urlparse(OPEN_REDIRECT_TARGET).netloc
            if target_host in location:
                return {
                    "risk": "Medium",
                    "name": "Possible Open Redirect",
                    "description": (
                        f"Parameter '{param}' is copied directly into the redirect "
                        f"Location header without validating it stays on-site, "
                        f"allowing attackers to craft links that appear to point at "
                        f"this domain but redirect victims elsewhere (used in "
                        f"phishing)."
                    ),
                    "evidence": f"Payload '{payload}' produced a {resp.status_code} redirect to '{location}' at: {test_url}",
                    "url": test_url,
                }, None

    return None, None


def scan_url(target_url, proxy=None, ca_bundle=None, progress_callback=None, auth_config=None):
    """
    Tests every query-string parameter on target_url for reflected XSS
    and SQL injection. Returns a list of finding dicts.

    If target_url has no query parameters, returns an empty list with a
    note - there's nothing here for this scanner to test (form/POST
    parameter testing is a future extension, not covered yet).

    auth_config: optional auth.manager.AuthConfig. If given, the scan
    runs using an authenticated session (cookie or form login), and
    will automatically detect and recover from a mid-scan logout.
    """
    parsed = urlparse(target_url)
    params = list(parse_qs(parsed.query).keys())
    findings = []
    errors = []

    if not params:
        return findings, ["No query parameters found on this URL - nothing for the active scanner to test here."]

    if auth_config:
        session, ok, msg = auth_manager.build_authenticated_session(auth_config, proxy=proxy, ca_bundle=ca_bundle)
        if not ok:
            return findings, [f"Authentication failed, aborting scan: {msg}"]
    else:
        session = requests.Session()
    for param in params:
        if progress_callback:
            progress_callback(f"Testing parameter: {param} (XSS)")
        finding, err = check_reflected_xss(session, target_url, param, proxy, ca_bundle)
        if finding:
            findings.append(finding)
        if err:
            errors.append(f"{param} (XSS check): {err}")

        if progress_callback:
            progress_callback(f"Testing parameter: {param} (SQLi - error-based)")
        finding, err = check_sql_injection(session, target_url, param, proxy, ca_bundle)
        sqli_found = finding is not None
        if finding:
            findings.append(finding)
        if err:
            errors.append(f"{param} (SQLi error-based check): {err}")

        if not sqli_found:
            if progress_callback:
                progress_callback(f"Testing parameter: {param} (SQLi - boolean blind)")
            finding, err = check_boolean_blind_sqli(session, target_url, param, proxy, ca_bundle)
            sqli_found = finding is not None
            if finding:
                findings.append(finding)
            if err:
                errors.append(f"{param} (SQLi boolean-blind check): {err}")

        if not sqli_found:
            # Slowest check by far (each payload can take several seconds) -
            # only run it if the faster checks above found nothing.
            if progress_callback:
                progress_callback(f"Testing parameter: {param} (SQLi - time-based blind, this can take a bit)")
            finding, err = check_time_based_blind_sqli(session, target_url, param, proxy, ca_bundle)
            if finding:
                findings.append(finding)
            if err:
                errors.append(f"{param} (SQLi time-based blind check): {err}")

        if progress_callback:
            progress_callback(f"Testing parameter: {param} (Path Traversal)")
        finding, err = check_path_traversal(session, target_url, param, proxy, ca_bundle)
        if finding:
            findings.append(finding)
        if err:
            errors.append(f"{param} (Path Traversal check): {err}")

        if progress_callback:
            progress_callback(f"Testing parameter: {param} (Command Injection)")
        finding, err = check_command_injection(session, target_url, param, proxy, ca_bundle)
        if finding:
            findings.append(finding)
        if err:
            errors.append(f"{param} (Command Injection check): {err}")

        if progress_callback:
            progress_callback(f"Testing parameter: {param} (Open Redirect)")
        finding, err = check_open_redirect(session, target_url, param, proxy, ca_bundle)
        if finding:
            findings.append(finding)
        if err:
            errors.append(f"{param} (Open Redirect check): {err}")

    return findings, errors
