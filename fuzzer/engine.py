"""
engine.py
Fuzzer core (Intruder-style): mark the injection point(s) in a request
template with the literal string FUZZ, then fire one request per line of
a payload wordlist, substituting FUZZ for that payload each time.

Same request-crafting trust model as Repeater - the person decides
exactly what template and payloads to use - but unlike Repeater this can
fire hundreds of requests at a live target in one call, so the API layer
(not this module) gates it behind confirm=True plus a hard payload-count
cap (MAX_PAYLOADS), the same posture as the active scanner.
"""

import time
from urllib.parse import quote

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

FUZZ_MARKER = "FUZZ"
MAX_PAYLOADS = 1000
_STRIP_HEADERS = {"content-length", "host", "connection"}

# Ready-to-go wordlists so people aren't stuck writing their own on day
# one. Intentionally small and generic - a real engagement will usually
# swap in a target-specific list, but these cover the obvious cases and
# are useful for sanity-checking the fuzzer itself.
WORDLISTS = {
    "common_usernames": ["admin", "administrator", "root", "test", "guest", "user", "demo", "sa"],
    "sqli_probes": ["'", '"', "' OR '1'='1", "1' AND '1'='1", "1 OR 1=1", "'; DROP TABLE x-- -"],
    "xss_probes": ["<script>alert(1)</script>", "\"><svg/onload=alert(1)>", "'><img src=x onerror=alert(1)>"],
    "path_traversal": ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "....//....//etc/passwd"],
    "numbers_1_100": [str(i) for i in range(1, 101)],
}


def has_marker(url, headers_text, body):
    return FUZZ_MARKER in (url or "") or FUZZ_MARKER in (headers_text or "") or FUZZ_MARKER in (body or "")


def parse_headers_text(headers_text):
    """Same "Key: value" text format used throughout glacier (History,
    Repeater) - so a template can be pasted straight in from either."""
    headers = {}
    if not headers_text:
        return headers
    for line in headers_text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip()] = v.strip()
    return headers


def _substitute(text, payload, url_encode=False):
    if not text:
        return text
    value = quote(payload, safe="") if url_encode else payload
    return text.replace(FUZZ_MARKER, value)


def run_fuzz(method, url, headers_text, body, payloads, proxy=None, ca_bundle=None,
             delay=0, timeout=15, stop_event=None, on_result=None):
    """
    Fires one request per payload, substituting FUZZ wherever it appears
    in the URL (URL-encoded, since that's a query-string/path context),
    headers, and body (both raw).

    on_result(index, payload, result_dict) is called after every request
    so the caller can persist/stream results incrementally instead of
    waiting for the whole run to finish. stop_event (a threading.Event)
    lets a long run be cancelled between requests.

    Never raises: a request that fails to send is recorded as its own
    result with ok=False rather than aborting the whole run - one bad
    payload shouldn't cost you the other 999 results.
    """
    for i, payload in enumerate(payloads):
        if stop_event is not None and stop_event.is_set():
            break

        test_url = _substitute(url, payload, url_encode=True)
        test_headers_text = _substitute(headers_text, payload, url_encode=False)
        test_body = _substitute(body, payload, url_encode=False)
        headers = parse_headers_text(test_headers_text)
        headers = {k: v for k, v in headers.items() if k.lower() not in _STRIP_HEADERS}

        kwargs = {
            "headers": headers,
            "timeout": timeout,
            "verify": ca_bundle if ca_bundle else False,
            "allow_redirects": False,
        }
        if proxy:
            kwargs["proxies"] = {"http": proxy, "https": proxy}
        if test_body:
            kwargs["data"] = test_body.encode("utf-8", errors="replace")

        start = time.time()
        try:
            resp = requests.request(method.upper(), test_url, **kwargs)
            result = {
                "ok": True,
                "status_code": resp.status_code,
                "reason": resp.reason,
                "length": len(resp.content),
                "elapsed_ms": round((time.time() - start) * 1000),
                "response_headers": "\n".join(f"{k}: {v}" for k, v in resp.headers.items()),
                "response_body": resp.text[:200_000],
                "url": test_url,
            }
        except requests.RequestException as e:
            result = {
                "ok": False,
                "error": str(e),
                "url": test_url,
                "elapsed_ms": round((time.time() - start) * 1000),
            }

        if on_result:
            on_result(i, payload, result)

        if delay:
            time.sleep(delay)
