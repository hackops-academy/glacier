"""
sender.py
Repeater core: sends exactly one manually-specified HTTP request and
returns the full response. This plays the same role as Burp's Repeater
or ZAP's manual request editor - a scalpel for a human to craft and
resend a single request by hand, tweak it, and compare responses.

This is deliberately NOT gated behind a confirm=True flag the way the
active scanner and pipeline are. Those decide *what* to send and expand
scope on their own (every parameter on a page, every page on a site);
this sends exactly and only the one request the person in front of the
keyboard explicitly typed - the same trust model as curl, a browser's
dev tools "resend", or Postman. The person is the one deciding, every
single time.
"""

import time

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Headers that are either stale once a request's been hand-edited
# (Content-Length no longer matches an edited body) or that `requests`
# manages itself - sending them through causes confusing double-header
# or mismatched-length errors rather than anything useful.
_STRIP_HEADERS = {"content-length", "host", "connection"}


def parse_headers_text(headers_text):
    """
    Parses the same "Key: value\\nKey2: value2" text format the rest of
    glacier already stores headers in (see proxy/addon.py's
    headers_to_text) - so a request copied from the History tab can be
    pasted straight into the Repeater without reformatting.
    """
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


def headers_to_text(headers):
    return "\n".join(f"{k}: {v}" for k, v in headers.items())


def send_request(method, url, headers_text=None, body=None, proxy=None, ca_bundle=None, timeout=30):
    """
    Sends the request and returns a result dict. Never raises - network
    or protocol failures come back as {"ok": False, "error": ...} so the
    caller can show them rather than crashing the request.
    """
    headers = parse_headers_text(headers_text)
    headers = {k: v for k, v in headers.items() if k.lower() not in _STRIP_HEADERS}

    kwargs = {
        "headers": headers,
        "timeout": timeout,
        "verify": ca_bundle if ca_bundle else False,
        # A manual tool shouldn't silently follow a redirect out from
        # under the user - show the 3xx and let them decide whether to
        # send the next request themselves.
        "allow_redirects": False,
    }
    if proxy:
        kwargs["proxies"] = {"http": proxy, "https": proxy}
    if body:
        kwargs["data"] = body.encode("utf-8", errors="replace") if isinstance(body, str) else body

    start = time.time()
    try:
        resp = requests.request(method.upper(), url, **kwargs)
    except requests.RequestException as e:
        return {"ok": False, "error": str(e)}

    elapsed_ms = round((time.time() - start) * 1000)
    return {
        "ok": True,
        "status_code": resp.status_code,
        "reason": resp.reason,
        "response_headers": headers_to_text(resp.headers),
        "response_body": resp.text[:1_000_000],  # cap so a huge response doesn't blow up the UI
        "elapsed_ms": elapsed_ms,
    }
