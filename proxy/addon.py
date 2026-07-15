"""
addon.py
mitmproxy addon: the intercepting proxy core.

This is loaded by mitmdump/mitmproxy and captures every request/response
that flows through it, writing each one to the shared SQLite database via
storage.py. This is the foundation phase 3 (passive scanner) and phase 4
(spider) will build on top of.

Run with:
    mitmdump -s addon.py -p 8081

Then point a browser (or curl, or a target app) at 127.0.0.1:8081 as its
HTTP/HTTPS proxy. For HTTPS interception you'll need to install mitmproxy's
CA certificate once — visit http://mitm.it while proxied through it.
"""

from urllib.parse import urlparse
import sys
from pathlib import Path

import storage

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "passive"))
import engine as passive_engine  # noqa: E402


def load(loader):
    storage.init_db()


def headers_to_text(headers):
    return "\n".join(f"{k}: {v}" for k, v in headers.items())


def response(flow):
    """Called by mitmproxy once a full request/response pair has completed."""
    req = flow.request
    resp = flow.response

    host = urlparse(req.pretty_url).hostname or req.host

    try:
        req_body = req.get_text(strict=False) or ""
    except Exception:
        req_body = ""
    try:
        resp_body = resp.get_text(strict=False) or ""
    except Exception:
        resp_body = ""

    # Cap stored body size so huge responses (video, binaries) don't bloat the DB.
    resp_body = resp_body[:200_000]
    req_body = req_body[:50_000]

    traffic_id = storage.record_traffic(
        host=host,
        method=req.method,
        url=req.pretty_url,
        req_headers=headers_to_text(req.headers),
        req_body=req_body,
        status_code=resp.status_code,
        resp_headers=headers_to_text(resp.headers),
        resp_body=resp_body,
    )

    record = storage.get_message(traffic_id)
    passive_engine.scan(traffic_id, record)
