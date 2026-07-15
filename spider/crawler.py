"""
crawler.py
Spider/crawler: given a starting URL, follows links (and form actions)
to map out a site's structure.

Requests are routed through the same mitmproxy instance used everywhere
else in this project (127.0.0.1:8081 by default), so every page the
spider visits automatically flows through addon.py -> gets captured ->
gets passively scanned. The spider itself doesn't touch storage.py
directly for traffic - it only tracks its own crawl progress/results.

Scope is restricted to the same registrable host as the start URL, so
a crawl of https://target.example.com won't wander off into unrelated
sites it happens to link to (analytics domains, social share links, etc).
"""

import re
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "auth"))
import manager as auth_manager  # noqa: E402

LINK_PATTERN = re.compile(r'href=["\']([^"\']+)["\']', re.I)
FORM_ACTION_PATTERN = re.compile(r'<form[^>]+action=["\']([^"\']+)["\']', re.I)

SKIP_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff", ".woff2",
                    ".ico", ".pdf", ".zip", ".mp4", ".mp3")


def same_scope(url, root_host):
    host = urlparse(url).hostname or ""
    return host == root_host


def extract_links(html, base_url):
    links = set()
    for pattern in (LINK_PATTERN, FORM_ACTION_PATTERN):
        for match in pattern.findall(html):
            absolute = urljoin(base_url, match)
            absolute = absolute.split("#")[0]  # drop fragments
            if absolute.startswith("http") and not absolute.lower().endswith(SKIP_EXTENSIONS):
                links.add(absolute)
    return links


def crawl(start_url, max_depth=2, max_pages=50, proxy=None, delay=0.3,
          progress_callback=None, ca_bundle=None, auth_config=None):
    """
    BFS crawl starting from start_url.

    proxy: e.g. "http://127.0.0.1:8081" - routes traffic through the
           project's proxy so it gets captured/scanned automatically.
    ca_bundle: path to mitmproxy's CA cert (~/.mitmproxy/mitmproxy-ca-cert.pem)
               for proper certificate verification through the proxy.
               If not given, falls back to verify=False (still functional,
               just doesn't validate the proxy's cert chain).
    progress_callback: optional fn(visited_count, total_queued, current_url)
                        called after each page, for live progress reporting.
    auth_config: optional auth.manager.AuthConfig - crawls using an
                 authenticated session so pages behind a login can be
                 discovered too, with automatic re-login if the session
                 drops mid-crawl.

    Returns: sorted list of every URL discovered (visited or just linked-to).
    """
    root_host = urlparse(start_url).hostname
    verify = ca_bundle if ca_bundle else False

    if auth_config:
        session, ok, msg = auth_manager.build_authenticated_session(auth_config, proxy=proxy, ca_bundle=ca_bundle)
        if not ok:
            if progress_callback:
                progress_callback(0, 0, f"AUTH FAILED: {msg}")
            return []
    else:
        session = requests.Session()
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}

    visited = set()
    discovered = set([start_url])
    queue = [(start_url, 0)]

    while queue and len(visited) < max_pages:
        url, depth = queue.pop(0)
        if url in visited or depth > max_depth:
            continue
        visited.add(url)

        try:
            resp = session.get(url, timeout=8, verify=verify, allow_redirects=True)
            if auth_config and auth_manager.looks_logged_out(resp.text, auth_config):
                ok, _ = auth_manager.reauthenticate(session, proxy=proxy, ca_bundle=ca_bundle)
                if ok:
                    resp = session.get(url, timeout=8, verify=verify, allow_redirects=True)
            html = resp.text if "text/html" in resp.headers.get("Content-Type", "") else ""
        except requests.RequestException as e:
            if progress_callback:
                progress_callback(len(visited), len(discovered), f"FAILED: {url} ({e})")
            time.sleep(delay)
            continue

        if html and depth < max_depth:
            for link in extract_links(html, url):
                if same_scope(link, root_host) and link not in discovered:
                    discovered.add(link)
                    queue.append((link, depth + 1))

        if progress_callback:
            progress_callback(len(visited), len(discovered), url)

        time.sleep(delay)  # polite pacing - don't hammer the target

    return sorted(discovered)
