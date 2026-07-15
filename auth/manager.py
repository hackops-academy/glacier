"""
manager.py
Authentication support: lets the spider and active scanner test areas of
a site that require being logged in.

Two modes:
  - cookie: you provide a raw pre-authenticated Cookie header (e.g.
    copied from your browser's devtools after logging in manually).
    Simplest option, no login flow needed, but the session will
    eventually expire and there's nothing to automatically refresh it.
  - form: you provide a login URL and credentials. This module performs
    the login POST itself to get a fresh session, and can detect if the
    scan gets logged out partway through (session timeout, CSRF token
    rotation, etc.) and automatically re-authenticate before continuing.

Design: rather than threading an auth_config parameter through every
function signature in crawler.py and scanner.py, the AuthConfig is
attached directly to the requests.Session object as an attribute
(session.glacier_auth). Every place that already receives a session
can check for it without an API change - this keeps auth support
backward compatible with code that doesn't know about it.
"""

import requests


class AuthConfig:
    def __init__(self, mode, cookie_header=None, login_url=None,
                 username_field="username", password_field="password",
                 username=None, password=None, extra_fields=None,
                 success_indicator=None, logout_indicator=None):
        """
        mode: "cookie" | "form"
        cookie_header: raw "Cookie: ..." header value, for mode="cookie"
        login_url, username/password_field, username, password, extra_fields:
            for mode="form" - extra_fields is an optional dict of any
            additional form fields the login page requires (e.g. a
            hidden CSRF token with a fixed test value).
        success_indicator: a string that should appear in the response
            when logged in successfully (used to verify login worked,
            and to detect logout later - its ABSENCE signals logout).
        logout_indicator: a string that, if PRESENT in a response,
            signals the session has been logged out (e.g. "Please log in").
            Either success_indicator or logout_indicator should be given;
            using both is fine too.
        """
        self.mode = mode
        self.cookie_header = cookie_header
        self.login_url = login_url
        self.username_field = username_field
        self.password_field = password_field
        self.username = username
        self.password = password
        self.extra_fields = extra_fields or {}
        self.success_indicator = success_indicator
        self.logout_indicator = logout_indicator


def _apply_cookie_header(session, cookie_header):
    # Parse a raw "name=value; name2=value2" Cookie header into the
    # session's cookie jar.
    for part in cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            session.cookies.set(k.strip(), v.strip())


def login(session, auth_config, proxy=None, ca_bundle=None, timeout=10):
    """
    Performs the actual authentication for the given session, in place.
    Returns (ok: bool, message: str).
    """
    kwargs = {"timeout": timeout, "verify": ca_bundle if ca_bundle else False}
    if proxy:
        kwargs["proxies"] = {"http": proxy, "https": proxy}

    if auth_config.mode == "cookie":
        _apply_cookie_header(session, auth_config.cookie_header)
        return True, "cookie applied"

    if auth_config.mode == "form":
        if not auth_config.login_url:
            return False, "form mode requires login_url"
        payload = {
            auth_config.username_field: auth_config.username,
            auth_config.password_field: auth_config.password,
        }
        payload.update(auth_config.extra_fields)
        try:
            resp = session.post(auth_config.login_url, data=payload, **kwargs)
        except requests.RequestException as e:
            return False, f"login request failed: {e}"

        if auth_config.success_indicator and auth_config.success_indicator not in resp.text:
            return False, "login response did not contain success_indicator - check credentials/URL"
        if auth_config.logout_indicator and auth_config.logout_indicator in resp.text:
            return False, "login response contained logout_indicator - login likely failed"
        return True, "login successful"

    return False, f"unknown auth mode: {auth_config.mode}"


def build_authenticated_session(auth_config, proxy=None, ca_bundle=None):
    """
    Creates a fresh requests.Session, logs it in per auth_config, and
    attaches the config to the session so downstream code (crawler,
    scanner) can detect logout and re-authenticate automatically.
    Returns (session, ok, message).
    """
    session = requests.Session()
    session.glacier_auth = auth_config
    ok, msg = login(session, auth_config, proxy=proxy, ca_bundle=ca_bundle)
    return session, ok, msg


def looks_logged_out(response_text, auth_config):
    """
    Checks a response body against the configured indicators to decide
    whether the session appears to have been logged out.
    """
    if auth_config is None:
        return False
    if auth_config.logout_indicator and auth_config.logout_indicator in response_text:
        return True
    if auth_config.success_indicator and auth_config.mode == "form":
        # Absence of the success indicator on what should be an
        # authenticated page is a softer signal - only useful if the
        # caller specifically checks pages that normally show it.
        return False  # left to caller: too easy to false-positive on
                       # pages that never show the indicator anyway.
    return False


def reauthenticate(session, proxy=None, ca_bundle=None):
    """Re-runs login using the AuthConfig already attached to the session."""
    auth_config = getattr(session, "glacier_auth", None)
    if auth_config is None:
        return False, "no auth config attached to this session"
    return login(session, auth_config, proxy=proxy, ca_bundle=ca_bundle)
