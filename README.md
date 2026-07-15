# Glacier
### made by HackOps Academy

A web application security scanner built from scratch — intercepting proxy,
passive scanner, spider, active scanner, and a native desktop GUI — under
the HackOps Academy banner.

> **stay legal, stay anonymous.**
> Only ever point this at systems you own or are explicitly authorized to
> test. The active scanner in particular sends real test payloads to the
> target — treat it the same way you'd treat Burp Suite's active scanner
> or sqlmap: powerful, and only for authorized use.

## What it does

- **Intercepting proxy** — captures every request/response that flows
  through it (built on [mitmproxy](https://mitmproxy.org/))
- **Passive scanner** — inspects captured traffic automatically for
  missing security headers, insecure cookies, server version disclosure,
  verbose error messages, and exposed secrets (API keys, JWTs, private
  keys) — never sends extra traffic, pure inspection
- **Spider** — crawls a target from a starting URL, following links and
  form actions within the same host
- **Active scanner** — on-demand, per-URL testing for reflected XSS,
  SQL injection (error-based, boolean-based blind, and time-based blind),
  path traversal / local file inclusion, OS command injection (reflected
  and blind/time-based), and open redirect, using standard published
  detection methodology. Requires explicit confirmation before it runs.
- **Repeater** — a manual request editor: craft a request from scratch or
  pull one straight from History, tweak method/headers/body, resend, and
  compare responses. Every send is logged so you can jump back to any
  earlier attempt. No confirmation gate, unlike the active scanner - it
  sends exactly and only the one request you explicitly typed, the same
  trust model as curl or a browser's dev tools.
- **Fuzzer** — Intruder-style batch testing: mark an injection point with
  the literal text `FUZZ` anywhere in a request (URL, header, or body),
  supply a wordlist, and one request goes out per payload. Results land
  in a sortable table (by status code, response length, or timing) so
  the one anomalous response in a batch of hundreds stands out. Escalate
  straight into it with one click from History or Repeater. Gated behind
  explicit confirmation and a 1000-payload hard cap, same posture as the
  active scanner.
- **Findings management** — deduplicates repeated issues across many
  pages into grouped findings, with open/fixed/false-positive status
  tracking
- **HUD** — a native Electron desktop GUI tying it all together

## Architecture

```
proxy (mitmproxy addon)  →  SQLite  ←  API (FastAPI)  ←  HUD (Electron)
        ↓
  passive scanner (runs automatically on every captured response)

spider / active scanner → triggered on demand via the API, write into
the same SQLite findings table
```

Every component talks to the same SQLite database (`proxy/glacier.db`,
created automatically, gitignored). The proxy and API are separate
processes so the API can serve the HUD live while the proxy keeps
capturing in the background.

## Quickstart

Requires Python 3.10+, Node.js 18+, and (optionally) `tmux` for the
one-command launch.

```bash
git clone <your-repo-url>
cd glacier
./setup.sh      # creates the venv, installs Python + Node dependencies
./start.sh      # launches proxy, API, and HUD together in tmux panes
```

No `tmux`? `start.sh` will print the three commands to run manually in
separate terminals instead.

Once the HUD window opens, enter `http://localhost:8090` and hit
**Connect**.

### Using the proxy

Point your browser's HTTP/HTTPS proxy at `127.0.0.1:8081`, then visit
`http://mitm.it` through that proxy once to install and trust mitmproxy's
CA certificate (needed for HTTPS interception).

### Testing safely before scanning anything real

`tools/vulnerable_test_app.py` is a small deliberately-vulnerable local
Flask app (SQLi, XSS, path traversal, OS command injection, and open
redirect endpoints, plus properly-guarded "safe" endpoints for each one
as a negative control). Use it to confirm the active scanner is working
correctly before pointing it at anything real:

```bash
. venv/bin/activate
python3 tools/vulnerable_test_app.py   # http://127.0.0.1:5001
```

### Testing authenticated areas

The spider and active scanner can both run against a logged-in session, so
protected pages get discovered and tested instead of silently skipped.
Two modes, passed as an optional `auth` object on `/api/spider/start`,
`/api/active/scan`, and `/api/pipeline/scan`:

**Cookie mode** - paste a session cookie you already have (e.g. copied
from your browser after logging in manually):
```json
{"auth": {"mode": "cookie", "cookie_header": "session=abc123"}}
```

**Form mode** - the tool performs the login itself, and will detect a
mid-scan logout (session timeout, etc.) and automatically re-authenticate:
```json
{"auth": {
  "mode": "form",
  "login_url": "https://target.example.com/login",
  "username": "hackops", "password": "hackops",
  "success_indicator": "Welcome back",
  "logout_indicator": "Please log in"
}}
```
`success_indicator` / `logout_indicator` are optional but recommended -
they're what let the tool notice it got logged out partway through a
scan and recover on its own. The included `tools/vulnerable_test_app.py`
has a real login flow (`hackops` / `hackops`) and a protected `/account`
page to test this against.

## Project layout

```
proxy/      intercepting proxy addon + shared SQLite storage layer
passive/    passive scan rules + engine
spider/     crawler
active/     active scanner (XSS / SQLi / path traversal / cmd injection / open redirect detection)
auth/       authentication support (cookie or form login, session/logout handling)
repeater/   manual request editor core (sender.py)
fuzzer/     Intruder-style batch request engine (engine.py)
api/        FastAPI server tying it all together
tools/      vulnerable_test_app.py - safe local test target
hud/        Electron desktop GUI
```

## API reference (brief)

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/sites` | GET | Captured hosts |
| `/api/traffic` | GET | Captured requests/responses |
| `/api/traffic/{id}` | GET | Single message detail |
| `/api/findings` | GET | Flat findings list |
| `/api/findings/grouped` | GET | Deduplicated findings by host+name+risk |
| `/api/findings/summary` | GET | Open finding counts by risk |
| `/api/findings/{id}` | PATCH | Update one finding's status |
| `/api/findings/bulk-status` | PATCH | Update all matching findings at once |
| `/api/spider/start` | POST | Start a crawl |
| `/api/spider/status/{job_id}` | GET | Crawl progress |
| `/api/spider/results/{job_id}` | GET | Discovered URLs |
| `/api/active/scan` | POST | Start an active scan on one URL (`confirm: true` required) |
| `/api/active/status/{job_id}` | GET | Scan progress/results |
| `/api/pipeline/scan` | POST | Crawl a site AND auto-scan every discovered parameterized URL (`confirm: true` required, optional `auth` for authenticated crawling/scanning) |
| `/api/pipeline/status/{job_id}` | GET | Pipeline progress/results |
| `/api/repeater/send` | POST | Send one manually-specified request, log it, return the response |
| `/api/repeater/history` | GET | List sent Repeater requests |
| `/api/repeater/{id}` | GET | Full detail (request + response) for one Repeater entry |
| `/api/repeater/{id}` | DELETE | Remove one Repeater entry |
| `/api/fuzz/start` | POST | Start a fuzz run (`confirm: true` + a `FUZZ` marker required, 1000-payload cap) |
| `/api/fuzz/stop/{job_id}` | POST | Cancel a running fuzz job |
| `/api/fuzz/status/{job_id}` | GET | Progress (`completed`/`total`/`status`) |
| `/api/fuzz/results/{job_id}` | GET | Results, sortable via `sort_by`/`order` query params |
| `/api/fuzz/result/{id}` | GET | Full detail (payload + response) for one fuzz result |
| `/api/fuzz/jobs` | GET | List past fuzz jobs |
| `/api/fuzz/wordlists` | GET | Built-in wordlist names and sizes |

## License

Apache License 2.0 — see [LICENSE](LICENSE).
