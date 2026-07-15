"""
server.py
Local API layer for glacier.

Runs as its own process, separate from the mitmproxy addon. Both
processes read/write the same SQLite file (proxy/glacier.db), which is
why storage.py uses WAL mode - it lets the proxy write and this server
read at the same time without locking conflicts.

This is what the UI (Electron, browser, whatever) talks to - it never
talks to the proxy process directly.

Run with:
    uvicorn server:app --port 8090 --reload
"""

import asyncio
import sys
import threading
import uuid
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from typing import List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "proxy"))
import storage  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "spider"))
from crawler import crawl  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "active"))
from scanner import scan_url as active_scan_url  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "auth"))
import manager as auth_manager  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "repeater"))
import sender as repeater_sender  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "fuzzer"))
import engine as fuzz_engine  # noqa: E402

app = FastAPI(title="glacier API")

# Local tool, local traffic only - permissive CORS is fine here since
# nothing here is reachable outside 127.0.0.1 unless you deliberately
# expose the port.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    storage.init_db()


@app.get("/api/sites")
def get_sites():
    return storage.list_sites()


@app.post("/api/session/new")
def new_session():
    storage.clear_session()
    return {"ok": True}


@app.get("/api/traffic")
def get_traffic(host: str | None = None, limit: int = 200):
    return storage.list_traffic(host=host, limit=limit)


@app.get("/api/traffic/{msg_id}")
def get_traffic_item(msg_id: int):
    msg = storage.get_message(msg_id)
    if msg is None:
        return {"error": "not found"}
    return msg


@app.get("/api/findings")
def get_findings(host: str | None = None, limit: int = 500):
    return storage.list_findings(host=host, limit=limit)


@app.get("/api/findings/summary")
def get_findings_summary():
    return storage.findings_summary()


@app.get("/api/findings/grouped")
def get_findings_grouped(host: str | None = None):
    return storage.list_findings_grouped(host=host)


class FindingStatusUpdate(BaseModel):
    status: str  # 'open' | 'fixed' | 'false_positive'


class FindingBulkStatusUpdate(BaseModel):
    host: str
    name: str
    risk: str
    status: str


@app.patch("/api/findings/bulk-status")
def patch_finding_bulk(body: FindingBulkStatusUpdate):
    if body.status not in ("open", "fixed", "false_positive"):
        return {"error": "status must be one of: open, fixed, false_positive"}
    count = storage.update_finding_status_bulk(body.host, body.name, body.risk, body.status)
    return {"ok": True, "updated": count}


@app.patch("/api/findings/{finding_id}")
def patch_finding(finding_id: int, body: FindingStatusUpdate):
    if body.status not in ("open", "fixed", "false_positive"):
        return {"error": "status must be one of: open, fixed, false_positive"}
    storage.update_finding_status(finding_id, body.status)
    return {"ok": True}


# ---- Auth ----
# Shared across spider, active scan, and pipeline - lets any of them
# operate on an authenticated session instead of an anonymous one.

class AuthConfigModel(BaseModel):
    mode: str  # "cookie" | "form"
    cookie_header: Optional[str] = None
    login_url: Optional[str] = None
    username_field: str = "username"
    password_field: str = "password"
    username: Optional[str] = None
    password: Optional[str] = None
    extra_fields: dict = {}
    success_indicator: Optional[str] = None
    logout_indicator: Optional[str] = None


def _to_auth_config(model: Optional[AuthConfigModel]):
    if model is None:
        return None
    return auth_manager.AuthConfig(
        mode=model.mode, cookie_header=model.cookie_header, login_url=model.login_url,
        username_field=model.username_field, password_field=model.password_field,
        username=model.username, password=model.password, extra_fields=model.extra_fields,
        success_indicator=model.success_indicator, logout_indicator=model.logout_indicator,
    )


# ---- Spider ----

SPIDER_JOBS = {}  # job_id -> {"status", "visited", "total", "current", "results"}
MITMPROXY_CA = str(Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem")


class SpiderStartRequest(BaseModel):
    url: str
    max_depth: int = 2
    max_pages: int = 50
    proxy: Optional[str] = "http://127.0.0.1:8081"
    auth: Optional[AuthConfigModel] = None


def _run_spider_job(job_id, req: SpiderStartRequest):
    def progress(visited, total, current):
        SPIDER_JOBS[job_id]["visited"] = visited
        SPIDER_JOBS[job_id]["total"] = total
        SPIDER_JOBS[job_id]["current"] = current
        storage.save_spider_job(
            job_id, req.url, req.max_depth, req.max_pages,
            "running", visited, total, current, SPIDER_JOBS[job_id]["results"],
        )

    ca = MITMPROXY_CA if Path(MITMPROXY_CA).exists() else None
    try:
        results = crawl(
            req.url,
            max_depth=req.max_depth,
            max_pages=req.max_pages,
            proxy=req.proxy,
            ca_bundle=ca,
            progress_callback=progress,
            auth_config=_to_auth_config(req.auth),
        )
        SPIDER_JOBS[job_id]["results"] = results
        SPIDER_JOBS[job_id]["status"] = "done"
        storage.save_spider_job(
            job_id, req.url, req.max_depth, req.max_pages,
            "done", SPIDER_JOBS[job_id]["visited"], SPIDER_JOBS[job_id]["total"],
            SPIDER_JOBS[job_id]["current"], results,
        )
    except Exception as e:
        SPIDER_JOBS[job_id]["status"] = "error"
        SPIDER_JOBS[job_id]["error"] = str(e)
        storage.save_spider_job(
            job_id, req.url, req.max_depth, req.max_pages,
            "error", SPIDER_JOBS[job_id]["visited"], SPIDER_JOBS[job_id]["total"],
            str(e), [],
        )


@app.post("/api/spider/start")
def spider_start(req: SpiderStartRequest):
    job_id = str(uuid.uuid4())
    SPIDER_JOBS[job_id] = {
        "status": "running", "visited": 0, "total": 1, "current": req.url, "results": [],
    }
    t = threading.Thread(target=_run_spider_job, args=(job_id, req), daemon=True)
    t.start()
    return {"job_id": job_id}


@app.get("/api/spider/status/{job_id}")
def spider_status(job_id: str):
    job = SPIDER_JOBS.get(job_id)
    if job is None:
        job = storage.get_spider_job(job_id)
        if job is None:
            return {"error": "not found"}
        return {"status": job["status"], "visited": job["visited"], "total": job["total"], "current": job["current"]}
    return {
        "status": job["status"],
        "visited": job["visited"],
        "total": job["total"],
        "current": job["current"],
    }


@app.get("/api/spider/results/{job_id}")
def spider_results(job_id: str):
    job = SPIDER_JOBS.get(job_id)
    if job is None:
        job = storage.get_spider_job(job_id)
        if job is None:
            return {"error": "not found"}
        return {"status": job["status"], "results": job["results"]}
    return {"status": job["status"], "results": job["results"]}


@app.get("/api/spider/jobs")
def spider_jobs_list():
    return storage.list_spider_jobs()


# ---- Active Scanner ----
# This is the one component that sends attack-style traffic to a target
# rather than only observing. It never runs automatically and never
# expands scope beyond the single URL explicitly given to it.

ACTIVE_JOBS = {}


class ActiveScanRequest(BaseModel):
    url: str
    confirm: bool = False
    proxy: Optional[str] = "http://127.0.0.1:8081"
    auth: Optional[AuthConfigModel] = None


def _run_active_job(job_id, req: ActiveScanRequest):
    def progress(msg):
        ACTIVE_JOBS[job_id]["current"] = msg

    ca = MITMPROXY_CA if Path(MITMPROXY_CA).exists() else None
    try:
        findings, errors = active_scan_url(
            req.url, proxy=req.proxy, ca_bundle=ca, progress_callback=progress,
            auth_config=_to_auth_config(req.auth),
        )
        for f in findings:
            storage.record_finding(
                traffic_id=0,  # active findings aren't tied to a single captured traffic row
                host=urlparse(req.url).hostname,
                url=f["url"],
                risk=f["risk"],
                name=f["name"],
                description=f["description"],
                evidence=f["evidence"],
                source="active",
            )
        ACTIVE_JOBS[job_id]["status"] = "done"
        ACTIVE_JOBS[job_id]["findings"] = findings
        ACTIVE_JOBS[job_id]["errors"] = errors
    except Exception as e:
        ACTIVE_JOBS[job_id]["status"] = "error"
        ACTIVE_JOBS[job_id]["errors"] = [str(e)]


@app.post("/api/active/scan")
def active_scan_start(req: ActiveScanRequest):
    if not req.confirm:
        return {
            "error": "Active scanning sends real test payloads to the target. "
                     "Resend with confirm=true once you've verified you're authorized to test this URL."
        }
    job_id = str(uuid.uuid4())
    ACTIVE_JOBS[job_id] = {"status": "running", "current": "starting", "findings": [], "errors": []}
    t = threading.Thread(target=_run_active_job, args=(job_id, req), daemon=True)
    t.start()
    return {"job_id": job_id}


@app.get("/api/active/status/{job_id}")
def active_scan_status(job_id: str):
    job = ACTIVE_JOBS.get(job_id)
    if job is None:
        return {"error": "not found"}
    return job


# ---- Pipeline: spider -> auto active-scan every discovered URL with params ----
# This is what makes the tool feel like a real scanner instead of a manual
# one-URL-at-a-time tool: crawl a site, then automatically test every
# parameterized URL it found. Still requires confirm=True since the
# active-scan half of this sends real test payloads.

PIPELINE_JOBS = {}


class PipelineScanRequest(BaseModel):
    url: str
    confirm: bool = False
    max_depth: int = 2
    max_pages: int = 50
    proxy: Optional[str] = "http://127.0.0.1:8081"
    auth: Optional[AuthConfigModel] = None


def _run_pipeline_job(job_id, req: PipelineScanRequest):
    ca = MITMPROXY_CA if Path(MITMPROXY_CA).exists() else None
    job = PIPELINE_JOBS[job_id]
    auth_config = _to_auth_config(req.auth)

    def spider_progress(visited, total, current):
        job["phase"] = "spidering"
        job["spider_visited"] = visited
        job["spider_total"] = total
        job["current"] = current

    try:
        discovered = crawl(
            req.url, max_depth=req.max_depth, max_pages=req.max_pages,
            proxy=req.proxy, ca_bundle=ca, progress_callback=spider_progress,
            auth_config=auth_config,
        )
    except Exception as e:
        job["status"] = "error"
        job["error"] = f"spider failed: {e}"
        return

    # Only URLs with query parameters are worth active-scanning - the
    # scanner has nothing to test on a URL with no parameters.
    targets = [u for u in discovered if urlparse(u).query]
    job["phase"] = "scanning"
    job["scan_total"] = len(targets)
    job["scan_done"] = 0
    job["findings"] = []

    session_findings = []
    for target in targets:
        job["current"] = target
        try:
            findings, errors = active_scan_url(target, proxy=req.proxy, ca_bundle=ca, auth_config=auth_config)
            for f in findings:
                storage.record_finding(
                    traffic_id=0, host=urlparse(target).hostname, url=f["url"],
                    risk=f["risk"], name=f["name"], description=f["description"],
                    evidence=f["evidence"], source="active",
                )
                session_findings.append(f)
        except Exception as e:
            job.setdefault("errors", []).append(f"{target}: {e}")
        job["scan_done"] += 1

    job["findings"] = session_findings
    job["status"] = "done"


@app.post("/api/pipeline/scan")
def pipeline_scan_start(req: PipelineScanRequest):
    if not req.confirm:
        return {
            "error": "This pipeline crawls the target AND actively tests every URL with "
                     "parameters it finds. Resend with confirm=true once you've verified "
                     "you're authorized to test this target."
        }
    job_id = str(uuid.uuid4())
    PIPELINE_JOBS[job_id] = {
        "status": "running", "phase": "spidering",
        "spider_visited": 0, "spider_total": 1, "current": req.url,
        "scan_total": 0, "scan_done": 0, "findings": [],
    }
    t = threading.Thread(target=_run_pipeline_job, args=(job_id, req), daemon=True)
    t.start()
    return {"job_id": job_id}


@app.get("/api/pipeline/status/{job_id}")
def pipeline_scan_status(job_id: str):
    job = PIPELINE_JOBS.get(job_id)
    if job is None:
        return {"error": "not found"}
    return job



# ---- Repeater ----
# Manual request editor: send exactly one request the person crafted or
# pulled from History, then view/tweak/resend. No confirm=True gate -
# unlike active scan/pipeline, this never decides what to send on its
# own; it's a single explicit request per call, same trust model as curl.

class RepeaterSendRequest(BaseModel):
    method: str = "GET"
    url: str
    headers_text: Optional[str] = ""
    body: Optional[str] = ""
    name: Optional[str] = None
    proxy: Optional[str] = None  # None by default - most repeater use is direct-to-target, not through the intercepting proxy


@app.post("/api/repeater/send")
def repeater_send(req: RepeaterSendRequest):
    ca = MITMPROXY_CA if Path(MITMPROXY_CA).exists() else None
    result = repeater_sender.send_request(
        req.method, req.url, headers_text=req.headers_text, body=req.body,
        proxy=req.proxy, ca_bundle=ca,
    )
    entry_id = storage.save_repeater_entry(
        name=req.name,
        method=req.method.upper(),
        url=req.url,
        req_headers=req.headers_text or "",
        req_body=req.body or "",
        status_code=result.get("status_code"),
        reason=result.get("reason"),
        resp_headers=result.get("response_headers"),
        resp_body=result.get("response_body"),
        elapsed_ms=result.get("elapsed_ms"),
        error=result.get("error"),
    )
    result["id"] = entry_id
    return result


@app.get("/api/repeater/history")
def repeater_history(limit: int = 100):
    return storage.list_repeater_entries(limit=limit)


@app.get("/api/repeater/{entry_id}")
def repeater_get(entry_id: int):
    entry = storage.get_repeater_entry(entry_id)
    if entry is None:
        return {"error": "not found"}
    return entry


@app.delete("/api/repeater/{entry_id}")
def repeater_delete(entry_id: int):
    storage.delete_repeater_entry(entry_id)
    return {"ok": True}


# ---- Fuzzer (Intruder-style) ----
# Fires many requests at a live target from a single template - mark the
# injection point with the literal string FUZZ, supply payloads (a list
# and/or a built-in wordlist name), and one request goes out per payload.
# Same "sends real traffic" posture as the active scanner: gated behind
# confirm=True, plus a hard payload-count cap so a typo can't accidentally
# fire an unbounded flood at someone's server.

FUZZ_JOBS = {}


class FuzzStartRequest(BaseModel):
    method: str = "GET"
    url: str
    headers_text: Optional[str] = ""
    body: Optional[str] = ""
    payloads: Optional[List[str]] = None
    wordlist: Optional[str] = None
    delay: float = 0
    confirm: bool = False
    proxy: Optional[str] = None


def _run_fuzz_job(job_id, req: FuzzStartRequest, payloads):
    stop_event = FUZZ_JOBS[job_id]["stop_event"]
    ca = MITMPROXY_CA if Path(MITMPROXY_CA).exists() else None

    def on_result(i, payload, result):
        storage.save_fuzz_result(
            job_id, i, payload,
            result.get("status_code"), result.get("reason"), result.get("length"),
            result.get("elapsed_ms"), result.get("response_headers"), result.get("response_body"),
            result.get("error"),
        )
        FUZZ_JOBS[job_id]["completed"] = i + 1
        storage.update_fuzz_job(job_id, completed=i + 1)

    try:
        fuzz_engine.run_fuzz(
            req.method, req.url, req.headers_text, req.body, payloads,
            proxy=req.proxy, ca_bundle=ca, delay=req.delay,
            stop_event=stop_event, on_result=on_result,
        )
        final_status = "stopped" if stop_event.is_set() else "done"
    except Exception as e:
        final_status = "error"
        FUZZ_JOBS[job_id]["error"] = str(e)
    FUZZ_JOBS[job_id]["status"] = final_status
    storage.update_fuzz_job(job_id, status=final_status)


@app.post("/api/fuzz/start")
def fuzz_start(req: FuzzStartRequest):
    if not req.confirm:
        return {
            "error": "Fuzzing sends many test requests to the target. "
                     "Resend with confirm=true once you've verified you're authorized to test this URL."
        }
    if not fuzz_engine.has_marker(req.url, req.headers_text, req.body):
        return {
            "error": f"No {fuzz_engine.FUZZ_MARKER} marker found in the URL, headers, or body - "
                     f"mark the injection point with the literal text {fuzz_engine.FUZZ_MARKER} first."
        }

    payloads = list(req.payloads or [])
    if req.wordlist:
        payloads = fuzz_engine.WORDLISTS.get(req.wordlist, []) + payloads
    if not payloads:
        return {"error": "No payloads provided - supply a payloads list and/or a built-in wordlist name."}
    if len(payloads) > fuzz_engine.MAX_PAYLOADS:
        return {"error": f"{len(payloads)} payloads exceeds the {fuzz_engine.MAX_PAYLOADS} cap - split into smaller batches."}

    job_id = str(uuid.uuid4())
    FUZZ_JOBS[job_id] = {"status": "running", "completed": 0, "total": len(payloads), "stop_event": threading.Event()}
    storage.save_fuzz_job(job_id, req.method.upper(), req.url, req.headers_text or "", req.body or "", len(payloads), 0, "running")
    t = threading.Thread(target=_run_fuzz_job, args=(job_id, req, payloads), daemon=True)
    t.start()
    return {"job_id": job_id, "total": len(payloads)}


@app.post("/api/fuzz/stop/{job_id}")
def fuzz_stop(job_id: str):
    job = FUZZ_JOBS.get(job_id)
    if job is None:
        return {"error": "not found"}
    job["stop_event"].set()
    return {"ok": True}


@app.get("/api/fuzz/status/{job_id}")
def fuzz_status(job_id: str):
    job = FUZZ_JOBS.get(job_id)
    if job is not None:
        return {"status": job["status"], "completed": job["completed"], "total": job["total"]}
    # Fall back to the persisted row in case the server restarted mid-job.
    persisted = storage.get_fuzz_job(job_id)
    if persisted is None:
        return {"error": "not found"}
    return {"status": persisted["status"], "completed": persisted["completed"], "total": persisted["total"]}


@app.get("/api/fuzz/results/{job_id}")
def fuzz_results(job_id: str, sort_by: str = "seq", order: str = "asc", limit: int = 1000, offset: int = 0):
    return storage.list_fuzz_results(job_id, sort_by=sort_by, order=order, limit=limit, offset=offset)


@app.get("/api/fuzz/result/{result_id}")
def fuzz_result(result_id: int):
    r = storage.get_fuzz_result(result_id)
    if r is None:
        return {"error": "not found"}
    return r


@app.get("/api/fuzz/jobs")
def fuzz_jobs_list():
    return storage.list_fuzz_jobs()


@app.get("/api/fuzz/wordlists")
def fuzz_wordlists():
    return {name: len(items) for name, items in fuzz_engine.WORDLISTS.items()}


@app.websocket("/api/ws/live")
async def live_feed(ws: WebSocket):
    """
    Pushes newly captured traffic to the client as it arrives, by polling
    the DB for rows past the last seen id. Polling (not a true event push)
    because the proxy and API are separate processes - simplest reliable
    way to bridge them without adding a message queue dependency.
    """
    await ws.accept()
    last_id = storage.max_id()
    try:
        while True:
            new_rows = storage.traffic_since(last_id)
            for row in new_rows:
                await ws.send_json(row)
                last_id = row["id"]
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
