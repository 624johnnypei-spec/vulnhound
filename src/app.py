"""VulnHound's dependency-free demo dashboard.

Run: .venv/bin/uvicorn src.app:app --port 3000

Integration contract: src.orchestrator.run_scan(target=None) may be synchronous
or asynchronous and returns a findings list or a dict containing ``findings``.
Generators may yield findings or progress dictionaries during a scan. A hook
returning its own scan ID is bridged through src.orchestrator.get_scan(id). All
project modules and sponsor SDKs are imported only from request-time code.

Omitting target delegates deployment of the owned Juice Shop sandbox to the
orchestrator. Explicit targets must match VULNHOUND_TARGET_URL exactly by origin;
the orchestrator/agent must also constrain every command and redirect to that
owned host. This dashboard never executes attack commands itself.

Scan state is in memory for this single-process hackathon demo and resets on
restart. Seed findings are illustration data, never reported as scan results.
"""
from __future__ import annotations

import asyncio
import copy
import importlib
import inspect
import json
import os
import re
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field


_scans: dict[str, dict[str, Any]] = {}
_tasks: set[asyncio.Task] = set()
_scan_lock = asyncio.Lock()
_health_lock = asyncio.Lock()
_health_cache: dict[str, Any] = {}
_HEALTH_TTL = 60
_PROBE_TIMEOUT = 25


@asynccontextmanager
async def lifespan(_app: FastAPI):
    yield
    for task in tuple(_tasks):
        task.cancel()
    if _tasks:
        await asyncio.gather(*tuple(_tasks), return_exceptions=True)


app = FastAPI(title="VulnHound", version="1.0.0", lifespan=lifespan)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_environment() -> None:
    try:
        from dotenv import load_dotenv
        load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=False)
    except Exception:
        # An absent optional dependency or .env never prevents the offline demo.
        pass


def _neo4j_configured() -> bool:
    uri = os.getenv("NEO4J_URI", "")
    return bool(uri and "xxxxxxx" not in uri and os.getenv("NEO4J_PASSWORD"))


def _check_daytona() -> bool:
    if not os.getenv("DAYTONA_API_KEY"):
        return False
    from daytona import Daytona, ListSandboxesQuery
    # Authenticated connectivity without provisioning a sandbox on each poll.
    next(iter(Daytona().list(ListSandboxesQuery(limit=1), request_timeout=6)), None)
    return True


def _check_neo4j() -> bool:
    if not _neo4j_configured():
        return False
    from neo4j import GraphDatabase
    with GraphDatabase.driver(
        os.environ["NEO4J_URI"],
        auth=(os.getenv("NEO4J_USERNAME") or "neo4j", os.environ["NEO4J_PASSWORD"]),
        connection_timeout=5, connection_acquisition_timeout=6,
        max_transaction_retry_time=0,
    ) as driver:
        driver.verify_connectivity()
    return True


def _check_nosana() -> bool:
    base = os.getenv("NOSANA_BASE_URL", "").strip()
    if not base:
        return False  # A fallback provider must never turn the Nosana pill green.
    from openai import OpenAI
    with OpenAI(base_url=base.rstrip("/"),
                api_key=os.getenv("NOSANA_API_KEY") or "not-required",
                timeout=22, max_retries=0) as client:
        model = os.getenv("NOSANA_MODEL")
        if not model:
            models = client.models.list().data
            if not models:
                return False
            model = models[0].id
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "/no_think\nReply with the single word: ready"}],
            max_tokens=512,
        )
        # A returned completion proves the inference endpoint is live. Qwen 3.5 is
        # a hybrid reasoning model that often answers in the 'reasoning' channel
        # with empty content, so accept either channel.
        if not response.choices:
            return False
        message = response.choices[0].message
        text = (message.content or "").strip() or (getattr(message, "reasoning", None) or "").strip()
        return bool(text)


async def _probe(check: Any) -> bool:
    try:
        return bool(await asyncio.wait_for(asyncio.to_thread(check), _PROBE_TIMEOUT))
    except Exception:
        # Independent failures, like scripts/smoke_test.py; no raw SDK errors
        # are exposed because they may contain credentials or connection URLs.
        return False


@app.get("/api/health")
async def health() -> dict[str, bool]:
    """Independent, cached sponsor checks. No import of the mutating smoke script."""
    async with _health_lock:
        if _health_cache and time.monotonic() - _health_cache["time"] < _HEALTH_TTL:
            return _health_cache["value"]
        _load_environment()
        values = await asyncio.gather(*(_probe(fn) for fn in
                                       (_check_daytona, _check_neo4j, _check_nosana)))
        result = dict(zip(("daytona", "neo4j", "nosana"), values))
        _health_cache.update(time=time.monotonic(), value=result)
        return result


SEED_FINDINGS = [
    {"id": "VH-001", "node_id": "sqli", "title": "SQL injection in authentication",
     "severity": "critical", "endpoint": "/rest/user/login", "category": "Injection",
     "agent": "Injection agent", "description": "An untrusted login value reaches a database query. In this sample scenario, the authentication boundary can be bypassed and customer data becomes reachable.",
     "evidence": "Illustrative attack chain: public entry → login API → SQL injection → customer database. No exploit has been executed by this preview.",
     "remediation": "Use parameterized queries for authentication lookups and give the application database account only the permissions it needs.", "source": "seed"},
    {"id": "VH-002", "node_id": "xss", "title": "Reflected cross-site scripting",
     "severity": "high", "endpoint": "/rest/products/search", "category": "Client-side injection",
     "agent": "Web agent", "description": "The sample search flow reflects untrusted input into a browser context without the required output encoding.",
     "evidence": "Illustrative finding on the product search surface. Browser execution has not been verified in this preview.",
     "remediation": "Apply context-aware output encoding, use safe DOM APIs, and add a restrictive content security policy.", "source": "seed"},
    {"id": "VH-003", "node_id": "exposure", "title": "Sensitive backup files exposed",
     "severity": "medium", "endpoint": "/ftp", "category": "Information exposure",
     "agent": "Recon agent", "description": "A public file surface exposes material that should be kept outside the web root in this sample attack graph.",
     "evidence": "Illustrative public-directory finding. No files have been downloaded by this preview.",
     "remediation": "Remove backups from the public web root, disable directory listing, and require authorization for private documents.", "source": "seed"},
]

SEED_GRAPH = {
    "nodes": [
        {"data": {"id": "entry", "label": "Juice Shop", "type": "entry", "detail": "Public entry point"}},
        {"data": {"id": "login", "label": "Login API", "type": "endpoint", "detail": "/rest/user/login"}},
        {"data": {"id": "search", "label": "Product search", "type": "endpoint", "detail": "/rest/products/search"}},
        {"data": {"id": "files", "label": "Public files", "type": "endpoint", "detail": "/ftp"}},
        *[{"data": {"id": f["node_id"], "label": label, "type": "finding", "severity": f["severity"],
                     "finding_id": f["id"], "detail": f["category"], "properties": f}}
          for f, label in zip(SEED_FINDINGS, ("SQL injection", "Reflected XSS", "Exposed backups"))],
        {"data": {"id": "database", "label": "Customer database", "type": "database", "detail": "Sensitive data at risk"}},
    ],
    "edges": [{"data": {"id": f"e{i}", "source": a, "target": b, "label": label}}
              for i, (a, b, label) in enumerate([
                  ("entry", "login", "REACHES"), ("entry", "search", "REACHES"),
                  ("entry", "files", "REACHES"), ("login", "sqli", "VULNERABLE_TO"),
                  ("search", "xss", "VULNERABLE_TO"), ("files", "exposure", "EXPOSES"),
                  ("sqli", "database", "ACCESSES"),
              ])],
}
SEED_PATHS = [{"id": "path-1", "nodes": ["entry", "login", "sqli", "database"],
               "severity": "critical", "hops": 3, "label": "Public entry → customer database"}]


def _graph_elements(payload: Any) -> dict[str, Any]:
    if isinstance(payload, dict):
        payload = payload.get("elements", payload)
    if isinstance(payload, list):
        nodes, edges = [], []
        for item in payload:
            data = item.get("data", item)
            (edges if "source" in data and "target" in data else nodes).append(item)
    elif isinstance(payload, dict):
        nodes, edges = payload.get("nodes", []), payload.get("edges", [])
    else:
        raise ValueError("Expected Cytoscape elements")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise ValueError("Expected node and edge lists")
    return jsonable_encoder({"nodes": nodes, "edges": edges})


async def _read_store(method: str) -> Any:
    def read():
        module = importlib.import_module("src.graph.store")
        store = module.GraphStore()
        try:
            # Public store methods connect lazily; no database work at import.
            return jsonable_encoder(getattr(store, method)())
        finally:
            store.close()
    return await asyncio.wait_for(asyncio.to_thread(read), timeout=10)


@app.get("/api/graph")
async def graph() -> dict[str, Any]:
    _load_environment()
    message = "Neo4j is not configured. Displaying the bundled sample graph."
    if _neo4j_configured():
        try:
            return {"source": "neo4j", "demo": False, "message": "Live attack graph from Neo4j.",
                    **_graph_elements(await _read_store("to_cytoscape"))}
        except Exception as exc:
            message = f"Attack graph unavailable ({type(exc).__name__}). Displaying the bundled sample graph."
    return {"source": "seed", "demo": True, "message": message, **copy.deepcopy(SEED_GRAPH)}


@app.get("/api/paths")
async def paths() -> dict[str, Any]:
    _load_environment()
    if _neo4j_configured():
        try:
            result = await _read_store("attack_paths")
            if isinstance(result, dict):
                result = result.get("paths", [])
            if not isinstance(result, list):
                raise ValueError("Expected attack path list")
            return {"source": "neo4j", "demo": False, "paths": result}
        except Exception as exc:
            # Never overlay sample paths on an unrelated live graph.
            return {"source": "unavailable", "demo": False, "paths": [],
                    "message": f"Attack paths unavailable ({type(exc).__name__})."}
    return {"source": "seed", "demo": True, "paths": copy.deepcopy(SEED_PATHS),
            "message": "Sample attack path; no scan has run."}


class ScanRequest(BaseModel):
    target: str | None = Field(default=None, max_length=2048, strict=True)


def _origin(value: str) -> tuple[str, str, int]:
    """An origin only, never a shell fragment, credentials, path or query."""
    if re.search(r"[\s\\\x00-\x1f\x7f]", value):
        raise ValueError("Invalid characters in target")
    url = urlsplit(value)
    if (url.scheme not in {"http", "https"} or not url.hostname or
            url.username is not None or url.password is not None or
            url.path not in {"", "/"} or url.query or url.fragment):
        raise ValueError("Target must be an HTTP(S) origin")
    host = url.hostname.lower()
    if not re.fullmatch(r"[a-z0-9.:-]+", host):
        raise ValueError("Invalid target hostname")
    port = url.port if url.port is not None else (443 if url.scheme == "https" else 80)
    if port < 1:
        raise ValueError("Invalid target port")
    return url.scheme, host, port


def _scoped_target(target: str | None) -> str | None:
    if target is None or not target.strip():
        return None
    allowed = os.getenv("VULNHOUND_TARGET_URL", "").strip()
    if not allowed:
        raise HTTPException(400, "Explicit targets require VULNHOUND_TARGET_URL for the owned sandbox. Omit target to deploy a managed Juice Shop target.")
    try:
        requested_origin, allowed_origin = _origin(target.strip()), _origin(allowed)
    except ValueError:
        raise HTTPException(400, "Target must be a plain HTTP(S) origin without credentials, paths, or query parameters.") from None
    if requested_origin != allowed_origin:
        raise HTTPException(403, "Target is outside the configured owned sandbox scope.")
    # Forward the trusted configuration, never the caller's raw string.
    return allowed.rstrip("/")


def _apply_progress(record: dict[str, Any], value: Any) -> None:
    value = jsonable_encoder(value)
    if isinstance(value, list):
        findings = value
    elif isinstance(value, dict) and "findings" in value:
        findings = value["findings"]
    elif isinstance(value, dict) and ("severity" in value or "title" in value):
        findings = [*record["findings"], value]
    else:
        findings = record["findings"]
    if isinstance(findings, list):
        record["findings"] = [item for item in findings if isinstance(item, dict)]
    if isinstance(value, dict) and isinstance(value.get("message"), str):
        record["message"] = value["message"]
    record["updated_at"] = _now()


async def _execute_scan(scan_id: str, hook: Any, target: str | None, get_scan: Any = None) -> None:
    record = _scans[scan_id]
    record.update(status="running", started_at=_now(), message="Agents are testing the owned Juice Shop target.")
    try:
        kwargs = {"target": target}
        # Permit a deployment-only hook with no arguments when target is omitted.
        if target is None and not inspect.signature(hook).parameters:
            kwargs = {}
        if inspect.iscoroutinefunction(hook):
            result = await hook(**kwargs)
        else:
            result = await asyncio.to_thread(hook, **kwargs)
        if inspect.isawaitable(result):
            result = await result
        if isinstance(result, str):
            # The current orchestrator starts its own background thread and
            # returns an ID. Track that job rather than declaring it complete.
            if not callable(get_scan):
                raise TypeError("An ID-returning orchestrator requires get_scan")
            record["orchestrator_id"] = result
            while True:
                upstream = await asyncio.to_thread(get_scan, record["orchestrator_id"])
                if inspect.isawaitable(upstream):
                    upstream = await upstream
                if not isinstance(upstream, dict):
                    raise ValueError("Orchestrator scan status is unavailable")
                _apply_progress(record, upstream)
                phase = upstream.get("status", "running")
                if phase in {"done", "completed", "failed", "error", "cancelled"}:
                    result = {**upstream, "status": "failed" if phase in {"failed", "error", "cancelled"} else "completed"}
                    break
                record["message"] = {
                    "starting": "Preparing the owned target and attack agents.",
                    "deploying_target": "Deploying Juice Shop into an owned Daytona sandbox.",
                    "scanning": "Agents are testing the owned target and reporting findings.",
                }.get(phase, "Scan is running in the orchestrator.")
                await asyncio.sleep(1)
        if inspect.isasyncgen(result):
            async for event in result:
                _apply_progress(record, event)
            result = None
        elif inspect.isgenerator(result):
            def advance():
                try:
                    return True, next(result)
                except StopIteration:
                    return False, None
            while True:
                has_event, event = await asyncio.to_thread(advance)
                if not has_event:
                    break
                _apply_progress(record, event)
            result = None
        _apply_progress(record, result)
        failed = isinstance(result, dict) and result.get("status") in {"failed", "error"}
        record.update(status="failed" if failed else "completed", completed_at=_now(),
                      message="The orchestrator reported a scan failure." if failed else "Scan complete. Review the findings and attack paths.")
    except asyncio.CancelledError:
        record.update(status="interrupted", message="Dashboard stopped; check the orchestrator's sandbox cleanup.")
        raise
    except Exception as exc:
        record.update(status="failed", completed_at=_now(),
                      message=f"Scan failed ({type(exc).__name__}). Check orchestrator configuration and logs.")
    finally:
        record["updated_at"] = _now()


@app.post("/api/scan", status_code=202)
async def start_scan(request: ScanRequest | None = None) -> dict[str, Any]:
    _load_environment()
    target = _scoped_target(request.target if request else None)
    async with _scan_lock:
        active = next((s for s in _scans.values() if s["status"] in {"queued", "running"}), None)
        if active:
            raise HTTPException(409, {"message": "A scan is already active.", "scan_id": active["scan_id"]})
        scan_id = uuid4().hex[:12]
        record = {"scan_id": scan_id, "status": "queued", "findings": [], "mode": "live",
                  "target": target, "scope": "owned Daytona sandbox only",
                  "created_at": _now(), "updated_at": _now(), "message": "Scan queued."}
        if len(_scans) >= 100:
            _scans.pop(next(iter(_scans)))
        _scans[scan_id] = record
        try:
            module = await asyncio.wait_for(asyncio.to_thread(importlib.import_module, "src.orchestrator"), 3)
            hook = getattr(module, "run_scan")
            if not callable(hook):
                raise AttributeError("run_scan is not callable")
        except Exception as exc:
            record.update(status="not_wired", mode="stub",
                          message=f"Orchestrator not wired yet: src.orchestrator.run_scan is unavailable ({type(exc).__name__}). No scan was started; the dashboard can display its sample graph.")
        else:
            task = asyncio.create_task(_execute_scan(scan_id, hook, target, getattr(module, "get_scan", None)))
            _tasks.add(task)
            task.add_done_callback(_tasks.discard)
        return copy.deepcopy(record)


@app.get("/api/scan/{scan_id}")
async def scan_status(scan_id: str) -> dict[str, Any]:
    if scan_id not in _scans:
        raise HTTPException(404, "Unknown scan ID. Demo scan history resets when the server restarts.")
    return copy.deepcopy(_scans[scan_id])


HTML = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VulnHound · Is your app safe?</title>
<style>
:root{
  --paper:#f5f0e8;--card:#fffdf8;--ink:#1f2129;--muted:#6c7080;--line:#e8e1d3;--soft:#f0e9dc;
  --danger:#e0403f;--danger-bg:#fdecea;--warn:#e08a00;--warn-bg:#fdf1dd;--safe:#1f9d5b;--safe-bg:#e5f4ea;
  --brand:#ff5a3c;--ink-2:#3a3d49;
  --display:"Iowan Old Style","Palatino Linotype",Georgia,"Times New Roman",serif;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;
  --mono:ui-monospace,SFMono-Regular,Menlo,monospace;
  color-scheme:light;
}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--sans);font-size:16px;line-height:1.5;-webkit-font-smoothing:antialiased}
button{font:inherit;color:inherit;cursor:pointer;border:0;background:none}
button:disabled{cursor:progress;opacity:.65}
:focus-visible{outline:2px solid var(--brand);outline-offset:3px;border-radius:6px}
.wrap{max-width:940px;margin:0 auto;padding:0 20px}

/* header */
header{background:rgba(245,240,232,.9);backdrop-filter:blur(8px);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:20}
.bar{display:flex;align-items:center;justify-content:space-between;gap:16px;height:64px}
.brand{display:flex;align-items:center;gap:10px;font-weight:800;font-size:20px;letter-spacing:-.4px}
.brand .mark{width:30px;height:30px;border-radius:9px;background:var(--brand);display:grid;place-items:center;font-size:17px}
.brand b{color:var(--brand)}
.head-right{display:flex;align-items:center;gap:14px}
.powered{display:flex;align-items:center;gap:7px;font:11px var(--mono);color:var(--muted)}
.chip{display:inline-flex;align-items:center;gap:5px;padding:4px 8px;border:1px solid var(--line);border-radius:20px;background:var(--card);font-size:11px;color:var(--muted)}
.chip .d{width:7px;height:7px;border-radius:50%;background:#c9c2b4}
.chip.on{color:var(--ink-2);border-color:#bfe3cd}.chip.on .d{background:var(--safe);box-shadow:0 0 0 3px var(--safe-bg)}
.cta{background:var(--brand);color:#fff;font-weight:700;font-size:14px;padding:11px 18px;border-radius:10px;display:inline-flex;align-items:center;gap:8px;box-shadow:0 2px 0 #d8452c}
.cta:hover:not(:disabled){background:#ff6f54}
.cta .sp{width:14px;height:14px;border:2px solid #ffffff80;border-top-color:#fff;border-radius:50%;animation:spin .8s linear infinite;display:none}
.cta.busy .sp{display:inline-block}

/* verdict */
.verdict{margin:30px 0 10px;display:flex;gap:22px;align-items:flex-start;opacity:0;animation:rise .6s .05s forwards}
.badge{flex:none;width:82px;height:82px;border-radius:22px;display:grid;place-items:center;font-size:40px}
.badge.danger{background:var(--danger-bg)}.badge.warn{background:var(--warn-bg)}.badge.safe{background:var(--safe-bg)}
.badge.danger{box-shadow:0 0 0 0 #e0403f55;animation:pulse 2s infinite}
.verdict h1{font-family:var(--display);font-weight:700;font-size:clamp(28px,5vw,42px);line-height:1.1;margin:2px 0 8px;letter-spacing:-.5px}
.verdict p{margin:0;font-size:17px;color:var(--ink-2);max-width:58ch}
.vmeta{margin-top:12px;font:12px var(--mono);color:var(--muted);display:flex;gap:14px;flex-wrap:wrap}
.vmeta span{display:inline-flex;align-items:center;gap:6px}

/* section */
.sec{margin:38px 0}
.sec-head{display:flex;align-items:baseline;justify-content:space-between;gap:12px;margin-bottom:16px}
.sec-head h2{font-family:var(--display);font-weight:700;font-size:24px;margin:0;letter-spacing:-.3px}
.sec-head .note{font-size:13px;color:var(--muted)}

/* journey */
.journey{display:flex;gap:0;align-items:stretch;overflow-x:auto;padding-bottom:6px}
.step{flex:1;min-width:150px;background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px 16px;position:relative;opacity:0;animation:rise .5s forwards}
.step+.step{margin-left:34px}
.step:before{content:"→";position:absolute;left:-30px;top:50%;transform:translateY(-50%);color:var(--brand);font-size:22px;font-weight:700}
.step:first-child:before{display:none}
.step .ico{font-size:30px;line-height:1}
.step .lab{font:10px var(--mono);letter-spacing:.6px;text-transform:uppercase;color:var(--muted);margin:12px 0 5px}
.step h3{margin:0 0 6px;font-size:16px;font-weight:700;letter-spacing:-.2px}
.step p{margin:0;font-size:13px;color:var(--muted);line-height:1.45}
.step.end{border-color:#f2c9c6;background:linear-gradient(180deg,#fff6f5,#fff)}
.step.end h3{color:var(--danger)}
.step.end:before{color:var(--danger)}
.jrny-foot{margin-top:14px;font-size:13px;color:var(--ink-2);background:var(--soft);border-radius:12px;padding:12px 15px;display:flex;gap:10px;align-items:flex-start}
.jrny-foot b{color:var(--ink)}

/* findings */
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px}
.fcard{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px;opacity:0;animation:rise .5s forwards;border-top:4px solid var(--sev)}
.fcard-top{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:12px}
.sev{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:700;color:var(--sev)}
.sev .d{width:9px;height:9px;border-radius:50%;background:var(--sev)}
.reaches{font:10px var(--mono);letter-spacing:.4px;color:var(--danger);background:var(--danger-bg);border-radius:20px;padding:4px 9px;font-weight:600;display:inline-flex;gap:5px;align-items:center}
.fcard h3{margin:0 0 12px;font-size:17px;font-weight:700;line-height:1.3;letter-spacing:-.2px}
.frow{margin-top:11px}
.frow .k{font:10px var(--mono);letter-spacing:.6px;text-transform:uppercase;color:var(--muted);margin-bottom:4px}
.frow .v{font-size:14px;color:var(--ink-2);line-height:1.5}
.frow.fix .v{color:var(--ink)}
.empty{grid-column:1/-1;text-align:center;color:var(--muted);padding:30px;font-size:15px}

/* footer */
footer{border-top:1px solid var(--line);margin-top:40px;background:var(--card)}
.foot{display:flex;gap:14px;align-items:flex-start;padding:22px 0;color:var(--muted);font-size:13px;line-height:1.55}
.foot .lock{font-size:20px;flex:none}
.toast{position:fixed;left:50%;bottom:22px;transform:translateX(-50%);background:var(--ink);color:#fff;padding:12px 18px;border-radius:12px;font-size:14px;box-shadow:0 12px 30px #0003;max-width:90vw;z-index:40}
.toast[hidden]{display:none}

@keyframes spin{to{transform:rotate(360deg)}}
@keyframes rise{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
@keyframes pulse{0%{box-shadow:0 0 0 0 #e0403f44}70%{box-shadow:0 0 0 16px #e0403f00}100%{box-shadow:0 0 0 0 #e0403f00}}
@media(max-width:640px){
  .powered{display:none}
  .verdict{gap:16px}.badge{width:64px;height:64px;font-size:30px;border-radius:18px}
  .journey{flex-direction:column}.step+.step{margin-left:0;margin-top:30px}
  .step:before{content:"↓";left:50%;top:-27px;transform:translateX(-50%)}
}
@media(prefers-reduced-motion:reduce){*{animation:none!important}}
</style>
</head>
<body>
<header><div class="wrap bar">
  <div class="brand"><span class="mark">🐾</span>Vuln<b>Hound</b></div>
  <div class="head-right">
    <div class="powered">Checking with
      <span class="chip" id="c-daytona"><span class="d"></span>Daytona</span>
      <span class="chip" id="c-neo4j"><span class="d"></span>Neo4j</span>
      <span class="chip" id="c-nosana"><span class="d"></span>Nosana</span>
    </div>
    <button class="cta" id="scan"><span class="sp"></span><span id="scan-label">Check my app</span></button>
  </div>
</div></header>

<main class="wrap">
  <section class="verdict">
    <div class="badge danger" id="badge">🔴</div>
    <div>
      <h1 id="verdict-title">Checking your app…</h1>
      <p id="verdict-sub">Give us a moment while we look at your app the way an attacker would.</p>
      <div class="vmeta">
        <span>🎯 <b id="vmeta-target">OWASP Juice Shop</b></span>
        <span>🧪 Tested in a sealed sandbox</span>
        <span id="vmeta-count"></span>
      </div>
    </div>
  </section>

  <section class="sec" id="journey-sec" hidden>
    <div class="sec-head"><h2>How they'd break in</h2><span class="note" id="journey-note"></span></div>
    <div class="journey" id="journey"></div>
    <div class="jrny-foot"><span>💡</span><div><b>Read it left to right.</b> Each step is one move an attacker makes. On its own, most steps look harmless — chained together, they lead somewhere they shouldn't. Break any one link and the whole path is stopped.</div></div>
  </section>

  <section class="sec">
    <div class="sec-head"><h2>What we found</h2><span class="note" id="found-note"></span></div>
    <div class="cards" id="cards"></div>
  </section>
</main>

<footer><div class="wrap foot">
  <span class="lock">🔒</span>
  <div><b>You're in control.</b> VulnHound only tests an app you point it at, running inside an isolated sandbox that's wiped when the check ends. It never touches anything else, and it can't attack a site you don't own.</div>
</div></footer>

<div class="toast" id="toast" hidden></div>

<script>
const BOOT = __BOOTSTRAP__;
const $ = id => document.getElementById(id);
function el(tag, cls, txt){const e=document.createElement(tag);if(cls)e.className=cls;if(txt!=null)e.textContent=txt;return e;}
function T(v, fallback=''){return (v==null||v==='')?fallback:String(v);}

// ---- plain-language dictionaries ----
const SEV = {
  critical:{word:'Critical',color:'#e0403f',rank:0},
  high:{word:'Serious',color:'#e0403f',rank:1},
  medium:{word:'Moderate',color:'#e08a00',rank:2},
  low:{word:'Minor',color:'#1f9d5b',rank:3},
  info:{word:'Info',color:'#6c7080',rank:4},
};
function sev(s){return SEV[String(s||'').toLowerCase()]||SEV.medium;}

const STEP_ROLE = {
  target:{ico:'🌐',lab:'The way in'}, entry:{ico:'🌐',lab:'The way in'},
  endpoint:{ico:'🚪',lab:'A page on your app'}, form:{ico:'📝',lab:'A form on your app'},
  vulnerability:{ico:'🔓',lab:'A weak spot'}, finding:{ico:'💥',lab:'The break-in'},
  asset:{ico:'🗄️',lab:'Your data'}, database:{ico:'🗄️',lab:'Your data'},
};
// plain-English rewrites of common jargon, matched loosely
const PLAIN = [
  [/sql/i,           {t:'The login form can be tricked', d:'Typed-in text is treated as a command, so an attacker can make the database do what they want.'}],
  [/auth|login|bypass|credential|password/i, {t:'The login can be fooled', d:'The check that’s meant to keep strangers out can be slipped past without the right password.'}],
  [/xss|cross-site|script/i, {t:'The site can be turned against its visitors', d:'An attacker can make the page run their code in someone else’s browser.'}],
  [/backup|exposed|expos|directory|file/i, {t:'Private files are left in the open', d:'Files that should be hidden can be reached by anyone who knows the link.'}],
  [/port|service|open/i, {t:'A server door is left open', d:'A service is reachable from the public internet when it probably shouldn’t be.'}],
  [/idor|access control|permission/i, {t:'People can see things that aren’t theirs', d:'Changing a number in the link lets someone open another person’s data.'}],
];
function plainFor(type, fallbackTitle, fallbackDesc){
  for(const [re,v] of PLAIN){ if(re.test(type||'')||re.test(fallbackTitle||'')) return v; }
  return {t:T(fallbackTitle, T(type,'A weakness')), d:T(fallbackDesc,'This is worth a closer look by a developer.')};
}
function pageName(path){
  const p=String(path||'').toLowerCase();
  if(/login|auth|signin|user/.test(p)) return 'login';
  if(/search|product|catalog/.test(p)) return 'search';
  if(/ftp|file|backup|upload/.test(p)) return 'file';
  if(/admin|dashboard/.test(p)) return 'admin';
  if(/cart|checkout|order|pay/.test(p)) return 'checkout';
  const seg=(p.split('?')[0].split('/').filter(Boolean).pop()||'').replace(/[^a-z0-9]/g,'');
  return seg && seg.length<14 ? seg : 'inner';
}
function fixFor(type, remediation){
  if(remediation) return remediation;
  const t=(type||'').toLowerCase();
  if(/sql/.test(t)) return 'Have your developer use parameterised database queries so typed-in text can never be run as a command.';
  if(/xss|script/.test(t)) return 'Escape user input before showing it, and add a content-security policy.';
  if(/auth|login|password|credential/.test(t)) return 'Enforce the login check on the server for every request, and rotate any default passwords.';
  if(/backup|file|expos|directory/.test(t)) return 'Move private files out of the public folder and require a login to reach them.';
  if(/port|service|open/.test(t)) return 'Close the service to the public or put it behind a firewall.';
  return 'Share this with a developer to review and patch the affected area.';
}

// ---- data plumbing (same APIs as before) ----
let graphNodes=[], graphSource='seed', paths=[], liveFindings=null, scanId=null, polling=false;

async function api(url, opts){const r=await fetch(url,opts);const d=await r.json().catch(()=>({}));if(!r.ok)throw Object.assign(new Error(d.detail||('HTTP '+r.status)),{status:r.status,body:d});return d;}
function nodeData(n){return n&&n.data?n.data:n;}
function normGraph(payload){
  let nodes=(payload.nodes||[]).map(n=>{const d=nodeData(n),p=d.properties||{};return{
    id:T(d.id??d.key), label:T(d.label||d.name||p.name||p.title||d.id,'Item'),
    type:T(d.type||(d.labels||[])[0]||p.type,'item').toLowerCase(),
    severity:T(d.severity||p.severity),
    description:T(d.description||p.description||p.triage),
    evidence:T(p.evidence||d.evidence), remediation:T(p.remediation||d.remediation),
    detail:T(d.detail||p.endpoint||p.url), finding_id:T(d.finding_id||p.id), props:p};});
  return nodes;
}
// turn a path (live: [{node_label,name}]  |  seed: {nodes:[ids]}) into ordered steps
function pathSteps(path){
  const raw = Array.isArray(path)?path:(path.nodes||path.node_ids||[]);
  return raw.map(h=>{
    if(h && typeof h==='object'){ return {type:T(h.node_label||h.type).toLowerCase(), label:T(h.name||h.label), id:T(h.id||h.name)}; }
    const n=graphNodes.find(g=>g.id===h); return n?{type:n.type,label:n.label,id:n.id}:{type:'item',label:T(h),id:T(h)};
  });
}
function reachesDB(steps){const last=steps[steps.length-1];return last && /asset|database|data/.test(last.type);}
function bestPath(){
  const all=paths.map(pathSteps).filter(s=>s.length>1);
  const db=all.filter(reachesDB).sort((a,b)=>b.length-a.length);
  return db[0] || all.sort((a,b)=>b.length-a.length)[0] || [];
}
function dbMemberSet(){
  const set=new Set();
  paths.map(pathSteps).filter(reachesDB).forEach(steps=>steps.forEach(s=>{set.add(s.label);set.add(s.id);}));
  return set;
}

function collectFindings(){
  if(liveFindings && liveFindings.length){
    return liveFindings.map((f,i)=>({raw:f, id:T(f.id,'f'+i), type:T(f.type||f.title,'Weakness'),
      severity:f.severity, description:T(f.description), evidence:T(f.evidence), remediation:T(f.remediation),
      endpoint:T(f.endpoint), key:T(f.type||f.title)}));
  }
  if(graphSource!=='seed'){
    return graphNodes.filter(n=>n.type==='finding').map(n=>({raw:n,id:n.id,type:T(n.label),severity:n.severity,
      description:n.description,evidence:n.evidence,remediation:n.remediation,endpoint:n.detail,key:n.label}));
  }
  return BOOT.findings.map(f=>({raw:f,id:f.id,type:f.title,severity:f.severity,description:f.description,
    evidence:f.evidence,remediation:f.remediation,endpoint:f.endpoint,key:f.node_id}));
}

// ---- render ----
function renderVerdict(steps, findingCount){
  const dbPath = reachesDB(steps) && steps.length>1;
  const badge=$('badge'), title=$('verdict-title'), sub=$('verdict-sub');
  badge.classList.remove('danger','warn','safe');
  if(dbPath){
    badge.classList.add('danger'); badge.textContent='🔴';
    title.textContent='We found a way in.';
    sub.textContent=`An attacker could reach your data in ${steps.length-1} step${steps.length-1===1?'':'s'}. Below is exactly how — and how to shut each step down.`;
  }else if(findingCount>0){
    badge.classList.add('warn'); badge.textContent='🟠';
    title.textContent='We found some weak spots.';
    sub.textContent='None of them chain all the way to your data yet — but they’re worth fixing before they can be combined.';
  }else{
    badge.classList.add('safe'); badge.textContent='🟢';
    title.textContent='No break-in path found.';
    sub.textContent='We couldn’t find a way through in this check. Keep testing as your app changes.';
  }
  $('vmeta-count').textContent = findingCount? `⚠️ ${findingCount} thing${findingCount===1?'':'s'} to look at` : '';
}
function renderJourney(steps){
  const sec=$('journey-sec'), box=$('journey'); box.replaceChildren();
  if(!reachesDB(steps) || steps.length<2){sec.hidden=true; return;}
  sec.hidden=false;
  $('journey-note').textContent = `${steps.length-1} steps from the front door to your data`;
  steps.forEach((s,i)=>{
    const role=STEP_ROLE[s.type]||{ico:'•',lab:'Step'};
    const isVuln=/vulnerab|finding/.test(s.type), isEnd=/asset|database|data/.test(s.type);
    const isEntry=/target|entry/.test(s.type), isPage=/endpoint|form/.test(s.type);
    const plain=isVuln?plainFor(s.label,s.label,''):null;
    let title, desc;
    if(isVuln){ title=plain.t; desc=plain.d; }
    else if(isEnd){ title='Your customer data'; desc='The prize — the private data an attacker is after.'; }
    else if(isEntry){ title='Your app’s front door'; desc='The public web page anyone can open, no login needed.'; }
    else if(isPage){ title='The '+pageName(s.label)+' page'; desc='A page an attacker can reach from the front door.'; }
    else { title=T(s.label); desc=''; }
    const card=el('div','step'+(isEnd?' end':'')); card.style.animationDelay=(i*90)+'ms';
    card.append(el('div','ico',role.ico), el('div','lab',role.lab), el('h3',null,title), el('p',null,desc));
    box.append(card);
  });
}
function renderFindings(){
  const cards=$('cards'); cards.replaceChildren();
  const members=dbMemberSet();
  const items=collectFindings().map(f=>{
    const plain=plainFor(f.type, f.type, f.description);
    return {...f, plainTitle:T(f.description,plain.t), means:plain.d, fix:fixFor(f.type,f.remediation),
      reaches: members.has(f.key)||members.has(f.type)||members.has(f.id)};
  }).sort((a,b)=>(b.reaches-a.reaches)|| (sev(a.severity).rank-sev(b.severity).rank));
  $('found-note').textContent = items.length? `${items.length} finding${items.length===1?'':'s'}` : '';
  if(!items.length){cards.append(el('div','empty', scanId?'Waiting for the first finding…':'Nothing found yet. Hit “Check my app” to run a fresh check.')); return;}
  items.forEach((f,i)=>{
    const s=sev(f.severity);
    const c=el('div','fcard'); c.style.setProperty('--sev',s.color); c.style.animationDelay=(i*70)+'ms';
    const top=el('div','fcard-top');
    const badge=el('span','sev'); badge.append(el('span','d'), document.createTextNode(s.word));
    top.append(badge);
    if(f.reaches){const r=el('span','reaches'); r.append(document.createTextNode('⚠ Reaches your data')); top.append(r);}
    c.append(top, el('h3',null,f.plainTitle));
    const m=el('div','frow'); m.append(el('div','k','What it means'), el('div','v',f.means)); c.append(m);
    const fx=el('div','frow fix'); fx.append(el('div','k','How to fix it'), el('div','v',f.fix)); c.append(fx);
    cards.append(c);
  });
}
function renderAll(){
  const steps=bestPath();
  const count=collectFindings().length;
  renderVerdict(steps,count); renderJourney(steps); renderFindings();
  $('vmeta-target').textContent = graphSource==='seed' ? 'OWASP Juice Shop (sample)' : 'OWASP Juice Shop';
}

async function loadGraph(){
  try{
    const [g,p]=await Promise.all([api('/api/graph'),api('/api/paths')]);
    graphSource=g.source; graphNodes=normGraph(g);
    paths = (p.source===g.source)? (p.paths||[]) : (g.source==='seed'?BOOT.paths:[]);
    if(!paths.length && g.source==='seed') paths=BOOT.paths;
    renderAll();
  }catch(e){ /* keep whatever is shown */ }
}
async function health(){
  try{const d=await api('/api/health');
    for(const n of ['daytona','neo4j','nosana']) $('c-'+n).classList.toggle('on', d[n]===true);
  }catch(e){}
}

// scan flow
const PHASE={queued:'Waking up a sandbox for your app…',running:'Our agents are poking at your app…',
  deploying_target:'Setting up a safe copy of your app…',scanning:'Our agents are poking at your app…'};
async function poll(){
  if(!scanId||polling)return; polling=true;
  try{const r=await api('/api/scan/'+encodeURIComponent(scanId));
    liveFindings=r.findings||[]; renderAll();
    if(['queued','running','deploying_target','scanning'].includes(r.status)){
      $('verdict-title').textContent=PHASE[r.status]||'Checking your app…';
      await loadGraph();
    }else{ endScan(r); }
  }catch(e){ if(e.status===404) endScan({status:'failed'}); }
  finally{ polling=false; if(scanId) setTimeout(poll,1600); }
}
function endScan(r){
  scanId=null; $('scan').classList.remove('busy'); $('scan').disabled=false; $('scan-label').textContent='Check again';
  loadGraph();
  if(r.status && r.status!=='completed' && r.status!=='done') toast('Live scanning isn’t wired up yet — showing the latest result.');
}
$('scan').addEventListener('click', async ()=>{
  if(scanId)return;
  $('scan').classList.add('busy'); $('scan').disabled=true; $('scan-label').textContent='Checking…';
  $('badge').className='badge warn'; $('badge').textContent='⏳'; $('verdict-title').textContent='Checking your app…';
  $('verdict-sub').textContent='Spinning up a sealed sandbox and letting our agents look for a way in.';
  try{const r=await api('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
    if(r.status==='not_wired'){ endScan(r); return; }
    scanId=r.scan_id; liveFindings=r.findings||[]; poll();
  }catch(e){ endScan({status:'failed'}); }
});
let tt; function toast(m){$('toast').textContent=m;$('toast').hidden=false;clearTimeout(tt);tt=setTimeout(()=>$('toast').hidden=true,5000);}

// boot: show seed instantly, then live data
graphSource='seed'; graphNodes=normGraph(BOOT.graph); paths=BOOT.paths; renderAll();
loadGraph(); health(); setInterval(()=>{if(!document.hidden)health();},60000);
</script>
</body></html>'''.replace("__BOOTSTRAP__", json.dumps({"graph": SEED_GRAPH, "findings": SEED_FINDINGS, "paths": SEED_PATHS}).replace("<", "\\u003c"))


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse(HTML)
