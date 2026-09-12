"""Wires the VulnHound pipeline: target -> agents -> attack graph.

Coded to the module contracts in scripts/dispatch2.sh. If a worker's final
signature differs, this is the single file to reconcile at integration time.

    from src.orchestrator import run_scan, get_scan
"""
from __future__ import annotations

import threading
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

# In-memory scan registry (fine for a single-node hackathon demo).
_SCANS: dict[str, dict[str, Any]] = {}
_LOCK = threading.Lock()

ROLES = ("recon", "injection", "auth")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# Keywords that indicate a finding actually reaches data — used to decide whether
# to link it to the crown-jewel database Asset. Findings that don't (e.g. an open
# port, an info leak) stay on the graph but off the path-to-database.
_DB_KEYWORDS = ("sql", "inject", "auth", "credential", "password",
                "database", "idor", "dump", "bypass", "token", "session")


def _reaches_database(finding: dict[str, Any]) -> bool:
    if str(finding.get("severity", "")).lower() == "critical":
        return True
    blob = " ".join(str(finding.get(k, "")) for k in ("type", "description", "evidence")).lower()
    return any(word in blob for word in _DB_KEYWORDS)


from pathlib import Path

# Selectable scan targets. Demo sites are single-file apps deployed via deploy_app;
# "juiceshop" (default) uses the dedicated Juice Shop deployer.
DEMO_SITES = {
    "site_a": ("targets/site_a_sqli.py", "CoolStore (SQL injection demo)"),
    "site_b": ("targets/site_b_xss.py", "QuickSearch (XSS demo)"),
    "site_c": ("targets/site_c_exposure.py", "DevPortal (exposure demo)"),
}


def _deploy_for_target(target, deploy_target, deploy_app, scan_id):
    """Resolve a target spec to a deployed {host, preview_url,...} + a label."""
    key = (target or "juiceshop").strip().lower()
    if key in DEMO_SITES:
        rel, label = DEMO_SITES[key]
        code = (Path(__file__).resolve().parents[1] / rel).read_text()
        _log(scan_id, f"deploying {label} into a Daytona sandbox")
        tgt = deploy_app(code, 3000)
    else:
        label = "OWASP Juice Shop"
        _log(scan_id, "deploying OWASP Juice Shop into a Daytona sandbox")
        tgt = deploy_target()
    return label, tgt


def _write_finding_chain(graph: Any, target_url: str, finding: dict[str, Any]) -> None:
    """Persist a finding as Target->Endpoint->Vulnerability->Finding[->Asset(db)]."""
    path = str(finding.get("endpoint") or "/").strip() or "/"
    try:
        endpoint = graph.add_endpoint(target_url, path, {"name": path})
    except Exception:
        endpoint = graph.add_endpoint(target_url, "/", {"name": "/"})
    vuln_type = str(finding.get("type") or "Unspecified weakness")
    vuln = graph.add_vulnerability(endpoint, vuln_type)
    finding_key = graph.add_finding({
        "type": vuln_type,
        "severity": finding.get("severity", "medium"),
        "evidence": finding.get("evidence") or "(no evidence captured)",
        "description": finding.get("description") or vuln_type,
        "endpoint_key": endpoint,
        "role": finding.get("role"),
    })
    graph.link(vuln, "ENABLES", finding_key)
    if _reaches_database(finding):
        asset = graph.upsert_entity(
            "Asset", f"asset:database:{target_url}",
            {"type": "database", "name": "Application database"},
        )
        graph.link(finding_key, "LEADS_TO", asset)


def get_scan(scan_id: str) -> Optional[dict[str, Any]]:
    with _LOCK:
        s = _SCANS.get(scan_id)
        return dict(s) if s else None


def _set(scan_id: str, **fields: Any) -> None:
    with _LOCK:
        _SCANS[scan_id].update(fields)


def _add_finding(scan_id: str, finding: dict[str, Any]) -> None:
    with _LOCK:
        _SCANS[scan_id]["findings"].append(finding)


def run_scan(target: Optional[str] = None, live: bool = True) -> str:
    """Start a scan in a background thread. Returns a scan_id immediately."""
    scan_id = uuid.uuid4().hex[:12]
    with _LOCK:
        _SCANS[scan_id] = {
            "id": scan_id,
            "status": "starting",
            "target": target,
            "started_at": _now(),
            "findings": [],
            "paths": [],
            "error": None,
            "log": [],
        }
    t = threading.Thread(target=_run, args=(scan_id, target, live), daemon=True)
    t.start()
    return scan_id


def _log(scan_id: str, msg: str) -> None:
    with _LOCK:
        _SCANS[scan_id]["log"].append({"t": _now(), "msg": msg})


def _run(scan_id: str, target: Optional[str], live: bool) -> None:
    """Background pipeline. Degrades to the seed graph if creds/target missing."""
    try:
        from src.graph.store import GraphStore  # lazy: avoid import-time DB

        graph = GraphStore()
        graph.connect()

        if not live:
            _log(scan_id, "seed mode: loading demo attack graph")
            graph.wipe()
            graph.build_seed_graph()
            _finish(scan_id, graph)
            return

        from src.agents.sandbox import (
            deploy_app,
            deploy_target,
            run_agents_parallel,
            run_tool,
        )
        from src.agents.pentest_agent import run_agent

        _set(scan_id, status="deploying_target")
        label, tgt = _deploy_for_target(target, deploy_target, deploy_app, scan_id)
        host = tgt["host"]
        target_url = tgt["preview_url"]
        graph.wipe()
        graph.add_target(target_url)
        _set(scan_id, status="scanning", target=target_url, preview=tgt)
        _log(scan_id, f"target ready at {target_url}; fanning out agents")

        def record_for(role: str):
            def record(finding: dict[str, Any]) -> None:
                finding = {**finding, "role": role, "found_at": _now()}
                _add_finding(scan_id, finding)
                try:
                    # Build the full attack chain, not a standalone node, so
                    # attack_paths() can trace Target -> ... -> database.
                    _write_finding_chain(graph, target_url, finding)
                except Exception as e:  # graph write must never kill the agent
                    _log(scan_id, f"graph write failed: {e}")
            return record

        # sandbox.py's run_agents_parallel hands each callable its own pre-tooled
        # sandbox; we bind that sandbox's guarded run_tool into the agent loop so
        # one sandbox serves the whole agent (not one sandbox per command).
        def agent_fn_for(role: str):
            record = record_for(role)

            def agent_fn(sandbox: Any) -> Any:
                def bound_run_tool(command: str, timeout: int = 120) -> dict[str, Any]:
                    return run_tool(sandbox, command, timeout)  # enforces allowlist
                return run_agent(role, host, bound_run_tool, record)

            return agent_fn

        run_agents_parallel([agent_fn_for(r) for r in ROLES], max_workers=len(ROLES))

        _finish(scan_id, graph)
    except Exception as e:
        _log(scan_id, f"ERROR: {e}")
        _set(scan_id, status="error", error=f"{type(e).__name__}: {e}")
        traceback.print_exc()


def _finish(scan_id: str, graph: Any) -> None:
    try:
        paths = graph.attack_paths(asset_type="database")
    except Exception as e:
        paths = []
        _log(scan_id, f"attack_paths failed: {e}")
    _set(scan_id, status="done", paths=paths, finished_at=_now())
    _log(scan_id, f"scan complete: {len(paths)} attack path(s) to database")
    try:
        graph.close()
    except Exception:
        pass


if __name__ == "__main__":
    # Offline seed run — exercises the pipeline with no creds.
    sid = run_scan(live=False)
    import time
    for _ in range(20):
        s = get_scan(sid)
        if s and s["status"] in ("done", "error"):
            break
        time.sleep(0.5)
    print(get_scan(sid))
