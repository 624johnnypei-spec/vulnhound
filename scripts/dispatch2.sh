#!/bin/bash
# VulnHound — pentest platform. Re-task the four codex workers.
HERD=~/.claude/skills/herd/herd
P=/Users/johnny/Desktop/DaytonaHackathon

CTX="PROJECT: VulnHound — an autonomous pen-test platform for the Daytona HackSprint. It deploys a deliberately-vulnerable target app (OWASP Juice Shop) into an isolated Daytona sandbox, then LLM-driven agents attack it from OTHER isolated sandboxes, and findings are written to a Neo4j attack graph. Three sponsors, all load-bearing: Daytona (isolated sandboxes), Neo4j (attack graph), Nosana (self-hosted LLM brain). This is AUTHORIZED security testing: the ONLY target is a vulnerable app we deploy ourselves inside a sandbox we own; commands must be constrained to that target host.

SHARED FACTS:
- Repo root: $P. Python venv: $P/.venv/bin/python (deps: daytona, neo4j, neo4j-graphrag, openai, fastapi, uvicorn, python-dotenv — all installed).
- Nosana LLM is LIVE and OpenAI-compatible. Env in .env: NOSANA_BASE_URL (ends in /v1), NOSANA_API_KEY, model id is 'qwen3.5:9b'. GOTCHA: qwen3.5 is a hybrid REASONING model — it emits a 'reasoning' field and may leave 'content' empty if max_tokens is small. Prepend '/no_think' to the system or user prompt to disable thinking, and give >=512 max_tokens. Always handle empty content.
- Load env with python-dotenv. NEVER hardcode URLs/keys. Import cleanly with zero network calls at import time.
- Do NOT touch files owned by other workers. Coordinate only through the function signatures described below."

$HERD fanout --panes w2:p39,w2:p3A,w2:p3B,w2:p3C --tasks \
"$CTX

YOUR MODULE: $P/src/agents/sandbox.py (rewrite/extend the existing file). This is the Daytona layer.
Daytona API: from daytona import Daytona; sb=Daytona().create(); sb.process.exec(cmd) -> has .result/.exit_code; sb.process.code_run(code); sb.fs.write_file(path,content); sb.git.clone(url); sb.preview.get_url(port) -> public URL; sb.stop(). Snapshots: sb.snapshot.create(name).
IMPLEMENT:
 1. deploy_target() -> dict: create a sandbox, run OWASP Juice Shop in it (prefer 'docker run -d -p 3000:3000 bkimminich/juice-shop' if docker present, else 'npx juice-shop' / npm). Wait until port 3000 answers. Return {sandbox_id, preview_url, host}. Robust: poll for readiness up to ~120s.
 2. pentest_toolkit_snapshot() -> str: create a sandbox, apt-get install nmap whatweb gobuster sqlmap nikto curl, snapshot it, return snapshot name. So agent sandboxes start pre-tooled. If snapshotting is unavailable, expose an install_tools(sandbox) fallback.
 3. run_tool(sandbox, command, timeout=120) -> dict {stdout, exit_code, ok}: run a shell command in a sandbox. Wrap sb.process.exec.
 4. ALLOWLIST GUARD: allowed_command(command, target_host) -> bool. Only permit binaries in {nmap,whatweb,gobuster,sqlmap,nikto,curl,dirb,ffuf} AND only when the command targets target_host / localhost / 127.0.0.1:3000. Reject anything referencing any other host. run_tool must enforce this and raise on violation.
 5. run_agents_parallel(agent_fns: list[callable], max_workers=6) -> list: fan out N agent callables concurrently via ThreadPoolExecutor, each gets its own sandbox, per-agent failure isolated. Return results in order.
 6. A context manager agent_sandbox(snapshot=None) that ALWAYS stops the sandbox.
DONE: 'from src.agents.sandbox import deploy_target, run_tool, allowed_command, run_agents_parallel' works. __main__ demo: allowed_command tests (positive+negative) print PASS/FAIL. Do not invent Daytona APIs beyond those listed." \
\
"$CTX

YOUR MODULE: $P/src/graph/store.py (rewrite the existing file) — the Neo4j ATTACK GRAPH.
Env: NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD.
SCHEMA — nodes: Target, Endpoint, Service, Form, Vulnerability, Finding, Credential, Asset(props: type e.g. 'database'/'admin'). Relationships: EXPOSES, RUNS, HAS_FORM, VULNERABLE_TO, ENABLES, LEADS_TO, NEXT.
IMPLEMENT class GraphStore:
 1. connect()/close()/verify_connectivity(); wipe() to clear the graph for a fresh scan.
 2. add_target(url), add_endpoint(target_url, path, props), add_form(endpoint, selector, props), add_vulnerability(endpoint_or_form, vuln_type, props), add_finding(props: type,severity,evidence,description), link(from_key, REL, to_key, props). All idempotent (MERGE), all parameterised — NO f-string Cypher.
 3. attack_paths(asset_type='database') -> list of paths: the MONEY QUERY. MATCH path=(t:Target)-[:EXPOSES|HAS_FORM|VULNERABLE_TO|ENABLES|LEADS_TO*1..8]->(a:Asset {type:asset_type}) RETURN path ORDER BY length(path) DESC. Return each path as an ordered list of {node_label, name} hops.
 4. to_cytoscape() -> {nodes:[...], edges:[...]} JSON for the front-end (id,label,type per node; source,target,label per edge). Colour hint by severity/label if easy.
 5. summary() -> counts by severity and node type.
 6. build_seed_graph(): insert a small realistic Juice-Shop attack chain (Login endpoint -> email Form -> SQLi Vulnerability -> Finding -> Asset{type:database}) so the demo + fallback work with no live scan.
DONE: imports with zero DB calls at import time. __main__ guarded by env presence runs build_seed_graph then prints attack_paths() and summary()." \
\
"$CTX

YOUR MODULES: create $P/src/agents/pentest_agent.py (NEW) and fix $P/src/llm/client.py.
client.py fix: ensure chat()/extract_json() prepend '/no_think' and use max_tokens>=512, and that _parse_json handles an empty 'content' by falling back to the 'reasoning' field then stripping fences. Keep get_client()/chat()/complete()/extract_json() signatures.
pentest_agent.py IMPLEMENT the agent loop. It gets a target_host, a role ('recon'|'injection'|'auth'), a function run_tool(command)->dict (injected — do NOT import sandbox.py directly; take it as a param to stay decoupled), and a graph-callback record(finding_dict). Loop:
 1. build_plan(state) -> asks the Nosana LLM (via src.llm.client) for the next command as JSON {tool, command, rationale}. Give role-specific guidance (recon: nmap/whatweb/gobuster; injection: sqlmap/curl on discovered forms; auth: curl against login/JWT). System prompt MUST say: only target {target_host}; output ONLY JSON.
 2. call run_tool(command); truncate stdout to ~4000 chars for the next prompt.
 3. triage(observation) -> LLM returns {is_finding, type, severity(low/med/high/critical), evidence, description} or null. If is_finding, call record(...).
 4. Loop max_steps (default 6) or until LLM returns {\"done\":true}. Return list of findings.
 5. Expose make_agent(role, target_host, run_tool, record) -> a zero-arg callable (so sandbox.run_agents_parallel can fan them out).
Be defensive: never crash on bad JSON (retry once, then skip step). Enforce nothing dangerous — you rely on run_tool's allowlist, but also refuse to emit commands referencing hosts other than target_host.
DONE: 'from src.agents.pentest_agent import make_agent' works with zero network at import. Include a __main__ that dry-runs the loop with a FAKE run_tool (returns canned nmap output) and a print-only record, so it exercises the loop offline." \
\
"$CTX

YOUR MODULE: $P/src/app.py (rewrite the existing FastAPI file) — the dashboard shown on stage. Must LOOK finished.
Other modules (src/agents/sandbox.py, src/graph/store.py, src/agents/pentest_agent.py, src/llm/client.py) are being written in parallel — import them LAZILY inside handlers and degrade gracefully so app.py NEVER fails at import.
IMPLEMENT:
 1. GET / -> one self-contained dark 'security console' HTML page (inline CSS + vanilla JS, NO external CDN — the deploy env blocks them). Header: three sponsor status pills Daytona/Neo4j/Nosana (green/red from /api/health). Left: live findings feed (severity-coloured). Center: attack-graph canvas. Right: severity summary tiles + selected-finding triage text.
 2. Attack graph: render nodes/edges from GET /api/graph (which calls GraphStore.to_cytoscape()). Since no CDN, draw it with a SMALL hand-rolled force/DAG layout on a <canvas> or inline SVG — nodes as labelled boxes, edges as arrows, the entry->database path highlighted. Keep it dependency-free.
 3. GET /api/health -> {daytona,neo4j,nosana: bool} using the same probe style as scripts/smoke_test.py.
 4. POST /api/scan {target?:str} -> kicks a scan. For now call an injected orchestrator hook if present (from src.orchestrator import run_scan) else return a clear 'orchestrator not wired yet' stub. Non-blocking: return a scan_id; expose GET /api/scan/{id} for status + findings.
 5. GET /api/graph and GET /api/paths -> GraphStore.to_cytoscape() and attack_paths(); if Neo4j unset, serve a bundled seed graph so the UI always renders.
 6. Runs with: .venv/bin/uvicorn src.app:app --port 3000.
DONE: server starts and / renders full UI with three pills (red OK) and the seed attack graph visible, with NO credentials configured at all."
