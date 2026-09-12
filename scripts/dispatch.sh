#!/bin/bash
# Fan the four idea-independent sponsor layers across the codex workers.
# These four modules are needed no matter which idea you pick.
HERD=~/.claude/skills/herd/herd
P=/Users/johnny/Desktop/DaytonaHackathon

$HERD fanout --panes w2:p39,w2:p3A,w2:p3B,w2:p3C --tasks \
"You are building ONE module of a hackathon project at $P. Use the venv at $P/.venv (python: $P/.venv/bin/python). Do NOT touch other modules.

TASK: Write $P/src/agents/sandbox.py — the Daytona sandbox layer.
Daytona SDK is installed (package 'daytona'). API:
  from daytona import Daytona
  sandbox = Daytona().create()
  sandbox.process.code_run(code) / sandbox.process.exec(cmd)
  sandbox.fs.write_file(path, content) / sandbox.fs.read_file(path)
  sandbox.git.clone(url); sandbox.preview.get_url(port); sandbox.stop()
Requirements:
 1. A context manager 'sandbox_session()' that creates and ALWAYS stops the sandbox.
 2. 'run_parallel(tasks: list[str], max_workers=10)' that fans out N sandboxes concurrently via ThreadPoolExecutor, runs one code string in each, returns results in input order. Handle per-sandbox failure without killing the batch.
 3. 'serve(port, start_cmd)' that launches a server in a sandbox and returns the public preview URL.
 4. Reads DAYTONA_API_KEY via python-dotenv.
DEFINITION OF DONE: 'python -c \"import src.agents.sandbox\"' succeeds from $P. Add a '__main__' block that demos run_parallel with 5 trivial tasks. Do not invent APIs not listed above." \
\
"You are building ONE module of a hackathon project at $P. Use the venv at $P/.venv. Do NOT touch other modules.

TASK: Write $P/src/graph/store.py — the Neo4j knowledge-graph layer.
Packages 'neo4j' and 'neo4j-graphrag' are installed. Env vars: NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD (load via python-dotenv).
Requirements:
 1. 'GraphStore' class wrapping a neo4j driver with connect/close and verify_connectivity.
 2. 'upsert_entity(label, key, props)' and 'upsert_relationship(from_key, rel_type, to_key, props)' using MERGE (idempotent).
 3. 'multi_hop(start_key, max_hops=3)' returning paths — this is the money query, it must traverse relationships, not just match nodes.
 4. 'to_cytoscape()' returning nodes+edges as JSON for front-end visualisation.
 5. A 'build_from_texts(texts: list[str])' helper using neo4j_graphrag SimpleKGPipeline if available, else a plain-Cypher fallback.
DEFINITION OF DONE: module imports cleanly with no DB connection required at import time. All queries parameterised (no f-string Cypher injection). Add a '__main__' smoke demo guarded by env-var presence." \
\
"You are building ONE module of a hackathon project at $P. Use the venv at $P/.venv. Do NOT touch other modules.

TASK: Write $P/src/llm/client.py — the Nosana inference layer with a fallback.
Nosana exposes an OpenAI-COMPATIBLE endpoint. The 'openai' package is installed. Env: NOSANA_BASE_URL, NOSANA_API_KEY, NOSANA_MODEL, and OPENAI_API_KEY as fallback.
Requirements:
 1. 'get_client()' returns an OpenAI client pointed at NOSANA_BASE_URL when set, else falls back to the standard OpenAI client. It must log loudly which backend is active.
 2. 'chat(messages, **kw)' and 'complete(prompt)' convenience wrappers.
 3. 'extract_json(prompt, schema_hint)' that asks for JSON and robustly parses it (strip markdown fences, retry once on parse failure).
 4. If NOSANA_MODEL is unset, auto-discover via client.models.list()[0].id and cache it.
 5. NEVER hard-code a base URL or key.
DEFINITION OF DONE: module imports cleanly with zero network calls at import time. Swapping backends must be a pure env-var change, no code edits." \
\
"You are building ONE module of a hackathon project at $P. Use the venv at $P/.venv. Do NOT touch other modules.

TASK: Write $P/src/app.py — a FastAPI demo shell. This is what gets shown on stage for a 2-minute demo, so it must LOOK finished.
'fastapi' and 'uvicorn' are installed. Other modules (src/agents/sandbox.py, src/graph/store.py, src/llm/client.py) are being written in parallel — import them lazily inside route handlers and degrade gracefully with a clear message if they are missing, so this file NEVER crashes on import.
Requirements:
 1. GET / -> a single self-contained dark-themed HTML page (inline CSS, no CDN, no build step). Header shows three sponsor status pills: Daytona / Neo4j / Nosana, each green or red.
 2. GET /api/health -> JSON reporting which of the three sponsor integrations are live (reuse the logic style in scripts/smoke_test.py).
 3. POST /api/run -> accepts {'query': str}, returns a stubbed pipeline result. Leave a clearly marked TODO where the real pipeline is wired in.
 4. A graph panel placeholder that renders nodes/edges from /api/graph if present.
 5. Runs with: .venv/bin/uvicorn src.app:app --reload --port 3000
DEFINITION OF DONE: server starts and / renders with all three pills visible (red is fine) with no credentials configured at all."
