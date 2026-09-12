# Daytona HackSprint Tokyo — build environment

Hack window: 2:00–4:00 PM. Demos 4:20 (2 min/team). Winners 5:30.

## Sponsors (integration = 1 of 4 judging criteria)
- **Daytona** (title) — isolated agent sandboxes, sub-second start, preview URLs
- **Neo4j** — knowledge graph + GraphRAG; show *relationships*, not key-value use
- **Nosana** — decentralized GPU inference via OpenAI-compatible endpoint

## First move
1. Fill `.env` (copy of `.env.example`) — Nosana is the long pole, get it first.
2. `./.venv/bin/python scripts/smoke_test.py` — must show 3× PASS.
3. Only then build features.

## Layout
    src/agents/sandbox.py   Daytona: sandbox_session, run_parallel, serve
    src/graph/store.py      Neo4j: upsert, multi_hop, to_cytoscape
    src/llm/client.py       Nosana: OpenAI-compatible client + fallback
    src/app.py              FastAPI demo shell (sponsor status pills)
    scripts/smoke_test.py   Proves all three sponsors live
    scripts/dispatch.sh     Fans the four modules across codex workers

## Run the demo
    .venv/bin/uvicorn src.app:app --reload --port 3000
