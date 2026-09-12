# VulnHound — Teammate Briefing

*Daytona HackSprint Tokyo. Read time: ~4 minutes. Everything below is grounded in the actual code in this repo.*

---

## 1. TL;DR

VulnHound is an **autonomous penetration-testing platform**. It deploys a deliberately-vulnerable target app (OWASP Juice Shop) into an isolated Daytona sandbox, then turns loose LLM-driven attack agents — recon, injection, auth — each from its *own* isolated sandbox, and writes every finding into a Neo4j **attack graph**. The headline output isn't a flat bug list; it's the **ATTACK PATH** — the chain from the public entry point to the customer database (think BloodHound, which is itself a Neo4j app). We win because we hit all four judging criteria at once: three sponsors are load-bearing (not bolted on), the "attack path" framing is genuinely novel, it solves a real problem (scanners drown you in findings; we tell you which ones actually reach the crown jewels), and it's a complete working system, not a mockup.

---

## 2. The pitch

**One-sentence pitch:** *VulnHound is a swarm of self-hosted-LLM hackers that attack an app from isolated sandboxes and map the exact path from the front door to your user database.*

**What to say to each sponsor's judge:**

- **Daytona:** "Every actor gets its own isolated sandbox — the vulnerable target lives in one, and each attack agent (recon/injection/auth) fans out into its own pre-tooled sandbox in parallel. Sandboxes *are* our isolation and blast-radius control." (`src/agents/sandbox.py`)
- **Neo4j:** "We don't use Neo4j as a bucket — the whole product is the *relationships*. A single multi-hop Cypher query returns the exploit chain `Target → Endpoint → Vulnerability → Database`, ranked by whether it reaches the database asset." (`src/graph/store.py`, `attack_paths()`)
- **Nosana:** "The attacker's brain is a self-hosted Qwen 3.5 model on a Nosana GPU endpoint. Self-hosted matters here — a hosted model refuses offensive-security prompts; ours reasons about real attacks because we run it." (`src/llm/client.py`)

---

## 3. How it works

Plain language: You hit **Start scan** on the dashboard. The orchestrator deploys a fresh Juice Shop into a Daytona sandbox and grabs its preview URL. It wipes the graph, registers the target, then fans out three agents — each in its own sandbox. Each agent runs a small loop: **ask Nosana for the next shell command → run it (through a strict allowlist) → feed output back to Nosana → is this a finding?**. Every finding is written to Neo4j as it happens. When the agents finish, the orchestrator runs one Cypher query for all `Target → … → database` paths, and the dashboard renders the graph and the ranked attack path.

```
                                  ┌──────────────────────────┐
        Browser (localhost:3000)  │  FastAPI dashboard        │
        ── Start scan ──────────▶ │  src/app.py               │
                                  └────────────┬─────────────┘
                                               │ run_scan()
                                               ▼
                                  ┌──────────────────────────┐
                                  │  Orchestrator             │
                                  │  src/orchestrator.py      │
                                  └───┬───────────────┬───────┘
                    deploy_target()   │               │  fan out 3 agents
                                      ▼               ▼
                     ┌────────────────────┐   ┌────────────────────────────┐
                     │ DAYTONA sandbox     │   │ DAYTONA sandbox × 3         │
                     │ OWASP Juice Shop    │◀──│ recon / injection / auth    │
                     │ (the target)        │   │ each: plan→exec→triage loop │
                     └────────────────────┘   └──────────────┬─────────────┘
                              ▲                               │ next command?
                              │ allowlisted tools             ▼
                              │ (nmap, sqlmap, curl…)  ┌───────────────┐
                              └────────────────────────│ NOSANA        │
                                                        │ Qwen 3.5 LLM  │
                                       findings ───┐    └───────────────┘
                                                   ▼
                                        ┌────────────────────────┐
                                        │ NEO4J attack graph      │
                                        │ src/graph/store.py      │
                                        │ Target→…→Database path  │
                                        └────────────────────────┘
```

---

## 4. The stack

| Layer | Tech / Sponsor | File | Status |
|---|---|---|---|
| Dashboard / API | FastAPI (dependency-free UI, dark console + Cytoscape graph) | `src/app.py` | Live — port 3000, sponsor pills + seeded graph render |
| Orchestration | Python threads; wires target → agents → graph | `src/orchestrator.py` | Live — `run_scan()`/`get_scan()` wired to dashboard |
| Sandboxes / target deploy / tool runner | **Daytona** SDK | `src/agents/sandbox.py` | Live (smoke 3/3); live scan = in progress |
| Attack agents (recon/injection/auth) | LLM loop, decoupled from Daytona | `src/agents/pentest_agent.py` | Built; exercised end-to-end in seed path, live scan in progress |
| Attack graph + multi-hop path query | **Neo4j** (AuraDB) | `src/graph/store.py` | Live (smoke 3/3); seed graph proven end-to-end |
| Attacker reasoning | **Nosana** self-hosted Qwen 3.5 (OpenAI-compatible), OpenAI fallback | `src/llm/client.py` | Live (smoke 3/3) |
| Proof-of-life | Independent 3-sponsor check | `scripts/smoke_test.py` | Passing 3/3 |

---

## 5. How to run it locally

```bash
cd /Users/johnny/Desktop/DaytonaHackathon

# 1. Virtualenv (repo expects a .venv)
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt   # fastapi, uvicorn, daytona, neo4j, openai, python-dotenv

# 2. Config — copy the example and fill in real values
cp .env.example .env
# Fill in: DAYTONA_API_KEY, NEO4J_URI/USERNAME/PASSWORD,
#          NOSANA_BASE_URL/API_KEY/MODEL (OPENAI_API_KEY is the fallback).
#          Ask the Nosana rep for the endpoint — it's the long pole.

# 3. Prove all three sponsors are live BEFORE building anything
.venv/bin/python scripts/smoke_test.py       # must print 3× PASS, exit 0

# 4. Run the dashboard
.venv/bin/uvicorn src.app:app --reload --port 3000

# 5. Open it
open http://localhost:3000
```

Notes:
- The dashboard degrades gracefully: with no Neo4j configured it shows a **bundled sample graph** clearly labeled as demo data (never reported as real scan results). Sponsor pills go green only on a *real* authenticated check — the Nosana pill will not turn green on the OpenAI fallback.
- Optional env you may see referenced: `VULNHOUND_TARGET_URL` (scope guard for explicit scan targets), `VULNHOUND_TOOLKIT_SNAPSHOT`, `JUICE_SHOP_IMAGE` / `JUICE_SHOP_SOURCE`.
- Do **not** commit `.env`. Do not paste secret values into this doc or the demo.

---

## 6. The 2-minute demo script (no slides)

1. **Frame it (15s):** "Scanners give you a 400-item to-do list. VulnHound gives you the *attack path* — the chain from the public front door to the user database — and ranks bugs by whether they actually reach it."
2. **Show sponsors are real (15s):** Point at the three pills at the top — Daytona, Neo4j, Nosana — all green. "That's not decoration; each is a live authenticated check. `smoke_test.py` passes 3/3." (Have a terminal with the 3× PASS output ready as backup.)
3. **Explain the swarm (20s):** "One vulnerable app in its own Daytona sandbox. Three attacker agents, each in *its own* isolated sandbox, reasoning with a self-hosted Qwen model on Nosana. They pick their own commands — nmap, sqlmap, curl — against an allowlist."
4. **The graph is the story (45s):** Show the Neo4j attack graph on screen. Trace the highlighted path with your finger: **Juice Shop → Login API → SQL injection → Customer database.** "This is one Cypher query, `Target → … → database`, longest chain first. That's Neo4j doing what a flat findings table can't."
5. **The payoff line (15s):** "Two critical XSS bugs might not reach the database. This SQLi does — so it's ranked first. We tell you what to fix *first*, not just what's broken."
6. **(Stretch, if the live scan is green):** Hit **Start scan**, show status stepping through *deploying target → agents testing → findings appearing live*, then the freshly-built path. If it's not ready, stay on the seeded graph — it tells the same story cleanly.

---

## 7. Current status & what's left

**Tier 1 — DONE and demoable right now:**
- All three sponsor integrations LIVE — `scripts/smoke_test.py` passes **3/3** (Daytona runs code in a sandbox, Neo4j traverses a 2-hop path, Nosana returns a completion).
- Dashboard runs on port 3000, all three sponsor pills green, renders a seeded attack graph and the ranked path.
- Graph pipeline proven **end-to-end**: `orchestrator.run_scan(live=False)` → `GraphStore.build_seed_graph()` → `attack_paths()` returns the `Target → … → database` chain the UI draws.
- Command allowlist / target-scoping in `sandbox.py` is thorough and self-tests (`python -m src.agents.sandbox` runs its own PASS/FAIL policy cases).

**Tier 2 — IN PROGRESS / stretch:**
- **First fully LIVE scan** (deploy real Juice Shop + real agents driving Nosana against it) is being attempted in parallel now. May or may not be green yet — treat as stretch. The moving parts: Juice Shop deploy (docker path preferred, npm-degit fallback), agent sandbox tooling/snapshots, and Nosana latency inside the 6-step agent loop.
- If the live scan isn't stable by demo time, **the seeded graph carries the demo** — it exercises the same pipeline and renders the same headline path.

---

## 8. Safety / scope note

This is offensive tooling, so scope control is built in and load-bearing — not an afterthought:

- **We only attack our own deployed target.** The target host is registered by `deploy_target()` in `sandbox.py`; it is never inferred from an LLM's command or an agent-controlled attribute.
- **Allowlist-guarded execution.** `run_tool()` accepts only a finite set of binaries (`nmap, whatweb, gobuster, sqlmap, nikto, curl, dirb, ffuf`) with a finite, validated option grammar. Off-target hosts, redirects, proxies, shell metacharacters, config/target files, and encoded off-target references are all rejected *before* execution. Commands run via `env -i` with a scrubbed environment and no proxy inheritance.
- **Belt and suspenders.** The agent loop (`pentest_agent.py`) refuses to even *send* a command that names a host other than the target, in front of the sandbox allowlist.
- **The dashboard never executes attacks itself**, and explicit scan targets must exactly match `VULNHOUND_TARGET_URL` (the owned sandbox) or the request is refused (403).
- **Seed data is clearly labeled** as illustrative and is never reported as real scan results.

*This is command-level validation, not an OS network firewall — keep the target in an isolated Daytona sandbox, which is exactly the design.*
