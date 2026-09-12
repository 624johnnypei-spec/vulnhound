# VulnHound demo targets

Three tiny, self-contained vulnerable web apps (Python standard library only —
no dependencies). Each has **one distinct, real, detectable** security issue so
a scan produces a clear, different result on each.

| Site | App | Issue | Severity | How the scan finds it |
|------|-----|-------|----------|-----------------------|
| **A** | `site_a_sqli.py` (:8100) | **SQL injection** in login | Critical | `sqlmap` on `/login`, or an auth-bypass probe: `username=' OR '1'='1' --` |
| **B** | `site_b_xss.py` (:8101) | **Reflected XSS** in search | High | `curl "/search?q=<script>…"` — payload comes back unescaped |
| **C** | `site_c_exposure.py` (:8102) | **Sensitive file exposure** | Medium | `gobuster`/`curl` finds `/.env`, `/backup.zip` returning 200 |

Run one:   `python targets/site_a_sqli.py 8100`
Run all:   `python targets/serve_all.py`

Each issue is genuine: normal/wrong requests are rejected — only the attack works.

---

## How a website connects to the scan

A scan is just **one target host + a swarm of allowlist-locked agents**. The
agents may only run known tools (`nmap`, `sqlmap`, `curl`, …) and only against
the one target host — every command aimed anywhere else is rejected before it
runs (`allowed_command()` in `src/agents/sandbox.py`).

So "connecting a website" = telling the scan what the **one target host** is.
There are three ways to supply it:

**1. VulnHound deploys it (the isolated-sandbox path — what Juice Shop uses).**
The app is started *inside a Daytona sandbox*, which hands back a public preview
URL; that URL becomes the target. Flow:

    sandbox.serve(port, start_cmd)  ->  public preview URL   (src/agents/sandbox.py)
        e.g. serve(8100, ".venv/bin/python targets/site_a_sqli.py 8100")
    preview URL -> registered as the target host -> agents scan only that host

This is the safest option: the target runs in a throwaway, network-isolated
box that is destroyed after the scan.

**2. Point at a URL you already run (a site you own).**
Give the scan an explicit target and it skips deployment:

    POST /api/scan   { "target": "https://staging.mysite.com" }

The allowlist then locks every agent tool to that exact host. Only use this on
a site you are authorized to test.

**3. Local development.**
Run the app on your machine and target it directly, e.g.
`http://127.0.0.1:8100` (the local port must be added to the allowlist).

### Where the target flows in the code
    deploy/serve  ->  host string  ->  sandbox._target_host (allowlist source)
                                   ->  make_run_tool(host) / run_tool(sandbox, cmd)
                                   ->  each agent's tools, constrained to that host
                                   ->  findings -> Neo4j attack graph -> dashboard
