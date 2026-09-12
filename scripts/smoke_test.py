"""Prove all three sponsor integrations are live. Run this FIRST and often.

    ./.venv/bin/python scripts/smoke_test.py

Each check is independent: one sponsor being down never hides the others.
Exit code 0 only when all three PASS.
"""
import os
import sys
import traceback

from dotenv import load_dotenv

load_dotenv()

RESULTS = {}


def check(name):
    def deco(fn):
        def wrapped():
            try:
                detail = fn()
                RESULTS[name] = ("PASS", detail)
            except Exception as e:
                RESULTS[name] = ("FAIL", f"{type(e).__name__}: {e}")
                if os.getenv("SMOKE_VERBOSE"):
                    traceback.print_exc()
        return wrapped
    return deco


@check("Daytona")
def daytona_check():
    if not os.getenv("DAYTONA_API_KEY"):
        raise RuntimeError("DAYTONA_API_KEY unset -> app.daytona.io > settings")
    from daytona import Daytona

    sandbox = Daytona().create()
    try:
        r = sandbox.process.code_run('print(6 * 7)')
        out = (getattr(r, "result", "") or "").strip()
        if "42" not in out:
            raise RuntimeError(f"sandbox ran but returned {out!r}")
        return f"sandbox executed code, got {out}"
    finally:
        try:
            sandbox.stop()
        except Exception:
            pass


@check("Neo4j")
def neo4j_check():
    uri = os.getenv("NEO4J_URI")
    pwd = os.getenv("NEO4J_PASSWORD")
    if not uri or not pwd or "xxxxxxx" in uri:
        raise RuntimeError("NEO4J_URI/PASSWORD unset -> AuraDB Free instance creds")
    from neo4j import GraphDatabase

    driver = GraphDatabase.driver(
        uri, auth=(os.getenv("NEO4J_USERNAME", "neo4j"), pwd)
    )
    try:
        driver.verify_connectivity()
        with driver.session() as s:
            # write a 2-hop path, read it back, then clean up -- proves
            # relationships work, not just connectivity.
            s.run(
                "MERGE (a:SmokeTest {id:'a'})-[:LINKS_TO]->"
                "(b:SmokeTest {id:'b'})-[:LINKS_TO]->(c:SmokeTest {id:'c'})"
            )
            hops = s.run(
                "MATCH p=(a:SmokeTest {id:'a'})-[:LINKS_TO*2]->(c:SmokeTest {id:'c'}) "
                "RETURN length(p) AS n"
            ).single()
            s.run("MATCH (n:SmokeTest) DETACH DELETE n")
        return f"connected, traversed {hops['n']}-hop path"
    finally:
        driver.close()


@check("Nosana")
def nosana_check():
    base = os.getenv("NOSANA_BASE_URL")
    if not base:
        raise RuntimeError("NOSANA_BASE_URL unset -> get endpoint from Nosana rep")
    from openai import OpenAI

    client = OpenAI(
        base_url=base.rstrip("/"),
        api_key=os.getenv("NOSANA_API_KEY") or "not-required",
    )
    model = os.getenv("NOSANA_MODEL")
    if not model:
        model = client.models.list().data[0].id
    r = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": "Reply with the single word: ready"}],
        max_tokens=16,
    )
    return f"model {model} replied {r.choices[0].message.content.strip()!r}"


for fn in (daytona_check, neo4j_check, nosana_check):
    fn()

print("\n  SPONSOR INTEGRATION SMOKE TEST\n" + "  " + "-" * 46)
for sponsor in ("Daytona", "Neo4j", "Nosana"):
    status, detail = RESULTS[sponsor]
    mark = "PASS" if status == "PASS" else "FAIL"
    print(f"  [{mark}] {sponsor:<9} {detail}")
print()

failed = [k for k, (s, _) in RESULTS.items() if s == "FAIL"]
if failed:
    print(f"  {len(failed)} of 3 sponsors not yet wired: {', '.join(failed)}")
    print("  Sponsor integration is 1 of 4 judging criteria -- fix before building.\n")
    sys.exit(1)
print("  All three sponsors live. Judging criterion #4 is banked.\n")
