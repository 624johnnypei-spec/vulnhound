"""Offline check that the agent loop complies, returns clean JSON, and triages.

Feeds the agent canned tool output (no real scanning) to verify the LLM fix:
it should plan commands (not refuse), parse JSON, and record a finding.

    ./.venv/bin/python scripts/test_agent_loop.py
"""
import logging

from dotenv import load_dotenv

load_dotenv()

from src.agents.pentest_agent import run_agent

logging.basicConfig(level=logging.WARNING)

CANNED = {
    "nmap": "PORT     STATE SERVICE VERSION\n3000/tcp open  http    Node.js Express",
    "curl": "HTTP/1.1 200 OK\n<h3>Welcome, admin (admin)!</h3>",
    "sqlmap": ("[*] testing parameter 'username'\n"
               "[+] parameter 'username' is injectable (boolean-based blind)\n"
               "available databases: users, orders"),
    "whatweb": "http://target [200 OK] Express, Node.js",
    "gobuster": "/login (Status: 200)\n/search (Status: 200)",
}
calls: list[str] = []


def run_tool(command: str) -> dict:
    calls.append(command)
    tool = command.split()[0] if command.split() else ""
    return {"stdout": CANNED.get(tool, "no useful output"), "exit_code": 0, "ok": True}


def record(f: dict) -> None:
    print(f"  FINDING: {f.get('severity')} :: {f.get('type')} :: {str(f.get('evidence'))[:60]}")


if __name__ == "__main__":
    print("Running injection agent vs 127.0.0.1:3000 (max 3 steps)...")
    out = run_agent("injection", "127.0.0.1:3000", run_tool, record, max_steps=3)
    print("commands chosen by the model:", calls)
    print("findings produced:", len(out))
    print("RESULT:", "PASS — model complied and produced findings" if out
          else "FAIL — no findings (still refusing or JSON broken)")
