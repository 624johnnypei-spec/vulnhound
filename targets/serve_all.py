#!/usr/bin/env python3
"""Run all three demo targets at once (for local testing / a live demo).

    python targets/serve_all.py
      A · SQL injection      http://127.0.0.1:8100
      B · reflected XSS      http://127.0.0.1:8101
      C · file exposure      http://127.0.0.1:8102
"""
import runpy, sys, threading
for mod, port in (("site_a_sqli", 8100), ("site_b_xss", 8101), ("site_c_exposure", 8102)):
    t = threading.Thread(target=lambda m=mod, p=port: (sys.argv.__setitem__(slice(None), [m, str(p)]),
                                                       runpy.run_module("targets." + m, run_name="__main__")),
                         daemon=True)
    t.start()
print("Targets A/B/C serving on 8100/8101/8102 — Ctrl+C to stop.")
try:
    threading.Event().wait()
except KeyboardInterrupt:
    pass
