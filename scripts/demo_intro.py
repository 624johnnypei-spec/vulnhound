#!/usr/bin/env python3
"""VulnHound demo intro server (port 3001).

An interactive landing page: type a target URL, hit "Run scan", watch a live
scan animation (sandboxes spinning up, agents probing, findings streaming),
then click through to the full results dashboard on http://localhost:3000.

    python scripts/demo_intro.py        # serves on http://localhost:3001

This is the DEMO front door — the animation is scripted so it's fast and
reliable on camera. The real results live on the :3000 dashboard.
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RESULTS_URL = "http://localhost:3000"

HTML = r"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>VulnHound - Is your app safe?</title>
<style>
:root{--paper:#f5f0e8;--card:#fffdf8;--ink:#1f2129;--muted:#6c7080;--line:#e8e1d3;
--danger:#e0403f;--warn:#e08a00;--safe:#1f9d5b;--brand:#ff5a3c;
--display:"Iowan Old Style","Palatino Linotype",Georgia,serif;
--sans:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;
--mono:ui-monospace,SFMono-Regular,Menlo,monospace;color-scheme:light}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:
radial-gradient(1200px 500px at 50% -10%,#fff 0,transparent 60%),var(--paper);
color:var(--ink);font-family:var(--sans);display:flex;flex-direction:column}
header{display:flex;align-items:center;justify-content:space-between;
padding:20px 30px;border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:10px;font-weight:800;font-size:20px;letter-spacing:-.4px}
.brand .m{width:30px;height:30px;border-radius:9px;background:var(--brand);display:grid;place-items:center;font-size:17px}
.brand b{color:var(--brand)}
.pills{display:flex;gap:7px;font:11px var(--mono);color:var(--muted);align-items:center}
.pill{display:inline-flex;align-items:center;gap:5px;padding:4px 9px;border:1px solid #bfe3cd;
border-radius:20px;background:#fff;color:#3a3d49}
.pill .d{width:7px;height:7px;border-radius:50%;background:var(--safe);box-shadow:0 0 0 3px #e5f4ea}
main{flex:1;display:grid;place-items:center;padding:30px}
.card{width:min(680px,92vw);background:var(--card);border:1px solid var(--line);
border-radius:20px;padding:44px;box-shadow:0 30px 60px -30px #0002}
.eyebrow{font:11px var(--mono);letter-spacing:1.5px;text-transform:uppercase;color:var(--brand);margin-bottom:14px}
h1{font-family:var(--display);font-size:clamp(30px,5vw,46px);line-height:1.08;letter-spacing:-.6px;margin:0 0 12px}
.sub{color:#3a3d49;font-size:17px;margin:0 0 26px;max-width:52ch}
.field{display:flex;gap:10px;margin-bottom:14px}
.field input{flex:1;border:1px solid var(--line);border-radius:12px;padding:15px 16px;
font-size:15px;font-family:var(--mono);background:#fff;color:var(--ink)}
.field input:focus{outline:2px solid var(--brand);outline-offset:1px}
.btn{background:var(--brand);color:#fff;font-weight:700;font-size:15px;border:0;cursor:pointer;
border-radius:12px;padding:15px 22px;white-space:nowrap;box-shadow:0 3px 0 #d8452c;display:flex;align-items:center;gap:9px}
.btn:hover{background:#ff6f54}.btn:disabled{opacity:.7;cursor:progress}
.hint{font-size:12px;color:var(--muted)}.hint b{color:#3a3d49}
.chips{display:flex;gap:8px;margin-top:16px;flex-wrap:wrap}
.chip{border:1px solid var(--line);background:#fff;border-radius:20px;padding:7px 12px;font-size:12px;cursor:pointer;color:#3a3d49}
.chip:hover{border-color:var(--brand);color:var(--brand)}
/* scan console */
.console{display:none}
.console.on{display:block;animation:rise .4s}
.bar{height:8px;border-radius:6px;background:#eee4d4;overflow:hidden;margin:4px 0 20px}
.bar>i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--brand),#ffb199);transition:width .5s}
.scanhead{display:flex;align-items:baseline;justify-content:space-between;margin-bottom:6px}
.scanhead h2{font-family:var(--display);font-size:24px;margin:0}
.count{font:12px var(--mono);color:var(--muted)}
.log{font:13px/1.9 var(--mono);background:#12161d;color:#d6e2ee;border-radius:14px;
padding:16px 18px;min-height:230px;max-height:230px;overflow:hidden}
.log .l{opacity:0;transform:translateY(6px);animation:in .3s forwards}
.log .l.ok{color:#8bd6b0}.log .l.hit{color:#ff9a8a}.log .l.dim{color:#7f8ea0}
.done{display:none;margin-top:22px;text-align:center}
.done.on{display:block;animation:rise .5s}
.verdict{font-family:var(--display);font-size:30px;color:var(--danger);margin:0 0 6px}
.done p{color:#3a3d49;margin:0 0 18px}
.big{font-size:16px;padding:16px 26px}
@keyframes in{to{opacity:1;transform:none}}
@keyframes rise{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
footer{padding:16px 30px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);
display:flex;gap:8px;align-items:center}
</style></head><body>
<header>
  <div class=brand><span class=m>&#128062;</span>Vuln<b>Hound</b></div>
  <div class=pills>Powered by
    <span class=pill><span class=d></span>Daytona</span>
    <span class=pill><span class=d></span>Neo4j</span>
    <span class=pill><span class=d></span>Nosana</span>
  </div>
</header>
<main><div class=card>
  <div id=intro>
    <div class=eyebrow>Autonomous security testing</div>
    <h1>Is your app safe?</h1>
    <p class=sub>Point VulnHound at your app. Our agents attack it like a real hacker would &mdash; inside an isolated sandbox &mdash; and show you the exact path to your data.</p>
    <div class=field>
      <input id=url value="https://coolstore.example" spellcheck=false>
      <button class=btn id=go>&#9658; Run security scan</button>
    </div>
    <div class=hint><b>Try it:</b> hit Run scan on the sample target, or paste your own.</div>
    <div class=chips>
      <span class=chip data-u="https://coolstore.example">CoolStore (shop)</span>
      <span class=chip data-u="https://quicksearch.example">QuickSearch</span>
      <span class=chip data-u="https://devportal.example">DevPortal</span>
    </div>
  </div>

  <div class=console id=console>
    <div class=scanhead><h2 id=phase>Starting scan&hellip;</h2><span class=count id=count>0 findings</span></div>
    <div class=bar><i id=fill></i></div>
    <div class=log id=log></div>
    <div class=done id=done>
      <p class=verdict>&#128308; We found a way in.</p>
      <p>An attacker could reach the customer database in 4 steps &mdash; and we found 6 issues total.</p>
      <a class="btn big" id=report href="__RESULTS__">See the full report &rarr;</a>
    </div>
  </div>
</div></main>
<footer>&#128274; VulnHound only tests an app you own, inside an isolated sandbox that is destroyed after the scan.</footer>

<script>
const $=s=>document.querySelector(s);
const STEPS=[
 ['dim','&#128274; Spinning up an isolated sandbox on Daytona&hellip;',6],
 ['dim','&#127760; Deploying a disposable copy of your app&hellip;',16],
 ['ok','&#9989; Target is live in the sandbox',24],
 ['dim','&#128269; Recon agent &mdash; mapping ports, pages and forms&hellip;',34],
 ['hit','&#9888; Open admin page found with no login required',44],
 ['dim','&#128137; Injection agent &mdash; probing forms&hellip;',56],
 ['hit','&#128293; SQL injection in the login form &mdash; auth bypassed',66],
 ['hit','&#128293; Product lookup is UNION-injectable &mdash; database dumped',74],
 ['dim','&#128273; Auth agent &mdash; testing access control&hellip;',82],
 ['hit','&#9888; IDOR &mdash; any customer invoice is readable',88],
 ['hit','&#128273; /.env exposed with live database credentials',93],
 ['dim','&#128376; Building the attack graph in Neo4j&hellip;',98],
 ['ok','&#9989; Scan complete &mdash; entry &rarr; database path confirmed',100],
];
function run(){
 $('#go').disabled=true; $('#intro').style.display='none'; $('#console').classList.add('on');
 const log=$('#log'); let hits=0; const phases=['Deploying target','Reconnaissance','Injection testing','Access-control testing','Building attack graph','Complete'];
 STEPS.forEach((s,i)=>setTimeout(()=>{
   const [cls,txt,pct]=s;
   const d=document.createElement('div'); d.className='l '+cls; d.innerHTML=txt; log.appendChild(d);
   while(log.children.length>8) log.removeChild(log.firstChild);
   $('#fill').style.width=pct+'%';
   if(cls==='hit'){hits++; $('#count').textContent=hits+' finding'+(hits>1?'s':'');}
   $('#phase').textContent = pct<20?'Deploying target&hellip;':pct<50?'Reconnaissance&hellip;':pct<80?'Probing for vulnerabilities&hellip;':pct<100?'Building attack graph&hellip;':'Scan complete';
   if(i===STEPS.length-1){ setTimeout(()=>{$('#phase').innerHTML='Scan complete'; $('#done').classList.add('on');},500); }
 }, 500 + i*750));
}
$('#go').addEventListener('click',run);
$('#url').addEventListener('keydown',e=>{if(e.key==='Enter')run();});
document.querySelectorAll('.chip').forEach(c=>c.addEventListener('click',()=>{$('#url').value=c.dataset.u;}));
</script></body></html>""".replace("__RESULTS__", RESULTS_URL)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        body = HTML.encode()
        self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 3001
    print(f"VulnHound demo intro on http://localhost:{port}  (results dashboard: {RESULTS_URL})")
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
