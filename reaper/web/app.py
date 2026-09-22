"""REAPER Web UI — FastAPI application."""
import asyncio
import uuid
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from ..db import Database, PROFILES, PROFILE_COLORS

app = FastAPI(title="REAPER", version="1.0.0", docs_url="/api/docs")
db = Database()
_executor = ThreadPoolExecutor(max_workers=4)

# In-memory job store: job_id -> {status, queue, result, session_id, module}
_jobs: dict[str, dict] = {}


# ── Request models ────────────────────────────────────────────────────────────

class SessionCreate(BaseModel):
    name: str
    target: str
    profile: str = "recon"


class ProfileUpdate(BaseModel):
    profile: str


class RunRequest(BaseModel):
    target: Optional[str] = None
    options: dict = {}
    timeout: Optional[int] = None


# ── Module registry ───────────────────────────────────────────────────────────

def _load_modules() -> dict:
    from ..modules.recon import (
        NmapModule, SubfinderModule, HttpxModule, TheHarvesterModule,
        TruffleHogModule, MasscanModule, KatanaModule, WaybackModule,
    )
    from ..modules.web import (
        NucleiModule, FfufModule, SqlmapModule, NiktoModule,
        DalfoxModule, WhatwebModule, CorsModule,
    )
    from ..modules.ad import (
        NetExecModule, KerbruteModule, BloodhoundModule, CertipyModule,
        ResponderModule, LinWinPwnModule,
    )
    from ..modules.post import (
        HashcatModule, HydraModule, LinpeasModule, PacuModule,
        ProwlerModule, LigoloModule,
    )
    all_modules = [
        NmapModule, SubfinderModule, HttpxModule, TheHarvesterModule,
        TruffleHogModule, MasscanModule, KatanaModule, WaybackModule,
        NucleiModule, FfufModule, SqlmapModule, NiktoModule,
        DalfoxModule, WhatwebModule, CorsModule,
        NetExecModule, KerbruteModule, BloodhoundModule, CertipyModule,
        ResponderModule, LinWinPwnModule,
        HashcatModule, HydraModule, LinpeasModule, PacuModule,
        ProwlerModule, LigoloModule,
    ]
    return {cls.name: cls for cls in all_modules}


_MODULE_REGISTRY = _load_modules()

_MODULE_CATEGORIES = {
    "recon": ["nmap", "masscan", "subfinder", "httpx", "theharvester", "trufflehog", "katana", "wayback"],
    "web": ["nuclei", "ffuf", "sqlmap", "nikto", "dalfox", "whatweb", "cors"],
    "ad": ["netexec", "kerbrute", "bloodhound", "certipy", "responder", "linwinpwn"],
    "post": ["hashcat", "hydra", "linpeas", "pacu", "prowler", "ligolo"],
}


# ── Session API ───────────────────────────────────────────────────────────────

@app.get("/api/sessions")
def list_sessions():
    sessions = db.list_sessions()
    active_id = db.get_active_session_id()
    for s in sessions:
        s["active"] = s["id"] == active_id
        s["findings_count"] = db.findings_count(s["id"])
    return sessions


@app.post("/api/sessions", status_code=201)
def create_session(body: SessionCreate):
    sid = db.create_session(body.name, body.target, body.profile)
    db.set_active_session(sid)
    return db.get_session(sid)


@app.get("/api/sessions/{session_id}")
def get_session(session_id: int):
    s = db.get_session(session_id)
    if not s:
        raise HTTPException(404, "Session not found")
    s["findings_count"] = db.findings_count(session_id)
    return s


@app.delete("/api/sessions/{session_id}", status_code=204)
def delete_session(session_id: int):
    if not db.get_session(session_id):
        raise HTTPException(404, "Session not found")
    db.delete_session(session_id)
    if db.get_active_session_id() == session_id:
        db.clear_active_session()


@app.post("/api/sessions/{session_id}/activate")
def activate_session(session_id: int):
    if not db.get_session(session_id):
        raise HTTPException(404, "Session not found")
    db.set_active_session(session_id)
    return {"ok": True}


@app.patch("/api/sessions/{session_id}/profile")
def update_profile(session_id: int, body: ProfileUpdate):
    if body.profile not in PROFILES:
        raise HTTPException(400, f"Invalid profile. Choose from: {PROFILES}")
    if not db.get_session(session_id):
        raise HTTPException(404, "Session not found")
    db.update_session_profile(session_id, body.profile)
    return db.get_session(session_id)


@app.get("/api/sessions/{session_id}/findings")
def get_findings(session_id: int, severity: Optional[str] = None):
    if not db.get_session(session_id):
        raise HTTPException(404, "Session not found")
    return db.get_findings(session_id, severity)


@app.get("/api/sessions/{session_id}/runs")
def get_runs(session_id: int):
    if not db.get_session(session_id):
        raise HTTPException(404, "Session not found")
    return db.get_module_runs(session_id)


@app.post("/api/sessions/{session_id}/report")
def generate_report(session_id: int, fmt: str = "html"):
    from ..report import generate_report as _gen
    if not db.get_session(session_id):
        raise HTTPException(404, "Session not found")
    path = _gen(db, session_id, fmt=fmt)
    return {"path": path, "format": fmt}


# ── Module API ────────────────────────────────────────────────────────────────

@app.get("/api/modules")
def list_modules():
    result = []
    for name, cls in _MODULE_REGISTRY.items():
        category = next(
            (cat for cat, names in _MODULE_CATEGORIES.items() if name in names), "other"
        )
        result.append({
            "name": name,
            "description": cls.description,
            "category": category,
            "timeout": cls.default_timeout,
        })
    result.sort(key=lambda x: (x["category"], x["name"]))
    return result


@app.post("/api/run/{module_name}")
async def run_module(module_name: str, body: RunRequest):
    if module_name not in _MODULE_REGISTRY:
        raise HTTPException(404, f"Module '{module_name}' not found")

    active = db.get_active_session()
    if not active:
        raise HTTPException(400, "No active session — create and activate one first")

    target = body.target or active["target"]
    session_id = active["id"]
    job_id = str(uuid.uuid4())

    loop = asyncio.get_event_loop()
    queue: asyncio.Queue = asyncio.Queue()
    _jobs[job_id] = {
        "status": "running",
        "queue": queue,
        "result": None,
        "session_id": session_id,
        "module": module_name,
        "target": target,
        "started_at": datetime.utcnow().isoformat(),
    }

    run_id = db.start_module_run(session_id, module_name)

    def _run_in_thread():
        mod_cls = _MODULE_REGISTRY[module_name]
        mod = mod_cls(db=db)
        if body.timeout:
            mod.default_timeout = body.timeout

        def on_line(line: str):
            loop.call_soon_threadsafe(queue.put_nowait, line)

        mod.set_output_callback(on_line)
        _jobs[job_id]["module_instance"] = mod

        try:
            try:
                result = mod.run(target, body.options)
            except Exception as exc:
                result_obj = type("R", (), {
                    "success": False, "findings": [], "raw_output": "",
                    "error": str(exc), "command": "",
                    "to_dict": lambda self: {"success": False, "error": str(exc), "findings": [], "raw_output": "", "command": ""},
                })()
                result = result_obj  # type: ignore

            db.complete_module_run(
                run_id,
                getattr(result, "raw_output", ""),
                getattr(result, "success", False),
                command=getattr(result, "command", ""),
            )

            for f in getattr(result, "findings", []):
                db.add_finding(
                    session_id=session_id,
                    module=module_name,
                    severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    title=f.title,
                    description=f.description,
                    evidence=f.evidence,
                    target=f.target or target,
                )

            _jobs[job_id]["status"] = "completed" if getattr(result, "success", False) else "failed"
            _jobs[job_id]["result"] = result.to_dict() if hasattr(result, "to_dict") else {}
        except Exception as exc:
            # A failure here (e.g. a locked/unavailable DB) must not leave the
            # job stuck "running" forever or the SSE client hanging on the
            # queue — always finalize status and push the sentinel.
            _jobs[job_id]["status"] = "failed"
            _jobs[job_id]["result"] = {"success": False, "error": str(exc), "findings": [], "raw_output": "", "command": ""}
        finally:
            loop.call_soon_threadsafe(queue.put_nowait, None)  # sentinel

    loop.run_in_executor(_executor, _run_in_thread)

    return {"job_id": job_id, "session_id": session_id, "module": module_name, "target": target}


@app.get("/api/jobs/{job_id}/stream")
async def stream_job(job_id: str):
    if job_id not in _jobs:
        raise HTTPException(404, "Job not found")

    async def event_generator():
        job = _jobs[job_id]
        q: asyncio.Queue = job["queue"]
        while True:
            try:
                item = await asyncio.wait_for(q.get(), timeout=120)
            except asyncio.TimeoutError:
                yield "data: [TIMEOUT]\n\n"
                break
            if item is None:
                result = job.get("result", {})
                yield f"data: [DONE] {json.dumps(result)}\n\n"
                break
            # Escape newlines for SSE format
            safe = item.replace("\r", "").replace("\n", "\\n")
            yield f"data: {safe}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/jobs/{job_id}/cancel")
def cancel_job(job_id: str):
    if job_id not in _jobs:
        raise HTTPException(404, "Job not found")
    job = _jobs[job_id]
    mod = job.get("module_instance")
    if mod is None:
        raise HTTPException(409, "Job has no running module instance to cancel")
    mod.cancel()
    return {"ok": True}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    if job_id not in _jobs:
        raise HTTPException(404, "Job not found")
    job = _jobs[job_id]
    return {
        "job_id": job_id,
        "status": job["status"],
        "module": job["module"],
        "target": job["target"],
        "started_at": job["started_at"],
        "result": job.get("result"),
    }


@app.get("/api/status")
def api_status():
    active = db.get_active_session()
    return {
        "active_session": active,
        "version": "1.0.0",
        "running_jobs": sum(1 for j in _jobs.values() if j["status"] == "running"),
    }


# ── HTML Dashboard ────────────────────────────────────────────────────────────

_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>REAPER</title>
<style>
:root{--bg:#0d1117;--surface:#161b22;--surface2:#21262d;--border:#30363d;
  --text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;--green:#3fb950;
  --critical:#ff3a3a;--high:#ff6b35;--medium:#ffd166;--low:#06d6a0;--info:#888}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);display:flex;flex-direction:column;min-height:100vh}
a{color:var(--accent);text-decoration:none}
button{cursor:pointer;border:none;border-radius:6px;padding:6px 14px;font-size:.85rem;font-weight:500;transition:opacity .15s}
button:hover{opacity:.85}
button:disabled{opacity:.4;cursor:not-allowed}
input,select,textarea{background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:6px 10px;font-size:.9rem;width:100%}
input:focus,select:focus,textarea:focus{outline:2px solid var(--accent);outline-offset:-1px}

/* Nav */
nav{background:var(--surface);border-bottom:1px solid var(--border);padding:12px 20px;display:flex;align-items:center;gap:16px}
.logo{font-size:1.3rem;font-weight:700;color:var(--critical);letter-spacing:.05em}
.logo span{color:var(--accent)}
nav select{max-width:260px;font-size:.85rem}
.nav-tabs{display:flex;gap:4px;margin-left:auto}
.tab-btn{background:transparent;color:var(--muted);border:1px solid transparent;padding:5px 14px;border-radius:6px}
.tab-btn.active{background:var(--surface2);color:var(--text);border-color:var(--border)}

/* Layout */
main{flex:1;padding:24px;max-width:1400px;width:100%;margin:0 auto}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px;margin-bottom:20px}
.panel h3{font-size:1rem;margin-bottom:14px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;font-weight:600}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.grid3{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.stat-card{background:var(--surface2);border-radius:8px;padding:16px;text-align:center}
.stat-card .n{font-size:2rem;font-weight:700}
.stat-card .l{font-size:.75rem;text-transform:uppercase;color:var(--muted);margin-top:4px}

/* Tables */
table{width:100%;border-collapse:collapse;font-size:.875rem}
th{text-align:left;padding:8px 10px;border-bottom:2px solid var(--border);color:var(--muted);font-size:.75rem;text-transform:uppercase}
td{padding:9px 10px;border-bottom:1px solid var(--border);vertical-align:top}
tr:hover td{background:#ffffff08}

/* Badges */
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.72rem;font-weight:600;text-transform:uppercase}
.badge-critical{background:var(--critical);color:#000}
.badge-high{background:var(--high);color:#000}
.badge-medium{background:var(--medium);color:#000}
.badge-low{background:var(--low);color:#000}
.badge-info{background:var(--info);color:#fff}
.badge-completed{background:#1e4620;color:var(--green)}
.badge-failed{background:#3d1010;color:var(--critical)}
.badge-running{background:#2d2810;color:var(--medium)}

/* Module cards */
.modules-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}
.mod-card{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px}
.mod-card h4{font-size:.9rem;margin-bottom:4px}
.mod-card p{font-size:.78rem;color:var(--muted);margin-bottom:10px;line-height:1.4}
.mod-card .cat{font-size:.7rem;text-transform:uppercase;color:var(--accent);margin-bottom:6px}
.btn-run{background:var(--accent);color:#000;font-weight:600}
.btn-danger{background:var(--critical);color:#fff}
.btn-secondary{background:var(--surface2);color:var(--text);border:1px solid var(--border)}

/* Terminal */
#terminal{background:#000;border:1px solid var(--border);border-radius:6px;padding:12px;font-family:'Courier New',monospace;font-size:.8rem;height:340px;overflow-y:auto;color:#7ee787;white-space:pre-wrap;word-break:break-all}
#terminal .err{color:#ff6b6b}
#terminal .inf{color:#888}

/* Forms */
.form-group{margin-bottom:12px}
label{font-size:.8rem;color:var(--muted);display:block;margin-bottom:4px}
.form-row{display:flex;gap:10px;align-items:flex-end}
.form-row .form-group{flex:1;margin:0}
</style>
</head>
<body>

<nav>
  <span class="logo">R<span>E</span>APER</span>
  <select id="sessionSelect" onchange="switchSession(this.value)" title="Active session"></select>
  <button class="btn-secondary" onclick="showModal('newSessionModal')" style="white-space:nowrap">+ Session</button>
  <div class="nav-tabs" id="navTabs">
    <button class="tab-btn active" onclick="showTab('dashboard')">Dashboard</button>
    <button class="tab-btn" onclick="showTab('modules')">Modules</button>
    <button class="tab-btn" onclick="showTab('findings')">Findings</button>
    <button class="tab-btn" onclick="showTab('reports')">Reports</button>
  </div>
</nav>

<main>
  <!-- Dashboard -->
  <div id="tab-dashboard">
    <div id="statusBanner" class="panel" style="display:none"></div>
    <div class="panel">
      <h3>Summary</h3>
      <div class="grid3" id="summaryCards"></div>
    </div>
    <div class="panel">
      <h3>Recent Module Runs</h3>
      <table id="runsTable">
        <thead><tr><th>Module</th><th>Status</th><th>Started</th><th>Command</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
  </div>

  <!-- Modules -->
  <div id="tab-modules" style="display:none">
    <div class="panel">
      <h3>Terminal Output</h3>
      <div id="terminal"><span class="inf">Ready. Click "Run" on any module below.</span></div>
      <div style="margin-top:10px;display:flex;gap:8px;align-items:center">
        <select id="targetOverride" style="max-width:300px" title="Override target (blank = session target)">
          <option value="">Use session target</option>
        </select>
        <button class="btn-danger" onclick="cancelJob()" id="btnCancel" style="display:none">■ Stop</button>
      </div>
    </div>
    <div class="modules-grid" id="moduleGrid"></div>
  </div>

  <!-- Findings -->
  <div id="tab-findings" style="display:none">
    <div class="panel">
      <h3>Findings</h3>
      <div style="display:flex;gap:10px;margin-bottom:14px">
        <select id="severityFilter" onchange="loadFindings()" style="max-width:160px">
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <button class="btn-secondary" onclick="loadFindings()">↻ Refresh</button>
      </div>
      <table id="findingsTable">
        <thead><tr><th>#</th><th>Sev</th><th>Module</th><th>Title</th><th>Target</th><th>Evidence</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
  </div>

  <!-- Reports -->
  <div id="tab-reports" style="display:none">
    <div class="panel">
      <h3>Generate Report</h3>
      <div style="display:flex;gap:10px;margin-bottom:14px;align-items:center">
        <select id="reportFmt" style="max-width:120px">
          <option value="html">HTML</option>
          <option value="md">Markdown</option>
          <option value="json">JSON</option>
        </select>
        <button class="btn-run" onclick="generateReport()">Generate</button>
      </div>
      <div id="reportResult"></div>
    </div>
  </div>
</main>

<!-- New Session Modal -->
<div id="newSessionModal" style="display:none;position:fixed;inset:0;background:#000a;z-index:100;display:flex;align-items:center;justify-content:center">
  <div style="background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:24px;min-width:380px;max-width:500px">
    <h3 style="margin-bottom:18px">New Session</h3>
    <div class="form-group"><label>Name</label><input id="ns_name" placeholder="corp-pentest-2025" /></div>
    <div class="form-group"><label>Target</label><input id="ns_target" placeholder="192.168.1.0/24  or  example.com" /></div>
    <div class="form-group"><label>Profile</label>
      <select id="ns_profile">
        <option>recon</option><option>web</option><option>ad</option>
        <option>internal</option><option>external</option><option>cloud</option>
      </select>
    </div>
    <div style="display:flex;gap:8px;margin-top:18px;justify-content:flex-end">
      <button class="btn-secondary" onclick="hideModal('newSessionModal')">Cancel</button>
      <button class="btn-run" onclick="createSession()">Create</button>
    </div>
  </div>
</div>

<script>
const API = '/api';
let activeSessionId = null;
let currentJob = null;
let currentEs = null;

// ── Utils ─────────────────────────────────────────────────────────────────────
async function api(path, opts={}) {
  const r = await fetch(API + path, {headers:{'Content-Type':'application/json'}, ...opts});
  if (!r.ok) { const e = await r.json().catch(()=>({detail:r.statusText})); throw new Error(e.detail||r.statusText); }
  if (r.status === 204) return null;
  return r.json();
}

function showModal(id) { document.getElementById(id).style.display='flex'; }
function hideModal(id) { document.getElementById(id).style.display='none'; }

function showTab(name) {
  ['dashboard','modules','findings','reports'].forEach(t => {
    document.getElementById('tab-'+t).style.display = t===name ? '' : 'none';
  });
  document.querySelectorAll('.tab-btn').forEach((b,i) => {
    b.classList.toggle('active', ['dashboard','modules','findings','reports'][i]===name);
  });
  if (name==='findings') loadFindings();
  if (name==='modules') loadModules();
}

function sevBadge(s) {
  return `<span class="badge badge-${s}">${s}</span>`;
}

function log(msg, type='') {
  const t = document.getElementById('terminal');
  const line = document.createElement('span');
  if (type) line.className = type;
  line.textContent = msg + '\n';
  t.appendChild(line);
  t.scrollTop = t.scrollHeight;
}

function clearTerminal() {
  document.getElementById('terminal').innerHTML = '';
}

// ── Sessions ──────────────────────────────────────────────────────────────────
async function loadSessions() {
  const sessions = await api('/sessions');
  const sel = document.getElementById('sessionSelect');
  sel.innerHTML = '<option value="">— no session —</option>';
  sessions.forEach(s => {
    const opt = document.createElement('option');
    opt.value = s.id;
    opt.textContent = `[${s.profile}] ${s.name} → ${s.target}`;
    if (s.active) { opt.selected = true; activeSessionId = s.id; }
    sel.appendChild(opt);
  });
  await refreshDashboard();
}

async function switchSession(id) {
  if (!id) return;
  await api(`/sessions/${id}/activate`, {method:'POST'});
  activeSessionId = parseInt(id);
  await refreshDashboard();
}

async function createSession() {
  const name = document.getElementById('ns_name').value.trim();
  const target = document.getElementById('ns_target').value.trim();
  const profile = document.getElementById('ns_profile').value;
  if (!name || !target) { alert('Name and target required'); return; }
  const s = await api('/sessions', {method:'POST', body: JSON.stringify({name, target, profile})});
  hideModal('newSessionModal');
  activeSessionId = s.id;
  await loadSessions();
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
async function refreshDashboard() {
  if (!activeSessionId) return;
  const s = await api(`/sessions/${activeSessionId}`);
  const runs = await api(`/sessions/${activeSessionId}/runs`);

  const banner = document.getElementById('statusBanner');
  const pc = {'internal':'#58a6ff','external':'#3fb950','cloud':'#79c0ff',
               'ad':'#ff7b72','web':'#d2a8ff','recon':'#e3b341'};
  const color = pc[s.profile] || '#888';
  banner.style.display = '';
  banner.innerHTML = `<div style="display:flex;gap:24px;flex-wrap:wrap;align-items:center">
    <div><span style="color:var(--muted);font-size:.8rem">SESSION</span><br><strong>${s.name}</strong></div>
    <div><span style="color:var(--muted);font-size:.8rem">TARGET</span><br><code style="color:var(--accent)">${s.target}</code></div>
    <div><span style="color:var(--muted);font-size:.8rem">PROFILE</span><br><strong style="color:${color}">${s.profile.toUpperCase()}</strong></div>
    <div><span style="color:var(--muted);font-size:.8rem">CREATED</span><br>${s.created_at.slice(0,10)}</div>
  </div>`;

  const counts = s.findings_count || {};
  const sevs = ['critical','high','medium','low','info'];
  const colors = {critical:'var(--critical)',high:'var(--high)',medium:'var(--medium)',low:'var(--low)',info:'var(--info)'};
  let cards = '';
  let total = 0;
  sevs.forEach(sv => {
    const n = counts[sv]||0; total+=n;
    cards += `<div class="stat-card"><div class="n" style="color:${colors[sv]}">${n}</div><div class="l">${sv}</div></div>`;
  });
  cards += `<div class="stat-card"><div class="n" style="color:var(--accent)">${total}</div><div class="l">Total</div></div>`;
  document.getElementById('summaryCards').innerHTML = cards;

  const tbody = document.querySelector('#runsTable tbody');
  tbody.innerHTML = runs.slice(0,20).map(r =>
    `<tr>
      <td><strong>${r.module_name}</strong></td>
      <td><span class="badge badge-${r.status}">${r.status}</span></td>
      <td>${r.started_at.slice(0,16)}</td>
      <td><code style="font-size:.75rem">${(r.command||'').slice(0,80)}</code></td>
    </tr>`
  ).join('');
}

// ── Modules ───────────────────────────────────────────────────────────────────
async function loadModules() {
  const mods = await api('/modules');
  const grid = document.getElementById('moduleGrid');
  const cats = {};
  mods.forEach(m => { (cats[m.category]||(cats[m.category]=[])).push(m); });

  let html = '';
  Object.entries(cats).forEach(([cat, items]) => {
    html += `<div style="grid-column:1/-1;margin-top:8px;font-size:.75rem;text-transform:uppercase;color:var(--muted);letter-spacing:.08em;font-weight:600">${cat}</div>`;
    items.forEach(m => {
      html += `<div class="mod-card">
        <div class="cat">${cat}</div>
        <h4>${m.name}</h4>
        <p>${m.description}</p>
        <button class="btn-run" onclick="runModule('${m.name}')">▶ Run</button>
      </div>`;
    });
  });
  grid.innerHTML = html;
}

async function runModule(name) {
  if (!activeSessionId) { alert('No active session'); return; }
  clearTerminal();
  log(`[*] Starting module: ${name}`, 'inf');

  const targetOvr = document.getElementById('targetOverride').value.trim();
  const body = { options: {} };
  if (targetOvr) body.target = targetOvr;

  let job;
  try {
    job = await api(`/run/${name}`, {method:'POST', body: JSON.stringify(body)});
  } catch(e) { log('[!] ' + e.message, 'err'); return; }

  currentJob = job.job_id;
  document.getElementById('btnCancel').style.display = '';
  log(`[*] Job: ${job.job_id} | Target: ${job.target}`, 'inf');

  if (currentEs) currentEs.close();
  const es = new EventSource(`${API}/jobs/${job.job_id}/stream`);
  currentEs = es;

  es.onmessage = (e) => {
    const data = e.data;
    if (data.startsWith('[DONE]')) {
      log('[+] Done', 'inf');
      es.close(); currentEs = null; currentJob = null;
      document.getElementById('btnCancel').style.display = 'none';
      refreshDashboard();
      return;
    }
    if (data === '[TIMEOUT]') { log('[!] Job timed out', 'err'); es.close(); return; }
    log(data.replace(/\\n/g, '\n'));
  };
  es.onerror = () => { log('[!] Stream error', 'err'); es.close(); };
}

async function cancelJob() {
  if (currentJob) {
    try { await api(`/jobs/${currentJob}/cancel`, {method:'POST'}); }
    catch(e) { log('[!] Cancel request failed: ' + e.message, 'err'); }
  }
  if (currentEs) { currentEs.close(); currentEs = null; }
  currentJob = null;
  document.getElementById('btnCancel').style.display = 'none';
  log('[!] Cancelled by user', 'err');
}

// ── Findings ──────────────────────────────────────────────────────────────────
async function loadFindings() {
  if (!activeSessionId) return;
  const sev = document.getElementById('severityFilter').value;
  const url = `/sessions/${activeSessionId}/findings` + (sev ? `?severity=${sev}` : '');
  const findings = await api(url);

  const tbody = document.querySelector('#findingsTable tbody');
  tbody.innerHTML = findings.map((f, i) =>
    `<tr>
      <td style="color:var(--muted)">${i+1}</td>
      <td>${sevBadge(f.severity)}</td>
      <td>${f.module}</td>
      <td>${f.title.slice(0,100)}</td>
      <td><code style="font-size:.75rem">${f.target.slice(0,50)}</code></td>
      <td><details><summary style="cursor:pointer;font-size:.75rem;color:var(--muted)">show</summary>
        <pre style="font-size:.72rem;white-space:pre-wrap;word-break:break-all;max-height:100px;overflow:auto">${(f.evidence||'').slice(0,400)}</pre>
      </details></td>
    </tr>`
  ).join('');
}

// ── Reports ───────────────────────────────────────────────────────────────────
async function generateReport() {
  if (!activeSessionId) { alert('No active session'); return; }
  const fmt = document.getElementById('reportFmt').value;
  const r = await api(`/sessions/${activeSessionId}/report?fmt=${fmt}`, {method:'POST'});
  document.getElementById('reportResult').innerHTML =
    `<div style="background:var(--surface2);border-radius:6px;padding:12px;font-family:monospace;color:var(--green)">
      ✓ Report saved: ${r.path}
    </div>`;
}

// ── Init ──────────────────────────────────────────────────────────────────────
loadSessions();
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return HTMLResponse(_DASHBOARD_HTML)
