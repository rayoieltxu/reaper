"""REAPER CLI — Click + Rich."""
import re
import sys
import json as _json

# Force UTF-8 output on Windows so Rich can render box-drawing and Unicode
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except AttributeError:
        pass

import click
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .db import Database, PROFILES, PROFILE_COLORS

console = Console(legacy_windows=False)
db = Database()

_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "white",
}


def _abort(msg: str):
    console.print(f"[red][!] {msg}[/red]")
    sys.exit(1)


def _require_session() -> dict:
    s = db.get_active_session()
    if not s:
        _abort("No active session. Use `reaper session new <name> <target>` first.")
    return s  # type: ignore[return-value]


def _save_findings(result, session_id: int, module_name: str, default_target: str):
    for f in result.findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        db.add_finding(
            session_id=session_id,
            module=module_name,
            severity=sev,
            title=f.title,
            description=f.description,
            evidence=f.evidence,
            target=f.target or default_target,
        )


def _load_module_registry() -> dict:
    from .modules.recon import (
        NmapModule, SubfinderModule, HttpxModule, TheHarvesterModule,
        TruffleHogModule, MasscanModule, KatanaModule, WaybackModule,
    )
    from .modules.web import (
        NucleiModule, FfufModule, SqlmapModule, NiktoModule,
        DalfoxModule, WhatwebModule, CorsModule,
    )
    from .modules.ad import (
        NetExecModule, KerbruteModule, BloodhoundModule, CertipyModule,
        ResponderModule, LinWinPwnModule,
    )
    from .modules.post import (
        HashcatModule, HydraModule, LinpeasModule, PacuModule,
        ProwlerModule, LigoloModule,
    )
    all_cls = [
        NmapModule, SubfinderModule, HttpxModule, TheHarvesterModule,
        TruffleHogModule, MasscanModule, KatanaModule, WaybackModule,
        NucleiModule, FfufModule, SqlmapModule, NiktoModule,
        DalfoxModule, WhatwebModule, CorsModule,
        NetExecModule, KerbruteModule, BloodhoundModule, CertipyModule,
        ResponderModule, LinWinPwnModule,
        HashcatModule, HydraModule, LinpeasModule, PacuModule,
        ProwlerModule, LigoloModule,
    ]
    return {cls.name: cls for cls in all_cls}


# ── AUTO-RUN PLAN ─────────────────────────────────────────────────────────────

_AUTO_PLANS: dict[str, dict[str, list[str]]] = {
    "recon": {
        "ip":       ["nmap", "httpx", "nuclei"],
        "cidr":     ["masscan", "nmap", "httpx"],
        "domain":   ["subfinder", "httpx", "whatweb", "wayback", "theharvester"],
        "url":      ["whatweb", "httpx", "wayback", "nuclei", "cors"],
        "hostname": ["nmap", "httpx", "nuclei"],
    },
    "web": {
        "ip":       ["nmap", "httpx", "whatweb", "nuclei", "nikto", "cors"],
        "cidr":     ["masscan", "httpx", "nuclei"],
        "domain":   ["subfinder", "httpx", "whatweb", "nuclei", "cors", "wayback"],
        "url":      ["whatweb", "httpx", "nuclei", "nikto", "dalfox", "ffuf", "cors"],
        "hostname": ["nmap", "httpx", "whatweb", "nuclei", "nikto"],
    },
    "ad": {
        "ip":       ["nmap", "netexec", "kerbrute", "bloodhound"],
        "cidr":     ["masscan", "nmap", "netexec"],
        "domain":   ["nmap", "kerbrute", "bloodhound", "certipy"],
        "hostname": ["nmap", "netexec", "kerbrute"],
    },
    "cloud": {
        "domain":   ["subfinder", "httpx", "nuclei", "prowler"],
        "url":      ["httpx", "nuclei", "prowler", "pacu"],
        "ip":       ["nmap", "httpx", "nuclei"],
    },
    "internal": {
        "ip":       ["nmap", "netexec", "nuclei"],
        "cidr":     ["masscan", "nmap", "netexec", "nuclei"],
        "domain":   ["nmap", "subfinder", "httpx", "netexec", "kerbrute"],
        "hostname": ["nmap", "netexec"],
    },
    "external": {
        "domain":   ["subfinder", "theharvester", "httpx", "whatweb", "nuclei", "wayback"],
        "ip":       ["nmap", "httpx", "nuclei"],
        "cidr":     ["masscan", "nmap", "httpx"],
        "url":      ["whatweb", "httpx", "nuclei", "cors", "dalfox"],
    },
}

_DEFAULT_PLAN = ["nmap", "httpx", "nuclei"]


def _detect_target_type(target: str) -> str:
    t = target.strip()
    if re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", t):
        return "cidr"
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", t):
        return "ip"
    if t.startswith(("http://", "https://")):
        return "url"
    if "." in t and not re.match(r"^[\d.]+$", t):
        return "domain"
    return "hostname"


# ══════════════════════════════════════════════════════════════════════════════
# CLI Groups
# ══════════════════════════════════════════════════════════════════════════════

@click.group()
@click.version_option(version="1.0.0", prog_name="REAPER")
def cli():
    """REAPER — Red team Enumeration And Pentesting Enhanced Resource

    \b
    Quick start:
      reaper session new corp 192.168.1.0/24
      reaper run auto
      reaper findings
      reaper report
    """
    pass


# ── session ───────────────────────────────────────────────────────────────────

@cli.group()
def session():
    """Manage pentest sessions (create, list, switch, delete, profile)."""
    pass


@session.command("new")
@click.argument("name")
@click.argument("target")
@click.option("--profile", "-p", default="recon", type=click.Choice(PROFILES),
              show_default=True, help="Session profile")
def session_new(name: str, target: str, profile: str):
    """Create a new session for TARGET and make it active."""
    sid = db.create_session(name, target, profile)
    db.set_active_session(sid)
    color = PROFILE_COLORS.get(profile, "white")
    console.print(
        Panel(
            f"Session [bold]{name}[/bold] (id=[cyan]{sid}[/cyan]) created - now active\n"
            f"Target  : [cyan]{target}[/cyan]\n"
            f"Profile : [{color}]{profile}[/{color}]",
            title="[bold green][+] Session Created[/bold green]",
            border_style="green",
        )
    )


@session.command("list")
def session_list():
    """List all sessions."""
    sessions = db.list_sessions()
    if not sessions:
        console.print("[yellow]No sessions yet. Run: reaper session new <name> <target>[/yellow]")
        return

    active_id = db.get_active_session_id()
    t = Table(box=box.ROUNDED, border_style="dim", header_style="bold magenta", show_header=True)
    t.add_column("ID", width=5, style="dim")
    t.add_column("Name", min_width=10)
    t.add_column("Target", min_width=18, overflow="fold")
    t.add_column("Profile", width=10)
    t.add_column("Finds", width=7)
    t.add_column("Created", width=12)
    t.add_column("", width=3)

    for s in sessions:
        counts = db.findings_count(s["id"])
        total = sum(counts.values())
        color = PROFILE_COLORS.get(s["profile"], "white")
        active_mark = "[bold green]>[/bold green]" if s["id"] == active_id else ""
        t.add_row(
            str(s["id"]),
            f"{'[bold]' if s['id'] == active_id else ''}{s['name']}{'[/bold]' if s['id'] == active_id else ''}",
            s["target"],
            f"[{color}]{s['profile']}[/{color}]",
            str(total),
            s["created_at"][:10],
            active_mark,
        )
    console.print(t)


@session.command("use")
@click.argument("session_id", type=int)
def session_use(session_id: int):
    """Switch to SESSION_ID as the active session."""
    s = db.get_session(session_id)
    if not s:
        _abort(f"Session {session_id} not found")
    db.set_active_session(session_id)
    color = PROFILE_COLORS.get(s["profile"], "white")
    console.print(
        f"[green][+] Active → [bold]{s['name']}[/bold] "
        f"({s['target']}) [[{color}]{s['profile']}[/{color}]][/green]"
    )


@session.command("delete")
@click.argument("session_id", type=int)
@click.option("--yes", is_flag=True, help="Skip confirmation prompt")
def session_delete(session_id: int, yes: bool):
    """Delete a session and all its data."""
    s = db.get_session(session_id)
    if not s:
        _abort(f"Session {session_id} not found")
    if not yes:
        click.confirm(
            f"Delete session '{s['name']}' and ALL its findings/runs?",
            default=False,
            abort=True,
        )
    db.delete_session(session_id)
    if db.get_active_session_id() == session_id:
        db.clear_active_session()
    console.print(f"[green][+] Session {session_id} deleted[/green]")


@session.command("profile")
@click.argument("name")
@click.argument("profile_type", metavar="PROFILE", type=click.Choice(PROFILES))
def session_profile(name: str, profile_type: str):
    """Assign PROFILE to the session named NAME."""
    sessions = db.list_sessions()
    matches = [s for s in sessions if s["name"] == name]
    if not matches:
        _abort(f"Session named '{name}' not found — check `reaper session list`")
    s = matches[0]
    db.update_session_profile(s["id"], profile_type)
    color = PROFILE_COLORS.get(profile_type, "white")
    console.print(
        f"[green][+] Session [bold]{name}[/bold] profile → [{color}]{profile_type}[/{color}][/green]"
    )


# ── status ────────────────────────────────────────────────────────────────────

@cli.command()
def status():
    """Show the active session and finding summary."""
    s = db.get_active_session()
    if not s:
        console.print(
            Panel(
                "[yellow]No active session[/yellow]\n"
                "Run [bold]reaper session new <name> <target>[/bold] to get started.",
                title="REAPER Status",
            )
        )
        return

    profile = s.get("profile", "recon")
    color = PROFILE_COLORS.get(profile, "white")
    counts = db.findings_count(s["id"])
    runs = db.get_module_runs(s["id"])

    grid = Table.grid(padding=(0, 1))
    grid.add_column(style="dim", min_width=14)
    grid.add_column()

    grid.add_row("Session:", f"[bold]{s['name']}[/bold]  [dim](id={s['id']})[/dim]")
    grid.add_row("Target:", f"[cyan]{s['target']}[/cyan]")
    grid.add_row("Profile:", f"[{color}]{profile}[/{color}]")
    grid.add_row("Created:", s["created_at"][:19].replace("T", " ") + " UTC")
    grid.add_row("Module runs:", str(len(runs)))

    sev_parts = []
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in counts:
            sty = _SEVERITY_STYLE.get(sev, "white")
            sev_parts.append(f"[{sty}]{counts[sev]} {sev}[/{sty}]")
    grid.add_row("Findings:", " · ".join(sev_parts) if sev_parts else "[dim]none yet[/dim]")

    console.print(
        Panel(grid, title="[bold green]REAPER[/bold green] Status", border_style="green")
    )


# ── findings ──────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--severity", "-s", default=None, metavar="SEV",
              type=click.Choice(["critical", "high", "medium", "low", "info"]))
@click.option("--module", "-m", default=None, help="Filter by module name")
@click.option("--evidence", "-e", is_flag=True, help="Show evidence column")
def findings(severity: str, module: str, evidence: bool):
    """List findings for the active session."""
    s = _require_session()
    rows = db.get_findings(s["id"], severity)
    if module:
        rows = [r for r in rows if r["module"] == module]
    if not rows:
        console.print("[yellow]No findings match the filter[/yellow]")
        return

    t = Table(box=box.ROUNDED, header_style="bold blue", show_header=True)
    t.add_column("ID", width=5, style="dim")
    t.add_column("Severity", width=10)
    t.add_column("Module", width=12)
    t.add_column("Title")
    t.add_column("Target")
    if evidence:
        t.add_column("Evidence")

    for r in rows:
        sty = _SEVERITY_STYLE.get(r["severity"], "white")
        row = [
            str(r["id"]),
            f"[{sty}]{r['severity'].upper()}[/{sty}]",
            r["module"],
            r["title"][:90],
            r["target"][:50],
        ]
        if evidence:
            row.append(r["evidence"][:80])
        t.add_row(*row)
    console.print(t)


# ── run ───────────────────────────────────────────────────────────────────────

@cli.command("run")
@click.argument("module_or_action")
@click.option("--target", "-t", default=None, metavar="TARGET",
              help="Override session target")
@click.option("--timeout", default=None, type=int, metavar="SECS",
              help="Override module timeout")
@click.option("--opts", "-o", default="{}", metavar="JSON",
              help="Module options as JSON, e.g. '{\"ports\":\"80,443\"}'")
@click.option("--profile", "-p", default=None, type=click.Choice(PROFILES),
              help="(auto only) Override session profile for module selection")
@click.option("--dry-run", is_flag=True,
              help="(auto only) Print planned modules without running them")
def run_cmd(module_or_action: str, target: str, timeout: int, opts: str, profile: str, dry_run: bool):
    """Run a MODULE by name, or use 'auto' / 'list' as special actions.

    \b
    Examples:
      reaper run nmap
      reaper run nmap --target 10.0.0.1 --opts '{"ports":"80,443,8080"}'
      reaper run cors --target https://example.com
      reaper run auto
      reaper run auto --profile web
      reaper run list
    """
    if module_or_action == "list":
        _run_list()
        return
    if module_or_action == "auto":
        _run_auto(target=target, profile=profile, dry_run=dry_run)
        return

    # ── run a specific module ──────────────────────────────────────────────
    s = _require_session()
    registry = _load_module_registry()

    if module_or_action not in registry:
        console.print(f"[red][!] Unknown module or action: '{module_or_action}'[/red]")
        console.print(f"    Run [bold]reaper run list[/bold] to see all modules.")
        sys.exit(1)

    try:
        options = _json.loads(opts)
    except _json.JSONDecodeError as exc:
        _abort(f"Invalid JSON in --opts: {exc}")

    t_val = target or s["target"]
    mod_cls = registry[module_or_action]
    mod = mod_cls(db=db)
    if timeout:
        mod.default_timeout = timeout

    run_id = db.start_module_run(s["id"], module_or_action)

    console.print(
        Panel(
            f"Module : [bold green]{module_or_action}[/bold green]\n"
            f"Target : [cyan]{t_val}[/cyan]\n"
            f"Timeout: [yellow]{mod.default_timeout}s[/yellow]",
            title="Running",
            border_style="dim",
        )
    )

    buf: list[str] = []

    def on_output(line: str):
        buf.append(line)
        console.print(f"  {line}")

    mod.set_output_callback(on_output)

    try:
        result = mod.run(t_val, options)
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Interrupted[/yellow]")
        db.complete_module_run(run_id, "\n".join(buf), success=False)
        return
    except Exception as exc:
        console.print(f"[red][!] Module crashed: {exc}[/red]")
        db.complete_module_run(run_id, str(exc), success=False)
        sys.exit(1)

    db.complete_module_run(run_id, result.raw_output, success=result.success)
    _save_findings(result, s["id"], module_or_action, t_val)

    if result.findings:
        ft = Table(box=box.SIMPLE, header_style="bold", show_header=True)
        ft.add_column("Severity", width=10)
        ft.add_column("Finding")
        for f in result.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            sty = _SEVERITY_STYLE.get(sev, "white")
            ft.add_row(f"[{sty}]{sev.upper()}[/{sty}]", f.title[:100])
        console.print(ft)

    status_icon = "[green][OK][/green]" if result.success else "[red][FAIL][/red]"
    console.print(f"\n{status_icon} {len(result.findings)} finding(s) saved")
    if result.error:
        console.print(f"[red]  Error: {result.error}[/red]")


def _run_list():
    registry = _load_module_registry()
    from .modules.web import CorsModule  # representative

    categories = {
        "recon":  ["nmap", "masscan", "subfinder", "httpx", "theharvester", "trufflehog", "katana", "wayback"],
        "web":    ["nuclei", "ffuf", "sqlmap", "nikto", "dalfox", "whatweb", "cors"],
        "ad":     ["netexec", "kerbrute", "bloodhound", "certipy", "responder", "linwinpwn"],
        "post":   ["hashcat", "hydra", "linpeas", "pacu", "prowler", "ligolo"],
    }
    cat_colors = {"recon": "yellow", "web": "magenta", "ad": "red", "post": "cyan"}

    t = Table(box=box.ROUNDED, header_style="bold blue", show_header=True)
    t.add_column("Category", width=10)
    t.add_column("Module", width=14, style="bold green")
    t.add_column("Description")
    t.add_column("Timeout", width=9, justify="right", style="dim")

    for cat, names in categories.items():
        cc = cat_colors.get(cat, "white")
        for name in names:
            cls = registry.get(name)
            if cls:
                t.add_row(
                    f"[{cc}]{cat}[/{cc}]",
                    name,
                    cls.description,
                    f"{cls.default_timeout}s",
                )

    console.print(t)


def _run_auto(target: str = None, profile: str = None, dry_run: bool = False):
    s = _require_session()
    t_val = target or s["target"]
    p_val = profile or s.get("profile", "recon")
    t_type = _detect_target_type(t_val)

    profile_plans = _AUTO_PLANS.get(p_val, {})
    planned = profile_plans.get(t_type, _DEFAULT_PLAN)

    console.print(
        Panel(
            f"Target  : [cyan]{t_val}[/cyan]\n"
            f"Type    : [yellow]{t_type}[/yellow]\n"
            f"Profile : [green]{p_val}[/green]\n"
            f"Modules : [bold]{' → '.join(planned)}[/bold]",
            title="[bold]REAPER Auto-Run Plan[/bold]",
            border_style="green",
        )
    )

    if dry_run:
        console.print("[yellow][~] Dry run — no modules executed[/yellow]")
        return

    registry = _load_module_registry()
    total = len(planned)

    for i, mod_name in enumerate(planned, 1):
        if mod_name not in registry:
            console.print(f"[yellow][!] Module '{mod_name}' not in registry — skipping[/yellow]")
            continue

        console.rule(f"[bold cyan][{i}/{total}] {mod_name}[/bold cyan]")

        run_id = db.start_module_run(s["id"], mod_name)
        mod = registry[mod_name](db=db)
        buf: list[str] = []

        def on_output(line: str, _b=buf):
            _b.append(line)
            console.print(f"  {line}")

        mod.set_output_callback(on_output)

        try:
            result = mod.run(t_val, {})
        except KeyboardInterrupt:
            console.print("\n[yellow][!] Auto-run interrupted[/yellow]")
            db.complete_module_run(run_id, "\n".join(buf), success=False)
            break
        except Exception as exc:
            console.print(f"[red][!] {mod_name} error: {exc}[/red]")
            db.complete_module_run(run_id, str(exc), success=False)
            continue

        db.complete_module_run(run_id, result.raw_output, success=result.success)
        _save_findings(result, s["id"], mod_name, t_val)
        console.print(f"  → [green]{len(result.findings)} finding(s)[/green]")

    console.print("")
    console.rule("[bold green]Auto-run complete[/bold green]")
    counts = db.findings_count(s["id"])
    if counts:
        parts = [
            f"[{_SEVERITY_STYLE.get(k,'white')}]{v} {k}[/{_SEVERITY_STYLE.get(k,'white')}]"
            for k, v in counts.items()
        ]
        console.print("Findings: " + " · ".join(parts))
    console.print(f"\nView with: [bold]reaper findings[/bold]")
    console.print(f"Report  : [bold]reaper report[/bold]")


# ── report ────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--format", "-f", "fmt", default="html",
              type=click.Choice(["html", "md", "json"]), show_default=True)
@click.option("--output", "-o", default=None, metavar="FILE",
              help="Output file path (auto-named if omitted)")
def report(fmt: str, output: str):
    """Generate a pentest report for the active session."""
    from .report import generate_report
    s = _require_session()
    path = generate_report(db, s["id"], fmt=fmt, output_path=output)
    console.print(f"[green][+] Report → [bold]{path}[/bold][/green]")


# ── web ───────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", "-p", default=8080, type=int, show_default=True)
@click.option("--reload", is_flag=True, help="Enable auto-reload (dev mode)")
def web(host: str, port: int, reload: bool):
    """Start the REAPER Web UI (FastAPI + Dashboard)."""
    import uvicorn
    console.print(
        Panel(
            f"[bold]REAPER Web UI[/bold]\n"
            f"Dashboard: [link=http://{host}:{port}]http://{host}:{port}[/link]\n"
            f"API docs : [link=http://{host}:{port}/api/docs]http://{host}:{port}/api/docs[/link]",
            border_style="green",
        )
    )
    uvicorn.run(
        "reaper.web.app:app",
        host=host,
        port=port,
        reload=reload,
        log_level="warning",
    )
