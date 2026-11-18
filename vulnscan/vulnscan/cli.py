"""Command line:  vulnscan scan <target>  |  vulnscan tools  |  vulnscan verify <host>  |  vulnscan serve"""
from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .config import get_settings
from .db import Store
from .models import LLMEndpoint, ScanRequest, TargetKind

app = typer.Typer(add_completion=False, help="VulnScan - one command, many scanners, one report.")
con = Console()
SEV_STYLE = {"critical": "bold white on red", "high": "bold red", "medium": "yellow", "low": "cyan", "info": "dim"}


@app.command()
def scan(target: str = typer.Argument(..., help="GitHub URL, path to .zip, or website URL"),
         profile: str = typer.Option("standard", help="quick | standard | full"),
         only: str = typer.Option("", help="comma-separated tool names to run"),
         skip: str = typer.Option("", help="comma-separated tool names to skip"),
         llm_endpoint: str = typer.Option("", help='chatbot endpoint JSON, e.g. \'{"url":"http://demo-chat:8090/chat"}\''),
         cloud: str = typer.Option("", help="aws | azure | gcp | kubernetes (Prowler)")):
    """Run a scan in the foreground and print where the report is."""
    from .pipeline import new_scan_id, run_scan
    s = get_settings()
    store = Store(s)
    kind = TargetKind.zip if target.lower().endswith(".zip") and Path(target).exists() else None
    req = ScanRequest(target=str(Path(target).resolve()) if kind else target, kind=kind, profile=profile,
                      only_tools=[t for t in only.split(",") if t], skip_tools=[t for t in skip.split(",") if t],
                      llm_endpoint=LLMEndpoint(**json.loads(llm_endpoint)) if llm_endpoint else None,
                      cloud_provider=cloud or None)
    scan_id = new_scan_id()
    from .ingest import detect_kind
    store.create(scan_id, target, (kind or detect_kind(target)).value, profile, req.model_dump_json())
    con.print(f"[bold]scan {scan_id}[/] → {target} ({profile})")
    result = run_scan(scan_id, req, s, store, echo=True)
    t = Table(title="Top findings")
    for col in ("severity", "title", "location", "tool"):
        t.add_column(col)
    for f in [x for x in result["findings"] if x["status"] == "open"][:25]:
        loc = f["location"]
        t.add_row(f"[{SEV_STYLE[f['severity']]}]{f['severity']}[/]", f["title"][:80],
                  str(loc.get("file") or loc.get("url") or loc.get("host") or loc.get("component") or "-")[:60],
                  ",".join(f["sources"]))
    con.print(t)
    con.print(f"counts: {result['summary']['counts']}")
    con.print(f"report: {s.scans_dir / scan_id / 'report.html'}")


@app.command()
def tools():
    """Show which scanners are installed."""
    from .pipeline import tool_available
    from .scanners import ALL_SCANNERS
    t = Table(title="Scanners")
    for col in ("tool", "installed", "min profile", "description"):
        t.add_column(col)
    for sc in ALL_SCANNERS:
        ok, why = tool_available(sc.name)
        t.add_row(sc.name, "[green]yes[/]" if ok else f"[red]no[/] {why}", sc.min_profile, sc.description)
    con.print(t)


@app.command()
def verify(host: str):
    """Prove ownership of a host (DNS TXT or /.well-known file) so it can be scanned."""
    from .scope import verification_instructions, verify_ownership
    if verify_ownership(host):
        con.print(f"[green]{host} verified[/]")
    else:
        info = verification_instructions(host)
        con.print(f"[yellow]{host} not verified yet.[/] Do one of:")
        for o in info["options"]:
            con.print(f"  • {o}")


@app.command()
def serve(host: str = "0.0.0.0", port: int = 8000, reload: bool = False):  # nosec B104 - container binds all interfaces by design
    """Start the API + web UI."""
    import uvicorn
    uvicorn.run("vulnscan.api:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    app()
