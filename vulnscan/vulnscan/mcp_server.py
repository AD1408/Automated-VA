"""VulnScan MCP server (stdio).

Lets an AI assistant (VS Code Copilot Chat, Claude Desktop/Code, Cursor...) start scans, read findings and
fetch reports, plus run single tools. Every network tool goes through the same scope check as the
pipeline, so the assistant cannot scan hosts you have not allowed or verified.

Also fills the gaps where no official MCP server exists: gitleaks and modelscan.

Run inside the API container:  docker exec -i vulnscan-api python -m vulnscan.mcp_server
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import httpx
try:  # mcp >= 2
    from mcp.server.mcpserver import MCPServer as FastMCP
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP

from .config import get_settings
from .scope import ScopeError, ensure_in_scope

API = os.environ.get("VULNSCAN_API_URL", "http://localhost:8000")
settings = get_settings()
mcp = FastMCP("vulnscan")
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _api(method: str, path: str, **kw):
    headers = {"X-API-Key": settings.vulnscan_api_key} if settings.vulnscan_api_key else {}
    r = httpx.request(method, API + path, headers=headers, timeout=60, **kw)
    if r.status_code >= 400:
        return {"error": r.status_code, "detail": r.json() if "json" in r.headers.get("content-type", "") else r.text}
    return r.json()


@mcp.tool()
def start_scan(target: str, profile: str = "standard", llm_endpoint_url: str = "") -> dict:
    """Start a scan. target = GitHub repo URL or website URL. profile = quick|standard|full.
    llm_endpoint_url = optional chatbot endpoint (expects {"message": ...} -> {"reply": ...})."""
    body = {"target": target, "profile": profile}
    if llm_endpoint_url:
        body["llm_endpoint"] = {"url": llm_endpoint_url}
    return _api("POST", "/api/scans", json=body)


@mcp.tool()
def scan_status(scan_id: str) -> dict:
    """Current stage, per-tool status and live severity counts of a scan."""
    d = _api("GET", f"/api/scans/{scan_id}")
    if "progress" in d:
        p = d["progress"]
        d["progress"] = {"stage": p.get("stage"), "counts": p.get("counts"),
                         "tools": {k: v.get("status") for k, v in p.get("tools", {}).items()},
                         "last_logs": [l["msg"] for l in p.get("logs", [])[-8:]]}
    return d


@mcp.tool()
def list_scans() -> dict:
    """List previous scans with status and summary counts."""
    return _api("GET", "/api/scans")


@mcp.tool()
def get_findings(scan_id: str, min_severity: str = "medium", owasp: str = "", limit: int = 30) -> list[dict]:
    """Findings of a finished scan, highest risk first. Filter by min_severity and an OWASP id (e.g. A05 or LLM01)."""
    res = _api("GET", f"/api/scans/{scan_id}/result")
    if "findings" not in res:
        return [res]
    out = []
    for f in res["findings"]:
        if SEV_RANK[f["severity"]] < SEV_RANK.get(min_severity, 0) or f["status"] != "open":
            continue
        if owasp and not any(o.startswith(owasp.upper()) for o in f["owasp"] + f["owasp_llm"]):
            continue
        out.append({k: f[k] for k in ("id", "title", "severity", "confidence", "location", "owasp", "owasp_llm",
                                      "cwe", "cve", "sources", "remediation")})
        if len(out) >= limit:
            break
    return out


@mcp.tool()
def get_report(scan_id: str) -> dict:
    """Executive summary, counts and download links for the HTML/PDF/JSON/SARIF report."""
    res = _api("GET", f"/api/scans/{scan_id}/result")
    if "summary" not in res:
        return res
    links = {fmt: f"{API}/api/scans/{scan_id}/report.{fmt}" for fmt in ("html", "pdf", "json", "sarif")}
    return {"summary": res["summary"], "coverage": {k: v["findings"] for k, v in res["coverage"].items()}, "links": links}


@mcp.tool()
def explain_finding(scan_id: str, finding_id: str, question: str = "Explain this and show how to fix it.") -> dict:
    """Ask the configured LLM (with the security knowledge base) about one finding."""
    return _api("POST", f"/api/scans/{scan_id}/findings/{finding_id}/ask", json={"question": question})


@mcp.tool()
def check_scope(target: str) -> dict:
    """Is this host allowed to be scanned? Returns verification instructions if not."""
    return _api("POST", "/api/scope/check", json={"target": target})


# ---------------- single-tool runs (scope-checked) ------------------------------------------------
def _single(tool: str, target: str, profile: str = "quick") -> dict:
    """Runs one scanner through the normal pipeline so results are normalised + scope-checked."""
    try:
        if "://" in target or "." in target and not Path(target).exists():
            ensure_in_scope(target, settings)
    except ScopeError as e:
        return {"error": str(e)}
    return _api("POST", "/api/scans", json={"target": target, "profile": profile, "only_tools": [tool]})


@mcp.tool()
def run_nmap(target: str) -> dict:
    """Port + service scan with CVE lookup (only on in-scope hosts). Returns a scan id; poll scan_status."""
    return _single("nmap", target)


@mcp.tool()
def run_nuclei(url: str) -> dict:
    """Nuclei template scan of an in-scope URL. Returns a scan id."""
    return _single("nuclei", url)


@mcp.tool()
def run_nikto(url: str) -> dict:
    """Nikto web-server scan of an in-scope URL. Returns a scan id."""
    return _single("nikto", url, "standard")


@mcp.tool()
def run_sqlmap(url: str) -> dict:
    """SQL-injection detection (no data extraction) on an in-scope URL, after a ZAP crawl. Returns a scan id."""
    return _api("POST", "/api/scans", json={"target": url, "profile": "standard", "only_tools": ["zap", "sqlmap"]})


@mcp.tool()
def run_gitleaks(repo_url: str) -> dict:
    """Secret scan of a git repository (code + history). Returns a scan id."""
    return _api("POST", "/api/scans", json={"target": repo_url, "profile": "quick", "only_tools": ["gitleaks"]})


@mcp.tool()
def run_modelscan(repo_url: str) -> dict:
    """Scan ML model files in a repository for code-execution payloads (pickle etc.). Returns a scan id."""
    return _api("POST", "/api/scans", json={"target": repo_url, "profile": "quick", "only_tools": ["modelscan"]})


@mcp.tool()
def classify_prompt_injection(text: str) -> dict:
    """Score text with Llama Prompt Guard 2 (0 = benign, 1 = prompt injection / jailbreak)."""
    from .scanners.ai import injection_scores
    try:
        score = injection_scores([text[:4000]], settings)[0]
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}
    return {"score": round(score, 4), "malicious": score >= settings.prompt_guard_threshold}


if __name__ == "__main__":
    tempfile.tempdir = str(settings.data_dir)
    mcp.run()
