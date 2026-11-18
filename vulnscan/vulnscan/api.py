"""REST API + serves the web UI.  Run: uvicorn vulnscan.api:app --reload"""
from __future__ import annotations

import json
import os
import re
import shutil
import threading
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import __version__
from .config import get_settings
from .db import Store
from .ingest import detect_kind
from .llm import LLM, LLMError
from .models import LLMEndpoint, ScanRequest, TargetKind
from .owasp import OWASP_LLM_TOP10, OWASP_TOP10
from .pipeline import new_scan_id, normalise_url, run_scan, tool_available
from .rag import get_kb
from .scanners import ALL_SCANNERS, CATEGORY
from .scope import ScopeError, ensure_in_scope, host_of, verification_instructions, verify_ownership

settings = get_settings()
store = Store(settings)
app = FastAPI(title="VulnScan", version=__version__, docs_url="/api/docs", openapi_url="/api/openapi.json")
WEB_DIR = Path(__file__).resolve().parent / "web"

# The scanner must not itself be an easy target. Send hardening headers on every response.
_CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'self'; form-action 'self'; object-src 'none'")


@app.middleware("http")
async def security_headers(request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("Content-Security-Policy", _CSP)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    if "server" in resp.headers:
        del resp.headers["server"]
    return resp
SCAN_ID_RE = re.compile(r"^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$")


def auth(x_api_key: str | None = Header(default=None)):
    if settings.vulnscan_api_key and x_api_key != settings.vulnscan_api_key:
        raise HTTPException(401, "Missing or wrong X-API-Key")


def _scan_dir(scan_id: str) -> Path:
    if not SCAN_ID_RE.match(scan_id):
        raise HTTPException(400, "bad scan id")
    return settings.scans_dir / scan_id


def _dispatch(scan_id: str, req: ScanRequest) -> None:
    """Queue on Celery when RUN_MODE=celery (Docker), otherwise run in a background thread (local dev)."""
    if os.environ.get("RUN_MODE", "thread") == "celery":
        from .worker import run_scan_task
        run_scan_task.delay(scan_id, req.model_dump_json())
    else:
        threading.Thread(target=_run_safely, args=(scan_id, req), daemon=True).start()


def _run_safely(scan_id: str, req: ScanRequest) -> None:
    try:
        run_scan(scan_id, req, settings, store)
    except Exception:  # already recorded in the DB by the pipeline
        pass


# ------------------------------------------------------------------ meta
@app.get("/api/health")
def health():
    return {"ok": True, "version": __version__, "llm": LLM(settings).status(),
            "run_mode": os.environ.get("RUN_MODE", "thread")}


@app.get("/api/tools")
def tools():
    out = []
    for s in ALL_SCANNERS:
        avail, why = tool_available(s.name)
        out.append({"name": s.name, "category": CATEGORY.get(s.name), "description": s.description,
                    "min_profile": s.min_profile, "needs": s.needs, "installed": avail, "reason": why})
    return {"tools": out, "llm": LLM(settings).status(),
            "prompt_guard": {"model": settings.prompt_guard_model, "hf_token_set": bool(settings.hf_token)}}


@app.get("/api/owasp")
def owasp():
    return {"top10": OWASP_TOP10, "llm_top10": OWASP_LLM_TOP10}


@app.get("/api/scope")
def scope_info():
    from .scope import verified_hosts
    return {"allowed_targets": [t.strip() for t in settings.allowed_targets.split(",") if t.strip()],
            "verified_hosts": sorted(verified_hosts(settings)),
            "require_ownership_verification": settings.require_ownership_verification}


class ScopeCheck(BaseModel):
    target: str


@app.post("/api/scope/check", dependencies=[Depends(auth)])
def scope_check(body: ScopeCheck):
    try:
        host = ensure_in_scope(normalise_url(body.target), settings)
        return {"in_scope": True, "host": host}
    except ScopeError as e:
        h = host_of(body.target)
        return {"in_scope": False, "host": h, "reason": str(e), "verification": verification_instructions(h, settings)}


@app.post("/api/verify/{host}", dependencies=[Depends(auth)])
def verify(host: str):
    ok = verify_ownership(host.lower(), settings)
    return {"verified": ok, **({} if ok else verification_instructions(host.lower(), settings))}


# ------------------------------------------------------------------ scans
@app.post("/api/scans", dependencies=[Depends(auth)])
def create_scan(req: ScanRequest):
    kind = req.kind or detect_kind(req.target)
    if kind == TargetKind.zip:
        raise HTTPException(400, "Upload ZIP files with POST /api/scans/upload")
    try:
        if kind == TargetKind.url:
            ensure_in_scope(normalise_url(req.target), settings)
        if req.llm_endpoint:
            ensure_in_scope(req.llm_endpoint.url, settings)
    except ScopeError as e:
        h = host_of(req.target if kind == TargetKind.url else req.llm_endpoint.url)
        raise HTTPException(403, {"error": str(e), "verification": verification_instructions(h, settings)})
    req.kind = kind
    scan_id = new_scan_id()
    store.create(scan_id, req.target, kind.value, req.profile, req.model_dump_json())
    _dispatch(scan_id, req)
    return {"id": scan_id, "status": "queued"}


@app.post("/api/scans/upload", dependencies=[Depends(auth)])
async def upload_scan(file: UploadFile = File(...), profile: str = Form("standard"),
                      llm_endpoint: str = Form("")):
    if not (file.filename or "").lower().endswith(".zip"):
        raise HTTPException(400, "Please upload a .zip file")
    scan_id = new_scan_id()
    updir = settings.data_dir / "uploads"
    updir.mkdir(parents=True, exist_ok=True)
    dest = updir / f"{scan_id}.zip"
    size, limit = 0, settings.max_upload_mb * 1024 * 1024
    with open(dest, "wb") as fh:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > limit:
                fh.close()
                dest.unlink(missing_ok=True)
                raise HTTPException(413, f"ZIP larger than {settings.max_upload_mb} MB")
            fh.write(chunk)
    ep = LLMEndpoint(**json.loads(llm_endpoint)) if llm_endpoint.strip() else None
    req = ScanRequest(target=str(dest), kind=TargetKind.zip, profile=profile, llm_endpoint=ep, label=file.filename)
    store.create(scan_id, file.filename, "zip", profile, req.model_dump_json())
    _dispatch(scan_id, req)
    return {"id": scan_id, "status": "queued"}


@app.get("/api/scans", dependencies=[Depends(auth)])
def list_scans():
    return {"scans": [r.to_dict(with_progress=False) for r in store.list()]}


@app.get("/api/scans/{scan_id}", dependencies=[Depends(auth)])
def get_scan(scan_id: str):
    row = store.get(scan_id)
    if not row:
        raise HTTPException(404, "scan not found")
    return row.to_dict()


@app.post("/api/scans/{scan_id}/cancel", dependencies=[Depends(auth)])
def cancel_scan(scan_id: str):
    row = store.get(scan_id)
    if not row:
        raise HTTPException(404, "scan not found")
    if row.status in ("done", "failed", "cancelled"):
        return {"id": scan_id, "status": row.status, "note": "scan already finished"}
    # The worker polls the DB status and stops its running tools within a few seconds.
    store.update(scan_id, status="cancelling")
    return {"id": scan_id, "status": "cancelling"}


@app.get("/api/scans/{scan_id}/result", dependencies=[Depends(auth)])
def get_result(scan_id: str):
    p = _scan_dir(scan_id) / "result.json"
    if not p.exists():
        raise HTTPException(404, "result not ready")
    return JSONResponse(json.loads(p.read_text()))


REPORT_FILES = {"html": ("report.html", "text/html"), "pdf": ("report.pdf", "application/pdf"),
                "json": ("report.json", "application/json"), "sarif": ("report.sarif", "application/sarif+json"),
                "sbom": ("artifacts/sbom.cdx.json", "application/json"),
                "audit": ("audit-report.html", "text/html"), "audit_pdf": ("audit-report.pdf", "application/pdf")}


@app.get("/api/scans/{scan_id}/report.{fmt}", dependencies=[Depends(auth)])
def get_report(scan_id: str, fmt: str, download: bool = False):
    if fmt not in REPORT_FILES:
        raise HTTPException(400, f"format must be one of {list(REPORT_FILES)}")
    name, mime = REPORT_FILES[fmt]
    p = _scan_dir(scan_id) / name
    if not p.exists():
        raise HTTPException(404, f"{fmt} report not available" + (" (WeasyPrint not installed)" if "pdf" in fmt else ""))
    ext = {"sbom": "cdx.json", "audit": "html", "audit_pdf": "pdf"}.get(fmt, fmt)
    prefix = "vulnscan-audit" if fmt.startswith("audit") else "vulnscan"
    fname = f"{prefix}-{scan_id}.{ext}"
    inline = (fmt in ("html", "audit")) and not download
    return FileResponse(p, media_type=mime, filename=None if inline else fname)


@app.delete("/api/scans/{scan_id}", dependencies=[Depends(auth)])
def delete_scan(scan_id: str):
    d = _scan_dir(scan_id)
    shutil.rmtree(d, ignore_errors=True)
    (settings.data_dir / "uploads" / f"{scan_id}.zip").unlink(missing_ok=True)
    store.delete(scan_id)
    return {"deleted": scan_id}


class AskBody(BaseModel):
    question: str = "Explain this finding and how to fix it."


@app.post("/api/scans/{scan_id}/findings/{finding_id}/ask", dependencies=[Depends(auth)])
def ask_about_finding(scan_id: str, finding_id: str, body: AskBody):
    p = _scan_dir(scan_id) / "result.json"
    if not p.exists():
        raise HTTPException(404, "result not ready")
    f = next((x for x in json.loads(p.read_text())["findings"] if x["id"] == finding_id), None)
    if not f:
        raise HTTPException(404, "finding not found")
    llm = LLM(settings)
    kb = get_kb().search(" ".join([f["title"], *f["cwe"], *f["owasp"], *f["owasp_llm"]]), 3)
    context = "\n\n".join(f"[{c.source} / {c.heading}]\n{c.text}" for _, c in kb)
    if not llm.enabled:
        return {"answer": f["guidance"] or context or "No LLM configured; see the remediation section.", "llm": False}
    prompt = (f"FINDING:\n{json.dumps({k: f[k] for k in ('title', 'severity', 'description', 'evidence', 'remediation', 'location', 'cwe', 'owasp', 'owasp_llm')}, default=str)[:6000]}"
              f"\n\nKNOWLEDGE BASE:\n{context[:4000]}\n\nQUESTION: {body.question[:1000]}")
    try:
        answer = llm.complete("You are a friendly application-security mentor. Explain clearly for a developer: what the "
                              "issue is, why it matters, and exactly how to fix it, with a short code example when "
                              "relevant. Use Markdown. Base your answer on the finding and the knowledge base.", prompt,
                              max_tokens=1200)
    except LLMError as e:
        raise HTTPException(502, str(e))
    return {"answer": answer, "llm": True, "model": f"{llm.provider}:{llm.model}"}


# ------------------------------------------------------------------ false-positive / verdict feedback
class VerdictBody(BaseModel):
    verdict: str = ""  # "confirmed" (true positive) | "dismissed" (false positive) | "" (reset)


@app.post("/api/scans/{scan_id}/findings/{finding_id}/verdict", dependencies=[Depends(auth)])
def set_verdict(scan_id: str, finding_id: str, body: VerdictBody):
    if body.verdict not in ("", "confirmed", "dismissed"):
        raise HTTPException(400, "verdict must be confirmed, dismissed or empty")
    p = _scan_dir(scan_id) / "result.json"
    if not p.exists():
        raise HTTPException(404, "result not ready")
    result = json.loads(p.read_text())
    target = next((f for f in result["findings"] if f["id"] == finding_id), None)
    if not target:
        raise HTTPException(404, "finding not found")
    target["user_verdict"] = body.verdict
    from .pipeline import rescore_result
    result = rescore_result(result)
    p.write_text(json.dumps(result, indent=1, default=str))
    # re-render the downloadable reports so they reflect the reviewer's decision
    try:
        from .report.render import write_reports
        write_reports(result, _scan_dir(scan_id))
    except Exception:
        pass
    updated = next((f for f in result["findings"] if f["id"] == finding_id), target)
    return {"finding": updated, "summary": result["summary"], "audit": result["audit"]}


# ------------------------------------------------------------------ compliance frameworks
@app.get("/api/frameworks")
def frameworks():
    from .frameworks import FRAMEWORKS
    return {name: {"short": fw["short"], "url": fw["url"], "desc": fw["desc"],
                   "controls": [{"id": c[0], "title": c[1], "summary": c[2]} for c in fw["controls"]]}
            for name, fw in FRAMEWORKS.items()}


# ------------------------------------------------------------------ in-app AI assistant
class ChatBody(BaseModel):
    message: str
    scan_id: str | None = None
    history: list[dict] = []  # [{"role":"user"/"assistant","content":...}]


ASSISTANT_SYSTEM = (
    "You are VulnGuard, the built-in security assistant inside VulnScan — a combined vulnerability-assessment "
    "and compliance-audit tool. You help users understand findings, remediation, how the tool judges accuracy and "
    "false positives, and compliance audits against OWASP (Top 10 & ASVS), NIST CSF, CIS Controls, ISO 27001, "
    "PCI DSS, SOC 2, GDPR and HIPAA. Be precise and practical. Prefer the provided context and cite control IDs or "
    "CWE/OWASP IDs when relevant. If the user asks about a specific scan, ground your answer in the scan context "
    "provided. If you are unsure or lack data, say so plainly rather than inventing. Use concise Markdown."
)
COMPLIANCE_WORDS = re.compile(r"(audit|compl|iso|pci|soc\s?2|nist|cis|gdpr|hipaa|asvs|framework|control|standard|certif)", re.I)


def _scan_context(scan_id: str) -> str:
    p = _scan_dir(scan_id) / "result.json"
    if not p.exists():
        return ""
    r = json.loads(p.read_text())
    s = r["summary"]
    top = [f for f in r["findings"] if f["status"] == "open"][:12]
    audit = {name: {"score": a.get("score"), "gaps": a.get("gaps"), "posture": a.get("posture")}
             for name, a in r.get("audit", {}).items()}
    return json.dumps({
        "target": r["meta"]["target"], "risk": s["risk"], "counts": s["counts"],
        "accuracy": s.get("accuracy"), "audit_posture": audit,
        "top_findings": [{"title": f["title"], "severity": f["severity"], "verdict": f.get("verdict"),
                          "confidence": f.get("confidence_score"), "location": f["location"].get("file") or f["location"].get("url"),
                          "owasp": f["owasp"] + f["owasp_llm"], "frameworks": f.get("frameworks", [])} for f in top],
    }, default=str)[:6000]


GREETING_RE = re.compile(r"^\s*(hi|hey|hello|yo|hiya|good (morning|afternoon|evening)|sup|what'?s up|howdy|greetings|thanks|thank you|ok|okay|cool|nice)[\s!.?]*$", re.I)
GREETING_REPLY = (
    "👋 Hi, I'm **VulnGuard**, your security & audit assistant. I can help you with:\n\n"
    "- **Findings** — what a finding means and exactly how to fix it\n"
    "- **False positives** — which findings are likely real vs. noise, and why\n"
    "- **Compliance** — your posture against ISO 27001, PCI DSS, NIST, SOC 2, GDPR, HIPAA, OWASP\n"
    "- **Concepts** — e.g. *explain prompt injection* or *what is CWE-89?*\n\n"
    "What would you like to look at?")


@app.post("/api/chat", dependencies=[Depends(auth)])
def chat(body: ChatBody):
    msg = (body.message or "").strip()
    if not msg:
        raise HTTPException(400, "empty message")
    # Trivial greetings / acknowledgements get an instant friendly reply — no model needed.
    if GREETING_RE.match(msg):
        return {"answer": GREETING_REPLY, "llm": False, "sources": []}
    llm = LLM(settings)
    status = llm.status()
    # RAG: security knowledge base (+ compliance docs when the question is about audits)
    kb = get_kb().search(msg, 4)
    context_blocks = [f"[{c.source} / {c.heading}]\n{c.text}" for _, c in kb]
    context = "\n\n".join(context_blocks)
    scan_ctx = _scan_context(body.scan_id) if body.scan_id else ""
    # If no model is configured, or it's configured but not actually ready, degrade gracefully
    # to a knowledge-base answer plus a clear note — never a dead end.
    if not llm.enabled or not status.get("ready"):
        if context:
            note = ""
            if llm.enabled and not status.get("ready"):
                hint = status.get("hint") or status.get("error") or "the model is still starting or downloading"
                note = f"\n\n*(Answering from my knowledge base — the AI model isn't ready yet: {hint}.)*"
            return {"answer": context + note, "llm": False, "sources": [c.heading for _, c in kb]}
        if llm.enabled and not status.get("ready"):
            hint = status.get("hint") or status.get("error") or ""
            return {"answer": f"My AI model (`{status.get('model')}`) isn't ready yet — it may still be downloading. "
                              f"{hint}\n\nTry again shortly, or ask me about a specific finding or framework and I'll "
                              "answer from the knowledge base. You can check progress with `docker compose logs -f ollama-pull`.",
                    "llm": False, "sources": []}
        return {"answer": "I don't have an AI model configured right now. Set `LLM_PROVIDER` in `.env` "
                          "(e.g. `ollama`) to enable me, then ask again.", "llm": False, "sources": []}
    parts = []
    if scan_ctx:
        parts.append(f"CURRENT SCAN CONTEXT:\n{scan_ctx}")
    if context:
        parts.append(f"KNOWLEDGE BASE:\n{context[:5000]}")
    parts.append(f"USER QUESTION: {msg[:2000]}")
    history = [h for h in body.history[-6:] if isinstance(h, dict) and h.get("role") in ("user", "assistant")]
    convo = "\n".join(f"{h['role']}: {str(h.get('content',''))[:600]}" for h in history)
    user = (f"CONVERSATION SO FAR:\n{convo}\n\n" if convo else "") + "\n\n".join(parts)
    try:
        answer = llm.complete(ASSISTANT_SYSTEM, user, max_tokens=1100)
    except LLMError as e:
        raise HTTPException(502, str(e))
    return {"answer": answer, "llm": True, "model": f"{llm.provider}:{llm.model}",
            "sources": [c.heading for _, c in kb]}


# ------------------------------------------------------------------ UI
if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


@app.get("/", include_in_schema=False)
def index():
    return HTMLResponse((WEB_DIR / "index.html").read_text())
