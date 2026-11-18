"""The scan pipeline: ingest -> recon -> plan -> scan -> merge -> triage -> report."""
from __future__ import annotations

import concurrent.futures as cf
import json
import secrets
import threading
import time
import traceback
from datetime import datetime, timezone
from urllib.parse import urlparse

from .config import Settings, get_settings
from .correlate import (accuracy_summary, attach_guidance, enrich, executive_summary, llm_triage,
                        merge, prioritise, score_accuracy,
                        risk_score)
from .db import Store
from .ingest import IngestError, clone_repo, detect_kind, safe_extract_zip
from .llm import LLM
from .models import Finding, ScanRequest, Severity, TargetKind, ToolRun, ToolStatus
from .recon import fingerprint_code, fingerprint_url
from .runner import ToolCancelled, ToolNotInstalled, ToolSkipped, which


class ScanCancelled(Exception):
    """The user stopped the scan."""


def _make_cancel_check(store, scan_id: str):
    """Returns a cheap callable that reports whether the scan has been asked to stop.
    The API (a separate process) signals this by setting the scan's DB status to 'cancelling',
    so we poll the row, cached to at most once every ~1.5s."""
    state = {"t": 0.0, "v": False}
    lock = threading.Lock()

    def check() -> bool:
        if store is None:
            return False
        now = time.time()
        with lock:
            if now - state["t"] < 1.5:
                return state["v"]
            state["t"] = now
        row = store.get(scan_id)
        state["v"] = bool(row and row.status in ("cancelling", "cancelled"))
        return state["v"]

    return check
from .scanners import ALL_SCANNERS, BINARIES, CATEGORY, ScanContext, Scanner
from .scope import ScopeError, ensure_in_scope

STAGES = ["ingest", "recon", "plan", "scan", "merge", "triage", "report", "done"]


def new_scan_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(3)


def normalise_url(target: str) -> str:
    t = target.strip()
    if "://" not in t:
        t = "http://" + t
    p = urlparse(t)
    return f"{p.scheme}://{p.netloc}{p.path or '/'}"


PY_DEPS = {"prompt_guard": ["transformers", "torch"], "openvas": ["gvm"]}


def tool_available(name: str) -> tuple[bool, str]:
    import importlib.util
    missing_py = [m for m in PY_DEPS.get(name, []) if importlib.util.find_spec(m) is None]
    if missing_py:
        return False, f"python packages missing: {', '.join(missing_py)} (build with INSTALL_AI=true)"
    missing = [b for b in BINARIES.get(name, []) if not which(b)]
    if missing:
        return False, f"not installed: {', '.join(missing)}"
    return True, ""


class Progress:
    """Live progress, persisted to the DB (throttled) so the UI can poll it."""

    def __init__(self, store: Store | None, scan_id: str):
        self.store, self.scan_id = store, scan_id
        self.lock = threading.Lock()
        self.data = {"stage": "queued", "stages": STAGES, "tools": {}, "logs": [], "counts": {s.value: 0 for s in Severity},
                     "started_at": time.time(), "recon": {}, "findings_preview": []}
        self._last = 0.0

    def log(self, msg: str) -> None:
        with self.lock:
            self.data["logs"].append({"t": round(time.time() - self.data["started_at"], 1), "msg": str(msg)[:500]})
            self.data["logs"] = self.data["logs"][-300:]
        self.flush()

    def stage(self, name: str) -> None:
        with self.lock:
            self.data["stage"] = name
        self.log(f"── stage: {name}")
        if self.store:
            self.store.update(self.scan_id, stage=name)
        self.flush(force=True)

    def tool(self, name: str, **fields) -> None:
        with self.lock:
            self.data["tools"].setdefault(name, {"category": CATEGORY.get(name, "other")}).update(fields)
        self.flush(force=True)

    def add_findings(self, findings: list[Finding]) -> None:
        with self.lock:
            for f in findings:
                self.data["counts"][f.severity.value] += 1
            prev = self.data["findings_preview"] + [
                {"title": f.title, "severity": f.severity.value, "tool": f.tool} for f in findings
                if f.severity.rank >= Severity.medium.rank]
            self.data["findings_preview"] = prev[-40:]
        self.flush(force=True)

    def flush(self, force: bool = False) -> None:
        if not self.store:
            return
        now = time.time()
        if force or now - self._last > 1.0:
            self._last = now
            with self.lock:
                snapshot = json.loads(json.dumps(self.data, default=str))
            self.store.update(self.scan_id, progress=snapshot)


def plan(ctx: ScanContext, progress: Progress) -> list[Scanner]:
    req = ctx.request
    chosen = []
    for s in ALL_SCANNERS:
        if req.only_tools and s.name not in req.only_tools:
            progress.tool(s.name, status="skipped", reason="not selected")
            continue
        if s.name in req.skip_tools:
            progress.tool(s.name, status="skipped", reason="excluded by user")
            continue
        ok, why = s.applicable(ctx)
        if not ok:
            progress.tool(s.name, status="skipped", reason=why)
            continue
        avail, why = tool_available(s.name)
        if not avail:
            progress.tool(s.name, status="not_installed", reason=why)
            continue
        chosen.append(s)
        progress.tool(s.name, status="queued", reason="", stage=s.stage, description=s.description)
    return chosen


def run_scan(scan_id: str, req: ScanRequest, settings: Settings | None = None, store: Store | None = None,
             echo: bool = False) -> dict:
    settings = settings or get_settings()
    progress = Progress(store, scan_id)
    if echo:
        _orig = progress.log

        def _echo(msg):
            print(msg, flush=True)
            _orig(msg)
        progress.log = _echo  # type: ignore[method-assign]
    workdir = settings.scans_dir / scan_id
    workdir.mkdir(parents=True, exist_ok=True)
    if store:
        store.update(scan_id, status="running")
    cancelled = _make_cancel_check(store, scan_id)
    tool_runs: list[ToolRun] = []
    findings: list[Finding] = []
    try:
        # ---------------------------------------------------------------- ingest
        progress.stage("ingest")
        kind = req.kind or detect_kind(req.target)
        ctx = ScanContext(scan_id=scan_id, request=req, kind=kind, workdir=workdir, settings=settings, log=progress.log)
        if kind == TargetKind.repo:
            progress.log(f"cloning {req.target}")
            ctx.source_dir = clone_repo(req.target, workdir, settings)
        elif kind == TargetKind.zip:
            from pathlib import Path
            progress.log("extracting ZIP safely")
            ctx.source_dir = safe_extract_zip(Path(req.target), workdir, max_total_mb=settings.max_upload_mb * 4)
        else:
            ctx.base_url = normalise_url(req.target)
            ctx.host = ensure_in_scope(ctx.base_url, settings)
            progress.log(f"target {ctx.base_url} is in scope")
        if req.llm_endpoint:
            ensure_in_scope(req.llm_endpoint.url, settings)
        # ---------------------------------------------------------------- recon
        progress.stage("recon")
        if ctx.source_dir:
            ctx.recon = fingerprint_code(ctx.source_dir)
            langs = ", ".join(list(ctx.recon["languages"])[:5]) or "none detected"
            progress.log(f"languages: {langs}; frameworks: {', '.join(ctx.recon['frameworks']) or '-'}; "
                         f"IaC: {', '.join(ctx.recon['iac']) or '-'}; LLM usage: {'yes' if ctx.recon['uses_llm'] else 'no'}")
        if ctx.base_url:
            ctx.recon.update(fingerprint_url(ctx.base_url, req.auth_headers))
            if not ctx.recon.get("reachable"):
                raise IngestError(f"{ctx.base_url} is not reachable: {ctx.recon.get('error', 'no response')}")
            progress.log(f"reachable (HTTP {ctx.recon.get('status')}), server: {ctx.recon.get('server') or '-'}, "
                         f"title: {ctx.recon.get('title') or '-'}")
        with progress.lock:
            progress.data["recon"] = ctx.recon
        # ---------------------------------------------------------------- plan
        progress.stage("plan")
        chosen = plan(ctx, progress)
        progress.log(f"{len(chosen)} tools selected: {', '.join(s.name for s in chosen)}")
        # ---------------------------------------------------------------- scan
        progress.stage("scan")
        heavy_lock = threading.Semaphore(1)

        def execute(s: Scanner) -> list[Finding]:
            started = datetime.now(timezone.utc)
            t0 = time.time()
            # expose the cancel check to runner.run() / ZAP / OpenVAS, which run on this same thread
            threading.current_thread().cancel = cancelled  # type: ignore[attr-defined]
            if cancelled():
                progress.tool(s.name, status="skipped", reason="scan cancelled")
                return []
            if s.heavy:
                heavy_lock.acquire()
            progress.tool(s.name, status="running", started=time.time())
            progress.log(f"{s.name}: started")
            status, reason, out = ToolStatus.ok, "", []
            try:
                if cancelled():
                    raise ToolCancelled("scan cancelled")
                out = s.run(ctx) or []
                for f in out:
                    if not f.sources:
                        f.sources = [f.tool or s.name]
            except ToolCancelled as e:
                status, reason = ToolStatus.skipped, str(e)
            except ToolSkipped as e:
                status, reason = ToolStatus.skipped, str(e)
            except ToolNotInstalled as e:
                status, reason = ToolStatus.not_installed, str(e)
            except ScopeError as e:
                status, reason = ToolStatus.failed, f"scope: {e}"
            except Exception as e:  # noqa: BLE001 - one tool must never kill the scan
                status, reason = ToolStatus.failed, f"{e.__class__.__name__}: {str(e)[:400]}"
                progress.log(traceback.format_exc(limit=3)[-600:])
            finally:
                if s.heavy:
                    heavy_lock.release()
            dur = round(time.time() - t0, 1)
            tool_runs.append(ToolRun(tool=s.name, status=status, reason=reason, started_at=started, duration_s=dur,
                                     findings=len(out)))
            progress.tool(s.name, status=status.value, reason=reason, findings=len(out), duration=dur)
            progress.log(f"{s.name}: {status.value} in {dur}s, {len(out)} findings" + (f" ({reason})" if reason else ""))
            progress.add_findings(out)
            return out

        for stage_no in sorted({s.stage for s in chosen}):
            if cancelled():
                raise ScanCancelled()
            group = [s for s in chosen if s.stage == stage_no]
            with cf.ThreadPoolExecutor(max_workers=max(1, settings.max_parallel_tools)) as ex:
                for res in ex.map(execute, group):
                    findings.extend(res)
        if cancelled():
            raise ScanCancelled()
        for name, t in progress.data["tools"].items():
            if t.get("status") in ("skipped", "not_installed") and not any(r.tool == name for r in tool_runs):
                tool_runs.append(ToolRun(tool=name, status=ToolStatus(t["status"]), reason=t.get("reason", "")))
        # ---------------------------------------------------------------- merge
        progress.stage("merge")
        # drop findings inside excluded paths (deliberately-vulnerable fixtures, vendored code, .vulnscanignore)
        if ctx.source_dir:
            from .ingest import load_excludes, path_excluded
            excludes = load_excludes(ctx.source_dir)
            before = len(findings)
            findings = [f for f in findings if not (f.location.file and path_excluded(f.location.file, excludes))]
            if before != len(findings):
                progress.log(f"excluded {before - len(findings)} finding(s) in ignored paths (fixtures/vendored/.vulnscanignore)")
        raw_count = len(findings)
        findings = merge(findings)
        enrich(findings, settings, progress.log)
        attach_guidance(findings)
        progress.log(f"{raw_count} raw findings -> {len(findings)} after de-duplication")
        # ---------------------------------------------------------------- triage
        progress.stage("triage")
        if LLM(settings).enabled:
            progress.log(f"LLM triage with {LLM(settings).provider}:{LLM(settings).model}")
        llm_triage(findings, settings, ctx.source_dir, progress.log)
        score_accuracy(findings)
        from .frameworks import tag_findings_with_frameworks
        tag_findings_with_frameworks(findings)
        findings = prioritise(findings)
        meta = {"scan_id": scan_id, "target": req.label or req.target, "kind": kind.value, "profile": ctx.profile,
                "base_url": ctx.base_url, "started_at": datetime.fromtimestamp(progress.data["started_at"], timezone.utc).isoformat(),
                "finished_at": datetime.now(timezone.utc).isoformat()}
        summary_text = executive_summary(meta, findings, settings)
        # ---------------------------------------------------------------- report
        progress.stage("report")
        result = build_result(meta, ctx.recon, tool_runs, findings, summary_text)
        (workdir / "result.json").write_text(json.dumps(result, indent=1, default=str))
        from .report.render import write_reports
        paths = write_reports(result, workdir)
        progress.log(f"reports written: {', '.join(p.name for p in paths)}")
        progress.stage("done")
        if store:
            store.update(scan_id, status="done", finished_at=datetime.now(timezone.utc), summary=result["summary"])
        return result
    except ScanCancelled:
        progress.log("── scan cancelled by user")
        progress.stage("cancelled")
        if store:
            store.update(scan_id, status="cancelled", error="Cancelled by user",
                         finished_at=datetime.now(timezone.utc))
        return {}
    except (IngestError, ScopeError) as e:
        progress.log(f"ERROR: {e}")
        if store:
            store.update(scan_id, status="failed", error=str(e), finished_at=datetime.now(timezone.utc))
        raise
    except Exception as e:
        progress.log(f"ERROR: {e.__class__.__name__}: {e}")
        progress.log(traceback.format_exc(limit=5)[-1500:])
        if store:
            store.update(scan_id, status="failed", error=f"{e.__class__.__name__}: {e}",
                         finished_at=datetime.now(timezone.utc))
        raise


def _coverage(open_f, ran_ok):
    from .owasp import COVERAGE, OWASP_LLM_TOP10, OWASP_TOP10
    cov = {}
    for cat, name in {**OWASP_TOP10, **OWASP_LLM_TOP10}.items():
        hits = [f for f in open_f if cat in f.owasp or cat in f.owasp_llm]
        cov[cat] = {"name": name, "findings": len(hits), "tested_by": [t for t in COVERAGE.get(cat, []) if t in ran_ok],
                    "max_severity": max((f.severity for f in hits), key=lambda s: s.rank).value if hits else None}
    return cov


def rescore_result(result: dict) -> dict:
    """Recompute everything derived from findings (used after a user confirms/dismisses a finding)."""
    from .frameworks import audit_report, tag_findings_with_frameworks
    findings = [Finding.model_validate(d) for d in result["findings"]]
    score_accuracy(findings)
    tag_findings_with_frameworks(findings)
    findings = prioritise(findings)
    ran_ok = set(result.get("summary", {}).get("tools_ok", []))
    open_f = [f for f in findings if f.status == "open"]
    counts = {s.value: sum(1 for f in open_f if f.severity == s) for s in Severity}
    worst = next((s.value for s in (Severity.critical, Severity.high, Severity.medium, Severity.low) if counts[s.value]), "none")
    result["findings"] = [{**f.model_dump(mode="json"), "id": f.fingerprint, "risk_score": risk_score(f)} for f in findings]
    result["summary"].update(counts=counts, total_open=len(open_f),
                             likely_false_positives=len(findings) - len(open_f), risk=worst,
                             accuracy=accuracy_summary(findings))
    result["coverage"] = _coverage(open_f, ran_ok)
    result["audit"] = audit_report(findings, ran_ok)
    return result


def build_result(meta, recon, tool_runs, findings, summary_text) -> dict:
    from .owasp import COVERAGE, OWASP_LLM_TOP10, OWASP_TOP10
    open_f = [f for f in findings if f.status == "open"]
    counts = {s.value: sum(1 for f in open_f if f.severity == s) for s in Severity}
    ran_ok = {r.tool for r in tool_runs if r.status == ToolStatus.ok}
    coverage = {}
    for cat, name in {**OWASP_TOP10, **OWASP_LLM_TOP10}.items():
        hits = [f for f in open_f if cat in f.owasp or cat in f.owasp_llm]
        testers = [t for t in COVERAGE.get(cat, []) if t in ran_ok]
        coverage[cat] = {"name": name, "findings": len(hits), "tested_by": testers,
                         "max_severity": max((f.severity for f in hits), key=lambda s: s.rank).value if hits else None}
    worst = next((s.value for s in (Severity.critical, Severity.high, Severity.medium, Severity.low) if counts[s.value]), "none")
    from .frameworks import audit_report
    return {
        "meta": meta,
        "recon": recon,
        "summary": {"counts": counts, "total_open": len(open_f), "likely_false_positives": len(findings) - len(open_f),
                    "risk": worst, "executive_summary": summary_text,
                    "tools_ok": sorted(ran_ok), "tools_total": len(tool_runs),
                    "accuracy": accuracy_summary(findings)},
        "coverage": coverage,
        "audit": audit_report(findings, ran_ok),
        "tool_runs": [r.model_dump(mode="json") for r in tool_runs],
        "findings": [{**f.model_dump(mode="json"), "id": f.fingerprint, "risk_score": risk_score(f)} for f in findings],
    }
