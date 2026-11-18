"""Merge, enrich, prioritise and triage findings from all tools."""
from __future__ import annotations

import json
import time
from pathlib import Path

import httpx

from .config import Settings
from .llm import LLM, LLMError
from .models import Confidence, Finding, Severity
from .owasp import map_finding
from .rag import get_kb, guidance_text

CONF_RANK = {"high": 2, "medium": 1, "low": 0}


def merge(findings: list[Finding]) -> list[Finding]:
    """De-duplicate by fingerprint; also fold identical CVEs on the same host:port reported by different tools."""
    by_fp: dict[str, Finding] = {}
    for f in findings:
        f = map_finding(f.clip())
        if not f.sources:
            f.sources = [f.tool]
        fp = f.fingerprint
        if fp not in by_fp:
            by_fp[fp] = f
            continue
        cur = by_fp[fp]
        if f.severity.rank > cur.severity.rank:
            cur.severity = f.severity
        if CONF_RANK[f.confidence.value] > CONF_RANK[cur.confidence.value]:
            cur.confidence = f.confidence
        for attr in ("cve", "cwe", "owasp", "owasp_llm", "references", "sources"):
            vals = getattr(cur, attr)
            for v in getattr(f, attr):
                if v not in vals:
                    vals.append(v)
        cur.remediation = cur.remediation or f.remediation
        cur.description = cur.description or f.description
    merged = list(by_fp.values())
    # Cross-tool confirmation raises confidence
    for f in merged:
        if len(set(f.sources)) > 1 and f.confidence != Confidence.high:
            f.confidence = Confidence.high
    return merged


# ------------------------------------------------------------------ enrichment
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


def _kev_set(settings: Settings) -> set[str]:
    cache = settings.data_dir / "cache" / "kev.json"
    cache.parent.mkdir(parents=True, exist_ok=True)
    if not cache.exists() or time.time() - cache.stat().st_mtime > 86400:
        try:
            r = httpx.get(KEV_URL, timeout=30)
            r.raise_for_status()
            cache.write_text(r.text)
        except httpx.HTTPError:
            if not cache.exists():
                return set()
    try:
        return {v["cveID"] for v in json.loads(cache.read_text()).get("vulnerabilities", [])}
    except (ValueError, KeyError):
        return set()


def enrich(findings: list[Finding], settings: Settings, log=print) -> None:
    cves = sorted({c for f in findings for c in f.cve})
    if not cves or not settings.enrich_online:
        return
    kev = _kev_set(settings)
    epss: dict[str, float] = {}
    for i in range(0, len(cves), 100):
        try:
            r = httpx.get(EPSS_URL, params={"cve": ",".join(cves[i:i + 100])}, timeout=30)
            r.raise_for_status()
            for row in r.json().get("data", []):
                epss[row["cve"]] = float(row["epss"])
        except (httpx.HTTPError, ValueError, KeyError) as e:
            log(f"enrichment: EPSS lookup failed ({e.__class__.__name__})")
            break
    for f in findings:
        if any(c in kev for c in f.cve):
            f.kev = True
            if f.severity.rank < Severity.high.rank:
                f.severity = Severity.high
        scores = [epss[c] for c in f.cve if c in epss]
        if scores:
            f.epss = max(scores)


# ------------------------------------------------------------------ accuracy / confidence model
# How trustworthy each tool's raw finding is, before other signals. CVE/version-based tools are
# near-deterministic; pattern and LLM-based tools are softer and need corroboration.
BASE_TOOL_CONF = {
    "grype": 82, "trivy": 80, "openvas": 80, "nmap": 55, "sqlmap": 92, "testssl": 85,
    "gitleaks": 70, "semgrep": 68, "bandit": 62, "nikto": 45, "nuclei": 78, "zap": 60,
    "http_checks": 88, "modelscan": 85, "prowler": 85, "prompt_guard": 60,
    "llm_redteam": 72, "garak": 70, "llm_design_review": 35,
}


def score_accuracy(findings: list[Finding]) -> None:
    """Assign every finding a 0-100 confidence_score, a verdict tier and the human-readable signals
    behind it. This is how the tool estimates its own accuracy instead of trusting any single model."""
    for f in findings:
        signals: list[str] = []
        base = max(BASE_TOOL_CONF.get(s, 55) for s in (f.sources or [f.tool]))
        score = float(base)
        signals.append(f"base reliability of {'/'.join(f.sources or [f.tool])}: {base}%")

        # deterministic facts raise confidence a lot
        if f.cve and (f.cvss or f.epss is not None):
            score += 8; signals.append("backed by a published CVE with scoring data")
        if f.kev:
            score += 10; signals.append("on CISA KEV (known exploited in the wild)")
        if f.fixed_version:
            score += 4; signals.append("vendor confirms an affected/fixed version")

        # corroboration across independent tools
        n = len(set(f.sources))
        if n > 1:
            score += min(14, 7 * (n - 1)); signals.append(f"independently reported by {n} tools")

        # the tool's own confidence rating for this finding
        score += {"high": 6, "medium": 0, "low": -10}[f.confidence.value]
        if f.confidence.value != "medium":
            signals.append(f"tool-reported confidence: {f.confidence.value}")

        # evidence present
        if f.evidence.strip():
            score += 3; signals.append("concrete evidence captured")
        else:
            score -= 4

        # LLM triage outcome (if it ran)
        if f.triage_note:
            if f.status == "likely_false_positive":
                score -= 45; signals.append("AI triage flagged this as a likely false positive")
            else:
                score += 6; signals.append("AI triage reviewed it and did not dispute it")

        # design-review items are LLM-authored hypotheses -> keep them humble
        if f.tool == "llm_design_review":
            score -= 8; signals.append("generated by an AI design review — treat as a lead, verify manually")

        score = max(1, min(100, round(score)))

        # user feedback is authoritative
        if f.user_verdict == "confirmed":
            score, verdict = 100, "verified"; signals.insert(0, "confirmed by a reviewer")
        elif f.user_verdict == "dismissed":
            score, verdict = 0, "false_positive"; signals.insert(0, "dismissed by a reviewer")
        elif f.status == "likely_false_positive":
            verdict = "false_positive"  # AI triage already judged it a likely FP
        elif score >= 80:
            verdict = "verified"
        elif score >= 58:
            verdict = "likely"
        elif score >= 20:
            verdict = "uncertain"  # low confidence, but still a lead worth a human look
        else:
            verdict = "false_positive"

        f.confidence_score = score
        f.verdict = verdict
        f.accuracy_signals = signals[:6]
        f.status = "open" if verdict != "false_positive" else "likely_false_positive"


def apply_user_verdict(f: Finding, verdict: str) -> None:
    f.user_verdict = verdict if verdict in ("confirmed", "dismissed") else ""
    score_accuracy([f])


def accuracy_summary(findings: list[Finding]) -> dict:
    tiers = {"verified": 0, "likely": 0, "uncertain": 0, "false_positive": 0}
    for f in findings:
        tiers[f.verdict] = tiers.get(f.verdict, 0) + 1
    scored = [f.confidence_score for f in findings]
    open_f = [f for f in findings if f.status == "open"]
    return {
        "tiers": tiers,
        "mean_confidence": round(sum(scored) / len(scored)) if scored else 0,
        "high_confidence_pct": round(100 * sum(1 for f in open_f if f.confidence_score >= 80) / len(open_f)) if open_f else 0,
        "flagged_false_positives": tiers["false_positive"],
        "reviewed": sum(1 for f in findings if f.user_verdict),
    }


def risk_score(f: Finding) -> float:
    s = f.severity.rank * 22 + (f.confidence_score / 100) * 18 + (f.epss or 0) * 20 + (15 if f.kev else 0)
    if f.status == "likely_false_positive":
        s -= 60
    return round(s, 1)


def prioritise(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: -risk_score(f))


def attach_guidance(findings: list[Finding]) -> None:
    get_kb()
    for f in findings:
        if f.severity.rank >= Severity.low.rank or f.category == "ai":
            f.guidance = guidance_text(f)


# ------------------------------------------------------------------ LLM triage
TRIAGE_SYSTEM = """You are an application-security triage assistant. For each finding decide whether it is likely a
false positive given the evidence and code context. Be conservative: only mark likely_false_positive when the evidence
clearly shows the issue is not exploitable (test code, sanitised input, dead code, placeholder secret, etc.).
Return a JSON array with one object per finding: {"id": str, "likely_false_positive": bool, "note": str (max 40 words)}."""


def _code_context(f: Finding, source_dir: Path | None, radius: int = 6) -> str:
    if not source_dir or not f.location.file or not f.location.line:
        return ""
    p = (source_dir / f.location.file)
    try:
        lines = p.read_text(errors="ignore").splitlines()
    except OSError:
        return ""
    a, b = max(0, f.location.line - radius - 1), min(len(lines), f.location.line + radius)
    return "\n".join(f"{i + 1}: {lines[i]}" for i in range(a, b))


def llm_triage(findings: list[Finding], settings: Settings, source_dir: Path | None, log=print) -> None:
    llm = LLM(settings)
    if not (settings.llm_triage and llm.enabled):
        return
    candidates = [f for f in findings if f.tool in ("semgrep", "bandit", "gitleaks", "nikto", "zap", "nuclei")
                  and f.severity.rank >= Severity.medium.rank][: settings.llm_max_findings_to_triage]
    for i in range(0, len(candidates), 5):
        batch = candidates[i:i + 5]
        payload = [{"id": f.fingerprint, "title": f.title, "tool": f.tool, "rule": f.rule_id,
                    "location": f.location.short(), "description": f.description[:500], "evidence": f.evidence[:500],
                    "code": _code_context(f, source_dir)} for f in batch]
        try:
            verdicts = llm.complete_json(TRIAGE_SYSTEM, json.dumps(payload, indent=1), max_tokens=1200)
        except LLMError as e:
            log(f"triage: {e}")
            return
        by_id = {v.get("id"): v for v in verdicts if isinstance(v, dict)} if isinstance(verdicts, list) else {}
        for f in batch:
            v = by_id.get(f.fingerprint)
            if not v:
                continue
            f.triage_note = str(v.get("note", ""))[:400]
            if v.get("likely_false_positive") is True:
                f.status = "likely_false_positive"


def executive_summary(meta: dict, findings: list[Finding], settings: Settings) -> str:
    counts = {s.value: sum(1 for f in findings if f.severity == s and f.status == "open") for s in Severity}
    top = [f for f in findings if f.status == "open"][:8]
    fallback = (f"The scan of {meta['target']} produced {sum(counts.values())} open findings: "
                f"{counts['critical']} critical, {counts['high']} high, {counts['medium']} medium, {counts['low']} low. "
                + ("Priority items: " + "; ".join(f.title for f in top[:5]) + "." if top else "No significant issues were found."))
    llm = LLM(settings)
    if not llm.enabled:
        return fallback
    try:
        prompt = json.dumps({"target": meta["target"], "counts": counts,
                             "top_findings": [{"title": f.title, "severity": f.severity.value, "owasp": f.owasp + f.owasp_llm}
                                              for f in top]})
        text = llm.complete("You write concise executive summaries of security assessments for engineering managers. "
                            "Two short paragraphs, plain language, no markdown headings: overall risk, then the three "
                            "most important actions.", prompt, max_tokens=500)
        return text.strip() or fallback
    except LLMError:
        return fallback
