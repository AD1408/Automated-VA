"""Report writers: HTML (+PDF via WeasyPrint), JSON and SARIF 2.1.0."""
from __future__ import annotations

import json
from pathlib import Path

import markdown as md
from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup

from .. import __version__

TEMPLATES = Path(__file__).resolve().parent / "templates"
SEV_COLORS = {"critical": "#b42318", "high": "#d9480f", "medium": "#b08800", "low": "#1d6fb8", "info": "#667085"}


def _env() -> Environment:
    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html", "j2"]))
    env.filters["md"] = lambda s: Markup(md.markdown(str(s or ""), extensions=["fenced_code"]))  # nosec B704 - renders only trusted first-party knowledge-base markdown
    return env


def render_html(result: dict, for_pdf: bool = False) -> str:
    return _env().get_template("report.html.j2").render(r=result, sev_colors=SEV_COLORS, version=__version__,
                                                        for_pdf=for_pdf)


SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
EFFORT = {"critical": "High priority", "high": "High priority", "medium": "Medium priority",
          "low": "Low priority", "info": "Advisory"}


def audit_context(result: dict) -> dict:
    """Derive the extra structure a formal audit report needs (posture, gap register, roadmap)."""
    audit = result.get("audit", {})
    findings = result.get("findings", [])
    by_id = {f["id"]: f for f in findings}
    open_f = [f for f in findings if f["status"] == "open"]

    scored = [a["score"] for a in audit.values() if a.get("score") is not None]
    overall = round(sum(scored) / len(scored)) if scored else None
    opinion = ("Satisfactory" if overall is not None and overall >= 80 else
               "Needs Improvement" if overall is not None and overall >= 50 else
               "Unsatisfactory" if overall is not None else "Insufficient Data")

    # gap register: every control with a gap, across frameworks
    gaps = []
    for name, a in audit.items():
        for ct in a["controls"]:
            if ct["status"] == "gap":
                gaps.append({"framework": a["short"], "framework_full": name, "control": ct["id"],
                             "title": ct["title"], "max_severity": ct["max_severity"],
                             "findings": [by_id[x["id"]] for x in ct["findings"] if x["id"] in by_id],
                             "count": ct["finding_count"]})
    gaps.sort(key=lambda g: -SEV_RANK.get(g["max_severity"] or "info", 0))

    # remediation roadmap: prioritised open findings with the controls they unblock
    roadmap = []
    for i, f in enumerate(sorted(open_f, key=lambda f: -f.get("risk_score", 0))[:40], 1):
        roadmap.append({"n": i, "title": f["title"], "severity": f["severity"], "priority": EFFORT[f["severity"]],
                        "location": (f["location"].get("file") or f["location"].get("url") or
                                     f["location"].get("host") or f["location"].get("component") or "-"),
                        "action": f.get("remediation") or "Review and remediate per the detailed findings.",
                        "frameworks": f.get("frameworks", []), "verdict": f.get("verdict"),
                        "confidence": f.get("confidence_score")})

    return {
        "overall": overall, "opinion": opinion,
        "frameworks": sorted(audit.items(), key=lambda kv: (kv[1]["score"] is None, -(kv[1]["score"] or 0))),
        "gaps": gaps, "roadmap": roadmap,
        "total_gaps": len(gaps), "total_controls": sum(a["total"] for a in audit.values()),
        "total_assessed": sum(a["assessed"] for a in audit.values()),
        "open_findings": open_f,
    }


def render_audit_html(result: dict, for_pdf: bool = False) -> str:
    return _env().get_template("audit_report.html.j2").render(
        r=result, a=audit_context(result), sev_colors=SEV_COLORS, version=__version__, for_pdf=for_pdf)


SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def to_sarif(result: dict) -> dict:
    runs: dict[str, dict] = {}
    for f in result["findings"]:
        tool = f["tool"]
        run = runs.setdefault(tool, {"tool": {"driver": {"name": tool, "informationUri": "https://owasp.org", "rules": []}},
                                     "results": [], "_rules": set()})
        rid = f["rule_id"] or f["title"][:60]
        if rid not in run["_rules"]:
            run["_rules"].add(rid)
            run["tool"]["driver"]["rules"].append({
                "id": rid, "shortDescription": {"text": f["title"][:200]},
                "help": {"text": f.get("remediation") or ""},
                "properties": {"tags": f["cwe"] + f["owasp"] + f["owasp_llm"]}})
        loc = f["location"]
        res = {"ruleId": rid, "level": SARIF_LEVEL[f["severity"]],
               "message": {"text": f"{f['title']}: {(f.get('description') or '')[:800]}"},
               "properties": {"severity": f["severity"], "confidence": f["confidence"], "cve": f["cve"],
                              "status": f["status"]}}
        if loc.get("file"):
            region = {"startLine": loc["line"]} if loc.get("line") else {}
            res["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": loc["file"]}, **({"region": region} if region else {})}}]
        elif loc.get("url"):
            res["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": loc["url"]}}}]
        run["results"].append(res)
    for r in runs.values():
        r.pop("_rules")
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": list(runs.values())}


def write_reports(result: dict, workdir: Path) -> list[Path]:
    out = []
    p = workdir / "report.html"
    p.write_text(render_html(result))
    out.append(p)
    p = workdir / "report.json"
    p.write_text(json.dumps(result, indent=1, default=str))
    out.append(p)
    p = workdir / "report.sarif"
    p.write_text(json.dumps(to_sarif(result), indent=1))
    out.append(p)
    # separate professional compliance-audit report
    if result.get("audit"):
        p = workdir / "audit-report.html"
        p.write_text(render_audit_html(result))
        out.append(p)
    try:
        from weasyprint import HTML
        p = workdir / "report.pdf"
        HTML(string=render_html(result, for_pdf=True), base_url=str(workdir)).write_pdf(p)
        out.append(p)
        if result.get("audit"):
            p = workdir / "audit-report.pdf"
            HTML(string=render_audit_html(result, for_pdf=True), base_url=str(workdir)).write_pdf(p)
            out.append(p)
    except Exception:  # weasyprint not installed or system libs missing - PDF is optional
        pass
    return out
