"""Static scanners for source code: SAST, secrets, dependencies (SCA), IaC, model files."""
from __future__ import annotations

import json
from pathlib import Path

from ..models import Confidence, Finding, Location, Severity
from ..recon import AI_LIBS
from ..runner import ToolSkipped, require, run
from .base import ScanContext, Scanner

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
AI_LIB_NAMES = {lib.split("/")[-1].replace("_", "-").lower() for lib in AI_LIBS} | {"torch", "tensorflow", "keras"}


def _rel(path: str, root: Path | None) -> str:
    if root and path:
        try:
            return str(Path(path).resolve().relative_to(root.resolve()))
        except ValueError:
            pass
    return path


# ----------------------------------------------------------------- Semgrep
def parse_semgrep(data: dict, root: Path | None = None) -> list[Finding]:
    out = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        cwe = meta.get("cwe", [])
        cwe = [cwe] if isinstance(cwe, str) else cwe
        owasp = [o.split(" ")[0] for o in (meta.get("owasp") or []) if "2025" in str(o)]
        conf = str(meta.get("confidence", "medium")).lower()
        out.append(Finding(
            title=meta.get("title") or r.get("check_id", "").split(".")[-1].replace("-", " ").capitalize(),
            severity=Severity.parse(extra.get("severity"), Severity.medium),
            confidence=Confidence(conf) if conf in ("high", "medium", "low") else Confidence.medium,
            tool="semgrep",
            rule_id=r.get("check_id", ""),
            category=meta.get("category_override", "code"),
            description=extra.get("message", ""),
            evidence=(extra.get("lines") or "").strip(),
            references=[u for u in (meta.get("references") or []) if isinstance(u, str)][:5],
            location=Location(file=_rel(r.get("path", ""), root), line=(r.get("start") or {}).get("line")),
            cwe=cwe,
            owasp=owasp,
            owasp_llm=list(meta.get("owasp_llm") or []),
            remediation=meta.get("fix_guidance", ""),
        ))
    return out


class SemgrepScanner(Scanner):
    name = "semgrep"
    description = "SAST: injection, XSS, crypto, auth, deserialization + custom AI/LLM rules"

    def run(self, ctx: ScanContext) -> list[Finding]:
        exe = require("semgrep")
        out = ctx.artifact("semgrep.json")
        local_rules = str(RULES_DIR / "ai-security.yml")
        registry = ["p/default", "p/owasp-top-ten"] if ctx.profile != "quick" else ["p/default"]
        base = [exe, "scan", "--json", "--output", str(out), "--metrics", "off", "--quiet",
                "--timeout", "30", "--max-target-bytes", "2000000", "--jobs", "2"]
        cmd = base + [x for c in registry for x in ("--config", c)] + ["--config", local_rules, str(ctx.source_dir)]
        try:
            run(cmd, ctx.settings.tool_timeout, ok_codes=(0, 1))
        except RuntimeError as e:
            ctx.log(f"semgrep registry rules unavailable ({e}); running bundled rules only")
            run(base + ["--config", local_rules, str(ctx.source_dir)], ctx.settings.tool_timeout, ok_codes=(0, 1))
        return parse_semgrep(json.loads(out.read_text()), ctx.source_dir)


# ----------------------------------------------------------------- Bandit
def parse_bandit(data: dict, root: Path | None = None) -> list[Finding]:
    out = []
    for r in data.get("results", []):
        cwe = (r.get("issue_cwe") or {}).get("id")
        out.append(Finding(
            title=f"{r.get('test_name', '').replace('_', ' ')} ({r.get('test_id')})",
            severity=Severity.parse(r.get("issue_severity"), Severity.low),
            confidence=Confidence(str(r.get("issue_confidence", "medium")).lower()),
            tool="bandit", rule_id=r.get("test_id", ""), category="code",
            description=r.get("issue_text", ""), evidence=(r.get("code") or "").strip(),
            references=[r["more_info"]] if r.get("more_info") else [],
            location=Location(file=_rel(r.get("filename", ""), root), line=r.get("line_number")),
            cwe=[f"CWE-{cwe}"] if cwe else [],
        ))
    return out


class BanditScanner(Scanner):
    name = "bandit"
    min_profile = "standard"
    description = "Python-specific SAST"

    def applicable(self, ctx):
        ok, why = super().applicable(ctx)
        if ok and "python" not in ctx.recon.get("languages", {}):
            return False, "no Python code"
        return ok, why

    def run(self, ctx):
        exe = require("bandit")
        out = ctx.artifact("bandit.json")
        cmd = [exe, "-r", str(ctx.source_dir), "-f", "json", "-o", str(out), "-q",
               "-x", ",".join(f"*/{d}/*" for d in ("node_modules", ".venv", "venv", "tests", "test"))]
        pyproject = ctx.source_dir / "pyproject.toml"
        if pyproject.exists() and "[tool.bandit]" in pyproject.read_text(errors="ignore"):
            cmd += ["-c", str(pyproject)]  # honour the project's own bandit config (skips, excludes)
        run(cmd, ctx.settings.tool_timeout, ok_codes=(0, 1))
        return parse_bandit(json.loads(out.read_text()), ctx.source_dir)


# ----------------------------------------------------------------- Gitleaks
def parse_gitleaks(data: list) -> list[Finding]:
    out = []
    for r in data or []:
        commit = r.get("Commit") or ""
        out.append(Finding(
            title=f"Hard-coded secret: {r.get('Description') or r.get('RuleID')}",
            severity=Severity.high, confidence=Confidence.medium, tool="gitleaks", rule_id=r.get("RuleID", ""),
            category="secret",
            description="A credential or key was found in the source" + (f" (commit {commit[:10]})" if commit else "")
                        + ". Rotate it, remove it from git history, and load it from a secret store or env var.",
            evidence=r.get("Match", "")[:300],
            location=Location(file=r.get("File"), line=r.get("StartLine")),
            cwe=["CWE-798"], owasp_llm=["LLM02:2025"] if "openai" in str(r.get("RuleID", "")).lower()
            or "anthropic" in str(r.get("RuleID", "")).lower() or "huggingface" in str(r.get("RuleID", "")).lower() else [],
            remediation="Revoke/rotate the secret immediately; purge it from history (git filter-repo); use a secret manager.",
        ))
    return out


class GitleaksScanner(Scanner):
    name = "gitleaks"
    description = "Secrets in code and git history"

    def run(self, ctx):
        exe = require("gitleaks")
        out = ctx.artifact("gitleaks.json")
        cmd = [exe, "detect", "--source", str(ctx.source_dir), "--report-format", "json", "--report-path", str(out),
               "--redact", "--no-banner", "--exit-code", "0"]
        if not (ctx.source_dir / ".git").exists():
            cmd.append("--no-git")
        run(cmd, ctx.settings.tool_timeout)
        return parse_gitleaks(json.loads(out.read_text() or "[]"))


# ----------------------------------------------------------------- Syft + Grype
def parse_grype(data: dict) -> list[Finding]:
    out = []
    for m in data.get("matches", []):
        v = m.get("vulnerability", {})
        a = m.get("artifact", {})
        ids = [v.get("id", "")] + [rv.get("id", "") for rv in m.get("relatedVulnerabilities", [])]
        cves = sorted({i for i in ids if i.startswith("CVE-")})
        scores = [c.get("metrics", {}).get("baseScore") for c in (v.get("cvss") or []) + sum(
            [rv.get("cvss") or [] for rv in m.get("relatedVulnerabilities", [])], [])]
        scores = [s for s in scores if isinstance(s, (int, float))]
        fix = (v.get("fix") or {}).get("versions") or []
        locs = [l.get("path") for l in a.get("locations", []) if l.get("path")]
        desc = v.get("description") or next((rv.get("description") for rv in m.get("relatedVulnerabilities", [])
                                             if rv.get("description")), "")
        cwe = []
        name = (a.get("name") or "").lower()
        out.append(Finding(
            title=f"{v.get('id')} in {a.get('name')} {a.get('version')}",
            severity=Severity.parse(v.get("severity"), Severity.medium), confidence=Confidence.high,
            tool="grype", rule_id=v.get("id", ""), category="dependency", description=desc or "",
            references=(v.get("urls") or [])[:5], cve=cves, cwe=cwe, cvss=max(scores) if scores else None,
            fixed_version=", ".join(fix) or None,
            location=Location(component=a.get("name"), version=a.get("version"), file=locs[0] if locs else None),
            remediation=f"Upgrade {a.get('name')} to {', '.join(fix)}." if fix else "No fixed version yet; assess exposure or replace the package.",
            owasp_llm=["LLM03:2025"] if name in AI_LIB_NAMES else [],
        ))
    return out


class GrypeScanner(Scanner):
    name = "grype"
    description = "SBOM (Syft) + known-vulnerable dependencies (Grype)"

    def run(self, ctx):
        syft, grype = require("syft"), require("grype")
        sbom = ctx.artifact("sbom.cdx.json")
        run([syft, f"dir:{ctx.source_dir}", "-o", f"cyclonedx-json={sbom}", "-q"], ctx.settings.tool_timeout)
        out = ctx.artifact("grype.json")
        try:
            run([grype, f"sbom:{sbom}", "-o", "json", "--file", str(out)], ctx.settings.tool_timeout)
            return parse_grype(json.loads(out.read_text()))
        except RuntimeError as e:
            # Most common cause: the vulnerability DB could not be downloaded. Fall back to Trivy's DB.
            ctx.log(f"grype failed ({str(e)[-200:]}); falling back to trivy vulnerability scan")
            trivy = require("trivy")
            tout = ctx.artifact("trivy-vulns.json")
            try:
                run([trivy, "fs", "--scanners", "vuln", "--format", "json", "--output", str(tout), "--quiet",
                     str(ctx.source_dir)], ctx.settings.tool_timeout)
            except RuntimeError as e2:
                raise RuntimeError("could not download a vulnerability database (grype: toolbox-data.anchore.io, "
                                   f"trivy: mirror.gcr.io/ghcr.io). Check internet access. {str(e2)[-200:]}") from e2
            return parse_trivy_vulns(json.loads(tout.read_text()))


def parse_trivy_vulns(data: dict) -> list[Finding]:
    out = []
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            scores = [s.get("V3Score") for s in (v.get("CVSS") or {}).values() if s.get("V3Score")]
            name = (v.get("PkgName") or "").lower()
            vid = v.get("VulnerabilityID", "")
            fix = v.get("FixedVersion")
            out.append(Finding(
                title=f"{vid} in {v.get('PkgName')} {v.get('InstalledVersion')}",
                severity=Severity.parse(v.get("Severity"), Severity.medium), confidence=Confidence.high, tool="trivy",
                rule_id=vid, category="dependency", description=v.get("Title") or v.get("Description") or "",
                references=(v.get("References") or [])[:5], cve=[vid] if vid.startswith("CVE-") else [],
                cwe=v.get("CweIDs") or [], cvss=max(scores) if scores else None, fixed_version=fix,
                location=Location(component=v.get("PkgName"), version=v.get("InstalledVersion"), file=res.get("Target")),
                remediation=f"Upgrade {v.get('PkgName')} to {fix}." if fix else "No fixed version yet.",
                owasp_llm=["LLM03:2025"] if name in AI_LIB_NAMES else [],
            ))
    return out


# ----------------------------------------------------------------- Trivy (IaC misconfig)
def parse_trivy(data: dict) -> list[Finding]:
    out = []
    for res in data.get("Results", []) or []:
        for m in res.get("Misconfigurations", []) or []:
            if m.get("Status", "FAIL") != "FAIL":
                continue
            cause = m.get("CauseMetadata") or {}
            out.append(Finding(
                title=m.get("Title") or m.get("ID", ""), severity=Severity.parse(m.get("Severity"), Severity.medium),
                confidence=Confidence.high, tool="trivy", rule_id=m.get("AVDID") or m.get("ID", ""), category="iac",
                description=(m.get("Description") or "") + ("\n" + m["Message"] if m.get("Message") else ""),
                remediation=m.get("Resolution", ""), references=(m.get("References") or [])[:4],
                location=Location(file=res.get("Target"), line=cause.get("StartLine")),
            ))
    return out


class TrivyScanner(Scanner):
    name = "trivy"
    min_profile = "standard"
    description = "Infrastructure-as-code misconfiguration (Dockerfile, Kubernetes, Terraform, CloudFormation)"

    def applicable(self, ctx):
        ok, why = super().applicable(ctx)
        if ok and not ctx.recon.get("iac"):
            return False, "no Dockerfile / Kubernetes / Terraform files"
        return ok, why

    def run(self, ctx):
        exe = require("trivy")
        out = ctx.artifact("trivy.json")
        cmd = [exe, "fs", "--scanners", "misconfig", "--format", "json", "--output", str(out), "--quiet"]
        ignore = ctx.source_dir / ".trivyignore"
        if ignore.exists():  # honour the scanned project's own trivy ignore list
            cmd += ["--ignorefile", str(ignore)]
        cmd.append(str(ctx.source_dir))
        run(cmd, ctx.settings.tool_timeout)
        return parse_trivy(json.loads(out.read_text()))


# ----------------------------------------------------------------- ModelScan
def parse_modelscan(data: dict, root: Path | None = None) -> list[Finding]:
    out = []
    for i in data.get("issues", []) or []:
        src = str(i.get("source", ""))
        out.append(Finding(
            title=f"Unsafe operator in model file: {i.get('module', '')}.{i.get('operator', '')}",
            severity=Severity.parse(i.get("severity"), Severity.high), confidence=Confidence.high,
            tool="modelscan", rule_id=f"{i.get('module')}.{i.get('operator')}", category="ai",
            description=i.get("description", "") + " Loading this model can execute arbitrary code.",
            location=Location(file=_rel(src.split(":")[0], root)),
            cwe=["CWE-502"], owasp_llm=["LLM03:2025", "LLM04:2025"],
            remediation="Only load models from trusted sources; prefer the safetensors format; never unpickle untrusted files.",
        ))
    return out


class ModelScanScanner(Scanner):
    name = "modelscan"
    description = "Serialized ML model files that execute code on load (pickle, h5, ...)"

    def applicable(self, ctx):
        ok, why = super().applicable(ctx)
        if ok and not ctx.recon.get("model_files"):
            return False, "no model files"
        return ok, why

    def run(self, ctx):
        exe = require("modelscan")
        out = ctx.artifact("modelscan.json")
        run([exe, "-p", str(ctx.source_dir), "-r", "json", "-o", str(out)], ctx.settings.tool_timeout, ok_codes=None)
        if not out.exists():
            raise ToolSkipped("modelscan produced no report")
        return parse_modelscan(json.loads(out.read_text()), ctx.source_dir)
