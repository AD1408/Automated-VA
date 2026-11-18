"""Cloud posture: Prowler (AWS / Azure / GCP / Kubernetes). Uses credentials from the environment."""
from __future__ import annotations

import json

from ..models import Confidence, Finding, Location, Severity
from ..runner import require, run
from .base import ScanContext, Scanner


def parse_prowler_ocsf(items: list[dict]) -> list[Finding]:
    out = []
    for i in items:
        if str(i.get("status_code", "")).upper() != "FAIL":
            continue
        info = i.get("finding_info", {}) or {}
        res = (i.get("resources") or [{}])[0]
        rem = i.get("remediation", {}) or {}
        out.append(Finding(
            title=info.get("title") or i.get("message", "Prowler check failed"),
            severity=Severity.parse(i.get("severity"), Severity.medium), confidence=Confidence.high, tool="prowler",
            rule_id=(i.get("metadata", {}) or {}).get("event_code", ""), category="cloud",
            description=info.get("desc", "") + ("\n" + i["status_detail"] if i.get("status_detail") else ""),
            remediation=rem.get("desc", ""), references=(rem.get("references") or [])[:4],
            location=Location(resource=res.get("uid") or res.get("name"), host=res.get("region")),
        ))
    return out


class ProwlerScanner(Scanner):
    name = "prowler"
    needs = "cloud"
    heavy = True
    description = "Cloud security posture (CIS, misconfigurations) for AWS/Azure/GCP/Kubernetes"

    def run(self, ctx: ScanContext) -> list[Finding]:
        exe = require("prowler")
        provider = ctx.request.cloud_provider
        if provider not in ("aws", "azure", "gcp", "kubernetes"):
            raise ValueError(f"unsupported cloud provider {provider!r}")
        outdir = ctx.artifact("prowler")
        cmd = [exe, provider, "--output-formats", "json-ocsf", "--output-directory", str(outdir),
               "--output-filename", "prowler", "--status", "FAIL", "--ignore-exit-code-3", "--no-banner"]
        if provider == "azure":
            cmd.append("--sp-env-auth")
        run(cmd, max(ctx.settings.tool_timeout, 3600), ok_codes=None)
        files = list(outdir.glob("*.ocsf.json"))
        if not files:
            raise RuntimeError("Prowler produced no output - check the cloud credentials in .env")
        return parse_prowler_ocsf(json.loads(files[0].read_text()))
