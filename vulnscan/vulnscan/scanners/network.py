"""Network / host scanners: Nmap (+vulners NSE) and OpenVAS (Greenbone Community Edition)."""
from __future__ import annotations

import re
import time
try:
    from defusedxml import ElementTree as ET  # hardened XML parsing (blocks XXE/entity bombs)
except ImportError:  # pragma: no cover
    import xml.etree.ElementTree as ET  # nosec B405 - fallback only; defusedxml used when installed
from pathlib import Path

from ..models import Confidence, Finding, Location, Severity
from ..runner import ToolNotInstalled, ToolSkipped, require, run
from ..scope import ensure_in_scope
from .base import ScanContext, Scanner

RISKY_PORTS = {
    21: "FTP", 23: "Telnet", 445: "SMB", 1433: "MSSQL", 1521: "Oracle DB", 2375: "Docker API (unauthenticated)",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB", 5601: "Kibana", 8500: "Consul", 2379: "etcd", 10250: "Kubelet",
}
CVE_LINE = re.compile(r"(CVE-\d{4}-\d{4,7})\s+(\d{1,2}\.\d)")


def parse_nmap_xml(xml_text: str) -> tuple[list[Finding], list[dict]]:
    findings, services = [], []
    root = ET.fromstring(xml_text)  # nosec B314 - parsed with defusedxml (hardened against XXE)
    for host in root.findall("host"):
        addr = host.find("address[@addrtype='ipv4']")
        if addr is None:
            addr = host.find("address")
        hn = host.find("hostnames/hostname")
        hostname = hn.get("name") if hn is not None else (addr.get("addr") if addr is not None else "?")
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            pnum, proto = int(port.get("portid")), port.get("protocol")
            svc = port.find("service")
            sname = svc.get("name", "") if svc is not None else ""
            product = " ".join(x for x in (svc.get("product", ""), svc.get("version", "")) if x) if svc is not None else ""
            services.append({"host": hostname, "port": pnum, "proto": proto, "service": sname, "product": product,
                             "tunnel": svc.get("tunnel") if svc is not None else None})
            sev = Severity.medium if pnum in RISKY_PORTS else Severity.info
            findings.append(Finding(
                title=f"Open port {pnum}/{proto} ({RISKY_PORTS.get(pnum, sname or 'unknown')})",
                severity=sev, confidence=Confidence.high, tool="nmap", rule_id=f"open-port-{pnum}", category="network",
                description=(f"Service '{sname}' {product}".strip() + " is reachable."
                             + (" This service type should normally not be exposed to untrusted networks." if pnum in RISKY_PORTS else "")),
                location=Location(host=hostname, port=pnum, component=sname, version=product or None),
                remediation="Close the port or restrict it with a firewall/security group if it does not need to be public." if pnum in RISKY_PORTS else "",
            ))
            for script in port.findall("script[@id='vulners']"):
                seen = set()
                for cve, score in CVE_LINE.findall(script.get("output", "")):
                    if cve in seen:
                        continue
                    seen.add(cve)
                    findings.append(Finding(
                        title=f"{cve} in {product or sname} on port {pnum}",
                        severity=Severity.parse(float(score)), confidence=Confidence.low, tool="nmap",
                        rule_id=cve, category="network", cve=[cve], cvss=float(score),
                        description=f"The detected version ({product}) is listed as affected by {cve}. "
                                    "Version-based match - confirm with OpenVAS or the vendor advisory.",
                        references=[f"https://nvd.nist.gov/vuln/detail/{cve}"],
                        location=Location(host=hostname, port=pnum, component=sname, version=product or None),
                        remediation=f"Upgrade {product or sname} to a version that fixes {cve}.",
                    ))
    return findings, services


class NmapScanner(Scanner):
    name = "nmap"
    needs = "web"
    description = "Port/service discovery + CVE lookup for detected versions (vulners NSE)"

    def run(self, ctx: ScanContext) -> list[Finding]:
        exe = require("nmap")
        ensure_in_scope(ctx.host, ctx.settings)
        ports = {"quick": ["--top-ports", "100"], "standard": ["--top-ports", "1000"], "full": ["-p-"]}[ctx.profile]
        out = ctx.artifact("nmap.xml")
        run([exe, "-sV", "-Pn", "-T4", "--open", *ports, "--script", "vulners", "--script-args", "mincvss=5.0",
             "-oX", str(out), ctx.host], ctx.settings.tool_timeout)
        findings, services = parse_nmap_xml(out.read_text())
        ctx.recon["services"] = services
        return findings


# ---------------------------------------------------------------- OpenVAS
FULL_AND_FAST = "daba56c8-73ec-11df-a475-002264764cea"
OPENVAS_SCANNER = "08b69003-5fc2-4037-a479-93b440211c73"
ALL_IANA_TCP = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"


def _tag(tags: str, key: str) -> str:
    for part in (tags or "").split("|"):
        if part.startswith(key + "="):
            return part[len(key) + 1:]
    return ""


def parse_openvas_results(results) -> list[Finding]:
    """`results` is an iterable of lxml/ElementTree <result> elements."""
    out = []
    for r in results:
        sev = float(r.findtext("severity") or 0)
        if sev <= 0:
            continue
        nvt = r.find("nvt")
        tags = nvt.findtext("tags") if nvt is not None else ""
        cves = [ref.get("id") for ref in (nvt.findall("refs/ref") if nvt is not None else []) if ref.get("type") == "cve"]
        urls = [ref.get("id") for ref in (nvt.findall("refs/ref") if nvt is not None else []) if ref.get("type") == "url"]
        port_s = r.findtext("port") or ""
        pm = re.match(r"(\d+)/", port_s)
        host_el = r.find("host")
        host = (host_el.text or "").strip() if host_el is not None else None
        out.append(Finding(
            title=r.findtext("name") or "OpenVAS finding", severity=Severity.parse(sev), confidence=Confidence.high,
            tool="openvas", rule_id=nvt.get("oid") if nvt is not None else "", category="network",
            description="\n".join(x for x in (_tag(tags, "summary"), _tag(tags, "insight"), _tag(tags, "impact")) if x),
            evidence=(r.findtext("description") or "").strip(),
            remediation=(nvt.findtext("solution") if nvt is not None else "") or _tag(tags, "solution"),
            references=urls[:5], cve=cves[:20], cvss=sev,
            location=Location(host=host, port=int(pm.group(1)) if pm else None),
        ))
    return out


class OpenVASScanner(Scanner):
    name = "openvas"
    needs = "web"
    min_profile = "full"
    heavy = True
    description = "Deep network vulnerability scan (Greenbone Community Edition)"

    def run(self, ctx):
        try:
            from gvm.connections import UnixSocketConnection
            from gvm.protocols.gmp import Gmp
            from gvm.transforms import EtreeCheckCommandTransform
        except ImportError as e:
            raise ToolNotInstalled("python-gvm not installed") from e
        if not Path(ctx.settings.gvm_socket).exists():
            raise ToolSkipped("OpenVAS is not running (start it with scripts/openvas.sh up)")
        ensure_in_scope(ctx.host, ctx.settings)
        conn = UnixSocketConnection(path=ctx.settings.gvm_socket, timeout=600)
        with Gmp(connection=conn, transform=EtreeCheckCommandTransform()) as gmp:
            gmp.authenticate(ctx.settings.gvm_username, ctx.settings.gvm_password)
            name = f"vulnscan-{ctx.scan_id}"
            target_id = gmp.create_target(name=name, hosts=[ctx.host], port_list_id=ALL_IANA_TCP).get("id")
            task_id = gmp.create_task(name=name, config_id=FULL_AND_FAST, target_id=target_id,
                                      scanner_id=OPENVAS_SCANNER).get("id")
            report_id = gmp.start_task(task_id).xpath("report_id/text()")[0]
            ctx.log(f"openvas: task {task_id} started (report {report_id})")
            deadline = time.time() + max(ctx.settings.tool_timeout, 4 * 3600)
            status = ""
            while time.time() < deadline:
                t = gmp.get_task(task_id)
                status = (t.xpath("task/status/text()") or [""])[0]
                progress = (t.xpath("task/progress/text()") or ["?"])[0]
                if status in ("Done", "Stopped", "Interrupted"):
                    break
                ctx.log(f"openvas: {status} {progress}%")
                time.sleep(30)
            report = gmp.get_report(report_id, filter_string="apply_overrides=0 min_qod=70 rows=-1 first=1",
                                    details=True, ignore_pagination=True)
            results = report.xpath("report/report/results/result")
            ctx.artifact("openvas-report-id.txt").write_text(report_id)
            if status != "Done":
                ctx.log(f"openvas: task ended with status {status!r}; using partial results")
            return parse_openvas_results(results)
