from vulnscan.models import Severity
from vulnscan.report.render import render_html, to_sarif
from vulnscan.scanners.code import parse_bandit, parse_gitleaks, parse_grype, parse_semgrep, parse_trivy
from vulnscan.scanners.network import parse_nmap_xml
from vulnscan.scanners.web import (parse_nuclei, parse_sqlmap_csv, parse_testssl, parse_zap_alerts,
                                   pick_injection_candidates)

NMAP_XML = """<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.5" addrtype="ipv4"/>
<hostnames><hostname name="target"/></hostnames><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="7.4"/>
<script id="vulners" output="cpe:/a:openbsd:openssh:7.4:&#xa;    CVE-2023-38408  9.8  https://vulners.com/cve/CVE-2023-38408&#xa;    CVE-2020-15778  6.8  https://vulners.com/cve/CVE-2020-15778"/></port>
<port protocol="tcp" portid="6379"><state state="open"/><service name="redis"/></port>
<port protocol="tcp" portid="81"><state state="closed"/></port>
</ports></host></nmaprun>"""


def test_nmap():
    findings, services = parse_nmap_xml(NMAP_XML)
    assert len(services) == 2
    cves = [f for f in findings if f.cve]
    assert {f.cve[0] for f in cves} == {"CVE-2023-38408", "CVE-2020-15778"}
    assert next(f for f in cves if f.cve[0] == "CVE-2023-38408").severity == Severity.critical
    assert any(f.location.port == 6379 and f.severity == Severity.medium for f in findings)


def test_semgrep():
    data = {"results": [{"check_id": "python.lang.security.audit.sqli", "path": "/src/app.py", "start": {"line": 9},
                         "extra": {"severity": "ERROR", "message": "SQLi", "lines": "cur.execute(q)",
                                   "metadata": {"cwe": ["CWE-89: SQL Injection"], "confidence": "HIGH"}}}]}
    f = parse_semgrep(data)[0]
    assert f.severity == Severity.high and f.location.line == 9 and f.cwe == ["CWE-89: SQL Injection"]


def test_bandit_gitleaks_grype_trivy():
    b = parse_bandit({"results": [{"filename": "a.py", "line_number": 3, "issue_severity": "HIGH", "issue_confidence": "HIGH",
                                   "issue_text": "shell", "test_id": "B602", "test_name": "subprocess_popen_with_shell_equals_true",
                                   "issue_cwe": {"id": 78}}]})
    assert b[0].cwe == ["CWE-78"]
    g = parse_gitleaks([{"Description": "Generic API Key", "RuleID": "generic-api-key", "File": "app.py", "StartLine": 7, "Match": "api_key=REDACTED"}])
    assert g[0].category == "secret"
    gr = parse_grype({"matches": [{"vulnerability": {"id": "GHSA-x", "severity": "High", "fix": {"versions": ["2.3"]},
                                                     "cvss": [{"metrics": {"baseScore": 7.5}}]},
                                   "relatedVulnerabilities": [{"id": "CVE-2020-1", "cvss": [{"metrics": {"baseScore": 8.1}}]}],
                                   "artifact": {"name": "transformers", "version": "4.30.0", "locations": [{"path": "/requirements.txt"}]}}]})
    assert gr[0].cve == ["CVE-2020-1"] and gr[0].cvss == 8.1 and gr[0].owasp_llm == ["LLM03:2025"]
    t = parse_trivy({"Results": [{"Target": "Dockerfile", "Misconfigurations": [{"ID": "DS002", "Title": "root user", "Severity": "HIGH", "Status": "FAIL"}]}]})
    assert t[0].severity == Severity.high


def test_web_parsers():
    n = parse_nuclei(['{"template-id":"git-config","info":{"name":"Git Config","severity":"medium","classification":{"cwe-id":["cwe-538"]}},"matched-at":"http://x/.git/config"}'])
    assert n[0].cwe == ["CWE-538"]
    z = parse_zap_alerts([{"pluginId": "40012", "alert": "XSS", "risk": "High", "confidence": "Medium", "url": "http://x/?q=1", "param": "q", "cweid": "79"},
                          {"pluginId": "40012", "alert": "XSS", "risk": "High", "confidence": "Medium", "url": "http://x/?q=2", "param": "q", "cweid": "79"}])
    assert len(z) == 1 and z[0].cwe == ["CWE-79"]
    s = parse_sqlmap_csv("Target URL,Place,Parameter,Technique(s),Note(s)\nhttp://x/a?id=1,GET,id,BT,\n")
    assert s[0].severity == Severity.critical and s[0].location.param == "id"
    t = parse_testssl([{"id": "TLS1", "severity": "MEDIUM", "finding": "offered", "port": "443", "ip": "x/1.2.3.4"},
                       {"id": "TLS1_3", "severity": "OK", "finding": "offered"}])
    assert len(t) == 1
    c = pick_injection_candidates(["http://x/a?id=1", "http://x/a?id=2", "http://x/b", "http://x/c?q=1&p=2"])
    assert c == ["http://x/a?id=1", "http://x/c?q=1&p=2"]


def test_report_renders():
    from vulnscan.pipeline import build_result
    from vulnscan.models import Finding, Location, ToolRun, ToolStatus
    f = Finding(title="SQLi <script>", tool="sqlmap", severity=Severity.critical, cwe=["CWE-89"], owasp=["A05:2025"],
                location=Location(url="http://x/?id=1", param="id"), sources=["sqlmap"])
    res = build_result({"scan_id": "s", "target": "http://x", "kind": "url", "profile": "quick", "started_at": "2026-01-01T00:00:00",
                        "finished_at": "2026-01-01T00:01:00"}, {"languages": {"python": 3}}, [ToolRun(tool="sqlmap", status=ToolStatus.ok, findings=1)],
                       [f], "summary")
    html = render_html(res)
    assert "SQLi &lt;script&gt;" in html and "A05" in html
    assert to_sarif(res)["runs"][0]["results"][0]["level"] == "error"
    assert res["coverage"]["A05:2025"]["findings"] == 1
