"""Compliance / audit frameworks and how scan findings map to their controls.

This turns a vulnerability scan into an audit: each control is marked
  - gap          : an open finding maps to it,
  - pass         : the area was tested and nothing was found,
  - not_assessed : this control is outside what an automated scan can judge
                   (physical security, HR, governance, paper processes...).

Control identifiers and short ORIGINAL summaries are included for reference and mapping.
Full normative text of ISO/PCI/etc. is copyrighted and intentionally NOT reproduced; consult the
official publications for the authoritative wording. `triggers` lists the OWASP Top-10 (2025),
OWASP LLM Top-10 or finding-category keys that make a control a gap when an open finding matches.
"""
from __future__ import annotations

from .models import Finding, Severity
from .owasp import COVERAGE

# A control: (id, title, one-line original summary, [trigger keys])
# trigger keys: "A0x:2025", "LLMxx:2025", or a finding category: code/secret/dependency/iac/
# network/web/tls/cloud/ai/design
FRAMEWORKS: dict[str, dict] = {
    "OWASP ASVS 4.0": {
        "short": "ASVS",
        "url": "https://owasp.org/www-project-application-security-verification-standard/",
        "desc": "Application Security Verification Standard — what to verify in a web app.",
        "controls": [
            ("V1", "Architecture & Threat Modelling", "Security is designed in, with a documented threat model.", ["A06:2025", "design"]),
            ("V2", "Authentication", "Strong authentication, MFA, no default or hard-coded credentials.", ["A07:2025", "secret"]),
            ("V3", "Session Management", "Secure, rotated session tokens with proper cookie flags.", ["A07:2025", "web"]),
            ("V4", "Access Control", "Enforced server-side authorization; no IDOR or SSRF.", ["A01:2025"]),
            ("V5", "Validation, Sanitisation & Encoding", "Input validated and output encoded to stop injection/XSS.", ["A05:2025", "A10:2025"]),
            ("V6", "Stored Cryptography", "Modern algorithms; secrets protected at rest.", ["A04:2025"]),
            ("V7", "Error Handling & Logging", "Errors handled safely; security events logged, no secrets in logs.", ["A09:2025", "A10:2025"]),
            ("V8", "Data Protection", "Sensitive data minimised and protected.", ["A04:2025", "A02:2025"]),
            ("V9", "Communications", "TLS everywhere with strong configuration.", ["A04:2025", "tls"]),
            ("V10", "Malicious Code", "No backdoors; dependency and model integrity verified.", ["A08:2025", "LLM03:2025"]),
            ("V12", "Files & Resources", "Safe file upload/handling.", ["A05:2025", "A02:2025"]),
            ("V13", "API & Web Service", "APIs enforce the same controls; no misconfiguration.", ["A02:2025", "A01:2025"]),
            ("V14", "Configuration", "Hardened build, patched dependencies, no debug exposure.", ["A02:2025", "A03:2025", "iac", "dependency"]),
        ],
    },
    "NIST CSF 2.0": {
        "short": "NIST",
        "url": "https://www.nist.gov/cyberframework",
        "desc": "Cybersecurity Framework — Govern, Identify, Protect, Detect, Respond, Recover.",
        "controls": [
            ("GV", "Govern", "Security governance, roles and risk strategy are established.", []),
            ("ID.AM", "Identify: Asset Management", "Assets, software and dependencies are inventoried.", ["A03:2025", "dependency"]),
            ("ID.RA", "Identify: Risk Assessment", "Vulnerabilities are identified and risk-assessed.", ["A03:2025", "A06:2025"]),
            ("PR.AA", "Protect: Identity & Access", "Authentication and access control enforced.", ["A01:2025", "A07:2025"]),
            ("PR.DS", "Protect: Data Security", "Data protected in transit and at rest.", ["A04:2025", "tls", "secret"]),
            ("PR.PS", "Protect: Platform Security", "Secure configuration and patching.", ["A02:2025", "A05:2025", "A08:2025", "iac"]),
            ("DE.CM", "Detect: Continuous Monitoring", "Systems are monitored for events.", ["A09:2025"]),
            ("RS.MA", "Respond", "Incident response is prepared.", []),
            ("RC.RP", "Recover", "Recovery planning exists.", []),
        ],
    },
    "CIS Controls v8": {
        "short": "CIS",
        "url": "https://www.cisecurity.org/controls",
        "desc": "18 prioritised safeguards for cyber defence.",
        "controls": [
            ("CIS-2", "Inventory of Software Assets", "Track all software and its versions.", ["A03:2025", "dependency"]),
            ("CIS-3", "Data Protection", "Protect sensitive data; no exposed secrets.", ["A04:2025", "secret", "tls"]),
            ("CIS-4", "Secure Configuration", "Harden systems and applications.", ["A02:2025", "iac", "cloud"]),
            ("CIS-5", "Account Management", "Manage accounts; no default credentials.", ["A07:2025"]),
            ("CIS-6", "Access Control Management", "Least-privilege access enforced.", ["A01:2025"]),
            ("CIS-7", "Continuous Vulnerability Management", "Find and remediate vulnerabilities continuously.", ["A03:2025", "A06:2025", "network"]),
            ("CIS-8", "Audit Log Management", "Collect and review logs.", ["A09:2025"]),
            ("CIS-16", "Application Software Security", "Secure the software you develop and run.", ["A05:2025", "A08:2025", "A10:2025", "code", "ai"]),
            ("CIS-18", "Penetration Testing", "Test defences from an attacker's view.", ["web"]),
        ],
    },
    "ISO/IEC 27001:2022": {
        "short": "ISO",
        "url": "https://www.iso.org/standard/27001",
        "desc": "ISMS requirements — Annex A controls (themes A.5–A.8).",
        "controls": [
            ("A.5", "Organizational Controls", "Policies, supplier and threat-intelligence management.", ["A03:2025"]),
            ("A.6", "People Controls", "Awareness, responsibilities and screening.", []),
            ("A.7", "Physical Controls", "Physical and environmental security.", []),
            ("A.8.2", "Privileged Access Rights", "Restrict and control privileged access.", ["A01:2025", "A07:2025"]),
            ("A.8.5", "Secure Authentication", "Strong authentication technologies.", ["A07:2025", "secret"]),
            ("A.8.8", "Technical Vulnerability Mgmt", "Identify and remediate technical vulnerabilities.", ["A03:2025", "A06:2025", "dependency", "network"]),
            ("A.8.9", "Configuration Management", "Securely configure hardware and software.", ["A02:2025", "iac", "cloud"]),
            ("A.8.24", "Use of Cryptography", "Proper use of cryptography and keys.", ["A04:2025", "tls"]),
            ("A.8.26", "Application Security Requirements", "Security requirements for applications.", ["A05:2025", "A08:2025", "A10:2025", "code", "ai"]),
            ("A.8.28", "Secure Coding", "Apply secure coding principles.", ["A05:2025", "code"]),
        ],
    },
    "PCI DSS 4.0": {
        "short": "PCI",
        "url": "https://www.pcisecuritystandards.org/",
        "desc": "Protecting cardholder data (applies if you handle payment cards).",
        "controls": [
            ("Req 2", "Secure Configurations", "No vendor defaults; systems hardened.", ["A02:2025", "A07:2025", "iac"]),
            ("Req 3", "Protect Stored Data", "Cardholder data protected at rest.", ["A04:2025", "secret"]),
            ("Req 4", "Encrypt Transmission", "Strong cryptography over open networks.", ["A04:2025", "tls"]),
            ("Req 6", "Secure Systems & Software", "Develop securely and patch vulnerabilities.", ["A03:2025", "A05:2025", "A06:2025", "A08:2025", "code", "dependency", "ai"]),
            ("Req 7", "Restrict Access", "Access on need-to-know.", ["A01:2025"]),
            ("Req 8", "Identify & Authenticate", "Unique IDs and strong authentication.", ["A07:2025"]),
            ("Req 10", "Log & Monitor", "Log and monitor all access.", ["A09:2025"]),
            ("Req 11", "Test Security", "Regularly test security of systems.", ["network", "web"]),
        ],
    },
    "SOC 2 (TSC)": {
        "short": "SOC2",
        "url": "https://www.aicpa-cima.com/",
        "desc": "Trust Services Criteria — common criteria for service organisations.",
        "controls": [
            ("CC6.1", "Logical Access Controls", "Restrict logical access to authorised users.", ["A01:2025", "A07:2025"]),
            ("CC6.6", "Boundary Protection", "Protect against threats from outside boundaries.", ["A02:2025", "network", "web"]),
            ("CC6.7", "Data in Transit", "Protect data during transmission.", ["A04:2025", "tls"]),
            ("CC6.8", "Malicious Software", "Prevent/detect unauthorized or malicious software.", ["A08:2025", "LLM03:2025", "dependency"]),
            ("CC7.1", "Vulnerability Detection", "Detect and monitor vulnerabilities.", ["A03:2025", "A06:2025"]),
            ("CC7.2", "Security Monitoring", "Monitor for anomalies and security events.", ["A09:2025"]),
            ("CC8.1", "Change Management", "Changes are authorised and secure.", ["A02:2025", "iac"]),
        ],
    },
    "GDPR": {
        "short": "GDPR",
        "url": "https://gdpr-info.eu/",
        "desc": "EU data-protection regulation (applies to EU personal data).",
        "controls": [
            ("Art 5", "Principles", "Integrity and confidentiality of personal data.", ["A01:2025", "A04:2025"]),
            ("Art 25", "Data Protection by Design", "Security built in by design and default.", ["A06:2025", "A02:2025", "design"]),
            ("Art 32", "Security of Processing", "Appropriate technical measures incl. encryption.", ["A04:2025", "A05:2025", "A07:2025", "tls", "secret"]),
            ("Art 33/34", "Breach Notification", "Detect and be able to report breaches.", ["A09:2025"]),
        ],
    },
    "HIPAA Security Rule": {
        "short": "HIPAA",
        "url": "https://www.hhs.gov/hipaa/",
        "desc": "US health data safeguards (applies to PHI).",
        "controls": [
            ("Admin", "Administrative Safeguards", "Risk analysis and workforce security.", ["A06:2025"]),
            ("Physical", "Physical Safeguards", "Facility and device controls.", []),
            ("Access", "Technical: Access Control", "Unique IDs and access restriction to PHI.", ["A01:2025", "A07:2025"]),
            ("Transmission", "Technical: Transmission Security", "Encrypt PHI in transit.", ["A04:2025", "tls"]),
            ("Integrity", "Technical: Integrity", "Protect PHI from improper alteration.", ["A05:2025", "A08:2025"]),
            ("Audit", "Technical: Audit Controls", "Record and examine activity.", ["A09:2025"]),
        ],
    },
}


def _matches(triggers: list[str], finding: Finding) -> bool:
    cats = set(finding.owasp) | set(finding.owasp_llm) | {finding.category}
    return bool(set(triggers) & cats)


def _tested(triggers: list[str], tools_ok: set[str]) -> bool:
    """True if at least one OWASP area this control covers was exercised by a tool that ran."""
    owasp_triggers = [t for t in triggers if t[0].isalpha() and ":" in t]
    cat_triggers = [t for t in triggers if t not in owasp_triggers]
    for ot in owasp_triggers:
        if set(COVERAGE.get(ot, [])) & tools_ok:
            return True
    # category triggers: consider tested if any tool ran at all (categories are broad)
    return bool(cat_triggers and tools_ok)


def audit_report(findings: list[Finding], tools_ok: set[str]) -> dict:
    """Build the per-framework audit from open findings."""
    open_f = [f for f in findings if f.status == "open"]
    out = {}
    for name, fw in FRAMEWORKS.items():
        controls = []
        gaps = passed = assessed = 0
        for cid, title, summary, triggers in fw["controls"]:
            mapped = [f for f in open_f if triggers and _matches(triggers, f)]
            mapped.sort(key=lambda f: -f.severity.rank)
            if not triggers:
                status = "not_assessed"
            elif mapped:
                status = "gap"; gaps += 1; assessed += 1
            elif _tested(triggers, tools_ok):
                status = "pass"; passed += 1; assessed += 1
            else:
                status = "not_assessed"
            max_sev = mapped[0].severity.value if mapped else None
            controls.append({
                "id": cid, "title": title, "summary": summary, "status": status,
                "max_severity": max_sev,
                "findings": [{"id": f.fingerprint, "title": f.title, "severity": f.severity.value} for f in mapped[:12]],
                "finding_count": len(mapped),
            })
        score = round(100 * passed / assessed) if assessed else None
        out[name] = {
            "short": fw["short"], "url": fw["url"], "desc": fw["desc"],
            "controls": controls, "gaps": gaps, "passed": passed, "assessed": assessed,
            "total": len(fw["controls"]), "score": score,
            "posture": ("strong" if score is not None and score >= 80 else
                        "fair" if score is not None and score >= 50 else
                        "weak" if score is not None else "insufficient-data"),
        }
    return out


def tag_findings_with_frameworks(findings: list[Finding]) -> None:
    """Annotate each finding with the control ids it maps to (for the finding detail view)."""
    for f in findings:
        hits = []
        for name, fw in FRAMEWORKS.items():
            for cid, _t, _s, triggers in fw["controls"]:
                if triggers and _matches(triggers, f):
                    hits.append(f"{fw['short']} {cid}")
        f.frameworks = hits[:12]
