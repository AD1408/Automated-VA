# Compliance & audit frameworks

VulnScan audits a target against these frameworks by mapping findings to their controls. Control IDs and short summaries are for reference; consult the official publications for authoritative text.

## OWASP ASVS 4.0 (ASVS)
Application Security Verification Standard — what to verify in a web app. More: https://owasp.org/www-project-application-security-verification-standard/
- V1 Architecture & Threat Modelling: Security is designed in, with a documented threat model.
- V2 Authentication: Strong authentication, MFA, no default or hard-coded credentials.
- V3 Session Management: Secure, rotated session tokens with proper cookie flags.
- V4 Access Control: Enforced server-side authorization; no IDOR or SSRF.
- V5 Validation, Sanitisation & Encoding: Input validated and output encoded to stop injection/XSS.
- V6 Stored Cryptography: Modern algorithms; secrets protected at rest.
- V7 Error Handling & Logging: Errors handled safely; security events logged, no secrets in logs.
- V8 Data Protection: Sensitive data minimised and protected.
- V9 Communications: TLS everywhere with strong configuration.
- V10 Malicious Code: No backdoors; dependency and model integrity verified.
- V12 Files & Resources: Safe file upload/handling.
- V13 API & Web Service: APIs enforce the same controls; no misconfiguration.
- V14 Configuration: Hardened build, patched dependencies, no debug exposure.

## NIST CSF 2.0 (NIST)
Cybersecurity Framework — Govern, Identify, Protect, Detect, Respond, Recover. More: https://www.nist.gov/cyberframework
- GV Govern: Security governance, roles and risk strategy are established.
- ID.AM Identify: Asset Management: Assets, software and dependencies are inventoried.
- ID.RA Identify: Risk Assessment: Vulnerabilities are identified and risk-assessed.
- PR.AA Protect: Identity & Access: Authentication and access control enforced.
- PR.DS Protect: Data Security: Data protected in transit and at rest.
- PR.PS Protect: Platform Security: Secure configuration and patching.
- DE.CM Detect: Continuous Monitoring: Systems are monitored for events.
- RS.MA Respond: Incident response is prepared.
- RC.RP Recover: Recovery planning exists.

## CIS Controls v8 (CIS)
18 prioritised safeguards for cyber defence. More: https://www.cisecurity.org/controls
- CIS-2 Inventory of Software Assets: Track all software and its versions.
- CIS-3 Data Protection: Protect sensitive data; no exposed secrets.
- CIS-4 Secure Configuration: Harden systems and applications.
- CIS-5 Account Management: Manage accounts; no default credentials.
- CIS-6 Access Control Management: Least-privilege access enforced.
- CIS-7 Continuous Vulnerability Management: Find and remediate vulnerabilities continuously.
- CIS-8 Audit Log Management: Collect and review logs.
- CIS-16 Application Software Security: Secure the software you develop and run.
- CIS-18 Penetration Testing: Test defences from an attacker's view.

## ISO/IEC 27001:2022 (ISO)
ISMS requirements — Annex A controls (themes A.5–A.8). More: https://www.iso.org/standard/27001
- A.5 Organizational Controls: Policies, supplier and threat-intelligence management.
- A.6 People Controls: Awareness, responsibilities and screening.
- A.7 Physical Controls: Physical and environmental security.
- A.8.2 Privileged Access Rights: Restrict and control privileged access.
- A.8.5 Secure Authentication: Strong authentication technologies.
- A.8.8 Technical Vulnerability Mgmt: Identify and remediate technical vulnerabilities.
- A.8.9 Configuration Management: Securely configure hardware and software.
- A.8.24 Use of Cryptography: Proper use of cryptography and keys.
- A.8.26 Application Security Requirements: Security requirements for applications.
- A.8.28 Secure Coding: Apply secure coding principles.

## PCI DSS 4.0 (PCI)
Protecting cardholder data (applies if you handle payment cards). More: https://www.pcisecuritystandards.org/
- Req 2 Secure Configurations: No vendor defaults; systems hardened.
- Req 3 Protect Stored Data: Cardholder data protected at rest.
- Req 4 Encrypt Transmission: Strong cryptography over open networks.
- Req 6 Secure Systems & Software: Develop securely and patch vulnerabilities.
- Req 7 Restrict Access: Access on need-to-know.
- Req 8 Identify & Authenticate: Unique IDs and strong authentication.
- Req 10 Log & Monitor: Log and monitor all access.
- Req 11 Test Security: Regularly test security of systems.

## SOC 2 (TSC) (SOC2)
Trust Services Criteria — common criteria for service organisations. More: https://www.aicpa-cima.com/
- CC6.1 Logical Access Controls: Restrict logical access to authorised users.
- CC6.6 Boundary Protection: Protect against threats from outside boundaries.
- CC6.7 Data in Transit: Protect data during transmission.
- CC6.8 Malicious Software: Prevent/detect unauthorized or malicious software.
- CC7.1 Vulnerability Detection: Detect and monitor vulnerabilities.
- CC7.2 Security Monitoring: Monitor for anomalies and security events.
- CC8.1 Change Management: Changes are authorised and secure.

## GDPR (GDPR)
EU data-protection regulation (applies to EU personal data). More: https://gdpr-info.eu/
- Art 5 Principles: Integrity and confidentiality of personal data.
- Art 25 Data Protection by Design: Security built in by design and default.
- Art 32 Security of Processing: Appropriate technical measures incl. encryption.
- Art 33/34 Breach Notification: Detect and be able to report breaches.

## HIPAA Security Rule (HIPAA)
US health data safeguards (applies to PHI). More: https://www.hhs.gov/hipaa/
- Admin Administrative Safeguards: Risk analysis and workforce security.
- Physical Physical Safeguards: Facility and device controls.
- Access Technical: Access Control: Unique IDs and access restriction to PHI.
- Transmission Technical: Transmission Security: Encrypt PHI in transit.
- Integrity Technical: Integrity: Protect PHI from improper alteration.
- Audit Technical: Audit Controls: Record and examine activity.
