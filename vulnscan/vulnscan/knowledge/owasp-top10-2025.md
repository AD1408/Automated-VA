# OWASP Top 10 (2025)

## A01:2025 Broken Access Control
Users can act outside their intended permissions: IDOR (changing an id in a URL to read another user's data), missing function-level authorization on API endpoints, privilege escalation, CORS misconfiguration, forced browsing to admin pages, and SSRF (server-side request forgery, merged into A01 in 2025).
Fix: deny by default; enforce authorization server-side on every request using the session identity, never ids supplied by the client; check object ownership in the data layer; centralise access-control logic; rate-limit API access; log and alert on access-control failures; for SSRF, allow-list destination hosts and block internal and metadata addresses.

## A02:2025 Security Misconfiguration
Insecure defaults, unnecessary features or ports enabled, default accounts, verbose errors, missing security headers, permissive cloud storage, debug mode in production, outdated server software banners, XXE-enabled XML parsers.
Fix: a repeatable hardening process for every environment; minimal platform with unused features removed; security headers (CSP, HSTS, X-Content-Type-Options, frame-ancestors); disable directory listing and debug endpoints; automated configuration checks (IaC scanning, CSPM) in CI.

## A03:2025 Software Supply Chain Failures
Vulnerable, unmaintained or malicious third-party components, compromised build pipelines, unsigned artifacts, dependency confusion and typosquatting.
Fix: maintain an SBOM; continuously scan dependencies (Grype/Trivy) and upgrade to fixed versions; pin versions and use lockfiles; only pull from trusted registries; verify signatures; protect CI/CD with least privilege and reviewed workflows; remove unused dependencies.

## A04:2025 Cryptographic Failures
Sensitive data sent in clear text, weak or deprecated algorithms (MD5, SHA1, DES, RC4), weak TLS configuration, hard-coded or reused keys, missing encryption at rest, predictable random numbers, passwords stored without a slow salted hash.
Fix: classify data and encrypt sensitive data in transit (TLS 1.2+, HSTS) and at rest; use vetted libraries with authenticated encryption (AES-GCM, ChaCha20-Poly1305); store passwords with Argon2id, scrypt or bcrypt; use a CSPRNG; keep keys in a KMS or secret manager, never in code.

## A05:2025 Injection
Untrusted data interpreted as code or commands: SQL, NoSQL, OS command, LDAP, XPath, template (SSTI) and expression-language injection, and cross-site scripting (XSS).
Fix: parameterised queries or ORM; never build commands with string concatenation; use safe APIs that avoid the interpreter; context-aware output encoding for XSS (templating auto-escape, CSP); server-side input validation with allow-lists; least-privilege database accounts.

## A06:2025 Insecure Design
Missing or ineffective security controls by design: no threat model, business-logic flaws, missing rate limits on sensitive flows, trusting client-side checks, unrestricted file upload, insecure password-recovery flows.
Fix: threat-model critical flows; use secure design patterns and reference architectures; write abuse-case tests; enforce limits (rate, size, quantity) server-side; segregate tenants; validate file type, size and storage location for uploads.

## A07:2025 Authentication Failures
Credential stuffing and brute force allowed, weak or default passwords, missing MFA, session ids in URLs, sessions not invalidated on logout, weak password recovery, hard-coded credentials in code.
Fix: MFA; block weak and breached passwords; throttle and lock out failed logins with alerting; secure, random, HttpOnly/Secure/SameSite session cookies rotated at login and invalidated at logout; never ship default credentials; keep secrets out of source code and rotate any that leaked.

## A08:2025 Software or Data Integrity Failures
Code or data used without integrity verification: insecure deserialization, auto-updates without signature checks, untrusted CI/CD plugins, loading pickled ML models from untrusted sources.
Fix: digital signatures for code, updates and artifacts; avoid native deserialization of untrusted data (use JSON with schema validation); review CI/CD changes; load ML models only in safe formats (safetensors) from trusted, pinned sources.

## A09:2025 Security Logging and Alerting Failures
Logins, failures and high-value transactions not logged; logs not monitored; no alerting; log injection; sensitive data written to logs.
Fix: log authentication, access-control and input-validation failures with user context; use a consistent, tamper-evident log format; centralise logs and alert on suspicious patterns; never log secrets or full personal data; have an incident response plan.

## A10:2025 Mishandling of Exceptional Conditions
Improper error handling and fail-open logic: unchecked return values, uncaught exceptions that crash services or leak stack traces, NULL dereferences, resource exhaustion, and security checks that fail open on error.
Fix: catch errors where they occur and fail closed; return generic error messages to clients and log details server-side; validate all return values; set resource limits and timeouts; add global exception handlers; test error paths.
