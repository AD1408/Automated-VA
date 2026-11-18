# Remediation guidance for common weaknesses (CWE)

## CWE-89 SQL Injection
Use prepared statements with bound parameters or an ORM for every query; never format user input into SQL strings. Use least-privilege database accounts and validate input types. Python: cursor.execute("SELECT * FROM t WHERE id = %s", (id,)). Node: db.query("... WHERE id = $1", [id]).

## CWE-79 Cross-site Scripting (XSS)
Rely on framework auto-escaping; never insert untrusted data with innerHTML, dangerouslySetInnerHTML, v-html or |safe; sanitise rich HTML with DOMPurify; deploy a strict Content-Security-Policy without unsafe-inline; set HttpOnly on session cookies.

## CWE-78 OS Command Injection
Avoid shells: call programs with an argument list (subprocess.run([...], shell=False)); allow-list permitted values; never pass user input to os.system, exec or child_process.exec.

## CWE-22 Path Traversal
Resolve the requested path and verify it stays inside the intended base directory; use generated ids rather than user-provided filenames; reject '..' and absolute paths.

## CWE-918 Server-Side Request Forgery (SSRF)
Allow-list destination hosts and schemes; resolve DNS and block private, loopback and link-local ranges (including 169.254.169.254); disable redirects or re-validate after each one; use IMDSv2 on AWS.

## CWE-352 Cross-Site Request Forgery
Use the framework's anti-CSRF tokens for state-changing requests, SameSite=Lax/Strict cookies, and verify Origin/Referer on sensitive endpoints.

## CWE-798 Hard-coded Credentials
Revoke and rotate the exposed credential first. Remove it from git history (git filter-repo or BFG), load secrets from environment variables or a secret manager, and add pre-commit secret scanning (gitleaks).

## CWE-502 Deserialization of Untrusted Data
Do not unpickle, unmarshal or deserialize untrusted data; use JSON with schema validation. For ML models use safetensors and torch.load(weights_only=True).

## CWE-327 Broken or Risky Cryptographic Algorithm
Replace MD5/SHA1/DES/RC4/ECB with SHA-256+, AES-GCM or ChaCha20-Poly1305; hash passwords with Argon2id/bcrypt/scrypt; use a maintained crypto library rather than custom code.

## CWE-287 Improper Authentication
Use a proven authentication framework; enforce MFA for privileged users; protect every endpoint by default; throttle login attempts; regenerate session ids on login.

## CWE-862 Missing Authorization
Check permissions on every request server-side, including APIs called by single-page apps; verify object ownership (IDOR); deny by default and write tests for access-control rules.

## CWE-601 Open Redirect
Only redirect to relative paths or an allow-list of hosts; never redirect to a URL taken directly from a parameter.

## CWE-611 XML External Entities (XXE)
Disable DTDs and external entity resolution in XML parsers (defusedxml in Python); prefer JSON.

## CWE-434 Unrestricted File Upload
Validate extension and content type against an allow-list, rename files, store them outside the web root or in object storage, scan them, and serve them with Content-Disposition: attachment.

## CWE-200 Information Exposure
Remove version banners, debug endpoints and verbose errors; restrict access to internal files (.git, .env, backups); return only the fields clients need.

## CWE-209 Error Message Information Leak
Use generic error pages in production, disable debug mode, and log details server-side with a correlation id.

## CWE-693 Missing Security Headers
Add Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options: nosniff, Referrer-Policy and frame-ancestors (or X-Frame-Options) via the web server or middleware (e.g. helmet for Express, django-csp, Talisman for Flask).

## CWE-614 / CWE-1004 Insecure Cookies
Set Secure, HttpOnly and SameSite on session cookies; scope Path and Domain narrowly; keep lifetimes short.

## CWE-942 Permissive CORS
Allow-list exact trusted origins; never reflect the Origin header together with Access-Control-Allow-Credentials: true; avoid 'null' origins.

## CWE-319 Cleartext Transmission
Serve everything over HTTPS, redirect HTTP to HTTPS, enable HSTS (with preload when ready), and encrypt internal service traffic.

## CWE-1427 Prompt Injection
Separate instructions from untrusted content, classify inputs and retrieved documents with an injection detector (Prompt Guard 2), restrict tool permissions, and require confirmation for consequential actions.

## CWE-770 Resource Allocation Without Limits
Set limits on request size, rate, concurrency, tokens and execution time; add quotas per user and alerting on spikes.
