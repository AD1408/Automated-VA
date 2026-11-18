# Security of VulnScan itself

VulnScan is a security tool, so it is built not to become an attack surface. It scans its own code
(`bash scripts/selfscan.sh`) and ships these protections:

## Hardening built in
- **Scope enforcement in code** (`vulnscan/scope.py`): the API, CLI, MCP server and every network scanner call
  `ensure_in_scope()` before touching a host. Cloud metadata addresses (169.254.169.254) are always refused. An
  LLM/agent can never aim a tool at a host you did not allow or verify.
- **No shell** — all tools run via `subprocess` with an argument list, never `shell=True`; processes run in their
  own group and are killed on cancel/timeout.
- **Safe archive extraction** (`vulnscan/ingest.py`): zip-slip, absolute paths, symlinks and zip-bombs are blocked.
- **HTTPS-only git clone** with protocol restrictions; the GitHub token is passed as a header, never written to
  `.git/config` or logs.
- **Hardened XML parsing** with `defusedxml` (XXE / entity-expansion safe) for Nmap output.
- **Security headers** on every API/UI response: Content-Security-Policy (no inline scripts), X-Frame-Options:
  DENY, X-Content-Type-Options: nosniff, Referrer-Policy, Permissions-Policy, COOP; the `Server` header is stripped.
- **Output escaping**: all scanner-supplied text is HTML-escaped in the UI; the report renders only first-party
  knowledge-base markdown.
- **Optional API key** (`VULNSCAN_API_KEY`) gates every `/api` route; ZAP's control API is protected by a random key
  on the internal Docker network only.
- **Non-root, least privilege**: the demo-chatbot target runs as a non-root user and is isolated; it is intentionally
  vulnerable and must never be exposed outside your machine.
- **Secrets** live only in `.env` (git-ignored) and are never logged.

## Intentional, reviewed exceptions (marked `# nosec`)
- `verify=False` on the HTTP clients in `recon.py` / `scanners/web.py`: a scanner must fingerprint and test targets
  that have invalid or self-signed TLS. These clients are used only against scan targets, never for the tool's own
  outbound calls.
- Binding `0.0.0.0` in `cli.py serve`: the container publishes the service by design; restrict exposure at the
  Docker/host level.

## Reporting
Found an issue in VulnScan itself? Open a GitHub issue (no exploit details in public) or contact the maintainer.
