# Architecture

```
 Browser UI (vanilla JS, served by FastAPI)      VS Code / Claude ── MCP (stdio) ──┐
            │                                                                       │
            ▼                                                                       ▼
   FastAPI  (vulnscan/api.py, :8000)  ◄───────────── vulnscan/mcp_server.py (calls the API)
     │  creates scan row (Postgres) + enqueues job (Redis)
     ▼
   Celery worker (vulnscan/worker.py) → vulnscan/pipeline.py
     1 INGEST   ingest.py   git clone (https only, token via header) / safe ZIP extract / URL normalise
                scope.py    allow-list + ownership verification; metadata IPs always blocked
     2 RECON    recon.py    languages, frameworks, IaC, AI libraries, model files, prompts | HTTP fingerprint, API docs
     3 PLAN     pipeline.py pick scanners by target type, profile, installed binaries
     4 SCAN     scanners/*  stage 1 in parallel (MAX_PARALLEL_TOOLS, heavy tools serialised) → stage 2 (uses
                            URLs crawled by ZAP and page text collected in stage 1)
     5 MERGE    correlate.py  normalise → CWE→OWASP map → de-dupe by fingerprint (cross-tool confirmation)
                              → EPSS + CISA KEV enrichment → RAG guidance (rag.py, BM25 over knowledge/*.md)
     6 TRIAGE   correlate.py  LLM marks likely false positives (never deletes), executive summary
     7 REPORT   report/render.py  HTML (Jinja2) · PDF (WeasyPrint) · JSON · SARIF 2.1.0
   Live progress is written to the scan row every second → UI polls /api/scans/{id}
```

## Containers (docker-compose.yml)

| Service | Purpose | Memory |
|---|---|---|
| api | REST API + UI | small |
| worker | runs scans; contains every CLI scanner | ≤ 8 GB |
| postgres, redis | state + queue | small |
| zap | OWASP ZAP daemon (API-key protected, internal only) | ≤ 4 GB |
| ollama + ollama-pull | local LLM (default `gpt-oss:20b`) | ≤ 16 GB |
| juice-shop, dvwa, demo-chat | practice targets (`--profile targets`) | small |
| Greenbone stack | OpenVAS (separate project via `scripts/openvas.sh`) | ~6–8 GB |

## Finding schema (models.py)

`title, severity, confidence, tool, rule_id, category, description, evidence, remediation, references,
location{file,line,url,param,host,port,component,version,resource}, cwe[], cve[], owasp[], owasp_llm[],
cvss, epss, kev, fixed_version, sources[], status, triage_note, guidance`

Each scanner adapter has a pure `parse_*` function (unit-tested in tests/test_parsers.py) and a `run()` that calls
the tool. Adding a tool = one class with `name`, `needs`, `min_profile`, `stage`, `run()`, registered in
`scanners/__init__.py`.

## Where MCP is used
* **vulnscan MCP server**: AI assistants start scans, read findings, fetch reports, explain findings and run
  single scope-checked tools (nmap, nuclei, nikto, sqlmap, gitleaks, modelscan, Prompt Guard classification).
* **Official servers** for interactive use in VS Code: Semgrep, GitHub (issues/PRs from findings), Grype, Trivy.
  See MCP.md for the review notes on the community servers.

## Where RAG is used
* `knowledge/*.md`: OWASP Top 10 2025, OWASP LLM Top 10 2025 and CWE remediation, retrieved per finding
  (exact ID match first, BM25 fallback). The result appears as "Guidance" in the report and is fed to "Ask AI".
* `scripts/build_kb.py` imports the full MITRE CWE catalogue.
* Upgrade path: swap BM25 for embeddings (e.g. `nomic-embed-text` in Ollama + pgvector in the existing Postgres)
  and add a code index of the scanned repo for reachability questions.

## Security of the scanner itself
* Scope enforced in code for API, CLI, MCP and every network scanner.
* No shell invocation (`subprocess` with argument lists only); ZIP-slip/symlink/zip-bomb protection; HTTPS-only
  clones with protocol restrictions; GitHub token sent as a header, never written to disk.
* UI escapes all scanner-provided text; ZAP API protected by a random key on the internal network.
* SQLMap runs with `--level 1 --risk 1` and no data-extraction options.
