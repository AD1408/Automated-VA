# VulnScan

Give it a **GitHub repo**, a **ZIP of source code**, a **website URL** or an **AI chatbot endpoint**.
VulnScan works out what the target is made of, runs the right security tools, merges everything into one
de-duplicated list mapped to the **OWASP Top 10 (2025)** and the **OWASP Top 10 for LLM Applications (2025)**,
triages it with a local LLM, and produces an **HTML / PDF / JSON / SARIF report**.

> ⚠️ Only scan systems you own or are explicitly authorised to test. Active scans are restricted to
> `ALLOWED_TARGETS` or domains whose ownership you verified (DNS TXT or `/.well-known` file).

## Quick start (Windows + WSL2 + Docker Desktop)

1. Unzip this project **inside Ubuntu** (e.g. `~/projects/vulnscanner`). Do not put it under `/mnt/c`.
2. In the Ubuntu terminal:
   ```bash
   cd ~/projects/vulnscanner
   bash scripts/setup.sh
   ```
3. Open **http://localhost:8000**.
4. Open the folder in VS Code from Ubuntu with `code .`.

The first build downloads ~3 GB of tools and takes 10–20 minutes. The local LLM (`gpt-oss:20b`, ~13 GB) is
downloaded in the background. Follow progress with `docker compose logs -f ollama-pull`.

Practice targets are started for you:

| Target | Use it as | URL to enter in VulnScan |
|---|---|---|
| OWASP Juice Shop | Website | `http://juice-shop:3000` |
| DVWA | Website | `http://dvwa` |
| Demo chatbot (ShopBot) | AI chatbot | `http://demo-chat:8090/chat` |
| An app on your own PC | Website | `http://host.docker.internal:<port>` |

## What runs

| Input | Tools | Covers |
|---|---|---|
| Repo / ZIP | Semgrep (+ bundled AI/LLM rules), Bandit, Gitleaks, Syft + Grype, Trivy, ModelScan, Prompt Guard 2, LLM design review | Injection, XSS, crypto, auth, secrets, vulnerable deps (SBOM), IaC misconfig, unsafe model files, LLM01–LLM10 code patterns |
| Website | Built-in HTTP checks, Nmap + vulners, Nuclei, Nikto, testssl.sh, OWASP ZAP, SQLMap (detection only), OpenVAS (full profile) | Headers, cookies, CORS, exposed files, ports & service CVEs, web vulns, SQLi, TLS |
| AI chatbot | Canary probes, Prompt Guard 2, garak (optional, full profile) | Prompt injection, system-prompt leakage, data leakage, output handling, hallucinated packages, excessive agency, unbounded consumption |
| Cloud | Prowler (optional build) | AWS / Azure / GCP / Kubernetes posture |

Profiles: **quick** (minutes), **standard** (adds active web scanning + AI checks), **full** (everything incl. OpenVAS & garak).

## Beyond scanning

- **Accuracy engine & false-positive workbench.** Every finding gets a 0–100 **confidence score** and a verdict
  (*verified / likely / needs review / false positive*) computed from tool reliability, cross-tool agreement, exploit
  data (EPSS/KEV) and AI triage — so you're not trusting one model blindly. Open any finding to see *why*, then
  **Confirm** or **Dismiss** it; the counts, report and audit update instantly.
- **Compliance Audit** (`Audit` tab). The same scan is mapped to real control frameworks — **OWASP ASVS, NIST CSF 2.0,
  CIS Controls v8, ISO 27001, PCI DSS 4.0, SOC 2, GDPR, HIPAA** — with a posture score per framework and a
  control-by-control view (gap / pass / not assessed). It's a VA **and** an audit tool.
- **Built-in AI assistant** (the *Ask AI* button, bottom-right). Ask your own questions — *"which findings are false
  positives?"*, *"am I PCI compliant?"*, *"how do I fix CWE-89?"* — answered by your configured LLM, grounded in the
  knowledge base, the frameworks and your current scan.
- **The scanner hardens itself.** VulnScan scans its own code (`bash scripts/selfscan.sh`, currently 0 findings) and
  ships CSP + security headers, hardened XML parsing, scope enforcement and more — see [SECURITY.md](SECURITY.md).

## Using it

* **Web UI**: http://localhost:8000. Live radar, per-tool progress, OWASP coverage grids, findings explorer, and an "Ask AI" button on each finding.
* **API docs**: http://localhost:8000/api/docs.
* **Get a report** once a scan is done:
  `GET /api/scans/<id>/report.html` · `report.pdf` · `report.json` · `report.sarif` · `report.sbom`
* **CLI** (inside the container):
  ```bash
  docker exec -it vulnscan-api vulnscan scan https://github.com/OWASP/NodeGoat --profile quick
  ```
  ```bash
  docker exec -it vulnscan-api vulnscan tools
  ```
* **MCP** (VS Code Copilot Chat / Claude / Cursor): see [docs/MCP.md](docs/MCP.md). `.vscode/mcp.json` is preconfigured.

## Optional add-ons

* **Prompt Guard 2**: accept Meta's licence on the [model page](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M), put a **Read** token in `.env` as `HF_TOKEN`, then `docker compose up -d`.
* **OpenVAS**: `bash scripts/openvas.sh up`, wait for the feed sync (30–60 min), then
  `docker compose -f docker-compose.yml -f docker-compose.openvas.yml up -d`.
* **garak / Prowler**: set `INSTALL_GARAK=true` / `INSTALL_PROWLER=true` in `.env`, then `docker compose build`.
* **Better or lighter LLM**: change `LLM_PROVIDER` / `LLM_MODEL` in `.env` (see comments there).
* **Full CWE knowledge base**: `docker exec vulnscan-api python scripts/build_kb.py`.

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install -e ".[dev,mcp]"
```
```bash
pytest
```
```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d   # live-reload API from ./vulnscan
```

Docs: [Architecture](docs/ARCHITECTURE.md) · [What you need to provide](docs/REQUIREMENTS.md) · [MCP servers](docs/MCP.md)
