# MCP servers

The scan pipeline calls the tools directly: it is deterministic and does not need an LLM to run. MCP is the
interactive layer, so an assistant in VS Code (Copilot Chat agent mode), Claude Desktop/Code or Cursor can drive
scans and work with the results.

`.vscode/mcp.json` is preconfigured with **vulnscan**, **semgrep** and **github**. In VS Code open the Command
Palette → *MCP: List Servers* → start the ones you want.

## 1. vulnscan (this project), recommended

Runs inside the API container: `docker exec -i vulnscan-api python -m vulnscan.mcp_server`

| Tool | What it does |
|---|---|
| `start_scan`, `scan_status`, `list_scans` | run and watch scans |
| `get_findings`, `get_report`, `explain_finding` | read results, report links, RAG+LLM explanations |
| `check_scope` | is a host allowed / how to verify it |
| `run_nmap`, `run_nuclei`, `run_nikto`, `run_sqlmap` | single-tool runs, **scope-checked** |
| `run_gitleaks`, `run_modelscan` | no official MCP server exists for these, so they are provided here |
| `classify_prompt_injection` | score text with Llama Prompt Guard 2 |

Claude Desktop (`claude_desktop_config.json`):
```json
{ "mcpServers": { "vulnscan": { "command": "wsl", "args": ["docker", "exec", "-i", "vulnscan-api", "python", "-m", "vulnscan.mcp_server"] } } }
```

## 2. The servers you listed: review notes

| Server | Status | How to run | Notes |
|---|---|---|---|
| [semgrep/mcp](https://github.com/semgrep/mcp) | official | `docker run -i --rm ghcr.io/semgrep/mcp -t stdio` | in mcp.json |
| [github/github-mcp-server](https://github.com/github/github-mcp-server) | official | `docker run -i --rm -e GITHUB_PERSONAL_ACCESS_TOKEN ghcr.io/github/github-mcp-server` | in mcp.json; use a fine-grained, least-privilege token |
| [anchore/grype-mcp](https://github.com/anchore/grype-mcp) | official | `uvx grype-mcp` | needs `uv` + `grype` on the host |
| [aquasecurity/trivy-mcp](https://github.com/aquasecurity/trivy-mcp) | official (Trivy plugin) | `trivy plugin install mcp` then `trivy mcp` | needs `trivy` on the host |
| [matteocolazilli/GreenboneMCP](https://github.com/matteocolazilli/GreenboneMCP) | community | build its image, run with `--volume greenbone-community-edition_gvmd_socket_vol:/run/gvmd` | works with `scripts/openvas.sh`; review the code and pin a commit |
| [imjdl/nmap-mcpserver](https://github.com/imjdl/nmap-mcpserver) | community | `pip install -e .` then `nmap-mcp` | **accepts any target and raw nmap options, with no scope control**. Prefer `vulnscan.run_nmap` |
| [weldpua2008/nikto-mcp](https://github.com/weldpua2008/nikto-mcp) | community | `npx nikto-mcp@<pinned-version>` | no scope control; prefer `vulnscan.run_nikto` |
| [mohdhaji87/sqlmap-mcp](https://github.com/mohdhaji87/sqlmap-mcp) | community | `python server.py` | can run exploitation options; prefer `vulnscan.run_sqlmap` (detection only) |
| gitleaks (issue #1869) | no server exists | n/a | covered by `vulnscan.run_gitleaks` |
| [protectai/modelscan](https://github.com/protectai/modelscan) | a CLI, not an MCP server | n/a | covered by `vulnscan.run_modelscan` |

Why the community scanner servers are optional: an MCP server that runs attack tools does whatever the model asks.
Prompt injection from scanned content could aim it at hosts you never authorised. The vulnscan server routes every
network action through the same scope check as the pipeline. If you add community servers anyway, read their code
and pin a specific commit or version.
