# What you need to provide

| # | Item | Needed for | Where it goes |
|---|---|---|---|
| 1 | Windows + WSL2 Ubuntu + Docker Desktop (WSL integration ON), 20 GB RAM for WSL in `.wslconfig` | everything | your PC |
| 2 | ~40 GB free disk | images, LLM, feeds | your PC |
| 3 | **Hugging Face Read token**, after accepting Meta's licence on the Prompt Guard 2 page | Prompt Guard 2 | `.env` → `HF_TOKEN` |
| 4 | Nothing for the default LLM (Ollama `gpt-oss:20b`, free). Optional: Anthropic key for Claude | triage, design review, Ask AI | `.env` → `LLM_*` |
| 5 | GitHub fine-grained token, read-only *Contents* | **private** repos only | `.env` → `GITHUB_TOKEN` |
| 6 | Websites you own: add to `ALLOWED_TARGETS` or verify them in the UI (Tools & scope) | website scans | `.env` / UI |
| 7 | Login cookie/header for authenticated scans (optional) | deeper web scans | UI → Advanced options |
| 8 | Read-only cloud credentials (optional) | Prowler | `.env` |

Secrets only ever go in `.env` (git-ignored). Never paste them into chat, issues or code.

## LLM choice

| Option | Cost | Notes |
|---|---|---|
| **Ollama `gpt-oss:20b`** (default) | free | OpenAI's open-weight model; best free quality; ~13 GB download / ~14 GB RAM; usable on CPU (mixture-of-experts) |
| Ollama `qwen3:8b` | free | lighter (~6 GB RAM); use when running OpenVAS at the same time |
| Claude (`claude-sonnet-5-5`) | paid API | highest-quality triage and explanations; `LLM_PROVIDER=anthropic` |
| Gemini / Groq free tiers | free (limits) | `LLM_PROVIDER=openai_compat`; free tiers may use your data for training, so avoid sending real findings |

Claude has no free API tier; a claude.ai subscription does not include API access.

## RAM budget (WSL 20 GB)
OpenVAS (~7 GB) + ZAP (~3 GB) + `gpt-oss:20b` (~14 GB) do not all fit at once. Either raise WSL to 24 GB
(`.wslconfig`), use `qwen3:8b` for full-profile scans with OpenVAS, or stop Ollama during OpenVAS scans.
