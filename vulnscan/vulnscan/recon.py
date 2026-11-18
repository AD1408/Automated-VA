"""Reconnaissance: work out what the target is made of, so the planner can pick tools."""
from __future__ import annotations

import os
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx

SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "dist", "build", ".next", "target", ".tox"}

LANG_BY_EXT = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".ts": "typescript",
    ".tsx": "typescript", ".java": "java", ".kt": "kotlin", ".go": "go", ".rb": "ruby", ".php": "php",
    ".cs": "csharp", ".rs": "rust", ".c": "c", ".cpp": "cpp", ".h": "c", ".swift": "swift", ".scala": "scala",
    ".sh": "shell", ".tf": "terraform", ".sol": "solidity",
}
MODEL_EXTS = {".pkl", ".pickle", ".pt", ".pth", ".h5", ".keras", ".onnx", ".safetensors", ".joblib", ".pb", ".ckpt", ".gguf"}
AI_LIBS = {
    "openai", "anthropic", "langchain", "langgraph", "llama_index", "llama-index", "transformers", "chromadb",
    "pinecone", "faiss", "ollama", "huggingface_hub", "cohere", "mistralai", "google.generativeai", "google-genai",
    "@anthropic-ai/sdk", "@langchain", "litellm", "crewai", "autogen", "semantic_kernel", "weaviate", "qdrant",
    "sentence_transformers", "vllm", "guardrails", "@modelcontextprotocol", "mcp",
}
VECTOR_LIBS = {"chromadb", "pinecone", "faiss", "weaviate", "qdrant", "pgvector", "milvus", "lancedb"}
FRAMEWORKS = {
    "django": "django", "flask": "flask", "fastapi": "fastapi", "express": "express", "next": "nextjs",
    "react": "react", "vue": "vue", "@angular/core": "angular", "spring-boot": "spring", "rails": "rails",
    "laravel/framework": "laravel", "streamlit": "streamlit", "gradio": "gradio",
}
MANIFESTS = {
    "package.json", "requirements.txt", "pyproject.toml", "Pipfile", "poetry.lock", "pom.xml", "build.gradle",
    "go.mod", "Gemfile", "composer.json", "Cargo.toml", "packages.config", "*.csproj",
}


def _iter_files(root: Path, limit: int = 60_000):
    n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            n += 1
            if n > limit:
                return
            yield Path(dirpath) / f


def fingerprint_code(root: Path) -> dict:
    langs: Counter = Counter()
    manifests, model_files, iac, prompt_files = [], [], set(), []
    dep_text = []
    ai_hits: set[str] = set()
    has_git = (root / ".git").exists()
    for p in _iter_files(root):
        rel = str(p.relative_to(root))
        ext = p.suffix.lower()
        if ext in LANG_BY_EXT:
            langs[LANG_BY_EXT[ext]] += 1
        if p.name in MANIFESTS or ext == ".csproj":
            manifests.append(rel)
            try:
                dep_text.append(p.read_text(errors="ignore")[:200_000])
            except OSError:
                pass
        if ext in MODEL_EXTS:
            model_files.append(rel)
        if p.name == "Dockerfile" or p.name.startswith("Dockerfile."):
            iac.add("dockerfile")
        if ext == ".tf":
            iac.add("terraform")
        if p.name in ("docker-compose.yml", "docker-compose.yaml", "compose.yaml"):
            iac.add("compose")
        if ".github/workflows" in rel.replace("\\", "/"):
            iac.add("github-actions")
        if ext in (".yml", ".yaml") and p.stat().st_size < 500_000:
            try:
                head = p.read_text(errors="ignore")[:4000]
                if "apiVersion:" in head and "kind:" in head:
                    iac.add("kubernetes")
                if "AWSTemplateFormatVersion" in head:
                    iac.add("cloudformation")
            except OSError:
                pass
        if ext in (".prompt", ".jinja", ".j2", ".txt", ".md") and "prompt" in rel.lower():
            prompt_files.append(rel)
        if ext in (".py", ".js", ".ts", ".tsx", ".mjs") and p.stat().st_size < 300_000:
            try:
                src = p.read_text(errors="ignore")
            except OSError:
                continue
            for lib in AI_LIBS:
                if re.search(rf"(import\s+{re.escape(lib)}|from\s+{re.escape(lib)}|require\(['\"]{re.escape(lib)}|from\s+['\"]{re.escape(lib)})", src):
                    ai_hits.add(lib)
    deps = "\n".join(dep_text).lower()
    for lib in AI_LIBS:
        if re.search(rf"(?m)(^|[\"'\s/]){re.escape(lib.lower())}([\"'\s=<>~^@:\[]|$)", deps):
            ai_hits.add(lib)
    frameworks = sorted({name for key, name in FRAMEWORKS.items()
                         if re.search(rf"(?m)(^|[\"'\s]){re.escape(key)}([\"'\s=<>~^@:\[]|$)", deps)})
    return {
        "languages": dict(langs.most_common()),
        "manifests": manifests[:200],
        "frameworks": frameworks,
        "iac": sorted(iac),
        "uses_llm": bool(ai_hits),
        "ai_libraries": sorted(ai_hits),
        "uses_vector_db": bool(ai_hits & VECTOR_LIBS),
        "model_files": model_files[:500],
        "prompt_files": prompt_files[:200],
        "has_git_history": has_git,
    }


LLM_HINTS = re.compile(r"(/api/chat|/v1/chat/completions|/chat\b|chatbot|assistant|openai|anthropic|langchain|copilot)", re.I)


def fingerprint_url(url: str, headers: dict | None = None) -> dict:
    info: dict = {"url": url, "reachable": False}
    try:
        with httpx.Client(timeout=15, follow_redirects=True, verify=False, headers=headers or {}) as c:  # nosec B501 - a scanner must fingerprint targets with invalid/self-signed TLS
            r = c.get(url)
            info.update(
                reachable=True,
                status=r.status_code,
                final_url=str(r.url),
                server=r.headers.get("server"),
                powered_by=r.headers.get("x-powered-by"),
                https=str(r.url).startswith("https"),
                cookies=[k for k in r.cookies.keys()],
            )
            m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S)
            info["title"] = m.group(1).strip()[:200] if m else None
            info["llm_hints"] = sorted({h.lower() for h in LLM_HINTS.findall(r.text[:500_000])})[:10]
            api_docs = []
            for path in ("/openapi.json", "/swagger.json", "/v3/api-docs", "/api-docs", "/swagger/v1/swagger.json"):
                try:
                    rr = c.get(urljoin(str(r.url), path))
                    if rr.status_code == 200 and ("openapi" in rr.text[:2000] or "swagger" in rr.text[:2000]):
                        api_docs.append(path)
                except httpx.HTTPError:
                    pass
            info["api_docs"] = api_docs
    except httpx.HTTPError as e:
        info["error"] = str(e)[:300]
    p = urlparse(url)
    info["host"] = p.hostname
    info["port"] = p.port or (443 if p.scheme == "https" else 80)
    return info
