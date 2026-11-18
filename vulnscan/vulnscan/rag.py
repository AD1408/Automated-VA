"""Lightweight RAG over the security knowledge base in vulnscan/knowledge/*.md.

BM25 keyword retrieval: no embedding model or vector DB needed, runs instantly on CPU.
Add more knowledge by dropping Markdown files (one '## ' section per topic) into that folder,
or run `python scripts/build_kb.py` to import the full MITRE CWE catalogue.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from rank_bm25 import BM25Okapi

from .models import Finding

KB_DIR = Path(__file__).resolve().parent / "knowledge"
TOKEN = re.compile(r"[a-z0-9]+(?:[-:][a-z0-9]+)*")


@dataclass
class Chunk:
    source: str
    heading: str
    text: str


def _tokens(text: str) -> list[str]:
    toks = TOKEN.findall(text.lower())
    extra = []
    for t in toks:  # make "cwe-89" also match "89" and "llm01:2025" match "llm01"
        if "-" in t or ":" in t:
            extra += re.split(r"[-:]", t)
    return toks + extra


class KnowledgeBase:
    def __init__(self, kb_dir: Path = KB_DIR):
        self.chunks: list[Chunk] = []
        for f in sorted(kb_dir.glob("*.md")):
            parts = re.split(r"(?m)^## ", f.read_text())
            for part in parts[1:]:
                heading, _, body = part.partition("\n")
                self.chunks.append(Chunk(f.stem, heading.strip(), body.strip()))
        self.bm25 = BM25Okapi([_tokens(c.heading + " " + c.heading + " " + c.text) for c in self.chunks]) \
            if self.chunks else None

    def search(self, query: str, k: int = 3) -> list[tuple[float, Chunk]]:
        if not self.bm25:
            return []
        scores = self.bm25.get_scores(_tokens(query))
        ranked = sorted(zip(scores, self.chunks), key=lambda x: -x[0])
        return [(s, c) for s, c in ranked[:k] if s > 0]

    def for_finding(self, f: Finding, k: int = 2) -> list[Chunk]:
        exact = []
        keys = f.cwe + f.owasp + f.owasp_llm
        for key in keys:
            for c in self.chunks:
                if c.heading.upper().startswith(key.upper()) or c.heading.upper().startswith(key.upper() + " "):
                    if c not in exact:
                        exact.append(c)
        if len(exact) >= k:
            return exact[:k]
        query = " ".join([f.title, f.category, *keys, f.description[:300]])
        for _, c in self.search(query, k + 2):
            if c not in exact:
                exact.append(c)
        return exact[:k]


@lru_cache
def get_kb() -> KnowledgeBase:
    return KnowledgeBase()


def guidance_text(f: Finding) -> str:
    return "\n\n".join(f"**{c.heading}** — {c.text}" for c in get_kb().for_finding(f))
