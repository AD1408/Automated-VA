"""Scanner interface and the shared per-scan context."""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..config import Settings
from ..models import Finding, ScanRequest, TargetKind

PROFILES = ("quick", "standard", "full")


@dataclass
class ScanContext:
    scan_id: str
    request: ScanRequest
    kind: TargetKind
    workdir: Path
    settings: Settings
    source_dir: Path | None = None  # code to analyse (repo / zip)
    base_url: str | None = None  # website to test
    host: str | None = None
    recon: dict = field(default_factory=dict)
    crawled_urls: set[str] = field(default_factory=set)  # filled by ZAP spider, used by sqlmap etc.
    page_texts: dict[str, str] = field(default_factory=dict)  # url -> text, for prompt-guard
    log: Callable[[str], None] = print
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def profile(self) -> str:
        return self.request.profile if self.request.profile in PROFILES else "standard"

    def artifact(self, name: str) -> Path:
        d = self.workdir / "artifacts"
        d.mkdir(parents=True, exist_ok=True)
        return d / name

    def add_urls(self, urls) -> None:
        with self._lock:
            self.crawled_urls.update(u for u in urls if u)


class Scanner:
    """Subclass and implement `run`. Raise ToolSkipped / ToolNotInstalled when appropriate."""

    name: str = "base"
    # what kind of target it needs: "code" (source_dir) or "web" (base_url) or "llm" or "cloud"
    needs: str = "code"
    # lowest profile that includes this scanner
    min_profile: str = "quick"
    # pipeline stage: scanners in a later stage can use what earlier stages discovered
    stage: int = 1
    # heavy scanners don't run in parallel with each other
    heavy: bool = False
    description: str = ""

    def applicable(self, ctx: ScanContext) -> tuple[bool, str]:
        if self.needs == "code" and not ctx.source_dir:
            return False, "no source code for this target"
        if self.needs == "web" and not ctx.base_url:
            return False, "no website URL for this target"
        if self.needs == "llm" and not ctx.request.llm_endpoint:
            return False, "no llm_endpoint configured for this scan"
        if self.needs == "cloud" and not ctx.request.cloud_provider:
            return False, "no cloud_provider configured for this scan"
        if PROFILES.index(ctx.profile) < PROFILES.index(self.min_profile):
            return False, f"only runs in '{self.min_profile}' profile or higher"
        return True, ""

    def run(self, ctx: ScanContext) -> list[Finding]:  # pragma: no cover - interface
        raise NotImplementedError
