"""Scanner registry. Order within a stage doesn't matter; stages run sequentially."""
from __future__ import annotations

from .ai import GarakScanner, LLMDesignReview, LLMProbeScanner, PromptGuardScanner
from .base import ScanContext, Scanner
from .cloud import ProwlerScanner
from .code import (BanditScanner, GitleaksScanner, GrypeScanner, ModelScanScanner, SemgrepScanner,
                   TrivyScanner)
from .network import NmapScanner, OpenVASScanner
from .web import (HttpChecksScanner, NiktoScanner, NucleiScanner, SqlmapScanner, TestsslScanner,
                  ZapScanner)

ALL_SCANNERS: list[Scanner] = [
    # code
    SemgrepScanner(), BanditScanner(), GitleaksScanner(), GrypeScanner(), TrivyScanner(), ModelScanScanner(),
    # network / web
    HttpChecksScanner(), NmapScanner(), NucleiScanner(), NiktoScanner(), TestsslScanner(), ZapScanner(),
    OpenVASScanner(), SqlmapScanner(),
    # cloud
    ProwlerScanner(),
    # AI
    LLMProbeScanner(), GarakScanner(), PromptGuardScanner(), LLMDesignReview(),
]
BY_NAME = {s.name: s for s in ALL_SCANNERS}

# Which external binaries each scanner needs (for the health page)
BINARIES = {
    "semgrep": ["semgrep"], "bandit": ["bandit"], "gitleaks": ["gitleaks"], "grype": ["syft", "grype"],
    "trivy": ["trivy"], "modelscan": ["modelscan"], "nmap": ["nmap"], "nuclei": ["nuclei"], "nikto": ["nikto.pl"],
    "testssl": ["testssl.sh"], "sqlmap": ["sqlmap"], "prowler": ["prowler"], "garak": ["garak"],
}

CATEGORY = {
    "semgrep": "code", "bandit": "code", "gitleaks": "code", "grype": "code", "trivy": "code", "modelscan": "ai",
    "http_checks": "web", "nmap": "network", "nuclei": "web", "nikto": "web", "testssl": "web", "zap": "web",
    "openvas": "network", "sqlmap": "web", "prowler": "cloud", "llm_redteam": "ai", "garak": "ai",
    "prompt_guard": "ai", "llm_design_review": "ai",
}

__all__ = ["ALL_SCANNERS", "BY_NAME", "BINARIES", "CATEGORY", "ScanContext", "Scanner"]
