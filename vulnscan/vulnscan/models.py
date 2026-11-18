"""The common data model every scanner's output is converted into."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]

    @classmethod
    def parse(cls, value: Any, default: "Severity" = None) -> "Severity":
        """Map the many severity vocabularies used by tools onto ours."""
        default = default or cls.info
        if value is None:
            return default
        if isinstance(value, (int, float)):  # CVSS score
            v = float(value)
            if v >= 9.0:
                return cls.critical
            if v >= 7.0:
                return cls.high
            if v >= 4.0:
                return cls.medium
            if v > 0:
                return cls.low
            return cls.info
        s = str(value).strip().lower()
        table = {
            "critical": cls.critical, "crit": cls.critical,
            "high": cls.high, "error": cls.high, "severe": cls.high,
            "medium": cls.medium, "moderate": cls.medium, "warning": cls.medium, "warn": cls.medium,
            "low": cls.low, "minor": cls.low, "negligible": cls.low,
            "info": cls.info, "informational": cls.info, "information": cls.info,
            "note": cls.info, "none": cls.info, "unknown": default, "ok": cls.info,
        }
        return table.get(s, default)


class Confidence(str, Enum):
    high = "high"
    medium = "medium"
    low = "low"


class Location(BaseModel):
    file: str | None = None
    line: int | None = None
    url: str | None = None
    method: str | None = None
    param: str | None = None
    host: str | None = None
    port: int | None = None
    component: str | None = None  # package / service name
    version: str | None = None
    resource: str | None = None  # cloud resource id

    def short(self) -> str:
        if self.file:
            return f"{self.file}:{self.line}" if self.line else self.file
        if self.url:
            return self.url + (f" [{self.param}]" if self.param else "")
        if self.host:
            return f"{self.host}:{self.port}" if self.port else self.host
        if self.component:
            return f"{self.component}@{self.version}" if self.version else self.component
        return self.resource or "-"


class Finding(BaseModel):
    title: str
    severity: Severity = Severity.info
    confidence: Confidence = Confidence.medium
    tool: str
    rule_id: str = ""
    category: str = "code"  # code|secret|dependency|iac|network|web|tls|cloud|ai|design
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    location: Location = Field(default_factory=Location)
    cwe: list[str] = Field(default_factory=list)  # "CWE-89"
    cve: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)  # "A05:2025"
    owasp_llm: list[str] = Field(default_factory=list)  # "LLM01:2025"
    cvss: float | None = None
    epss: float | None = None
    kev: bool = False
    fixed_version: str | None = None
    sources: list[str] = Field(default_factory=list)  # tools that reported it (after merge)
    status: str = "open"  # open | likely_false_positive
    triage_note: str = ""
    guidance: str = ""  # RAG-retrieved remediation guidance
    # --- accuracy model -------------------------------------------------
    confidence_score: int = 50  # 0-100, computed from multiple signals
    verdict: str = "uncertain"  # verified | likely | uncertain | false_positive
    accuracy_signals: list[str] = Field(default_factory=list)  # human-readable reasons
    user_verdict: str = ""  # "" | confirmed (true positive) | dismissed (false positive)
    frameworks: list[str] = Field(default_factory=list)  # compliance control ids this maps to

    @property
    def fingerprint(self) -> str:
        loc = self.location
        if self.cve:
            key = f"cve|{self.cve[0]}|{loc.component}|{loc.version}|{loc.host}|{loc.port}"
        else:
            key = "|".join(str(x) for x in (
                self.rule_id or self.title.lower(), loc.file, loc.line,
                (loc.url or "").split("?")[0], loc.param, loc.host, loc.port, loc.component))
        return hashlib.sha1(key.encode(), usedforsecurity=False).hexdigest()[:16]

    def clip(self, n: int = 2000) -> "Finding":
        if len(self.evidence) > n:
            self.evidence = self.evidence[:n] + " ...[truncated]"
        if len(self.description) > 4 * n:
            self.description = self.description[: 4 * n] + " ...[truncated]"
        return self


class ToolStatus(str, Enum):
    ok = "ok"
    failed = "failed"
    skipped = "skipped"
    not_installed = "not_installed"


class ToolRun(BaseModel):
    tool: str
    status: ToolStatus
    reason: str = ""
    started_at: datetime | None = None
    duration_s: float = 0.0
    findings: int = 0
    artifacts: list[str] = Field(default_factory=list)


class TargetKind(str, Enum):
    repo = "repo"
    zip = "zip"
    url = "url"


class ScanRequest(BaseModel):
    target: str  # git URL, website URL, or path to uploaded zip
    kind: TargetKind | None = None  # auto-detected if omitted
    label: str | None = None  # display name (e.g. original ZIP filename)
    profile: str = "standard"  # quick | standard | full
    only_tools: list[str] = Field(default_factory=list)
    skip_tools: list[str] = Field(default_factory=list)
    # Optional LLM endpoint to red-team (chatbot API of the target app)
    llm_endpoint: "LLMEndpoint | None" = None
    # Optional cloud provider for Prowler: aws | azure | gcp | kubernetes
    cloud_provider: str | None = None
    # Optional auth for web scanning: extra headers e.g. {"Cookie": "..."}
    auth_headers: dict[str, str] = Field(default_factory=dict)


class LLMEndpoint(BaseModel):
    url: str
    method: str = "POST"
    headers: dict[str, str] = Field(default_factory=dict)
    # JSON body; the string {{prompt}} is replaced by the attack prompt
    body_template: dict[str, Any] = Field(default_factory=lambda: {"message": "{{prompt}}"})
    # dotted path to the reply text in the JSON response, e.g. "choices.0.message.content"
    response_path: str = "reply"


ScanRequest.model_rebuild()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
