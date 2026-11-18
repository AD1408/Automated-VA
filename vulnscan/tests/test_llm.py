import json
from pathlib import Path

import httpx
import respx

from vulnscan.config import Settings
from vulnscan.correlate import executive_summary, llm_triage
from vulnscan.llm import LLM, extract_json
from vulnscan.models import Finding, Location, ScanRequest, Severity, TargetKind
from vulnscan.scanners.ai import LLMDesignReview
from vulnscan.scanners.base import ScanContext

FIX = Path(__file__).parent / "fixtures" / "vulnapp"


def test_extract_json_variants():
    assert extract_json('```json\n[{"a": 1}]\n```') == [{"a": 1}]
    assert extract_json('Sure! Here you go: {"x": true} hope it helps') == {"x": True}


@respx.mock
def test_ollama_and_triage(tmp_path):
    s = Settings(data_dir=tmp_path, llm_provider="ollama", llm_model="gpt-oss:20b", ollama_url="http://ollama:11434")
    f = Finding(title="Hard-coded secret", tool="gitleaks", severity=Severity.high, rule_id="generic-api-key",
                location=Location(file="app.py", line=12))
    verdict = json.dumps([{"id": f.fingerprint, "likely_false_positive": True, "note": "test placeholder"}])
    route = respx.post("http://ollama:11434/api/chat").mock(
        return_value=httpx.Response(200, json={"message": {"content": verdict}}))
    llm_triage([f], s, FIX)
    assert f.status == "likely_false_positive" and "placeholder" in f.triage_note
    body = json.loads(route.calls[0].request.content)
    assert body["model"] == "gpt-oss:20b" and body["think"] == "low"


@respx.mock
def test_anthropic_summary(tmp_path):
    s = Settings(data_dir=tmp_path, llm_provider="anthropic", anthropic_api_key="test", llm_model="claude-sonnet-5-5")
    route = respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(200, json={"content": [{"type": "text", "text": "Overall risk is high."}]}))
    text = executive_summary({"target": "x"}, [Finding(title="t", tool="x", severity=Severity.high)], s)
    assert text == "Overall risk is high."
    assert route.calls[0].request.headers["x-api-key"] == "test"


@respx.mock
def test_openai_compat_design_review(tmp_path):
    s = Settings(data_dir=tmp_path, llm_provider="openai_compat", openai_compat_base_url="http://llm/v1", llm_model="m")
    items = [{"title": "No authorization on /user", "severity": "high", "file": "app.py", "line": 15,
              "owasp": ["A01:2025"], "owasp_llm": [], "cwe": ["CWE-862"], "description": "d", "remediation": "r"}]
    respx.post("http://llm/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(items)}}]}))
    ctx = ScanContext(scan_id="t", request=ScanRequest(target="x", profile="standard"), kind=TargetKind.zip,
                      workdir=tmp_path, settings=s, source_dir=FIX, log=lambda m: None)
    assert LLMDesignReview().applicable(ctx)[0]
    out = LLMDesignReview().run(ctx)
    assert out and out[0].owasp == ["A01:2025"] and out[0].location.line == 15
    assert LLM(s).enabled
