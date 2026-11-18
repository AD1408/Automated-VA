import io
import json
import zipfile
from pathlib import Path

import pytest

from vulnscan.config import Settings
from vulnscan.correlate import merge
from vulnscan.ingest import IngestError, detect_kind, safe_extract_zip
from vulnscan.models import Finding, Location, Severity, TargetKind
from vulnscan.owasp import map_finding
from vulnscan.rag import get_kb
from vulnscan.recon import fingerprint_code
from vulnscan.scope import ScopeError, ensure_in_scope

FIX = Path(__file__).parent / "fixtures"


def test_detect_kind():
    assert detect_kind("https://github.com/OWASP/NodeGoat") == TargetKind.repo
    assert detect_kind("https://example.com") == TargetKind.url
    assert detect_kind("juice-shop:3000") == TargetKind.url


def test_severity_parse():
    assert Severity.parse("ERROR") == Severity.high
    assert Severity.parse(9.8) == Severity.critical
    assert Severity.parse("Negligible") == Severity.low


def _zip(entries: dict) -> io.BytesIO:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    b.seek(0)
    return b


def test_zip_slip_blocked(tmp_path):
    p = tmp_path / "evil.zip"
    p.write_bytes(_zip({"../../etc/evil.txt": "x"}).read())
    with pytest.raises(IngestError):
        safe_extract_zip(p, tmp_path / "out")


def test_zip_extract_single_root(tmp_path):
    p = tmp_path / "ok.zip"
    p.write_bytes(_zip({"proj/a.py": "print(1)", "proj/sub/b.txt": "hi"}).read())
    root = safe_extract_zip(p, tmp_path / "out")
    assert (root / "a.py").exists() and root.name == "proj"


def test_scope(tmp_path):
    s = Settings(data_dir=tmp_path, allowed_targets="juice-shop,*.lab.test,10.9.0.0/16")
    assert ensure_in_scope("http://juice-shop:3000", s) == "juice-shop"
    assert ensure_in_scope("https://app.lab.test", s) == "app.lab.test"
    assert ensure_in_scope("10.9.1.2", s) == "10.9.1.2"
    with pytest.raises(ScopeError):
        ensure_in_scope("http://169.254.169.254/latest", s)
    with pytest.raises(ScopeError):
        ensure_in_scope("https://example.org", s)
    with pytest.raises(ScopeError):
        ensure_in_scope("http://192.168.1.10", s)


def test_owasp_mapping():
    f = map_finding(Finding(title="x", tool="t", cwe=["CWE-89: SQL Injection"]))
    assert f.owasp == ["A05:2025"] and f.cwe == ["CWE-89"]
    f = map_finding(Finding(title="dep", tool="grype", category="dependency"))
    assert f.owasp == ["A03:2025"]
    f = map_finding(Finding(title="ssrf", tool="t", cwe=["CWE-918"]))
    assert f.owasp == ["A01:2025"]


def test_merge_dedupes_cross_tool():
    a = Finding(title="CVE-2023-1 in x", tool="nmap", cve=["CVE-2023-1"], severity=Severity.medium,
                location=Location(host="h", port=22, component="ssh", version="1"))
    b = a.model_copy(update={"tool": "openvas", "severity": Severity.high, "sources": []})
    out = merge([a, b])
    assert len(out) == 1 and out[0].severity == Severity.high and set(out[0].sources) == {"nmap", "openvas"}


def test_recon_fixture():
    r = fingerprint_code(FIX / "vulnapp")
    assert "python" in r["languages"]
    assert r["uses_llm"] and "openai" in r["ai_libraries"]
    assert "dockerfile" in r["iac"]
    assert "flask" in r["frameworks"]


def test_rag_lookup():
    kb = get_kb()
    f = Finding(title="SQL injection", tool="t", cwe=["CWE-89"], owasp=["A05:2025"])
    heads = [c.heading for c in kb.for_finding(f)]
    assert any("CWE-89" in h for h in heads)
    f = Finding(title="Prompt injection", tool="t", owasp_llm=["LLM01:2025"])
    assert kb.for_finding(f)[0].heading.startswith("LLM01")


def test_runner_cancel_kills_process():
    import threading, time
    from vulnscan.runner import run, ToolCancelled
    flag = {"stop": False}
    threading.current_thread().cancel = lambda: flag["stop"]
    def stop_soon():
        time.sleep(1); flag["stop"] = True
    threading.Thread(target=stop_soon, daemon=True).start()
    t0 = time.time()
    try:
        run(["sleep", "30"], timeout=60, poll=0.3)
        assert False, "should have been cancelled"
    except ToolCancelled:
        pass
    finally:
        threading.current_thread().cancel = None
    assert time.time() - t0 < 5  # killed quickly, not after 30s


def test_runner_timeout_kills_process():
    import threading, time
    from vulnscan.runner import run
    threading.current_thread().cancel = None
    t0 = time.time()
    try:
        run(["sleep", "30"], timeout=1, poll=0.3)
        assert False
    except RuntimeError as e:
        assert "timed out" in str(e)
    assert time.time() - t0 < 5
