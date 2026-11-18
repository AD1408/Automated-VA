"""OWASP Top 10 (2025) and OWASP Top 10 for LLM Applications (2025) mapping."""
from __future__ import annotations

from .models import Finding

OWASP_TOP10 = {
    "A01:2025": "Broken Access Control",
    "A02:2025": "Security Misconfiguration",
    "A03:2025": "Software Supply Chain Failures",
    "A04:2025": "Cryptographic Failures",
    "A05:2025": "Injection",
    "A06:2025": "Insecure Design",
    "A07:2025": "Authentication Failures",
    "A08:2025": "Software or Data Integrity Failures",
    "A09:2025": "Security Logging and Alerting Failures",
    "A10:2025": "Mishandling of Exceptional Conditions",
}

OWASP_LLM_TOP10 = {
    "LLM01:2025": "Prompt Injection",
    "LLM02:2025": "Sensitive Information Disclosure",
    "LLM03:2025": "Supply Chain",
    "LLM04:2025": "Data and Model Poisoning",
    "LLM05:2025": "Improper Output Handling",
    "LLM06:2025": "Excessive Agency",
    "LLM07:2025": "System Prompt Leakage",
    "LLM08:2025": "Vector and Embedding Weaknesses",
    "LLM09:2025": "Misinformation",
    "LLM10:2025": "Unbounded Consumption",
}

_CWE_GROUPS: dict[str, list[int]] = {
    "A01:2025": [22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497, 538,
                 540, 548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 918, 922, 1275],
    "A02:2025": [2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 693, 776, 942, 1004, 1021, 1032, 1174],
    "A03:2025": [477, 937, 1035, 1104, 1329, 1357, 1395],
    "A04:2025": [261, 296, 310, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338,
                 340, 347, 523, 720, 757, 759, 760, 780, 818, 916],
    "A05:2025": [20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 113, 116, 138, 184,
                 470, 471, 564, 610, 643, 644, 652, 917, 1336, 1427],
    "A06:2025": [73, 183, 213, 235, 256, 257, 266, 269, 311, 312, 313, 316, 419, 430, 434, 444, 451, 472, 501, 522,
                 525, 539, 579, 598, 602, 642, 646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1173],
    "A07:2025": [255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620, 640, 798,
                 940, 1216, 1391, 1392],
    "A08:2025": [345, 353, 426, 494, 502, 565, 784, 829, 830, 915],
    "A09:2025": [117, 223, 532, 778],
    "A10:2025": [209, 215, 234, 248, 252, 274, 280, 369, 390, 391, 394, 396, 397, 460, 476, 478, 484, 550, 636, 703,
                 754, 755, 756],
}
CWE_TO_OWASP: dict[int, str] = {cwe: cat for cat, cwes in _CWE_GROUPS.items() for cwe in cwes}

# fallback when a finding has no CWE
CATEGORY_DEFAULT = {
    "dependency": "A03:2025",
    "secret": "A07:2025",  # nosec B105 - category key, not a credential
    "iac": "A02:2025",
    "cloud": "A02:2025",
    "tls": "A04:2025",
    "network": "A02:2025",
}


def cwe_number(cwe: str) -> int | None:
    digits = "".join(ch for ch in str(cwe).split(":")[0] if ch.isdigit())
    return int(digits) if digits else None


def normalise_cwe(values) -> list[str]:
    out = []
    for v in values or []:
        n = cwe_number(v)
        if n and f"CWE-{n}" not in out:
            out.append(f"CWE-{n}")
    return out


def map_finding(f: Finding) -> Finding:
    f.cwe = normalise_cwe(f.cwe)
    cats = list(f.owasp)
    for c in f.cwe:
        cat = CWE_TO_OWASP.get(cwe_number(c) or -1)
        if cat and cat not in cats:
            cats.append(cat)
    if not cats and f.category in CATEGORY_DEFAULT:
        cats.append(CATEGORY_DEFAULT[f.category])
    f.owasp = [c for c in cats if c in OWASP_TOP10]
    f.owasp_llm = [c for c in f.owasp_llm if c in OWASP_LLM_TOP10]
    return f


# Which tools *test* each category -> used for the coverage matrix in the report.
COVERAGE = {
    "A01:2025": ["zap", "nuclei", "semgrep", "http_checks", "burp"],
    "A02:2025": ["nikto", "nuclei", "zap", "trivy", "http_checks", "prowler", "nmap", "openvas"],
    "A03:2025": ["grype", "trivy", "openvas", "nmap"],
    "A04:2025": ["testssl", "semgrep", "gitleaks", "http_checks", "bandit"],
    "A05:2025": ["sqlmap", "zap", "semgrep", "bandit", "nuclei"],
    "A06:2025": ["llm_design_review", "semgrep"],
    "A07:2025": ["gitleaks", "zap", "nuclei", "semgrep", "http_checks"],
    "A08:2025": ["semgrep", "bandit", "modelscan", "trivy"],
    "A09:2025": ["llm_design_review", "semgrep"],
    "A10:2025": ["zap", "semgrep", "bandit", "http_checks"],
    "LLM01:2025": ["prompt_guard", "llm_redteam", "garak", "semgrep"],
    "LLM02:2025": ["llm_redteam", "gitleaks", "garak"],
    "LLM03:2025": ["modelscan", "grype", "semgrep"],
    "LLM04:2025": ["modelscan", "prompt_guard", "semgrep"],
    "LLM05:2025": ["llm_redteam", "semgrep"],
    "LLM06:2025": ["semgrep", "llm_redteam", "llm_design_review"],
    "LLM07:2025": ["llm_redteam", "semgrep", "garak"],
    "LLM08:2025": ["prompt_guard", "llm_design_review", "semgrep"],
    "LLM09:2025": ["llm_redteam", "garak"],
    "LLM10:2025": ["llm_redteam", "semgrep"],
}
