"""Optional: import the full MITRE CWE catalogue into the RAG knowledge base.

    python scripts/build_kb.py      (inside the container: docker exec vulnscan-api python scripts/build_kb.py)

Downloads the CWE "Research Concepts" CSV and writes vulnscan/knowledge/cwe-catalog.md with one
'## CWE-n Name' section per weakness (description + mitigations).
"""
import csv
import io
import sys
import zipfile
from pathlib import Path

import httpx

URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"
OUT = Path(__file__).resolve().parent.parent / "vulnscan" / "knowledge" / "cwe-catalog.md"


def main():
    csv.field_size_limit(sys.maxsize)
    data = httpx.get(URL, timeout=60, follow_redirects=True).content
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        text = z.read(z.namelist()[0]).decode("utf-8", errors="ignore")
    lines = ["# MITRE CWE catalogue (imported)\n"]
    for row in csv.DictReader(io.StringIO(text)):
        cid, name = row.get("CWE-ID"), row.get("Name")
        if not cid or row.get("Status") == "Deprecated":
            continue
        mit = (row.get("Potential Mitigations") or "").replace("::", "\n").replace("PHASE:", "Phase: ")
        lines.append(f"## CWE-{cid} {name}\n{row.get('Description', '')}\nMitigations: {mit[:1500]}\n")
    OUT.write_text("\n".join(lines))
    print(f"wrote {OUT} ({len(lines) - 1} entries)")


if __name__ == "__main__":
    main()
