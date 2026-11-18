#!/usr/bin/env bash
# Scan VulnScan's own code with its own scanners. The tool should not itself be an easy target.
# Run after the stack is up:  bash scripts/selfscan.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo "▶ copying source into the worker container…"
docker cp vulnscan vulnscan-worker:/selfscan >/dev/null

echo "▶ secrets (gitleaks)…"
docker exec vulnscan-worker gitleaks detect --source /selfscan --no-git --redact --no-banner --exit-code 0 \
  -f json -r /tmp/self-gl.json >/dev/null 2>&1 || true
docker exec vulnscan-worker python3 -c "import json;d=json.load(open('/tmp/self-gl.json') or []);print(f'  {len(d)} secret(s)')"

echo "▶ Python SAST (bandit, high+medium, honouring # nosec)…"
docker exec vulnscan-worker bandit -r /selfscan -ll -q -f json -o /tmp/self-b.json >/dev/null 2>&1 || true
docker exec vulnscan-worker python3 -c "import json;r=json.load(open('/tmp/self-b.json'))['results'];print(f'  {len(r)} issue(s)');[print('   ',x['issue_severity'],x['test_id'],x['filename'].split('/')[-1]+':'+str(x['line_number'])) for x in r]"

echo "▶ SAST (semgrep, OWASP registry + our AI rules; local rules only if offline)…"
docker exec vulnscan-worker sh -c "rm -f /tmp/self-sg.json; semgrep scan --config p/owasp-top-ten --config /selfscan/rules/ai-security.yml --json --quiet --metrics off -o /tmp/self-sg.json /selfscan >/dev/null 2>&1 || semgrep scan --config /selfscan/rules/ai-security.yml --json --quiet --metrics off -o /tmp/self-sg.json /selfscan >/dev/null 2>&1 || true"
docker exec vulnscan-worker python3 -c "import json,os;p='/tmp/self-sg.json';r=(json.load(open(p))['results'] if os.path.exists(p) else []);print(f'  {len(r)} finding(s)');[print('   ',x['check_id'],x['path'].split('/')[-1]) for x in r[:20]]"

echo "✓ self-scan complete. Review any findings above; intentional ones carry a '# nosec' justification."
