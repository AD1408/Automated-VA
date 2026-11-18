"""Web application scanners: built-in HTTP checks, Nuclei, Nikto, OWASP ZAP, SQLMap, testssl.sh."""
from __future__ import annotations

import csv
import json
import re
import time
from urllib.parse import parse_qs, urljoin, urlparse

import httpx

from ..models import Confidence, Finding, Location, Severity
from ..runner import ToolCancelled, ToolSkipped, is_cancelled, require, run
from ..scope import ensure_in_scope
from .base import ScanContext, Scanner


def _strip_html(html: str) -> str:
    html = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", html)
    return re.sub(r"\s+", " ", re.sub(r"(?s)<[^>]+>", " ", html)).strip()


# ============================================================ built-in checks
SECURITY_HEADERS = {
    "content-security-policy": ("Missing Content-Security-Policy header", Severity.medium, ["CWE-693"],
                                "Define a restrictive Content-Security-Policy to limit script sources and mitigate XSS."),
    "x-content-type-options": ("Missing X-Content-Type-Options header", Severity.low, ["CWE-693"],
                               "Send 'X-Content-Type-Options: nosniff'."),
    "referrer-policy": ("Missing Referrer-Policy header", Severity.info, ["CWE-200"],
                        "Send 'Referrer-Policy: strict-origin-when-cross-origin' (or stricter)."),
}
SENSITIVE_PATHS = {
    "/.git/HEAD": (re.compile(r"^ref: refs/"), "Exposed .git directory", Severity.high, ["CWE-538"]),
    "/.env": (re.compile(r"(?m)^[A-Z_]{3,}=\S+"), "Exposed .env file", Severity.critical, ["CWE-538"]),
    "/server-status": (re.compile(r"Apache Server Status"), "Apache server-status exposed", Severity.medium, ["CWE-200"]),
    "/phpinfo.php": (re.compile(r"phpinfo\(\)|PHP Version"), "phpinfo() page exposed", Severity.medium, ["CWE-200"]),
    "/.DS_Store": (re.compile(r"Bud1"), "Exposed .DS_Store file", Severity.low, ["CWE-538"]),
    "/actuator/env": (re.compile(r"propertySources"), "Spring Boot actuator /env exposed", Severity.high, ["CWE-200"]),
}
STACK_TRACE = re.compile(r"(Traceback \(most recent call last\)|at [\w.$]+\([\w]+\.java:\d+\)|Exception in thread|"
                         r"System\.\w+Exception|Fatal error</b>:|Warning</b>:.*on line|SQLSTATE\[|ORA-\d{5}|"
                         r"node_modules/|ReferenceError:|TypeError:.*\n\s+at )")


class HttpChecksScanner(Scanner):
    name = "http_checks"
    needs = "web"
    description = "Built-in checks: security headers, cookies, CORS, HTTPS, exposed files, error leakage"

    def run(self, ctx: ScanContext) -> list[Finding]:
        ensure_in_scope(ctx.base_url, ctx.settings)
        out: list[Finding] = []
        base = ctx.base_url.rstrip("/") + "/"
        hdrs = dict(ctx.request.auth_headers)
        with httpx.Client(timeout=15, follow_redirects=True, verify=False, headers=hdrs) as c:  # nosec B501 - a scanner must reach targets regardless of TLS validity
            r = c.get(base)
            ctx.page_texts[str(r.url)] = _strip_html(r.text)[:50_000]
            h = {k.lower(): v for k, v in r.headers.items()}
            loc = Location(url=str(r.url))
            for name, (title, sev, cwe, fix) in SECURITY_HEADERS.items():
                if name not in h:
                    out.append(Finding(title=title, severity=sev, confidence=Confidence.high, tool=self.name,
                                       rule_id=f"missing-{name}", category="web", location=loc, cwe=cwe,
                                       description=f"The response does not include the {name} header.", remediation=fix))
            csp = h.get("content-security-policy", "")
            if "x-frame-options" not in h and "frame-ancestors" not in csp:
                out.append(Finding(title="Clickjacking protection missing", severity=Severity.low, tool=self.name,
                                   rule_id="missing-frame-options", category="web", location=loc, cwe=["CWE-1021"],
                                   confidence=Confidence.high,
                                   description="Neither X-Frame-Options nor CSP frame-ancestors is set, so the page can be framed.",
                                   remediation="Send 'Content-Security-Policy: frame-ancestors 'self'' or 'X-Frame-Options: DENY'."))
            if str(r.url).startswith("https") and "strict-transport-security" not in h:
                out.append(Finding(title="Missing HSTS header", severity=Severity.low, tool=self.name, rule_id="missing-hsts",
                                   category="web", location=loc, cwe=["CWE-319"], confidence=Confidence.high,
                                   description="Strict-Transport-Security is not set, allowing protocol downgrade attacks.",
                                   remediation="Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."))
            for hn in ("server", "x-powered-by", "x-aspnet-version"):
                if hn in h and re.search(r"\d", h[hn]):
                    out.append(Finding(title=f"Version disclosure in {hn} header", severity=Severity.low, tool=self.name,
                                       rule_id=f"version-{hn}", category="web", location=loc, cwe=["CWE-200"],
                                       evidence=f"{hn}: {h[hn]}", confidence=Confidence.high,
                                       description="The server reveals software versions, which helps attackers pick exploits.",
                                       remediation=f"Remove or genericise the {hn} header."))
            for raw in r.headers.get_list("set-cookie"):
                name = raw.split("=", 1)[0].strip()
                low = raw.lower()
                missing = [flag for flag, ok in (("Secure", "secure" in low or not str(r.url).startswith("https")),
                                                 ("HttpOnly", "httponly" in low), ("SameSite", "samesite" in low)) if not ok]
                if missing:
                    out.append(Finding(title=f"Cookie '{name}' missing {', '.join(missing)}", severity=Severity.low,
                                       tool=self.name, rule_id=f"cookie-flags-{name}", category="web", location=loc,
                                       cwe=["CWE-1004"] if "HttpOnly" in missing else ["CWE-614"],
                                       evidence=raw[:200], confidence=Confidence.high,
                                       description="Session cookies without these flags are easier to steal or misuse.",
                                       remediation="Set Secure, HttpOnly and SameSite=Lax/Strict on session cookies."))
            # CORS
            evil = "https://vulnscan-cors-check.example"
            try:
                rc = c.get(base, headers={"Origin": evil})
                acao = rc.headers.get("access-control-allow-origin", "")
                acac = rc.headers.get("access-control-allow-credentials", "").lower() == "true"
                if acao == evil or (acao == "null"):
                    out.append(Finding(title="CORS policy reflects arbitrary origins", tool=self.name, rule_id="cors-reflect",
                                       severity=Severity.high if acac else Severity.medium, category="web", location=loc,
                                       cwe=["CWE-942"], confidence=Confidence.high,
                                       evidence=f"Access-Control-Allow-Origin: {acao}; Allow-Credentials: {acac}",
                                       description="Any website can read responses from this origin"
                                                   + (" including authenticated data." if acac else "."),
                                       remediation="Use an explicit allow-list of trusted origins; never reflect the Origin header."))
            except httpx.HTTPError:
                pass
            # HTTP -> HTTPS
            p = urlparse(str(r.url))
            if p.scheme == "https":
                try:
                    rh = c.get(f"http://{p.hostname}/", follow_redirects=False)
                    if rh.status_code < 300 or rh.status_code >= 400 or not rh.headers.get("location", "").startswith("https"):
                        out.append(Finding(title="HTTP does not redirect to HTTPS", severity=Severity.low, tool=self.name,
                                           rule_id="no-https-redirect", category="web", cwe=["CWE-319"],
                                           location=Location(url=f"http://{p.hostname}/"), confidence=Confidence.medium,
                                           description="Plain HTTP is served without redirecting to HTTPS.",
                                           remediation="Redirect all HTTP traffic to HTTPS (301) and enable HSTS."))
                except httpx.HTTPError:
                    pass
            elif p.scheme == "http" and p.hostname not in ("localhost", "127.0.0.1") and "." in (p.hostname or ""):
                out.append(Finding(title="Site served over plain HTTP", severity=Severity.medium, tool=self.name,
                                   rule_id="plain-http", category="tls", cwe=["CWE-319"], location=loc,
                                   confidence=Confidence.high, description="Traffic, including credentials, is not encrypted.",
                                   remediation="Serve the site over HTTPS only."))
            # exposed files
            for path, (pattern, title, sev, cwe) in SENSITIVE_PATHS.items():
                try:
                    rr = c.get(urljoin(base, path.lstrip("/")), follow_redirects=False)
                except httpx.HTTPError:
                    continue
                if rr.status_code == 200 and pattern.search(rr.text[:5000]):
                    out.append(Finding(title=title, severity=sev, tool=self.name, rule_id=f"exposed{path}", category="web",
                                       location=Location(url=str(rr.url)), cwe=cwe, confidence=Confidence.high,
                                       evidence=rr.text[:200], description=f"{path} is publicly readable.",
                                       remediation="Block access to this path in the web server and remove the file from the web root."))
            # directory listing / error leakage
            if re.search(r"<title>Index of /", r.text, re.I):
                out.append(Finding(title="Directory listing enabled", severity=Severity.low, tool=self.name,
                                   rule_id="dir-listing", category="web", location=loc, cwe=["CWE-548"],
                                   confidence=Confidence.high, description="The server lists directory contents.",
                                   remediation="Disable auto-indexing."))
            try:
                re_ = c.get(urljoin(base, "vulnscan-%ff%00'\"<probe>"), follow_redirects=False)
                m = STACK_TRACE.search(re_.text[:100_000])
                if m:
                    out.append(Finding(title="Verbose error / stack trace returned to client", severity=Severity.medium,
                                       tool=self.name, rule_id="stack-trace", category="web", cwe=["CWE-209"],
                                       location=Location(url=str(re_.url)), evidence=re_.text[max(0, m.start() - 100):m.start() + 300],
                                       confidence=Confidence.medium,
                                       description="Malformed input produces an internal error message that leaks implementation details.",
                                       remediation="Return generic error pages; log details server-side only."))
            except httpx.HTTPError:
                pass
        return out


# ============================================================ Nuclei
def parse_nuclei(lines: list[str]) -> list[Finding]:
    out = []
    for line in lines:
        line = line.strip()
        if not line.startswith("{"):
            continue
        r = json.loads(line)
        info = r.get("info", {})
        cls = info.get("classification") or {}
        cves = [c.upper() for c in (cls.get("cve-id") or []) if c]
        cwes = [c.upper() for c in (cls.get("cwe-id") or []) if c]
        refs = info.get("reference") or []
        out.append(Finding(
            title=info.get("name") or r.get("template-id", ""), severity=Severity.parse(info.get("severity")),
            confidence=Confidence.high, tool="nuclei", rule_id=r.get("template-id", ""), category="web",
            description=info.get("description", "") or "", remediation=info.get("remediation", "") or "",
            references=refs if isinstance(refs, list) else [refs], cve=cves, cwe=cwes,
            cvss=cls.get("cvss-score"),
            evidence=", ".join(r.get("extracted-results") or [])[:500] or r.get("matcher-name", "") or "",
            location=Location(url=r.get("matched-at") or r.get("host")),
        ))
    return out


class NucleiScanner(Scanner):
    name = "nuclei"
    needs = "web"
    description = "Template-based detection of CVEs, exposures and misconfigurations"

    def run(self, ctx):
        exe = require("nuclei")
        ensure_in_scope(ctx.base_url, ctx.settings)
        out = ctx.artifact("nuclei.jsonl")
        sev = "medium,high,critical" if ctx.profile == "quick" else "low,medium,high,critical"
        tdir = ctx.settings.data_dir / "cache" / "nuclei-templates"
        if not tdir.exists() or not any(tdir.iterdir()):
            ctx.log("nuclei: downloading templates (first run only)")
            tdir.mkdir(parents=True, exist_ok=True)
            run([exe, "-update-templates", "-ud", str(tdir), "-duc"], 900, ok_codes=None)
            if not any(tdir.iterdir()):
                raise RuntimeError("nuclei templates could not be downloaded (needs access to github.com)")
        cmd = [exe, "-u", ctx.base_url, "-t", str(tdir), "-jsonl", "-o", str(out), "-silent", "-severity", sev,
               "-rl", "50", "-c", "10", "-ni", "-duc", "-exclude-tags", "dos,fuzz,intrusive", "-timeout", "10"]
        for k, v in ctx.request.auth_headers.items():
            cmd += ["-H", f"{k}: {v}"]
        proc = run(cmd, ctx.settings.tool_timeout, ok_codes=None)
        if "FTL" in (proc.stderr or "") or "Could not run nuclei" in (proc.stderr or ""):
            raise RuntimeError((proc.stderr or "").strip().splitlines()[-1][-300:])
        return parse_nuclei(out.read_text().splitlines()) if out.exists() else []


# ============================================================ Nikto
NIKTO_PATH = re.compile(r"^/[^:\s]*:\s*")


def parse_nikto(data) -> list[Finding]:
    """Group repeated messages. Large groups usually mean the app answers 200 for every path (SPA catch-all)."""
    groups: dict[str, list[tuple[str, dict]]] = {}
    hosts = data if isinstance(data, list) else [data]
    for h in hosts:
        base = f"{'https' if str(h.get('port')) == '443' else 'http'}://{h.get('host')}:{h.get('port')}"
        for v in h.get("vulnerabilities", []) or []:
            msg = v.get("msg", "")
            key = re.sub(r"\s+", " ", NIKTO_PATH.sub("", msg)).strip()
            groups.setdefault(key, []).append((base + (v.get("url") or ""), v))
    out = []
    for key, items in groups.items():
        url, v = items[0]
        low = key.lower()
        sev = Severity.medium if any(k in low for k in ("inject", "remote", "traversal", "backdoor", "default password",
                                                         "admin", "exposed", "disclos")) else Severity.low
        urls = sorted({u for u, _ in items})
        many = len(items) > 10
        refs = v.get("references") or ""
        desc = key
        if many:
            desc += (f"\n\nReported for {len(items)} paths. When a web app returns HTTP 200 for every path "
                     "(single-page apps do), this is usually a false positive - verify a few manually.")
        out.append(Finding(
            title=key[:140] + (f" ({len(items)} paths)" if len(items) > 1 else ""),
            severity=Severity.info if many and sev == Severity.low else sev,
            confidence=Confidence.low if many else Confidence.medium, tool="nikto", rule_id=str(v.get("id", "")),
            category="web", description=desc, references=[refs] if isinstance(refs, str) and refs else [],
            evidence="\n".join(u for u in urls[:15]) if len(urls) > 1 else "",
            location=Location(url=url, method=v.get("method")),
        ))
    return out


class NiktoScanner(Scanner):
    name = "nikto"
    needs = "web"
    min_profile = "standard"
    description = "Web server misconfiguration and dangerous files"

    def run(self, ctx):
        exe = require("nikto.pl")
        ensure_in_scope(ctx.base_url, ctx.settings)
        out = ctx.artifact("nikto.json")
        maxtime = {"quick": "10m", "standard": "20m", "full": "45m"}[ctx.profile]
        run(["perl", exe, "-h", ctx.base_url, "-Format", "json", "-output", str(out), "-ask", "no", "-nointeractive",
             "-maxtime", maxtime, "-Tuning", "x6"], ctx.settings.tool_timeout, ok_codes=None)
        if not out.exists() or not out.read_text().strip():
            return []
        text = out.read_text()
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = json.loads(text.rstrip().rstrip(",") + "]") if text.lstrip().startswith("[") else {}
        return parse_nikto(data)


# ============================================================ OWASP ZAP
ZAP_RISK = {"3": Severity.high, "2": Severity.medium, "1": Severity.low, "0": Severity.info,
            "High": Severity.high, "Medium": Severity.medium, "Low": Severity.low, "Informational": Severity.info}
ZAP_CONF = {"High": Confidence.high, "Confirmed": Confidence.high, "Medium": Confidence.medium, "Low": Confidence.low,
            "False Positive": Confidence.low}


def parse_zap_alerts(alerts: list[dict]) -> list[Finding]:
    """Group identical alerts (same rule + parameter) across URLs into one finding listing the affected URLs."""
    groups: dict[tuple, list[dict]] = {}
    for a in alerts:
        if a.get("confidence") == "False Positive":
            continue
        groups.setdefault((a.get("pluginId"), a.get("alert"), a.get("param") or ""), []).append(a)
    out = []
    for (plugin, _, param), items in groups.items():
        a = max(items, key=lambda x: ZAP_RISK.get(str(x.get("risk")), Severity.info).rank)
        urls = sorted({x.get("url", "").split("#")[0] for x in items if x.get("url")})
        cwe = a.get("cweid")
        evidence = a.get("evidence", "") or a.get("attack", "")
        if len(urls) > 1:
            evidence = (evidence + "\n\n" if evidence else "") + f"Affected URLs ({len(urls)}):\n" + "\n".join(urls[:15]) \
                + ("\n..." if len(urls) > 15 else "")
        out.append(Finding(
            title=(a.get("alert") or a.get("name", "")) + (f" ({len(urls)} URLs)" if len(urls) > 1 else ""),
            severity=ZAP_RISK.get(str(a.get("risk")), Severity.info),
            confidence=ZAP_CONF.get(a.get("confidence"), Confidence.medium), tool="zap",
            rule_id=f"zap-{plugin}", category="web", description=a.get("description", ""),
            evidence=evidence, remediation=a.get("solution", ""),
            references=[u for u in (a.get("reference") or "").split("\n") if u.startswith("http")][:4],
            cwe=[f"CWE-{cwe}"] if cwe and str(cwe) not in ("0", "-1") else [],
            location=Location(url=urls[0] if urls else a.get("url"), param=param or None, method=a.get("method")),
        ))
    return out


class ZapScanner(Scanner):
    name = "zap"
    needs = "web"
    heavy = True
    description = "OWASP ZAP: crawl + passive scan (quick) + active scan (standard/full)"

    def _api(self, c: httpx.Client, path: str, **params):
        r = c.get(path, params=params)
        r.raise_for_status()
        return r.json()

    def _wait(self, c, status_path, scan_id, label, ctx, limit_s):
        start = time.time()
        while time.time() - start < limit_s:
            if is_cancelled():
                raise ToolCancelled("zap cancelled")
            pct = int(self._api(c, status_path, scanId=scan_id).get("status", 0))
            if pct >= 100:
                return
            ctx.log(f"zap: {label} {pct}%")
            time.sleep(5)
        ctx.log(f"zap: {label} hit time limit, continuing with partial results")

    def run(self, ctx):
        ensure_in_scope(ctx.base_url, ctx.settings)
        key = ctx.settings.zap_api_key
        c = httpx.Client(base_url=ctx.settings.zap_url, params={"apikey": key}, timeout=60)
        try:
            self._api(c, "/JSON/core/view/version/")
        except httpx.HTTPError as e:
            c.close()
            raise ToolSkipped(f"ZAP is not reachable at {ctx.settings.zap_url} ({e.__class__.__name__})")
        try:
            self._api(c, "/JSON/core/action/newSession/", name=ctx.scan_id, overwrite="true")
            for i, (hk, hv) in enumerate(ctx.request.auth_headers.items()):
                self._api(c, "/JSON/replacer/action/addRule/", description=f"vulnscan-auth-{i}", enabled="true",
                          matchType="REQ_HEADER", matchRegex="false", matchString=hk, replacement=hv, initiators="")
            target = ctx.base_url
            self._api(c, "/JSON/core/action/accessUrl/", url=target, followRedirects="true")
            for doc in ctx.recon.get("api_docs", []):  # import OpenAPI/Swagger so API endpoints get tested too
                try:
                    self._api(c, "/JSON/openapi/action/importUrl/", url=target.rstrip("/") + doc, hostOverride="")
                    ctx.log(f"zap: imported API definition {doc}")
                except httpx.HTTPError:
                    ctx.log(f"zap: could not import API definition {doc}")
            limit = {"quick": 300, "standard": 900, "full": 1800}[ctx.profile]
            sid = self._api(c, "/JSON/spider/action/scan/", url=target, recurse="true", subtreeOnly="true",
                            maxChildren="" if ctx.profile == "full" else "50")["scan"]
            self._wait(c, "/JSON/spider/view/status/", sid, "spider", ctx, limit)
            urls = self._api(c, "/JSON/spider/view/results/", scanId=sid).get("results", [])
            ctx.add_urls(urls)
            ctx.log(f"zap: spider found {len(urls)} URLs")
            if ctx.profile == "full":
                try:
                    self._api(c, "/JSON/ajaxSpider/action/scan/", url=target, subtreeOnly="true")
                    t0 = time.time()
                    while time.time() - t0 < 600 and self._api(c, "/JSON/ajaxSpider/view/status/").get("status") == "running":
                        time.sleep(5)
                    self._api(c, "/JSON/ajaxSpider/action/stop/")
                except httpx.HTTPError:
                    ctx.log("zap: ajax spider unavailable")
            if ctx.profile != "quick":
                self._api(c, "/JSON/ascan/action/setOptionMaxScanDurationInMins/", Integer=str(limit // 60))
                # DOM XSS (40026) drives a headless browser: slow and memory hungry -> full profile only
                self._api(c, "/JSON/ascan/action/enableAllScanners/")
                if ctx.profile != "full":
                    self._api(c, "/JSON/ascan/action/disableScanners/", ids="40026")
                aid = self._api(c, "/JSON/ascan/action/scan/", url=target, recurse="true", inScopeOnly="false")["scan"]
                self._wait(c, "/JSON/ascan/view/status/", aid, "active scan", ctx, limit + 120)
            t0 = time.time()
            while time.time() - t0 < 300 and int(self._api(c, "/JSON/pscan/view/recordsToScan/").get("recordsToScan", 0)) > 0:
                time.sleep(3)
            alerts = self._api(c, "/JSON/core/view/alerts/", baseurl=target, start="0", count="5000").get("alerts", [])
            ctx.artifact("zap-alerts.json").write_text(json.dumps(alerts))
            return parse_zap_alerts(alerts)
        except httpx.TransportError as e:
            raise RuntimeError("ZAP stopped responding during the scan - usually out of memory. Raise the zap "
                               "service's mem_limit / _JAVA_OPTIONS -Xmx in docker-compose.yml.") from e
        finally:
            c.close()


# ============================================================ SQLMap (detection only)
def parse_sqlmap_csv(text: str) -> list[Finding]:
    out = []
    for row in csv.DictReader(text.splitlines()):
        url = row.get("Target URL") or row.get("target url")
        if not url or not row.get("Parameter"):
            continue
        out.append(Finding(
            title=f"SQL injection in parameter '{row['Parameter']}'", severity=Severity.critical,
            confidence=Confidence.high, tool="sqlmap", rule_id="sqli", category="web",
            description=f"SQLMap confirmed SQL injection ({row.get('Place')} parameter) using technique(s) "
                        f"{row.get('Technique(s)')}. An attacker can read or modify database contents.",
            evidence=row.get("Note(s)", ""), cwe=["CWE-89"],
            location=Location(url=url, param=row["Parameter"], method=row.get("Place")),
            remediation="Use parameterised queries / prepared statements or an ORM; never concatenate input into SQL.",
            references=["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
        ))
    return out


def pick_injection_candidates(urls, limit=30) -> list[str]:
    seen, picked = set(), []
    for u in sorted(urls):
        p = urlparse(u)
        if not p.query:
            continue
        key = (p.netloc, p.path, tuple(sorted(parse_qs(p.query).keys())))
        if key in seen:
            continue
        seen.add(key)
        picked.append(u)
        if len(picked) >= limit:
            break
    return picked


class SqlmapScanner(Scanner):
    name = "sqlmap"
    needs = "web"
    stage = 2  # uses URLs discovered by ZAP
    min_profile = "standard"
    description = "Confirms SQL injection in discovered parameters (detection only, no data extraction)"

    def run(self, ctx):
        exe = require("sqlmap")
        ensure_in_scope(ctx.base_url, ctx.settings)
        outdir = ctx.artifact("sqlmap")
        results = ctx.artifact("sqlmap-results.csv")
        candidates = [u for u in pick_injection_candidates(ctx.crawled_urls, 40 if ctx.profile == "full" else 15)
                      if urlparse(u).hostname == ctx.host]
        common = ["--batch", "--level", "1", "--risk", "1", "--smart", "--threads", "4", "--timeout", "15",
                  "--retries", "1", "--output-dir", str(outdir), "--results-file", str(results), "--disable-coloring"]
        for k, v in ctx.request.auth_headers.items():
            common += ["--headers", f"{k}: {v}"]
        if candidates:
            listfile = ctx.artifact("sqlmap-targets.txt")
            listfile.write_text("\n".join(candidates))
            cmd = [exe, "-m", str(listfile), *common]
        else:
            cmd = [exe, "-u", ctx.base_url, "--crawl", "2", "--forms", *common]
        run(cmd, ctx.settings.tool_timeout, ok_codes=None)
        return parse_sqlmap_csv(results.read_text()) if results.exists() else []


# ============================================================ testssl.sh
def parse_testssl(data, host: str | None = None) -> list[Finding]:
    out = []
    items = data if isinstance(data, list) else data.get("scanResult", [])
    for i in items:
        sev = str(i.get("severity", "")).upper()
        if sev not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            continue
        cves = [c for c in str(i.get("cve", "")).split() if c.startswith("CVE-")]
        cwe = [c for c in str(i.get("cwe", "")).split() if c.startswith("CWE-")]
        out.append(Finding(
            title=f"TLS: {i.get('id')} - {str(i.get('finding', ''))[:100]}", severity=Severity.parse(sev),
            confidence=Confidence.high, tool="testssl", rule_id=str(i.get("id")), category="tls",
            description=str(i.get("finding", "")), cve=cves, cwe=cwe or ["CWE-326"],
            location=Location(host=host or i.get("ip", "").split("/")[0], port=int(i["port"]) if str(i.get("port", "")).isdigit() else None),
            remediation="Disable legacy protocols/ciphers; use TLS 1.2+ with modern AEAD ciphers and a valid certificate.",
        ))
    return out


class TestsslScanner(Scanner):
    name = "testssl"
    needs = "web"
    min_profile = "standard"
    description = "TLS/SSL configuration, protocols, ciphers, certificate and known TLS vulnerabilities"

    def applicable(self, ctx):
        ok, why = super().applicable(ctx)
        if ok and not (ctx.base_url or "").startswith("https"):
            return False, "target is not HTTPS"
        return ok, why

    def run(self, ctx):
        exe = require("testssl.sh")
        ensure_in_scope(ctx.base_url, ctx.settings)
        p = urlparse(ctx.base_url)
        out = ctx.artifact("testssl.json")
        run([exe, "--jsonfile", str(out), "--quiet", "--warnings", "off", "--color", "0", "--sneaky",
             f"{p.hostname}:{p.port or 443}"], ctx.settings.tool_timeout, ok_codes=None)
        return parse_testssl(json.loads(out.read_text()), p.hostname) if out.exists() else []
