"""Turn the user's input (git URL, ZIP, website URL) into something scannable."""
from __future__ import annotations

import base64
import os
import re
import shutil
import stat
import subprocess
import zipfile
from pathlib import Path
from urllib.parse import urlparse

from .config import Settings
from .models import TargetKind

GIT_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org")


class IngestError(Exception):
    pass


def detect_kind(target: str) -> TargetKind:
    if target.lower().endswith(".zip") and Path(target).exists():
        return TargetKind.zip
    if target.startswith("git@") or target.endswith(".git"):
        return TargetKind.repo
    parsed = urlparse(target if "://" in target else "https://" + target)
    if parsed.hostname in GIT_HOSTS and len([p for p in parsed.path.split("/") if p]) >= 2:
        return TargetKind.repo
    return TargetKind.url


_REPO_RE = re.compile(r"^https://[A-Za-z0-9.\-]+(:\d+)?/[A-Za-z0-9._\-/]+$")


def clone_repo(url: str, dest: Path, settings: Settings, depth: int = 50) -> Path:
    """Shallow-clone over HTTPS only. Private GitHub repos use GITHUB_TOKEN via a
    header, so the token never lands in .git/config or in logs."""
    url = url.strip()
    if url.startswith("git@"):
        raise IngestError("SSH URLs are not supported; use the https:// URL of the repo.")
    # normalise github web URLs like https://github.com/o/r/tree/main -> https://github.com/o/r
    p = urlparse(url)
    parts = [x for x in p.path.split("/") if x]
    if p.hostname in GIT_HOSTS and len(parts) > 2:
        url = f"https://{p.hostname}/{parts[0]}/{parts[1]}"
    if not _REPO_RE.match(url):
        raise IngestError(f"Refusing unusual repository URL: {url!r}")
    dest.mkdir(parents=True, exist_ok=True)
    cmd = ["git", "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never",
           "-c", "core.symlinks=false"]
    if settings.github_token and urlparse(url).hostname == "github.com":
        basic = base64.b64encode(f"x-access-token:{settings.github_token}".encode()).decode()
        cmd += ["-c", f"http.extraHeader=Authorization: Basic {basic}"]
    cmd += ["clone", "--depth", str(depth), "--no-tags", "--single-branch", url, str(dest / "src")]
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600, env=env)
    if r.returncode != 0:
        msg = r.stderr.strip().splitlines()[-1] if r.stderr.strip() else "unknown error"
        if settings.github_token:
            msg = msg.replace(settings.github_token, "***")
        raise IngestError(f"git clone failed: {msg}. If the repo is private, set GITHUB_TOKEN in .env.")
    return dest / "src"


def safe_extract_zip(zip_path: Path, dest: Path, max_total_mb: int = 2000, max_files: int = 200_000) -> Path:
    """Extract a ZIP while blocking path traversal (zip-slip), symlinks and zip bombs."""
    out = (dest / "src").resolve()
    out.mkdir(parents=True, exist_ok=True)
    total = 0
    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as e:
        raise IngestError(f"Not a valid ZIP file: {e}") from e
    with zf:
        infos = zf.infolist()
        if len(infos) > max_files:
            raise IngestError(f"ZIP has too many entries ({len(infos)})")
        for info in infos:
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                continue  # never materialise symlinks
            name = info.filename.replace("\\", "/")
            if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
                raise IngestError(f"Absolute path in ZIP: {name}")
            target = (out / name).resolve()
            if not str(target).startswith(str(out) + os.sep) and target != out:
                raise IngestError(f"Path traversal in ZIP: {name}")
            total += info.file_size
            if total > max_total_mb * 1024 * 1024:
                raise IngestError(f"ZIP expands to more than {max_total_mb} MB")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
    children = [c for c in out.iterdir() if c.name != "__MACOSX"]
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return out


# ---- scan exclusions (.vulnscanignore) ----------------------------------------
import fnmatch  # noqa: E402

# Directories that are deliberately vulnerable test assets or vendored code and
# should never be reported as the scanned project's own vulnerabilities.
DEFAULT_EXCLUDES = [
    "tests/fixtures/", "test/fixtures/", "**/fixtures/vulnapp/", "demo/chatbot/",
    "node_modules/", "vendor/", ".venv/", "venv/", "site-packages/",
]


def load_excludes(source_dir: Path) -> list[str]:
    """Patterns from <source>/.vulnscanignore (gitignore-style, simple globs) plus sane defaults."""
    patterns = list(DEFAULT_EXCLUDES)
    f = source_dir / ".vulnscanignore"
    if f.exists():
        for line in f.read_text(errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
    return patterns


def path_excluded(rel_path: str, patterns: list[str]) -> bool:
    """True if a repo-relative file/dir path matches any exclude pattern."""
    if not rel_path:
        return False
    p = "/" + rel_path.replace("\\", "/").lstrip("/")
    for pat in patterns:
        pat = pat.replace("\\", "/")
        if pat.endswith("/"):  # a directory: match it anywhere in the path
            seg = "/" + pat.strip("/") + "/"
            if seg in p + "/":
                return True
        if fnmatch.fnmatch(p, "*" + pat) or fnmatch.fnmatch(p.lstrip("/"), pat) or fnmatch.fnmatch(p, "*/" + pat):
            return True
    return False
