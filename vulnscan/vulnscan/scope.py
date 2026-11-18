"""Scope enforcement: decides which hosts may be actively scanned.

Every network-facing scanner, the API, the CLI and the MCP server call
`ensure_in_scope()` before touching a host. This is deliberately enforced in
code, never left to an LLM.

A host is in scope if ANY of these is true:
  1. it matches ALLOWED_TARGETS (exact host, "*.example.com", or a CIDR), or
  2. its ownership was verified (DNS TXT record or /.well-known file), or
  3. REQUIRE_OWNERSHIP_VERIFICATION=false (not recommended).
Cloud metadata addresses are always refused.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import secrets
import socket
from urllib.parse import urlparse

import httpx

from .config import Settings, get_settings

ALWAYS_BLOCKED = {ipaddress.ip_network("169.254.169.254/32"), ipaddress.ip_network("fd00:ec2::254/128")}


class ScopeError(Exception):
    pass


def host_of(target: str) -> str:
    if "://" not in target:
        target = "http://" + target
    host = urlparse(target).hostname
    if not host:
        raise ScopeError(f"Cannot parse a host from {target!r}")
    return host.lower()


def _resolve(host: str) -> list[ipaddress._BaseAddress]:
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    return list({ipaddress.ip_address(i[4][0].split("%")[0]) for i in infos})


def _matches_allowlist(host: str, ips, settings: Settings) -> bool:
    for raw in settings.allowed_targets.split(","):
        entry = raw.strip().lower()
        if not entry:
            continue
        if entry.startswith("*.") and (host == entry[2:] or host.endswith(entry[1:])):
            return True
        if host == entry:
            return True
        if "/" in entry or _is_ip(entry):
            try:
                net = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            if any(ip in net for ip in ips):
                return True
    return False


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# --- ownership verification ------------------------------------------------

def _secret(settings: Settings) -> bytes:
    p = settings.data_dir / ".verify_secret"
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        p.write_text(secrets.token_hex(32))
    return p.read_text().strip().encode()


def verification_token(host: str, settings: Settings | None = None) -> str:
    settings = settings or get_settings()
    return "vulnscan-verify=" + hmac.new(_secret(settings), host.encode(), hashlib.sha256).hexdigest()[:32]


def _verified_file(settings: Settings):
    return settings.data_dir / "verified_hosts.json"


def verified_hosts(settings: Settings | None = None) -> set[str]:
    settings = settings or get_settings()
    f = _verified_file(settings)
    return set(json.loads(f.read_text())) if f.exists() else set()


def verification_instructions(host: str, settings: Settings | None = None) -> dict:
    token = verification_token(host, settings)
    return {
        "host": host,
        "token": token,
        "options": [
            f"DNS: add a TXT record on {host} (or _vulnscan.{host}) with value: {token}",
            f"HTTP: serve https://{host}/.well-known/vulnscan-verify.txt containing: {token}",
        ],
    }


def verify_ownership(host: str, settings: Settings | None = None) -> bool:
    settings = settings or get_settings()
    token = verification_token(host, settings)
    ok = False
    try:
        import dns.resolver

        for name in (host, f"_vulnscan.{host}"):
            try:
                for rr in dns.resolver.resolve(name, "TXT", lifetime=5):
                    if token in b"".join(rr.strings).decode(errors="ignore"):
                        ok = True
            except Exception:
                pass
    except ImportError:
        pass
    if not ok:
        for scheme in ("https", "http"):
            try:
                r = httpx.get(f"{scheme}://{host}/.well-known/vulnscan-verify.txt", timeout=10, follow_redirects=False)
                if r.status_code == 200 and token in r.text:
                    ok = True
                    break
            except httpx.HTTPError:
                continue
    if ok:
        hosts = verified_hosts(settings) | {host}
        _verified_file(settings).write_text(json.dumps(sorted(hosts)))
    return ok


# --- the gate ----------------------------------------------------------------

def ensure_in_scope(target: str, settings: Settings | None = None) -> str:
    """Raise ScopeError unless the target's host may be scanned. Returns the host."""
    settings = settings or get_settings()
    host = host_of(target)
    ips = _resolve(host)
    for ip in ips:
        if any(ip in net for net in ALWAYS_BLOCKED):
            raise ScopeError(f"{host} resolves to a cloud metadata address; refusing.")
    if _matches_allowlist(host, ips, settings):
        return host
    if host in verified_hosts(settings):
        return host
    if any(ip.is_private or ip.is_loopback for ip in ips) and not settings.allow_private_networks:
        raise ScopeError(
            f"{host} is a private/internal address and is not in ALLOWED_TARGETS. "
            "Add it to ALLOWED_TARGETS in .env if it is yours.")
    if not settings.require_ownership_verification:
        return host
    raise ScopeError(
        f"{host} is not in scope. Prove you own it first: POST /verify/{host} "
        f"(or `vulnscan verify {host}`), or add it to ALLOWED_TARGETS.")
