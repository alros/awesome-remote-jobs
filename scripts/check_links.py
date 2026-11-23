#!/usr/bin/env python3
"""Check every link in README.md and report domains that don't seem to work.

Usage:
    python3 scripts/check_links.py [--readme README.md] [--output link-report.md]

Optional: set GOOGLE_SAFE_BROWSING_KEY to also query the Google Safe Browsing
API (v4) for malware / phishing / unwanted-software warnings. Without the key,
only TLS/DNS/HTTP checks are performed.

Uses only the Python standard library.
Exit code: 0 if nothing is broken or flagged, 1 otherwise.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import http.client
import json
import os
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)
TIMEOUT = 20
MAX_BODY = 256 * 1024
WORKERS = 16

# Categories
OK = "ok"
BROKEN = "broken"
BLOCKED = "blocked"
SECURITY = "security"

MD_LINK_RE = re.compile(r"\]\((https?://[^)\s]+)\)")
ANGLE_LINK_RE = re.compile(r"<(https?://[^>\s]+)>")

# Cloudflare origin-side errors: the site behind Cloudflare is down/misconfigured.
CLOUDFLARE_ORIGIN_ERRORS = {520, 521, 522, 523, 524, 525, 526, 527, 530}
CLOUDFLARE_ERROR_CODES_RE = re.compile(r"error code:?\s*(1016|1001|1003|1014|1033)", re.I)

CHALLENGE_MARKERS = (
    "just a moment...",
    "attention required! | cloudflare",
    "cf-chl-",
    "challenge-platform",
    "/cdn-cgi/challenge",
    "verify you are human",
    "checking your browser",
    "ddos protection by",
    "px-captcha",            # PerimeterX
    "_incapsula_resource",   # Imperva
    "captcha-delivery.com",  # DataDome
    "access denied",         # Akamai and others
)

PARKED_MARKERS = (
    "this domain is for sale",
    "this domain may be for sale",
    "domain is for sale",
    "buy this domain",
    "the domain name is for sale",
    "hugedomains.com",
    "sedo.com/search",
    "dan.com",
    "afternic.com",
    "parkingcrew",
    "bodis.com",
    "domain has expired",
    "this domain has been registered",
)


@dataclass
class Result:
    url: str
    category: str
    reason: str
    status: int | None = None
    final_url: str | None = None
    notes: list[str] = field(default_factory=list)


def extract_links(markdown: str) -> list[str]:
    seen: dict[str, None] = {}
    for regex in (MD_LINK_RE, ANGLE_LINK_RE):
        for match in regex.finditer(markdown):
            url = match.group(1).rstrip(".,;")
            seen.setdefault(url, None)
    return list(seen)


def domain_of(url: str) -> str:
    host = urllib.parse.urlsplit(url).hostname or url
    return host.lower().removeprefix("www.")


def looks_like_challenge(body: str, headers) -> bool:
    if headers.get("cf-mitigated", "").lower() == "challenge":
        return True
    lowered = body.lower()
    return any(marker in lowered for marker in CHALLENGE_MARKERS)


def is_cloudflare(headers) -> bool:
    return "cloudflare" in headers.get("server", "").lower() or "cf-ray" in {
        k.lower() for k in headers.keys()
    }


def read_body(resp) -> str:
    try:
        raw = resp.read(MAX_BODY)
    except (http.client.IncompleteRead, OSError) as exc:
        raw = getattr(exc, "partial", b"") or b""
    charset = resp.headers.get_content_charset() or "utf-8"
    return raw.decode(charset, errors="replace")


def classify_error_response(url: str, status: int, headers, body: str) -> Result:
    cf_server = is_cloudflare(headers)

    if status in CLOUDFLARE_ORIGIN_ERRORS:
        return Result(url, BROKEN, f"Cloudflare origin error {status}", status)
    m = CLOUDFLARE_ERROR_CODES_RE.search(body)
    if cf_server and m:
        return Result(url, BROKEN, f"Cloudflare error {m.group(1)}", status)

    if status in (401, 403, 405, 406, 429, 503, 999) and (
        looks_like_challenge(body, headers) or cf_server or status in (403, 429, 999)
    ):
        who = "Cloudflare" if cf_server else "bot protection"
        return Result(url, BLOCKED, f"HTTP {status} – {who} challenge/deny", status)

    if status in (404, 410):
        return Result(url, BROKEN, f"HTTP {status} – page not found", status)
    if status >= 500:
        return Result(url, BROKEN, f"HTTP {status} – server error", status)
    return Result(url, BROKEN, f"HTTP {status}", status)


def fetch(url: str) -> Result:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        },
    )
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
            body = read_body(resp)
            final_url = resp.geturl()
            status = resp.status
            headers = resp.headers
    except urllib.error.HTTPError as exc:
        try:
            body = read_body(exc)
        except Exception:
            body = ""
        return classify_error_response(url, exc.code, exc.headers, body)
    except urllib.error.URLError as exc:
        return classify_network_error(url, exc.reason)
    except (ssl.SSLError, ssl.CertificateError) as exc:
        return classify_network_error(url, exc)
    except (TimeoutError, socket.timeout):
        return Result(url, BROKEN, f"Timed out after {TIMEOUT}s")
    except (http.client.HTTPException, ConnectionError, OSError) as exc:
        return Result(url, BROKEN, f"Connection error: {exc.__class__.__name__}: {exc}")

    result = Result(url, OK, f"HTTP {status}", status, final_url)

    if looks_like_challenge(body, headers) and len(body) < 20000:
        result.category = BLOCKED
        result.reason = f"HTTP {status} but served a bot challenge page"

    lowered = body.lower()
    parked = next((m for m in PARKED_MARKERS if m in lowered), None)
    if parked and len(body) < 60000:
        result.category = BROKEN
        result.reason = f"Looks like a parked/for-sale domain (matched '{parked}')"

    if final_url and domain_of(final_url) != domain_of(url):
        result.notes.append(f"redirects to {domain_of(final_url)}")
    if final_url and url.startswith("https://") and final_url.startswith("http://"):
        result.category = SECURITY
        result.reason = "HTTPS redirects to plain HTTP"

    return result


def classify_network_error(url: str, reason) -> Result:
    if isinstance(reason, ssl.SSLCertVerificationError):
        return Result(url, SECURITY, f"TLS certificate invalid: {reason.verify_message}")
    if isinstance(reason, (ssl.SSLError, ssl.CertificateError)):
        return Result(url, SECURITY, f"TLS/SSL error: {reason}")
    if isinstance(reason, socket.gaierror):
        return Result(url, BROKEN, "DNS lookup failed – domain does not resolve")
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return Result(url, BROKEN, f"Timed out after {TIMEOUT}s")
    if isinstance(reason, ConnectionRefusedError):
        return Result(url, BROKEN, "Connection refused")
    return Result(url, BROKEN, f"Network error: {reason}")


def check(url: str) -> Result:
    result = fetch(url)
    # Retry once for transient failures.
    if result.category == BROKEN and (
        result.reason.startswith(("Timed out", "Connection", "Network", "HTTP 5"))
    ):
        retry = fetch(url)
        if retry.category != BROKEN:
            return retry
    return result


def safe_browsing(urls: list[str], api_key: str) -> dict[str, list[str]]:
    """Return {url: [threat types]} for URLs flagged by Google Safe Browsing."""
    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find?key="
        + urllib.parse.quote(api_key)
    )
    flagged: dict[str, list[str]] = {}
    for i in range(0, len(urls), 500):
        payload = {
            "client": {"clientId": "readme-link-checker", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in urls[i : i + 500]],
            },
        }
        req = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.load(resp)
        for match in data.get("matches", []):
            flagged.setdefault(match["threat"]["url"], []).append(match["threatType"])
    return flagged


def render_report(results: list[Result], sb_status: str) -> str:
    by_cat: dict[str, list[Result]] = {BROKEN: [], SECURITY: [], BLOCKED: [], OK: []}
    for r in results:
        by_cat[r.category].append(r)

    def domain_table(items: list[Result]) -> list[str]:
        grouped: dict[str, list[Result]] = {}
        for r in items:
            grouped.setdefault(domain_of(r.url), []).append(r)
        lines = ["| Domain | URL | Problem |", "|---|---|---|"]
        for dom in sorted(grouped):
            for r in grouped[dom]:
                extra = f" ({'; '.join(r.notes)})" if r.notes else ""
                lines.append(f"| {dom} | {r.url} | {r.reason}{extra} |")
        return lines

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    bad_domains = sorted({domain_of(r.url) for r in by_cat[BROKEN] + by_cat[SECURITY]})
    out = [
        "# README link check report",
        "",
        f"Generated {now}. Checked {len(results)} unique links.",
        f"Safe Browsing: {sb_status}.",
        "",
        f"- Broken: **{len(by_cat[BROKEN])}**",
        f"- Security warnings: **{len(by_cat[SECURITY])}**",
        f"- Blocked by bot protection (check manually): **{len(by_cat[BLOCKED])}**",
        f"- OK: **{len(by_cat[OK])}**",
        "",
        "## Domains that don't seem to work",
        "",
    ]
    out += [f"- {d}" for d in bad_domains] or ["_None_ 🎉"]
    for cat, title in (
        (SECURITY, "Security warnings"),
        (BROKEN, "Broken"),
        (BLOCKED, "Blocked by Cloudflare / bot protection – check manually in a browser"),
    ):
        out += ["", f"## {title}", ""]
        out += domain_table(by_cat[cat]) if by_cat[cat] else ["_None_"]

    redirected = [r for r in by_cat[OK] if r.notes]
    if redirected:
        out += ["", "## OK but redirected to another domain (consider updating)", ""]
        out += domain_table(redirected)
    return "\n".join(out) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--readme", default="README.md")
    parser.add_argument("--output", default="link-report.md")
    args = parser.parse_args()

    with open(args.readme, encoding="utf-8") as f:
        urls = extract_links(f.read())
    print(f"Checking {len(urls)} links from {args.readme}...", file=sys.stderr)

    results: list[Result] = []
    with cf.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for r in pool.map(check, urls):
            mark = {OK: ".", BROKEN: "X", BLOCKED: "B", SECURITY: "!"}[r.category]
            print(mark, end="", flush=True, file=sys.stderr)
            results.append(r)
    print(file=sys.stderr)

    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_KEY")
    if api_key:
        try:
            flagged = safe_browsing(urls, api_key)
            sb_status = f"checked, {len(flagged)} URL(s) flagged"
            for r in results:
                if r.url in flagged:
                    r.category = SECURITY
                    r.reason = "Google Safe Browsing: " + ", ".join(sorted(set(flagged[r.url])))
        except Exception as exc:  # noqa: BLE001 - report and continue
            sb_status = f"FAILED ({exc})"
    else:
        sb_status = "skipped (set GOOGLE_SAFE_BROWSING_KEY to enable)"

    report = render_report(results, sb_status)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"Report written to {args.output}", file=sys.stderr)

    return 1 if any(r.category in (BROKEN, SECURITY) for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
