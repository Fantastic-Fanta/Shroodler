"""Malicious file-upload probe.

Uploads a benign-but-telltale SVG (a script plus a unique marker) to a file
field, then tries to confirm the real impact by locating where the app stored
it and fetching it back:

* ``upload-stored-xss`` (high, confirmed) -- the uploaded SVG/HTML is retrievable
  and served with an executable content-type (text/html, image/svg+xml, or an
  undeclared type a browser may sniff) with the marker intact, so it runs in a
  victim's browser.
* ``upload-unrestricted-type`` (medium, heuristic) -- the upload was accepted but
  the stored file could not be fetched back to confirm execution; a lead to
  verify by hand.

Non-destructive: the payload only pops a marker in a browser that renders it,
and the probe reads back its own upload, nothing else.
"""

from __future__ import annotations

import re
import uuid
from urllib.parse import urljoin

import httpx

from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.probes.common import body_text, dedupe, normalize_params, request, url_without_query

_FILE_PARAM_HINTS = ("file", "upload", "avatar", "attachment", "document", "image", "photo")
_EXECUTABLE_CT = ("text/html", "image/svg+xml", "application/xhtml")


def _looks_file_param(item: dict) -> bool:
    if str(item.get("in") or "").lower() == "file":
        return True
    name = (item.get("name") or "").lower()
    ftype = (item.get("type") or "").lower()
    return ftype == "file" or any(hint in name for hint in _FILE_PARAM_HINTS)


def _svg_payload(marker: str) -> bytes:
    return (
        f'<?xml version="1.0"?>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg">'
        f"<!-- {marker} --><script>/*{marker}*/</script>"
        f"<text>{marker}</text></svg>"
    ).encode()


def _served_executable(resp: httpx.Response, marker: str) -> bool:
    body = body_text(resp)
    if marker not in body:
        return False
    ctype = ""
    headers = getattr(resp, "headers", None) or {}
    try:
        ctype = str(headers.get("content-type") or headers.get("Content-Type") or "").lower()
    except Exception:  # noqa: BLE001
        ctype = ""
    if any(exe in ctype for exe in _EXECUTABLE_CT):
        return True
    # Only a truly absent or generic type is content-sniffed by browsers; an
    # explicit text/plain is NOT sniffed to HTML/SVG, so it is not executable.
    if ctype in ("", "application/octet-stream"):
        stripped = body.lstrip().lower()
        return (
            stripped.startswith("<?xml")
            or stripped.startswith("<svg")
            or stripped.startswith("<!doctype")
            or stripped.startswith("<html")
        )
    return False


def _candidate_urls(resp: httpx.Response, base_url: str, filename: str, marker: str) -> list[str]:
    """Pull URLs/paths out of the upload response that point at the stored file."""
    body = body_text(resp)
    out: list[str] = []
    seen: set[str] = set()
    stem = filename.split(".")[0]
    # Any URL/path token that references the filename, its stem, or the marker.
    for match in re.findall(r"""["'(]?((?:https?://|/)[^\s"'<>)]+)""", body):
        token = match.rstrip(".,);")
        if (filename in token or stem in token or marker in token) and token not in seen:
            seen.add(token)
            out.append(urljoin(base_url, token))
    return out


def _finding(fid: str, url: str, desc: str, evidence: str, sev: str, conf: str) -> Finding:
    return Finding(
        id=fid,
        severity=sev,  # type: ignore[arg-type]
        category="payload",
        url=url,
        description=desc,
        evidence=evidence,
        confidence=conf,  # type: ignore[arg-type]
    )


def probe_file_upload(
    url: str,
    method: str,
    params: list[dict],
    cookie_header: str,
    *,
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
    state=None,
    waf_detected: bool = False,
    waf_vendor: str | None = None,
) -> list[Finding]:
    """Upload an SVG marker file to each file field and confirm served execution."""
    method_u = (method or "POST").upper()
    if method_u not in {"POST", "PUT"}:
        return []
    normalized = normalize_params(params)
    file_params = [item for item in normalized if _looks_file_param(item)]
    if not file_params:
        return []

    findings: list[Finding] = []
    post_url = url_without_query(url)
    for item in file_params:
        field = item["name"]
        marker = f"shroodlerxss{uuid.uuid4().hex[:12]}"
        filename = f"{marker}.svg"
        resp = request(
            method_u,
            post_url,
            cookie_header=cookie_header,
            client=client,
            pacer=pacer,
            files={field: (filename, _svg_payload(marker), "image/svg+xml")},
        )
        if resp is None:
            continue
        status = int(getattr(resp, "status_code", 0) or 0)
        accepted = 200 <= status < 400
        confirmed = False
        for candidate in _candidate_urls(resp, post_url, filename, marker):
            fetched = request(
                "GET", candidate, cookie_header=cookie_header, client=client, pacer=pacer
            )
            if fetched is None:
                continue
            if _served_executable(fetched, marker):
                findings.append(
                    _finding(
                        "upload-stored-xss",
                        url,
                        desc=(
                            f"An SVG uploaded to {field!r} is served back executable "
                            f"at {candidate}; a browser opening it runs the embedded "
                            "script (stored XSS via file upload)."
                        ),
                        evidence=f"field={field} stored={candidate} marker={marker}",
                        sev="high",
                        conf="confirmed",
                    )
                )
                confirmed = True
                break
        if not confirmed and accepted:
            findings.append(
                _finding(
                    "upload-unrestricted-type",
                    url,
                    desc=(
                        f"A file field {field!r} accepted an SVG upload (status "
                        f"{status}). Could not fetch it back to confirm execution; "
                        "verify whether disallowed types/content are rejected."
                    ),
                    evidence=f"field={field} status={status} filename={filename}",
                    sev="medium",
                    conf="heuristic",
                )
            )
    return dedupe(findings)
