"""Reflected and stored XSS probes."""

from __future__ import annotations

import secrets

import httpx

from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.probes.common import (
    body_text,
    challenge_vendor,
    dedupe,
    inject,
    normalize_params,
    probe_challenge_finding,
    request,
)
from shroodler.waf_detect import expand_if_waf


def _payload(nonce: str) -> str:
    return f"<script>alert('shroodler-xss-{nonce}')</script>"


# Content types that a browser will parse as HTML (so a reflected <script>
# actually executes). Anything else — application/json, text/plain, an API
# payload — reflects the marker without running it, so a verbatim reflection
# there is not executable XSS on its own.
def _renders_html(resp: httpx.Response | None) -> bool:
    if resp is None:
        return False
    try:
        ctype = str((resp.headers or {}).get("content-type") or "").lower()
    except Exception:  # noqa: BLE001
        ctype = ""
    if not ctype:
        # No declared type: a browser may content-sniff to HTML, so stay
        # conservative and treat it as renderable.
        return True
    return "text/html" in ctype or "application/xhtml" in ctype or "image/svg" in ctype


def probe_xss(
    url: str,
    method: str,
    params: list[dict],
    cookie_header: str,
    *,
    view_url: str = "",
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
    state=None,
    waf_detected: bool = False,
    waf_vendor: str | None = None,
) -> list[Finding]:
    """Inject a nonce-tagged script payload per param; check reflect and store."""
    method_u = (method or "GET").upper()
    if method_u not in {"GET", "POST", "PUT", "PATCH"}:
        return []
    normalized = normalize_params(params)
    if not normalized:
        return []

    findings: list[Finding] = []
    follow_url = view_url or url
    # Params whose active probe hit a WAF challenge instead of the app: these
    # went UNTESTED, and are surfaced as a coverage gap (not a vuln) so a
    # challenge-blocked run is not mistaken for a clean one.
    challenged: dict[str, str] = {}

    for item in normalized:
        name = item["name"]
        nonce = secrets.token_hex(3)
        marker = _payload(nonce)
        variants = expand_if_waf(
            (marker,),
            state=state,
            waf_detected=waf_detected,
            waf_vendor=waf_vendor,
        )
        recorded = False
        for injected in variants:
            resp = inject(
                url,
                method_u,
                normalized,
                name,
                injected,
                cookie_header=cookie_header,
                client=client,
                pacer=pacer,
            )
            vendor = challenge_vendor(resp)
            if vendor is not None:
                # The injection reached a WAF challenge, not the app: any echo
                # here is the block page, not reflection. Note the coverage gap
                # and keep trying the remaining variants, since an evasion
                # variant may still get through.
                challenged.setdefault(name, vendor)
                continue
            body = body_text(resp)
            if marker in body or injected in body:
                if _renders_html(resp):
                    findings.append(
                        Finding(
                            id="xss-reflected",
                            severity="high",
                            category="payload",
                            url=url,
                            description=(
                                f"{method_u} parameter {name!r} reflected the XSS "
                                "payload verbatim in an HTML response body."
                            ),
                            evidence=f"param={name} nonce={nonce}",
                            confidence="confirmed",
                        )
                    )
                else:
                    # Reflected, but in a non-HTML response (e.g. a JSON API):
                    # not directly executable. Worth noting in case the value
                    # is later rendered as HTML elsewhere (second-order/DOM).
                    findings.append(
                        Finding(
                            id="xss-reflected-nonhtml",
                            severity="low",
                            category="payload",
                            url=url,
                            description=(
                                f"{method_u} parameter {name!r} reflected the XSS "
                                "payload verbatim in a non-HTML response; not "
                                "directly executable, but check whether this value "
                                "is rendered as HTML elsewhere."
                            ),
                            evidence=f"param={name} nonce={nonce}",
                            confidence="heuristic",
                        )
                    )
                recorded = True
                break
        if recorded:
            # A variant got through and was tested: not a coverage gap, even if
            # an earlier variant was challenged.
            challenged.pop(name, None)

        write_method = method_u if method_u in {"POST", "PUT", "PATCH"} else "POST"
        stored_resp = inject(
            url,
            write_method,
            normalized,
            name,
            variants[0],
            cookie_header=cookie_header,
            client=client,
            pacer=pacer,
        )
        if stored_resp is None and write_method != "POST":
            stored_resp = inject(
                url,
                "POST",
                normalized,
                name,
                variants[0],
                cookie_header=cookie_header,
                client=client,
                pacer=pacer,
            )
        if stored_resp is None and method_u not in {"POST", "PUT", "PATCH"}:
            continue
        view = request(
            "GET",
            follow_url,
            cookie_header=cookie_header,
            client=client,
            pacer=pacer,
        )
        view_vendor = challenge_vendor(view)
        if view_vendor is not None:
            # The confirmation read was challenged: persistence is unverifiable,
            # so record coverage rather than silently dropping it.
            challenged.setdefault(name, view_vendor)
            continue
        view_body = body_text(view)
        if nonce in view_body:
            if _renders_html(view):
                findings.append(
                    Finding(
                        id="xss-stored",
                        severity="critical",
                        category="payload",
                        url=url,
                        description=(
                            f"Parameter {name!r} stored an XSS payload that later "
                            f"appeared in the HTML at {follow_url}."
                        ),
                        evidence=f"param={name} nonce={nonce} view={follow_url}",
                        confidence="confirmed",
                    )
                )
            else:
                findings.append(
                    Finding(
                        id="xss-stored-nonhtml",
                        severity="low",
                        category="payload",
                        url=url,
                        description=(
                            f"Parameter {name!r} persisted a payload that later "
                            f"appeared in a non-HTML response at {follow_url}; not "
                            "directly executable, but check for HTML rendering "
                            "elsewhere."
                        ),
                        evidence=f"param={name} nonce={nonce} view={follow_url}",
                        confidence="heuristic",
                    )
                )

    if challenged:
        findings.append(
            probe_challenge_finding(
                url, "xss", list(challenged), next(iter(challenged.values()))
            )
        )
    return dedupe(findings)
