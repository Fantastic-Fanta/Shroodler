"""Server-side template injection probes against string parameters."""

from __future__ import annotations

import secrets

import httpx

from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.probes.common import (
    body_text,
    dedupe,
    inject,
    normalize_params,
    request,
)
from shroodler.waf_detect import expand_if_waf

# 4-digit primes used as per-request nonces so cached pages cannot fake a hit.
_FOUR_DIGIT_PRIMES: tuple[int, ...] = tuple(
    n
    for n in range(1009, 9974)
    if n % 2
    and all(n % p for p in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47))
    and all(n % p for p in range(53, int(n**0.5) + 1, 2))
)

# (payload, expected substring). Fixed-math results are accepted but the
# nonce payload is the primary confirmed signal.
MATH_PAYLOADS: tuple[tuple[str, str], ...] = (
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("#{7*7}", "49"),
    ("*{7*7}", "49"),
    ("{{7*'7'}}", "7777777"),
    ('${"freemarker"?upper_case}', "FREEMARKER"),
)


def nonce_prime() -> int:
    return int(secrets.choice(_FOUR_DIGIT_PRIMES))


def nonce_payload(prime: int) -> tuple[str, str]:
    """Jinja/Twig-style math using a random 4-digit prime."""
    return f"{{{{{prime}*7}}}}", str(int(prime) * 7)


def ssti_evaluated(body: str, expected: str, *, baseline: str = "") -> bool:
    """True when `expected` appears in the response and is not just cached HTML."""
    if not expected or expected not in (body or ""):
        return False
    if baseline and expected in baseline:
        return False
    return True


def _finding(url: str, evidence: str) -> Finding:
    return Finding(
        id="ssti-reflected",
        severity="critical",
        category="payload",
        url=url,
        description=("A template-engine math payload was evaluated in the response (SSTI)."),
        evidence=evidence,
        confidence="confirmed",
    )


def probe_ssti(
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
    """Inject SSTI math payloads into every string parameter."""
    method_u = (method or "GET").upper()
    if method_u not in {"GET", "POST"}:
        return []
    normalized = normalize_params(params)
    if not normalized:
        return []

    baseline_resp = request(
        method_u,
        url,
        cookie_header=cookie_header,
        client=client,
        pacer=pacer,
    )
    baseline = body_text(baseline_resp)

    findings: list[Finding] = []
    for item in normalized:
        name = item["name"]
        prime = nonce_prime()
        payload, expected = nonce_payload(prime)
        for injected in expand_if_waf(
            (payload,),
            state=state,
            waf_detected=waf_detected,
            waf_vendor=waf_vendor,
        ):
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
            body = body_text(resp)
            if ssti_evaluated(body, expected, baseline=baseline):
                findings.append(
                    _finding(
                        url,
                        f"param={name} payload={payload!r} expected={expected!r} nonce={prime}",
                    )
                )
                break
        else:
            hit = False
            for payload, expected in MATH_PAYLOADS:
                for injected in expand_if_waf(
                    (payload,),
                    state=state,
                    waf_detected=waf_detected,
                    waf_vendor=waf_vendor,
                ):
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
                    if resp is None:
                        continue
                    body = body_text(resp)
                    if not ssti_evaluated(body, expected, baseline=baseline):
                        continue
                    findings.append(
                        _finding(
                            url,
                            f"param={name} payload={payload!r} expected={expected!r}",
                        )
                    )
                    hit = True
                    break
                if hit:
                    break

    return dedupe(findings)
