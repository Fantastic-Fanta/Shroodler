"""Evidence binding: attach captured HTTP traffic to a finding as proof.

A finding without a proof is an assertion ("this parameter looks injectable").
A finding *with* a proof is a demonstration: it carries the exact request that
was sent and the response that came back, and it names the verbatim strings in
that traffic that establish the claim. Only a finding that survives this binding
may be marked ``verified`` -- a reviewer can reproduce the judgement from the
record alone, without trusting the prose.

This mirrors the architecture behind ARTEX's evidence binding (AGPL); the code
here is Shroodler's own, under Apache-2.0.

The one rule that gives the binding its teeth: ``bind_proof`` refuses to verify
a finding whose quotes do not appear character-for-character in the captured
request/response. A probe that overstates its evidence gets an exception, not a
false ``verified`` flag.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from shroodler.models import Finding, Proof, ProofQuote

# Response header the recording proxy (packages/proxy-go) stamps with the id of
# the session that captured the exchange, so a finding's proof can point at the
# full, unbounded record in the proxy store. Absent when a request did not go
# through the proxy; binding then simply records no session_id. The proxy-go
# side must emit this exact header for end-to-end session binding to light up.
PROXY_SESSION_HEADER = "X-Shroodler-Session"


def session_id_from_response(resp: object) -> str | None:
    """Return the proxy session id a response was stamped with, if any.

    Best-effort and case-insensitive; returns None for a response with no
    headers or no stamp (the common case when not proxying through proxy-go).
    """
    try:
        headers = getattr(resp, "headers", None)
        if headers is None:
            return None
        getter = getattr(headers, "get", None)
        if callable(getter):
            val = getter(PROXY_SESSION_HEADER) or getter(PROXY_SESSION_HEADER.lower())
            return str(val) if val else None
    except Exception:  # noqa: BLE001 - never let header reading break a proof
        return None
    return None

# Excerpts are bounded so a proof never balloons a report with a full binary
# body; the unbounded exchange lives in the proxy store, reachable by
# ``session_id``. Large enough to hold the interesting window around a match.
_MAX_EXCERPT = 8192


def _clip(text: str | None, limit: int = _MAX_EXCERPT) -> str | None:
    if text is None:
        return None
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...[truncated]..."


def _render_headers(headers: Mapping[str, str] | None) -> str:
    if not headers:
        return ""
    return "\n".join(f"{k}: {v}" for k, v in headers.items())


def render_request(
    method: str,
    url: str,
    headers: Mapping[str, str] | None = None,
    body: str | None = None,
) -> str:
    """Render a request to a stable, greppable text form for an excerpt."""
    lines = [f"{method.upper()} {url}"]
    rendered = _render_headers(headers)
    if rendered:
        lines.append(rendered)
    if body:
        lines.append("")
        lines.append(body)
    return "\n".join(lines)


def render_response(
    status_code: int,
    headers: Mapping[str, str] | None = None,
    body: str | None = None,
) -> str:
    """Render a response to a stable, greppable text form for an excerpt."""
    lines = [f"HTTP {status_code}"]
    rendered = _render_headers(headers)
    if rendered:
        lines.append(rendered)
    if body:
        lines.append("")
        lines.append(body)
    return "\n".join(lines)


class ProofBindingError(ValueError):
    """Raised when the claimed evidence is not present in the captured traffic."""


def build_proof(
    *,
    method: str,
    url: str,
    status_code: int | None = None,
    request_excerpt: str | None = None,
    response_excerpt: str | None = None,
    quotes: Iterable[tuple[str, str]] = (),
    session_id: str | None = None,
    captured_at: str | None = None,
    what: str = "finding",
) -> Proof:
    """Validate the evidence and return a :class:`Proof`, or raise.

    ``quotes`` is an iterable of ``(source, text)`` pairs where ``source`` is
    ``"request"`` or ``"response"``; each ``text`` must appear verbatim in the
    corresponding (clipped) excerpt. At least one quote is required -- a proof
    with no quote names nothing and cannot verify anything. ``what`` only names
    the subject in error messages.

    Raises :class:`ProofBindingError` if a quote is absent from its excerpt or
    no quote is supplied.
    """
    quote_list = [ProofQuote(source=src, text=text) for src, text in quotes]
    if not quote_list:
        raise ProofBindingError(f"refusing to verify {what}: no evidence quote supplied")

    req = _clip(request_excerpt)
    resp = _clip(response_excerpt)
    # Validate verbatim presence here so the caller gets ProofBindingError (a
    # clear, catchable signal) rather than a bare pydantic ValidationError.
    for q in quote_list:
        hay = req if q.source == "request" else resp
        if hay is None or q.text not in hay:
            raise ProofBindingError(
                f"refusing to verify {what}: quote not found verbatim in "
                f"captured {q.source}: {q.text!r}"
            )

    return Proof(
        method=method,
        url=url,
        status_code=status_code,
        session_id=session_id,
        request_excerpt=req,
        response_excerpt=resp,
        quotes=quote_list,
        captured_at=captured_at,
    )


def bind_proof(
    finding: Finding,
    *,
    method: str,
    url: str,
    status_code: int | None = None,
    request_excerpt: str | None = None,
    response_excerpt: str | None = None,
    quotes: Iterable[tuple[str, str]] = (),
    session_id: str | None = None,
    captured_at: str | None = None,
) -> Finding:
    """Return a copy of ``finding`` bound to the exchange that proves it.

    Thin wrapper over :func:`build_proof`; see it for the quote rules. Raises
    :class:`ProofBindingError` if the evidence does not check out. The returned
    finding is ``verified=True``; the input finding is not mutated.
    """
    proof = build_proof(
        method=method,
        url=url,
        status_code=status_code,
        request_excerpt=request_excerpt,
        response_excerpt=response_excerpt,
        quotes=quotes,
        session_id=session_id,
        captured_at=captured_at,
        what=f"finding {finding.id!r}",
    )
    return finding.model_copy(update={"proof": proof, "verified": True})
