from __future__ import annotations

import pytest
from pydantic import ValidationError

from shroodler.evidence import (
    ProofBindingError,
    bind_proof,
    render_request,
    render_response,
)
from shroodler.models import Finding, Proof


def _finding(**kw) -> Finding:
    base = dict(
        id="payload-sql-error",
        severity="high",
        category="payload",
        url="https://t.example/item?id=1",
        description="SQL error reflected",
        evidence="syntax error near ''",
    )
    base.update(kw)
    return Finding(**base)


def test_finding_defaults_unverified_no_proof():
    f = _finding()
    assert f.verified is False
    assert f.proof is None


def test_verified_without_proof_is_rejected():
    with pytest.raises(ValidationError):
        _finding(verified=True)


def test_verified_with_proof_but_no_quotes_is_rejected():
    # Proof itself is valid (no quotes to check), but a verified finding
    # requires at least one quote.
    proof = Proof(method="GET", url="https://t.example/item?id=1")
    with pytest.raises(ValidationError):
        _finding(verified=True, proof=proof)


def test_proof_quote_must_be_verbatim():
    with pytest.raises(ValidationError):
        Proof(
            method="GET",
            url="https://t.example/item?id=1",
            response_excerpt="HTTP 200\n\nhello world",
            quotes=[{"source": "response", "text": "NOT PRESENT"}],
        )


def test_bind_proof_verifies_when_quote_present():
    resp = render_response(200, {"Content-Type": "text/html"}, "you asked for SHRDLRIMPACT8.0.33")
    bound = bind_proof(
        _finding(),
        method="GET",
        url="https://t.example/item?id=1",
        status_code=200,
        response_excerpt=resp,
        quotes=[("response", "SHRDLRIMPACT8.0.33")],
        session_id="sess-123",
    )
    assert bound.verified is True
    assert bound.proof is not None
    assert bound.proof.session_id == "sess-123"
    assert bound.proof.quotes[0].text == "SHRDLRIMPACT8.0.33"
    assert bound.proof.status_code == 200


def test_bind_proof_refuses_absent_quote():
    resp = render_response(200, None, "benign body")
    with pytest.raises(ProofBindingError):
        bind_proof(
            _finding(),
            method="GET",
            url="https://t.example/item?id=1",
            response_excerpt=resp,
            quotes=[("response", "secret-not-here")],
        )


def test_bind_proof_requires_at_least_one_quote():
    with pytest.raises(ProofBindingError):
        bind_proof(
            _finding(),
            method="GET",
            url="https://t.example/item?id=1",
            response_excerpt="HTTP 200\n\nbody",
            quotes=[],
        )


def test_bind_proof_does_not_mutate_input():
    f = _finding()
    bind_proof(
        f,
        method="GET",
        url="https://t.example/item?id=1",
        request_excerpt=render_request("GET", "https://t.example/item?id=1' OR 1=1"),
        quotes=[("request", "OR 1=1")],
    )
    assert f.verified is False
    assert f.proof is None


def test_request_quote_checked_against_request_excerpt_only():
    # A quote claiming source=request must be in the request excerpt, not the
    # response -- sources are not interchangeable.
    with pytest.raises(ProofBindingError):
        bind_proof(
            _finding(),
            method="GET",
            url="https://t.example/x",
            request_excerpt=render_request("GET", "https://t.example/x"),
            response_excerpt="HTTP 200\n\nmarker-abc",
            quotes=[("request", "marker-abc")],
        )
