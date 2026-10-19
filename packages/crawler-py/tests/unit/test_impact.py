from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

from shroodler.impact import (
    annotate_impact,
    prove_idor,
    prove_reflected_xss,
    prove_sqli,
)
from shroodler.pacer import Pacer


class FakeResp:
    def __init__(self, status=200, text=""):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.elapsed = timedelta(seconds=0.0)
        self.headers = {}


class FakeClient:
    def __init__(self, handler):
        self.handler = handler

    def request(self, method, url, **kw):
        vals = []
        for key in ("params", "data"):
            blob = kw.get(key) or {}
            if isinstance(blob, dict):
                vals.extend(str(v) for v in blob.values())
        return self.handler(" ".join(vals))

    def close(self):
        pass


class IdentityClient:
    """Routes GET reads by the Cookie header: owner vs peer controlled bodies."""

    def __init__(self, owner_cookie, peer_cookie, owner_resp, peer_resp):
        self.owner_cookie = owner_cookie
        self.peer_cookie = peer_cookie
        self.owner_resp = owner_resp
        self.peer_resp = peer_resp
        self.calls = []

    def request(self, method, url, **kw):
        cookie = str((kw.get("headers") or {}).get("Cookie") or "")
        self.calls.append((method, cookie))
        if self.peer_cookie and self.peer_cookie in cookie:
            return self.peer_resp
        if self.owner_cookie and self.owner_cookie in cookie:
            return self.owner_resp
        return FakeResp(0, "")

    def close(self):
        pass


def _vuln_handler(value: str) -> FakeResp:
    # A real DB concatenates the split sentinel halves and appends version().
    if "SHRDLR" in value and "IMPACT" in value and ("concat" in value or "extractvalue" in value):
        return FakeResp(200, "<p>result: SHRDLRIMPACTMySQL-8.0.33-log</p>")
    return FakeResp(200, "<p>no rows</p>")


def _reflecting_handler(value: str) -> FakeResp:
    # Only reflects the raw payload (sentinel halves stay separate) -> no join.
    return FakeResp(200, f"<p>you searched for {value}</p>")


def test_prove_sqli_extracts_version():
    proof = prove_sqli(
        "http://t/search", "q", client=FakeClient(_vuln_handler), pacer=Pacer(0)
    )
    assert proof is not None
    assert "MySQL-8.0.33" in proof


def test_prove_sqli_no_false_positive_on_reflection():
    # A reflecting-but-not-injectable endpoint must not yield a proof.
    proof = prove_sqli(
        "http://t/search", "q", client=FakeClient(_reflecting_handler), pacer=Pacer(0)
    )
    assert proof is None


def test_prove_sqli_requires_url_and_param():
    assert prove_sqli("", "q", client=FakeClient(_vuln_handler), pacer=Pacer(0)) is None
    assert prove_sqli("http://t/x", "", client=FakeClient(_vuln_handler), pacer=Pacer(0)) is None


def test_annotate_impact_annotates_confirmed_sqli():
    finding = SimpleNamespace(
        id="sqli",
        confidence="confirmed",
        url="http://t/search",
        evidence="param=q payload=\"'\"",
    )
    n = annotate_impact([finding], client=FakeClient(_vuln_handler), pacer=Pacer(0))
    assert n == 1
    assert "IMPACT:" in finding.evidence
    assert "MySQL-8.0.33" in finding.evidence


def test_annotate_impact_skips_non_sqli_and_unconfirmed():
    xss = SimpleNamespace(
        id="xss-reflected", confidence="confirmed", url="http://t/", evidence="param=q"
    )
    heuristic = SimpleNamespace(
        id="sqli", confidence="heuristic", url="http://t/", evidence="param=q"
    )
    assert annotate_impact([xss, heuristic], client=FakeClient(_vuln_handler), pacer=Pacer(0)) == 0


def test_annotate_impact_skips_when_no_param_in_evidence():
    finding = SimpleNamespace(
        id="sqli", confidence="confirmed", url="http://t/", evidence="no param here"
    )
    assert annotate_impact([finding], client=FakeClient(_vuln_handler), pacer=Pacer(0)) == 0


# --- IDOR fetch-and-diff --------------------------------------------------

OWNER_C = "sid=owner"
PEER_C = "sid=peer"
IDOR_URL = "http://t/api/orders/42"
_OWNER_OBJ = '{"id": 42, "ownerId": 7, "email": "alice@corp.test", "balance": 900}'


def _idor(client, owner=OWNER_C, peer=PEER_C):
    return prove_idor(IDOR_URL, owner, peer, client=client, pacer=Pacer(0))


def test_prove_idor_identical_body_is_cross_user_read():
    client = IdentityClient(OWNER_C, PEER_C, FakeResp(200, _OWNER_OBJ), FakeResp(200, _OWNER_OBJ))
    proof = prove_idor(
        "http://t/api/orders/42", OWNER_C, PEER_C, client=client, pacer=Pacer(0)
    )
    assert proof is not None
    assert "identical response body" in proof
    # Exactly one owner read and one peer read.
    assert len(client.calls) == 2


def test_prove_idor_shared_object_ids_when_bodies_differ():
    # Peer gets a differently-wrapped response that still carries the owner's
    # distinctive ids (ownerId / email) -- cross-user object read.
    peer_body = '{"data": {"ownerId": 7, "email": "alice@corp.test"}, "ts": 123}'
    client = IdentityClient(OWNER_C, PEER_C, FakeResp(200, _OWNER_OBJ), FakeResp(200, peer_body))
    proof = prove_idor(
        "http://t/api/orders/42", OWNER_C, PEER_C, client=client, pacer=Pacer(0)
    )
    assert proof is not None
    assert "owner's object identifiers" in proof
    assert "alice@corp.test" in proof or "7" in proof


def test_prove_idor_no_proof_when_peer_denied():
    client = IdentityClient(OWNER_C, PEER_C, FakeResp(200, _OWNER_OBJ), FakeResp(403, "denied"))
    assert _idor(client) is None


def test_prove_idor_no_proof_when_bodies_unrelated():
    peer_body = '{"id": 99, "ownerId": 13, "email": "bob@corp.test"}'
    client = IdentityClient(OWNER_C, PEER_C, FakeResp(200, _OWNER_OBJ), FakeResp(200, peer_body))
    assert _idor(client) is None


def test_prove_idor_requires_peer_cookie():
    client = IdentityClient(OWNER_C, PEER_C, FakeResp(200, _OWNER_OBJ), FakeResp(200, _OWNER_OBJ))
    assert _idor(client, peer="") is None


def test_prove_idor_skips_tiny_bodies():
    client = IdentityClient(OWNER_C, PEER_C, FakeResp(200, "ok"), FakeResp(200, "ok"))
    assert _idor(client) is None


def test_annotate_impact_annotates_confirmed_idor():
    finding = SimpleNamespace(
        id="idor-cross-account",
        confidence="confirmed",
        url="http://t/api/orders/42",
        evidence="owner=200 peer=200",
    )
    client = IdentityClient(OWNER_C, PEER_C, FakeResp(200, _OWNER_OBJ), FakeResp(200, _OWNER_OBJ))
    n = annotate_impact(
        [finding], cookie_header=OWNER_C, peer_cookie_header=PEER_C, client=client, pacer=Pacer(0)
    )
    assert n == 1
    assert "IMPACT: peer identity read owner's order" in finding.evidence


def test_annotate_impact_idor_skips_without_peer():
    finding = SimpleNamespace(
        id="idor-cross-account",
        confidence="confirmed",
        url="http://t/api/orders/42",
        evidence="owner=200 peer=200",
    )
    client = IdentityClient(OWNER_C, PEER_C, FakeResp(200, _OWNER_OBJ), FakeResp(200, _OWNER_OBJ))
    assert annotate_impact([finding], cookie_header=OWNER_C, client=client, pacer=Pacer(0)) == 0


# --- IDOR with token (Authorization: Bearer) auth, no cookies -------------

OWNER_BEARER = "owner-tok-abc"
PEER_BEARER = "peer-tok-xyz"
OWNER_H = {"Authorization": f"Bearer {OWNER_BEARER}"}
PEER_H = {"Authorization": f"Bearer {PEER_BEARER}"}


class BearerClient:
    """Routes GET reads by the Authorization header: owner vs peer bodies."""

    def __init__(self, owner_tok, peer_tok, owner_resp, peer_resp):
        self.owner_tok = owner_tok
        self.peer_tok = peer_tok
        self.owner_resp = owner_resp
        self.peer_resp = peer_resp
        self.calls = []

    def request(self, method, url, **kw):
        headers = kw.get("headers") or {}
        auth = str(headers.get("Authorization") or "")
        cookie = str(headers.get("Cookie") or "")
        self.calls.append((method, auth, cookie))
        if self.peer_tok and self.peer_tok in auth:
            return self.peer_resp
        if self.owner_tok and self.owner_tok in auth:
            return self.owner_resp
        return FakeResp(0, "")

    def close(self):
        pass


def test_prove_idor_token_auth_identical_body_is_cross_user_read():
    client = BearerClient(
        OWNER_BEARER, PEER_BEARER, FakeResp(200, _OWNER_OBJ), FakeResp(200, _OWNER_OBJ)
    )
    proof = prove_idor(
        IDOR_URL,
        owner_headers=OWNER_H,
        peer_headers=PEER_H,
        client=client,
        pacer=Pacer(0),
    )
    assert proof is not None
    assert "identical response body" in proof
    # Exactly one owner read + one peer read, each carrying its bearer token.
    assert len(client.calls) == 2
    assert any(OWNER_BEARER in auth for _m, auth, _c in client.calls)
    assert any(PEER_BEARER in auth for _m, auth, _c in client.calls)
    # No cookies were sent -- pure token auth.
    assert all(cookie == "" for _m, _a, cookie in client.calls)


def test_prove_idor_token_auth_shared_ids_when_bodies_differ():
    peer_body = '{"data": {"ownerId": 7, "email": "alice@corp.test"}, "ts": 9}'
    client = BearerClient(
        OWNER_BEARER, PEER_BEARER, FakeResp(200, _OWNER_OBJ), FakeResp(200, peer_body)
    )
    proof = prove_idor(
        IDOR_URL, owner_headers=OWNER_H, peer_headers=PEER_H, client=client, pacer=Pacer(0)
    )
    assert proof is not None
    assert "owner's object identifiers" in proof


def test_prove_idor_token_auth_no_proof_when_peer_denied():
    # Secured twin: the peer token is rejected -> access control holds -> None.
    client = BearerClient(
        OWNER_BEARER, PEER_BEARER, FakeResp(200, _OWNER_OBJ), FakeResp(403, "forbidden")
    )
    assert (
        prove_idor(
            IDOR_URL, owner_headers=OWNER_H, peer_headers=PEER_H, client=client, pacer=Pacer(0)
        )
        is None
    )


def test_prove_idor_token_auth_no_proof_when_bodies_unrelated():
    peer_body = '{"id": 99, "ownerId": 13, "email": "bob@corp.test"}'
    client = BearerClient(
        OWNER_BEARER, PEER_BEARER, FakeResp(200, _OWNER_OBJ), FakeResp(200, peer_body)
    )
    assert (
        prove_idor(
            IDOR_URL, owner_headers=OWNER_H, peer_headers=PEER_H, client=client, pacer=Pacer(0)
        )
        is None
    )


def test_prove_idor_requires_some_peer_auth():
    # Owner token present but peer has neither cookie nor header -> no attempt.
    client = BearerClient(
        OWNER_BEARER, PEER_BEARER, FakeResp(200, _OWNER_OBJ), FakeResp(200, _OWNER_OBJ)
    )
    assert (
        prove_idor(IDOR_URL, owner_headers=OWNER_H, client=client, pacer=Pacer(0)) is None
    )


def test_prove_idor_requires_some_owner_auth():
    # Peer token present but owner has no credential -> no meaningful baseline.
    client = BearerClient(
        OWNER_BEARER, PEER_BEARER, FakeResp(200, _OWNER_OBJ), FakeResp(200, _OWNER_OBJ)
    )
    assert (
        prove_idor(IDOR_URL, peer_headers=PEER_H, client=client, pacer=Pacer(0)) is None
    )


def test_annotate_impact_annotates_confirmed_idor_token_auth():
    finding = SimpleNamespace(
        id="idor-cross-account",
        confidence="confirmed",
        url=IDOR_URL,
        evidence="owner=200 peer=200",
    )
    client = BearerClient(
        OWNER_BEARER, PEER_BEARER, FakeResp(200, _OWNER_OBJ), FakeResp(200, _OWNER_OBJ)
    )
    n = annotate_impact(
        [finding],
        owner_headers=OWNER_H,
        peer_headers=PEER_H,
        client=client,
        pacer=Pacer(0),
    )
    assert n == 1
    assert "IMPACT: peer identity read owner's order" in finding.evidence


def test_annotate_impact_idor_skips_without_any_peer_identity():
    finding = SimpleNamespace(
        id="idor-cross-account",
        confidence="confirmed",
        url=IDOR_URL,
        evidence="owner=200 peer=200",
    )
    client = BearerClient(
        OWNER_BEARER, PEER_BEARER, FakeResp(200, _OWNER_OBJ), FakeResp(200, _OWNER_OBJ)
    )
    # Owner token but no peer cookie and no peer headers -> skipped.
    assert annotate_impact([finding], owner_headers=OWNER_H, client=client, pacer=Pacer(0)) == 0


def test_annotate_impact_idor_skips_non_object_url():
    # GraphQL-style IDOR: the endpoint is not object-addressed, so the
    # fetch-and-diff proof does not apply.
    finding = SimpleNamespace(
        id="idor-cross-account",
        confidence="confirmed",
        url="http://t/graphql",
        evidence="",
    )
    client = IdentityClient(OWNER_C, PEER_C, FakeResp(200, _OWNER_OBJ), FakeResp(200, _OWNER_OBJ))
    assert (
        annotate_impact(
            [finding],
            cookie_header=OWNER_C,
            peer_cookie_header=PEER_C,
            client=client,
            pacer=Pacer(0),
        )
        == 0
    )


# --- reflected XSS execution ---------------------------------------------


def _xss_runner_executes(fired_url, sentinel, **kw):
    # Stand-in for the headless browser: the sentinel "ran".
    return f"payload executed in headless Chromium (alert() fired; sentinel {sentinel})"


def _xss_runner_inert(fired_url, sentinel, **kw):
    return None


def test_prove_reflected_xss_confirms_execution():
    proof = prove_reflected_xss(
        "http://t/search", "q", runner=_xss_runner_executes
    )
    assert proof is not None
    assert "payload executed" in proof


def test_prove_reflected_xss_none_when_inert():
    assert prove_reflected_xss("http://t/search", "q", runner=_xss_runner_inert) is None


def test_prove_reflected_xss_only_get():
    assert (
        prove_reflected_xss("http://t/search", "q", method="POST", runner=_xss_runner_executes)
        is None
    )


def test_prove_reflected_xss_fires_param_in_url():
    seen = {}

    def runner(fired_url, sentinel, **kw):
        seen["url"] = fired_url
        seen["sentinel"] = sentinel
        return f"executed; sentinel {sentinel}"

    prove_reflected_xss("http://t/search?page=2", "q", runner=runner)
    assert "q=" in seen["url"]
    assert "page=2" in seen["url"]  # existing params preserved
    assert seen["sentinel"] in seen["url"]  # the nonce payload was placed in q


def test_annotate_impact_annotates_confirmed_reflected_xss():
    finding = SimpleNamespace(
        id="xss-reflected",
        confidence="confirmed",
        url="http://t/search",
        evidence="param=q nonce=abc123",
    )
    n = annotate_impact([finding], prove_xss=True, xss_runner=_xss_runner_executes, pacer=Pacer(0))
    assert n == 1
    assert "IMPACT: reflected XSS executes" in finding.evidence


def test_annotate_impact_xss_gated_behind_prove_xss():
    finding = SimpleNamespace(
        id="xss-reflected",
        confidence="confirmed",
        url="http://t/search",
        evidence="param=q nonce=abc123",
    )
    # prove_xss defaults False -> the active execution proof does not fire.
    assert annotate_impact([finding], xss_runner=_xss_runner_executes, pacer=Pacer(0)) == 0


def test_annotate_impact_mixed_findings_each_class():
    sqli = SimpleNamespace(
        id="sqli", confidence="confirmed", url="http://t/search", evidence="param=q"
    )
    idor = SimpleNamespace(
        id="idor-cross-account",
        confidence="confirmed",
        url="http://t/api/orders/42",
        evidence="owner=200 peer=200",
    )
    xss = SimpleNamespace(
        id="xss-reflected", confidence="confirmed", url="http://t/x", evidence="param=q"
    )
    client = IdentityClient(OWNER_C, PEER_C, FakeResp(200, _OWNER_OBJ), FakeResp(200, _OWNER_OBJ))

    # SQLi proof needs its own vuln client; run the three with the clients that
    # match their endpoints. Here we just confirm IDOR + XSS annotate together.
    n = annotate_impact(
        [idor, xss],
        cookie_header=OWNER_C,
        peer_cookie_header=PEER_C,
        client=client,
        pacer=Pacer(0),
        prove_xss=True,
        xss_runner=_xss_runner_executes,
    )
    assert n == 2
    assert "cross-user object read" in idor.evidence
    assert "reflected XSS executes" in xss.evidence
    assert sqli.evidence == "param=q"  # untouched here
