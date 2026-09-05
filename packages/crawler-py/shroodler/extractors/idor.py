"""Same-session ID-sequence probing (IDOR).

For a crawled URL containing a purely-numeric path segment or query
parameter value (e.g. /orders/123, ?id=123 -- the classic sequential
object-reference shape), replay it with adjacent IDs (n-1, n+1) using the
crawl's OWN session/cookies (no privilege escalation involved -- this is
"can this same identity reach a neighboring object," not "can a lower-priv
session reach a higher-priv one," which is what authz_diff.py already
covers) and flag only when ALL of the following hold, to avoid the
false-positive/false-negative traps round-1 and round-2 review caught
elsewhere in this codebase:

1. The original URL's response is JSON and parses to an object (dict)
   with at least one top-level key -- this check only handles JSON API
   responses, where "does this look like the same kind of resource" has
   an unambiguous, structural answer (matching top-level key sets).
   HTML/other content types are skipped rather than guessed at.
2. A synthetic "almost certainly nonexistent" ID is probed first as a
   not-found baseline. If THAT also returns 2xx with a matching key
   shape, the target doesn't distinguish valid/invalid IDs via
   status/shape at all (e.g. it always returns 200), so nothing here can
   prove access to a genuinely different object -- skip the candidate
   entirely rather than report a finding neither status code nor shape
   actually supports.
3. Only then: the adjacent ID's response must itself be a genuine 2xx
   with the same top-level JSON key shape as the original. A 4xx/redirect
   response, or a 200 whose body key-shape matches the not-found
   baseline instead, is not evidence of anything and does not fire.
"""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from shroodler.models import Finding, Page
from shroodler.modes.static import StaticFetcher

_NUMERIC_SEGMENT = re.compile(r"^\d+$")
_MAX_CANDIDATES = 25
_NOT_FOUND_OFFSET = 987_654_321


def _is_json(content_type: str) -> bool:
    return "json" in content_type.lower()


def _json_object_keys(text: str) -> frozenset[str] | None:
    try:
        obj = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict) or not obj:
        return None
    return frozenset(obj.keys())


def _content_type(headers: dict[str, str]) -> str:
    for k, v in headers.items():
        if k.lower() == "content-type":
            return v
    return ""


class _Candidate:
    __slots__ = ("original_url", "build_url", "original_value")

    def __init__(self, original_url: str, build_url, original_value: int):
        self.original_url = original_url
        self.build_url = build_url
        self.original_value = original_value


def _path_candidates(url: str):
    parsed = urlparse(url)
    segments = parsed.path.split("/")
    for i, seg in enumerate(segments):
        if not _NUMERIC_SEGMENT.match(seg):
            continue

        def build(new_value: int, _i=i, _segments=list(segments), _parsed=parsed) -> str:
            new_segments = list(_segments)
            new_segments[_i] = str(new_value)
            return urlunparse(_parsed._replace(path="/".join(new_segments)))

        yield _Candidate(url, build, int(seg))


def _query_candidates(url: str):
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    for i, (key, value) in enumerate(pairs):
        if not _NUMERIC_SEGMENT.match(value):
            continue

        def build(new_value: int, _i=i, _pairs=list(pairs), _parsed=parsed, _key=key) -> str:
            new_pairs = list(_pairs)
            new_pairs[_i] = (_key, str(new_value))
            return urlunparse(_parsed._replace(query=urlencode(new_pairs)))

        yield _Candidate(url, build, int(value))


def find_id_candidates(pages: list[Page]):
    seen: set[str] = set()
    count = 0
    for page in pages:
        if count >= _MAX_CANDIDATES:
            break
        for candidate in list(_path_candidates(page.url)) + list(_query_candidates(page.url)):
            if candidate.original_url in seen:
                continue
            seen.add(candidate.original_url)
            count += 1
            yield candidate
            if count >= _MAX_CANDIDATES:
                break


def probe_idor(fetcher: StaticFetcher, pages: list[Page]) -> list[Finding]:
    findings: list[Finding] = []
    for candidate in find_id_candidates(pages):
        orig = fetcher.fetch(candidate.original_url)
        if not (200 <= orig.status_code < 300) or not _is_json(_content_type(orig.headers)):
            continue
        orig_keys = _json_object_keys(orig.text)
        if orig_keys is None:
            continue

        not_found_id = candidate.original_value + _NOT_FOUND_OFFSET
        not_found_url = candidate.build_url(not_found_id)
        not_found = fetcher.fetch(not_found_url)
        not_found_matches = (200 <= not_found.status_code < 300) and (
            _json_object_keys(not_found.text) == orig_keys
        )
        if not_found_matches:
            # This target doesn't distinguish a real ID from a made-up one
            # via status or shape -- can't prove anything either way here.
            continue

        for delta in (-1, 1):
            adjacent_id = candidate.original_value + delta
            if adjacent_id <= 0:
                continue
            adjacent_url = candidate.build_url(adjacent_id)
            if adjacent_url == candidate.original_url:
                continue
            adj = fetcher.fetch(adjacent_url)
            if not (200 <= adj.status_code < 300):
                continue
            if _json_object_keys(adj.text) != orig_keys:
                continue
            findings.append(
                Finding(
                    id="idor-adjacent-id-accessible",
                    severity="high",
                    category="auth",
                    url=candidate.original_url,
                    description=(
                        f"Adjacent ID {adjacent_id} returned a same-shaped JSON object using "
                        f"the same session that accessed {candidate.original_value} -- possible "
                        "broken object-level authorization"
                    ),
                    evidence=adjacent_url,
                )
            )
    return findings
