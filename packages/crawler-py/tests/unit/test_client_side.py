from __future__ import annotations

from shroodler.extractors.client_side import extract_client_side


def test_flags_message_listener_without_origin_check():
    js = "window.addEventListener('message', function(e){ handle(e.data); });"
    findings = extract_client_side(js, "http://app/app.js")
    assert len(findings) == 1
    f = findings[0]
    assert f.id == "postmessage-no-origin-check"
    assert f.severity == "medium"
    assert f.confidence == "heuristic"


def test_onmessage_assignment_also_flagged():
    js = "window.onmessage = function(e){ doThing(e.data); };"
    assert len(extract_client_side(js, "http://app/x.js")) == 1


def test_not_flagged_when_origin_is_checked():
    js = (
        "window.addEventListener('message', function(e){"
        "  if (e.origin !== 'https://trusted.example') return;"
        "  handle(e.data);"
        "});"
    )
    assert extract_client_side(js, "http://app/app.js") == []


def test_no_listener_no_finding():
    assert extract_client_side("console.log('hello');", "http://app/x.js") == []
    assert extract_client_side("", "http://app/x.js") == []
