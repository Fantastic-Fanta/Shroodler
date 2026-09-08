from __future__ import annotations

import io
import json

from shroodler_mcp.server import handle_request, serve


def _send(in_text: str) -> list[dict]:
    out = io.StringIO()
    serve(io.StringIO(in_text), out)
    lines = [ln for ln in out.getvalue().splitlines() if ln.strip()]
    return [json.loads(ln) for ln in lines]


def test_initialize():
    result = handle_request("initialize", {})
    assert result["protocolVersion"]
    assert result["serverInfo"]["name"] == "shroodler"


def test_tools_list_contains_expected_tools():
    result = handle_request("tools/list", {})
    names = {t["name"] for t in result["tools"]}
    assert names == {
        "scan_route",
        "check_idor",
        "check_ws_idor",
        "peer_write",
        "session_export",
        "extract_js_routes",
        "paced_fetch",
        "diff_since_baseline",
        "explain_finding",
        "reverify_fix",
    }
    for tool in result["tools"]:
        assert "inputSchema" in tool
        assert tool["inputSchema"]["type"] == "object"


def test_unknown_method_raises_via_rpc_layer():
    req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "nope", "params": {}}) + "\n"
    [resp] = _send(req)
    assert resp["error"]["code"] == -32601


def test_unknown_tool_returns_in_band_error():
    req = (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "does_not_exist", "arguments": {}},
            }
        )
        + "\n"
    )
    [resp] = _send(req)
    assert resp["error"]["code"] == -32602


def test_explain_finding_tool_call_end_to_end():
    req = (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {"name": "explain_finding", "arguments": {"finding_id": "missing-hsts"}},
            }
        )
        + "\n"
    )
    [resp] = _send(req)
    assert resp["id"] == 7
    assert resp["result"]["isError"] is False
    payload = json.loads(resp["result"]["content"][0]["text"])
    assert "Strict-Transport-Security" in payload["remediation"]


def test_explain_finding_bad_input_is_in_band_error_not_protocol_error():
    req = (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "explain_finding", "arguments": {}},
            }
        )
        + "\n"
    )
    [resp] = _send(req)
    assert "error" not in resp
    assert resp["result"]["isError"] is True


def test_notification_without_id_gets_no_reply():
    req = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"
    assert _send(req) == []


def test_ping():
    assert handle_request("ping", {}) == {}


def test_malformed_json_line_gets_parse_error():
    [resp] = _send("not json\n")
    assert resp["error"]["code"] == -32700


def test_list_tools_flag_prints_catalog(capsys):
    from shroodler_mcp.server import main

    assert main(["--list-tools"]) == 0
    payload = json.loads(capsys.readouterr().out)
    names = {t["name"] for t in payload["tools"]}
    assert names == {
        "scan_route",
        "check_idor",
        "check_ws_idor",
        "peer_write",
        "session_export",
        "extract_js_routes",
        "paced_fetch",
        "reverify_fix",
        "diff_since_baseline",
        "explain_finding",
    }
    for tool in payload["tools"]:
        assert tool["description"]
        assert tool["inputSchema"]["type"] == "object"


def test_help_names_every_tool(capsys):
    from shroodler_mcp.server import main

    try:
        main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0
    else:
        raise AssertionError("--help should SystemExit 0")
    text = capsys.readouterr().out
    for name in (
        "scan_route",
        "check_idor",
        "check_ws_idor",
        "peer_write",
        "session_export",
        "extract_js_routes",
        "paced_fetch",
        "reverify_fix",
        "diff_since_baseline",
        "explain_finding",
        "--list-tools",
    ):
        assert name in text
