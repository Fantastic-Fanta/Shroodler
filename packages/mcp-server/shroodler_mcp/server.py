"""Minimal MCP (Model Context Protocol) server exposing Shroodler as agent
tools over stdio JSON-RPC 2.0.

No coding agent client existed when ZAP/Burp/Nuclei were built; this is the
thin, near-term-buildable wrapper the roadmap calls out: a coding agent can
call `scan_route` mid-session before a commit, `check_idor` to confirm a
lead, `diff_since_baseline` to ask what's new, and `explain_finding` for
remediation guidance -- all without shelling out to the CLI and parsing
text.

Deliberately implements just enough of the MCP wire protocol (JSON-RPC 2.0
over newline-delimited stdio messages: `initialize`, `tools/list`,
`tools/call`, plus tolerating the `notifications/initialized` notification)
rather than depending on an MCP SDK, so this has zero new runtime
dependencies. The message shapes match the public MCP spec, so any
MCP-speaking client can drive it.

Known limitation: `serve()`'s loop is synchronous and single-threaded --
one request is fully handled (including any live HTTP calls a tool
makes, e.g. a crawl or a scan-policy fetch) before the next line of
stdin is even read. A slow target makes a single `scan_route`/
`check_idor` call block every other request, including `tools/list` and
`ping`, for that call's duration. Each such call is still bounded by the
underlying HTTP client's own timeouts, so nothing hangs forever, but
there is currently no concurrency or cancellation.
"""

from __future__ import annotations

import json
import sys
from typing import Any, TextIO

import jsonschema

from shroodler_mcp.tools import TOOLS

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "shroodler", "version": "0.1.0"}


class RpcError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _tool_list_payload() -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "description": spec["description"],
            "inputSchema": spec["input_schema"],
        }
        for name, spec in sorted(TOOLS.items())
    ]


def handle_request(method: str, params: dict[str, Any]) -> Any:
    if method == "initialize":
        return {
            "protocolVersion": PROTOCOL_VERSION,
            "serverInfo": SERVER_INFO,
            "capabilities": {"tools": {}},
        }
    if method == "tools/list":
        return {"tools": _tool_list_payload()}
    if method == "tools/call":
        name = params.get("name")
        if name not in TOOLS:
            raise RpcError(-32602, f"unknown tool: {name!r}")
        arguments = params.get("arguments") or {}
        try:
            jsonschema.validate(arguments, TOOLS[name]["input_schema"])
        except jsonschema.ValidationError as exc:
            return {
                "content": [{"type": "text", "text": f"error: invalid arguments: {exc.message}"}],
                "isError": True,
            }
        try:
            result = TOOLS[name]["handler"](arguments)
        except (ValueError, FileNotFoundError, TypeError) as exc:
            # A tool-level failure (bad input, missing file) is reported
            # to the model as a normal (non-protocol-error) tool result
            # with isError set, per MCP convention -- so the calling agent
            # can see and react to it in-band instead of the transport
            # erroring out.
            return {
                "content": [{"type": "text", "text": f"error: {exc}"}],
                "isError": True,
            }
        return {
            "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
            "isError": False,
        }
    if method == "ping":
        return {}
    raise RpcError(-32601, f"method not found: {method!r}")


def _write_message(out: TextIO, payload: dict[str, Any]) -> None:
    out.write(json.dumps(payload) + "\n")
    out.flush()


def serve(in_stream: TextIO | None = None, out_stream: TextIO | None = None) -> None:
    in_stream = in_stream or sys.stdin
    out_stream = out_stream or sys.stdout
    for line in in_stream:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            _write_message(
                out_stream,
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}},
            )
            continue

        msg_id = message.get("id")
        method = message.get("method", "")
        params = message.get("params") or {}

        if msg_id is None:
            # A notification (no id) never gets a reply, per JSON-RPC --
            # includes MCP's "notifications/initialized" handshake step.
            continue

        try:
            result = handle_request(method, params)
        except RpcError as exc:
            _write_message(
                out_stream,
                {"jsonrpc": "2.0", "id": msg_id, "error": {"code": exc.code, "message": exc.message}},
            )
            continue
        except Exception as exc:  # noqa: BLE001 - last-resort protocol-level guard
            _write_message(
                out_stream,
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32000, "message": f"internal error: {exc}"},
                },
            )
            continue

        _write_message(out_stream, {"jsonrpc": "2.0", "id": msg_id, "result": result})


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="shroodler mcp-server",
        description=(
            "MCP server exposing Shroodler as agent tools over stdio JSON-RPC 2.0.\n"
            "\n"
            "Tools:\n"
            "  scan_route            Crawl one URL (optional active payloads)\n"
            "  check_idor            Confirm or drop an IDOR lead (second session)\n"
            "  check_ws_idor         Test WS subscription authorization (IDOR probe)\n"
            "  peer_write            Replay known-object writes as a peer session\n"
            "  session_export        Dump storageState from HAR/JSONL/CDP\n"
            "  extract_js_routes     Mine {id} URL templates from a local JS file\n"
            "  paced_fetch           GET a short URL list at 1 req/s\n"
            "  reverify_fix          Re-scan a route; report whether a finding is gone\n"
            "  diff_since_baseline   Compare a scan against a checked-in baseline\n"
            "  explain_finding       Static remediation guidance for a finding id\n"
            "\n"
            "Active tools require a scan-policy consent manifest by default.\n"
            "This process speaks MCP on stdin/stdout; do not run it interactively\n"
            "unless an MCP client is driving it. Use --list-tools to inspect the\n"
            "catalog without starting the loop."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="Print the tool catalog as JSON and exit",
    )
    args = parser.parse_args(argv)
    if args.list_tools:
        json.dump({"tools": _tool_list_payload()}, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
