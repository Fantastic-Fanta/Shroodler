from __future__ import annotations

from shroodler.llm_agent.tools import TOOLS, tool_by_name

_EXPECTED = (
    "crawl",
    "probe_sqli",
    "probe_xss",
    "probe_idor",
    "probe_ssrf",
    "probe_open_redirect",
    "probe_path_traversal",
    "probe_ssti",
    "probe_host_header",
    "probe_jwt",
    "probe_graphql",
    "check_authz",
    "fetch_and_read",
    "hypothesise",
    "report",
)


def test_tools_list_has_exact_names_in_order():
    assert [t["name"] for t in TOOLS] == list(_EXPECTED)


def test_each_tool_has_description_and_params():
    for tool in TOOLS:
        assert tool["description"]
        assert isinstance(tool["params"], dict)


def test_tool_by_name_finds_and_misses():
    crawl = tool_by_name("crawl")
    assert crawl is not None
    assert crawl["name"] == "crawl"
    assert tool_by_name("nope") is None
    assert tool_by_name("") is None
    assert tool_by_name(None) is None  # type: ignore[arg-type]
