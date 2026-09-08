from __future__ import annotations

from shroodler.extractors.js_api_surface import extract_js_api_surface


def test_extracts_jsonrpc_trpc_react_query_and_graphql():
    js = """
    const body = '{"jsonrpc":"2.0","method":"tx.status","id":1}';
    trpc.user.get.query("user.me");
    api.query("billing.invoice");
    useQuery(["/api/folders/list"]);
    const q = gql`query FolderDetail { folder { id } }`;
    mutation UpdateFolder($id: ID!) { updateFolder(id: $id) }
    """
    endpoints, findings = extract_js_api_surface("http://127.0.0.1/app.js", js)
    ids = {f.id for f in findings}
    assert "js-jsonrpc-method" in ids
    assert "js-trpc-procedure" in ids
    assert "js-react-query-key" in ids
    assert "js-graphql-operation" in ids
    markers = {e.endpoint for e in endpoints}
    assert "jsonrpc:tx.status" in markers
    assert any(m.startswith("trpc:") for m in markers)
    assert "react-query:/api/folders/list" in markers
    assert "graphql-query:FolderDetail" in markers


def test_empty_js_is_empty():
    assert extract_js_api_surface("http://x/a.js", "") == ([], [])


def test_crawl_seeds_from_react_query_and_trpc():
    from shroodler.extractors.js_api_surface import crawl_seeds_from_endpoint

    origin = "http://127.0.0.1:8081"
    assert crawl_seeds_from_endpoint(origin, "react-query:/api/folders/list") == [
        "http://127.0.0.1:8081/api/folders/list"
    ]
    assert crawl_seeds_from_endpoint(origin, "trpc:user.get") == [
        "http://127.0.0.1:8081/trpc/user.get"
    ]
    assert crawl_seeds_from_endpoint(origin, "jsonrpc:tx.status") == []
    assert crawl_seeds_from_endpoint(origin, "react-query:https://evil.example/x") == []
    assert crawl_seeds_from_endpoint(origin, "react-query://evil.example/x") == []
    assert crawl_seeds_from_endpoint(origin, "trpc:../etc/passwd") == []
    assert crawl_seeds_from_endpoint(origin, "trpc:https://evil.example/x") == []
    assert crawl_seeds_from_endpoint(origin, "react-query:/api/\x0cfolder") == []
    assert crawl_seeds_from_endpoint(origin, "react-query:/../../admin") == []
