from __future__ import annotations

from types import SimpleNamespace

import httpx

from shroodler.probes import common
from shroodler.proxy_client import client_from_config, proxied_client


def test_proxied_client_sets_proxy_and_default_verify():
    captured = {}

    class FakeClient:
        def __init__(self, **kw):
            captured.update(kw)

    orig = httpx.Client
    httpx.Client = FakeClient
    try:
        proxied_client("http://127.0.0.1:8788")
    finally:
        httpx.Client = orig
    assert captured["proxy"] == "http://127.0.0.1:8788"
    assert captured["verify"] is True


def test_proxied_client_uses_ca_for_https_mitm():
    captured = {}

    class FakeClient:
        def __init__(self, **kw):
            captured.update(kw)

    orig = httpx.Client
    httpx.Client = FakeClient
    try:
        proxied_client("http://127.0.0.1:8788", ca_cert="/tmp/ca.pem")
    finally:
        httpx.Client = orig
    assert captured["verify"] == "/tmp/ca.pem"


def test_client_from_config_none_when_unset():
    assert client_from_config(SimpleNamespace()) is None
    assert client_from_config(SimpleNamespace(recording_proxy_url="")) is None


def test_client_from_config_builds_when_set():
    made = {}

    class FakeClient:
        def __init__(self, **kw):
            made.update(kw)

    orig = httpx.Client
    httpx.Client = FakeClient
    try:
        client_from_config(
            SimpleNamespace(
                recording_proxy_url="http://127.0.0.1:8788",
                recording_proxy_ca="/tmp/ca.pem",
            )
        )
    finally:
        httpx.Client = orig
    assert made["proxy"] == "http://127.0.0.1:8788"
    assert made["verify"] == "/tmp/ca.pem"


def test_fallback_client_plain_by_default():
    kinds = []

    class FakeClient:
        def __init__(self, **kw):
            kinds.append(kw)

    orig = httpx.Client
    httpx.Client = FakeClient
    try:
        common._new_fallback_client()
    finally:
        httpx.Client = orig
    assert kinds and "proxy" not in kinds[0]


def test_fallback_client_routes_through_bound_proxy():
    kinds = []

    class FakeClient:
        def __init__(self, **kw):
            kinds.append(kw)

    orig = httpx.Client
    httpx.Client = FakeClient
    try:
        with common.use_recording_proxy("http://127.0.0.1:8788"):
            common._new_fallback_client()
    finally:
        httpx.Client = orig
    assert kinds and kinds[0].get("proxy") == "http://127.0.0.1:8788"


def test_use_recording_proxy_empty_url_is_noop():
    with common.use_recording_proxy(""):
        assert common._recording_proxy.get() is None
