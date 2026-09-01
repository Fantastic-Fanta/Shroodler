from __future__ import annotations

from bs4 import BeautifulSoup

from shroodler.extractors.links import extract_css_urls, extract_links, is_honeypot


def test_extract_links_meta_css_and_honeypots():
    html = """
    <html><head>
    <link href="/s.css" rel="stylesheet">
    <meta http-equiv="refresh" content="0;url=/next">
    <style>.x{background:url(/bg.png)}</style>
    </head><body>
    <a href="/ok">ok</a>
    <a href="/hid" hidden>h</a>
    <a href="/aria" aria-hidden="true">a</a>
    <a class="honeypot" href="/hp">hp</a>
    <a style="display:none" href="/dn">dn</a>
    <a style="visibility:hidden" href="/vh">vh</a>
    <a style="left:-9999px" href="/off">off</a>
    <a style="opacity:0" href="/op">op</a>
    <div style="background:url(/inline.png)"></div>
    <form action="/go"></form>
    <script src="/app.js"></script>
    </body></html>
    """
    links = extract_links("http://127.0.0.1/", html)
    joined = " ".join(links)
    assert "/ok" in joined or "http://127.0.0.1/ok" in joined
    assert "hid" not in joined
    assert extract_css_urls("http://127.0.0.1/", "body{background:url(/z.png)}")


def test_is_honeypot_none_style():
    soup = BeautifulSoup("<a href='/x'>x</a>", "lxml")
    assert is_honeypot(soup.a) is False
