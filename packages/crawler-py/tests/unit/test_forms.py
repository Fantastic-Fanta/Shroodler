from __future__ import annotations

from shroodler.extractors.forms import extract_forms


def test_method_get_post_and_default():
    html = """
    <form action="/get" method="GET"><input name="q"></form>
    <form action="/post" method="POST"><input name="q"></form>
    <form action="/default"><input name="q"></form>
    """
    forms, _ = extract_forms(html, "http://127.0.0.1/")
    methods = {f.action: f.method for f in forms}
    assert methods["/get"] == "GET"
    assert methods["/post"] == "POST"
    assert methods["/default"] == "GET"


def test_enctype_urlencoded_and_multipart():
    html = """
    <form action="/u" enctype="application/x-www-form-urlencoded"><input name="a"></form>
    <form action="/m" enctype="multipart/form-data"><input name="b" type="file"></form>
    """
    forms, _ = extract_forms(html, "http://127.0.0.1/")
    enc = {f.action: f.enctype for f in forms}
    assert enc["/u"] == "application/x-www-form-urlencoded"
    assert enc["/m"] == "multipart/form-data"


def test_field_types():
    html = """
    <form action="/f">
      <input name="t" type="text">
      <input name="p" type="password">
      <input name="h" type="hidden">
      <input name="c" type="checkbox">
      <input name="r" type="radio">
      <select name="s"><option>1</option></select>
      <textarea name="a"></textarea>
      <input name="file" type="file">
    </form>
    """
    forms, _ = extract_forms(html, "http://127.0.0.1/")
    types = {f.name: f.type for f in forms[0].fields}
    assert types["t"] == "text"
    assert types["p"] == "password"
    assert types["h"] == "hidden"
    assert types["c"] == "checkbox"
    assert types["r"] == "radio"
    assert types["s"] == "select"
    assert types["a"] == "textarea"
    assert types["file"] == "file"
    hidden = {f.name: f.hidden for f in forms[0].fields}
    assert hidden["h"] is True
    assert hidden["t"] is False


def test_disabled_and_readonly():
    html = """
    <form action="/f">
      <input name="d" disabled>
      <input name="r" readonly>
      <input name="n">
    </form>
    """
    forms, _ = extract_forms(html, "http://127.0.0.1/")
    flags = {f.name: (f.disabled, f.readonly) for f in forms[0].fields}
    assert flags["d"][0] is True
    assert flags["r"][1] is True
    assert flags["n"][0] is None


def test_nested_and_multiple_forms():
    html = """
    <form action="/outer"><input name="o">
      <form action="/inner"><input name="i"></form>
    </form>
    <form action="/other"><input name="x"></form>
    """
    forms, _ = extract_forms(html, "http://127.0.0.1/")
    actions = [f.action for f in forms]
    assert "/outer" in actions
    assert "/other" in actions
    # BeautifulSoup still surfaces the inner form tag.
    assert "/inner" in actions or any(ff.name == "i" for f in forms for ff in f.fields)


def test_static_mode_misses_js_injected_form():
    html = (
        '<div id="root"></div>'
        '<script>document.body.innerHTML="<form action=/js><input name=x></form>"</script>'
    )
    forms, _ = extract_forms(html, "http://127.0.0.1/")
    assert forms == []

