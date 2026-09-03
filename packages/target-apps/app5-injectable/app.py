"""Intentionally injectable local target. Do not 'fix'."""

from flask import Flask, request

app = Flask(__name__)

PAGE = """
<!doctype html>
<title>app5</title>
<form method="post" action="/search">
  <input name="q" type="text">
  <button>search</button>
</form>
"""


@app.get("/")
def home():
    return PAGE


@app.post("/search")
def search():
    q = request.form.get("q", "")
    if "../" in q or "..\\" in q:
        return "root:x:0:0:root:/root:/bin/sh\n", 200
    if "{{7*7}}" in q:
        return "computed:49", 200
    if "'" in q or "or" in q.lower():
        return "sqlite3.OperationalError: near \"OR\": syntax error", 500
    return f"<p>no rows for {q}</p>"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8087, debug=False)
