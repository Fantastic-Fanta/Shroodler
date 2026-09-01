"""Intentionally vulnerable server-rendered target app (app1)."""

from __future__ import annotations

import traceback

from flask import (
    Flask,
    make_response,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)

app = Flask(__name__)
app.secret_key = "app1-dev-secret-not-for-production"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

VALID_USER = "admin"
VALID_PASS = "admin"


@app.after_request
def add_headers(resp):
    path = request.path
    if path != "/login":
        resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    if path not in ("/", "/about"):
        resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Server"] = "Werkzeug/3.0.3 Python/3.12"
    resp.headers["X-Powered-By"] = "Flask/3.0.3"
    return resp


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == VALID_USER and password == VALID_PASS:
            session["user"] = username
            nxt = request.args.get("redirect_to") or url_for("dashboard")
            return redirect(nxt)
        return render_template("login.html", error="Invalid credentials"), 401
    return render_template("login.html", error=None)


@app.route("/dashboard")
def dashboard():
    user = session.get("user")
    if user != VALID_USER:
        resp = make_response(
            render_template("dashboard.html", user=None),
            200,
        )
    else:
        resp = make_response(render_template("dashboard.html", user=user))
    # Intentionally insecure cookie on this page (fixture finding).
    resp.set_cookie(
        "session_id",
        "sid-insecure-demo",
        secure=False,
        httponly=True,
        samesite="Lax",
    )
    return resp


@app.route("/settings")
def settings():
    return render_template("settings.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/error")
def boom():
    try:
        raise RuntimeError("intentional verbose error for crawler tests")
    except RuntimeError:
        body = "<h1>Internal Server Error</h1><pre>" + traceback.format_exc() + "</pre>"
        return body, 500


@app.route("/.git/config")
def git_config():
    return send_from_directory("exposed", "git-config", mimetype="text/plain")


@app.route("/backup.sql.bak")
def backup():
    return send_from_directory("exposed", "backup.sql.bak", mimetype="text/plain")


@app.route("/robots.txt")
def robots():
    return (
        "User-agent: *\nDisallow: /error\nDisallow: /settings\n",
        200,
        {"Content-Type": "text/plain"},
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081, debug=False)
