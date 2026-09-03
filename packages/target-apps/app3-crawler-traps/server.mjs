import http from "node:http";
import { URL } from "node:url";

const port = Number(process.env.PORT || 8083);
const hits = new Map();

function html(body) {
  return `<!DOCTYPE html><html><head><title>app3</title></head><body>${body}</body></html>`;
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${port}`);
  const p = url.pathname;

  const send = (status, type, body, extra = {}) => {
    res.writeHead(status, { "Content-Type": type, "X-Frame-Options": "DENY", ...extra });
    res.end(body);
  };

  if (p === "/") {
    return send(
      200,
      "text/html; charset=utf-8",
      html(`
        <h1>Traps</h1>
        <a href="/page/1">Next</a>
        <a href="/loop-a">Loop</a>
        <a href="/limited">Limited</a>
        <a href="/visible">Visible</a>
        <a href="/secret-honey" hidden>honeypot hidden</a>
        <a href="/offscreen" style="display:none">honeypot css</a>
        <a class="honeypot" href="/class-hp">honeypot class</a>
      `),
    );
  }

  if (p.startsWith("/page/")) {
    const n = Number(p.split("/")[2] || "1");
    return send(
      200,
      "text/html; charset=utf-8",
      html(`<a href="/page/${n + 1}">next</a>`),
    );
  }

  if (p === "/loop-a") {
    res.writeHead(302, { Location: "/loop-b" });
    return res.end();
  }
  if (p === "/loop-b") {
    res.writeHead(302, { Location: "/loop-a" });
    return res.end();
  }

  if (p === "/limited") {
    const n = (hits.get("limited") || 0) + 1;
    hits.set("limited", n);
    if (n < 3) {
      return send(429, "text/plain", "slow down", { "Retry-After": "0" });
    }
    return send(200, "text/html; charset=utf-8", html("<p>ok</p>"));
  }

  if (p === "/visible") {
    return send(200, "text/html; charset=utf-8", html("<p>visible</p>"));
  }

  if (p === "/.env") {
    return send(200, "text/plain", "SECRET=app3-fixture-not-a-real-key\nGITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n");
  }

  if (p === "/robots.txt") {
    return send(200, "text/plain", "User-agent: *\nDisallow:\n");
  }

  send(404, "text/plain", "not found");
});

server.listen(port, "0.0.0.0", () => {
  console.log(`app3 listening on ${port}`);
});
