import http from "node:http";

const gport = Number(process.env.PORT || 8084);
const uport = 8085;
const oport = 8086;

function send(res, status, type, body, extra = {}) {
  res.writeHead(status, { "Content-Type": type, "X-Frame-Options": "SAMEORIGIN", ...extra });
  res.end(body);
}

function proxy(port, req, res, extraHeaders = {}) {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const pReq = http.request(
      {
        hostname: "127.0.0.1",
        port,
        path: req.url.replace(/^\/api\/[^/]+/, "") || "/",
        method: req.method,
        headers: { ...req.headers, host: `127.0.0.1:${port}`, ...extraHeaders },
      },
      (pRes) => {
        const buf = [];
        pRes.on("data", (c) => buf.push(c));
        pRes.on("end", () => {
          res.writeHead(pRes.statusCode, pRes.headers);
          res.end(Buffer.concat(buf));
        });
      },
    );
    pReq.on("error", () => send(res, 502, "text/plain", "upstream error"));
    pReq.end(Buffer.concat(chunks));
  });
}

http
  .createServer((req, res) => {
    if (req.url === "/health") return send(res, 200, "text/plain", "ok");
    send(res, 200, "application/json", JSON.stringify({ service: "users", items: ["ada", "linus"] }));
  })
  .listen(uport, "127.0.0.1");

http
  .createServer((req, res) => {
    if (req.headers["x-internal-auth"] !== "app4-token") {
      return send(res, 401, "application/json", JSON.stringify({ error: "no auth" }));
    }
    send(res, 200, "application/json", JSON.stringify({ service: "orders", items: [1, 2] }));
  })
  .listen(oport, "127.0.0.1");

http
  .createServer((req, res) => {
    const u = new URL(req.url, `http://127.0.0.1:${gport}`);
    if (u.pathname === "/") {
      return send(
        res,
        200,
        "text/html; charset=utf-8",
        `<!DOCTYPE html><html><body>
         <h1>Gateway</h1>
         <a href="/login">Login</a>
         <a href="/users">Users</a>
         <a href="/orders">Orders</a>
         <a href="/api/cors-reflect">cors reflect</a>
         <a href="/api/cors-star-creds">cors star creds</a>
         <a href="/api/cors-star">cors star</a>
         <a href="/api/cors-locked">cors locked</a>
         <script src="/static/gw.js"></script>
         </body></html>`,
      );
    }
    if (u.pathname === "/login") {
      if (req.method === "POST") {
        res.writeHead(302, { Location: "/", "Set-Cookie": "gw_session=1; HttpOnly; SameSite=Lax" });
        return res.end();
      }
      return send(
        res,
        200,
        "text/html; charset=utf-8",
        `<form action="/login" method="POST"><input name="user"><input name="password" type="password"><button>Go</button></form>`,
      );
    }
    if (u.pathname === "/users" || u.pathname.startsWith("/api/users")) {
      req.url = "/";
      return proxy(uport, req, res);
    }
    if (u.pathname === "/orders" || u.pathname.startsWith("/api/orders")) {
      const cookie = req.headers.cookie || "";
      const extra = cookie.includes("gw_session=1") ? { "x-internal-auth": "app4-token" } : {};
      req.url = "/";
      return proxy(oport, req, res, extra);
    }
    if (u.pathname === "/static/gw.js") {
      return send(
        res,
        200,
        "application/javascript",
        `fetch("/api/users"); fetch("/api/orders");`,
      );
    }
    if (u.pathname === "/api/cors-reflect") {
      const origin = req.headers.origin || "";
      return send(res, 200, "application/json", JSON.stringify({ cors: "reflect" }), {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
      });
    }
    if (u.pathname === "/api/cors-star-creds") {
      return send(res, 200, "application/json", JSON.stringify({ cors: "star-creds" }), {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
      });
    }
    if (u.pathname === "/api/cors-star") {
      return send(res, 200, "application/json", JSON.stringify({ cors: "star" }), {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
      });
    }
    if (u.pathname === "/api/cors-locked") {
      return send(res, 200, "application/json", JSON.stringify({ cors: "locked" }), {
        "Access-Control-Allow-Origin": "https://app.example",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
      });
    }
    if (u.pathname === "/openapi.json") {
      return send(
        res,
        200,
        "application/json",
        JSON.stringify({
          openapi: "3.0.3",
          info: { title: "app4 gateway", version: "1.0.0" },
          paths: {
            "/users": { get: { summary: "List users" } },
            "/internal/inventory": { get: { summary: "Unlinked inventory" } },
          },
        }),
      );
    }
    if (u.pathname === "/internal/inventory") {
      return send(res, 200, "application/json", JSON.stringify({ items: ["widget-1"] }));
    }
    send(res, 404, "text/plain", "not found");
  })
  .listen(gport, "0.0.0.0", () => console.log(`app4 gateway on ${gport}`));
