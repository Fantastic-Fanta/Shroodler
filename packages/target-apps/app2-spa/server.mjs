import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dist = path.join(__dirname, "dist");
const port = Number(process.env.PORT || 8082);

const mime = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
};

function send(res, status, headers, body) {
  res.writeHead(status, headers);
  res.end(body);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${port}`);
  if (url.pathname === "/api/session") {
    return send(
      res,
      200,
      { "Content-Type": "application/json", "X-Frame-Options": "DENY" },
      JSON.stringify({ user: "guest", links: ["/account"] }),
    );
  }
  if (url.pathname === "/api/internal/debug") {
    return send(res, 200, { "Content-Type": "application/json" }, JSON.stringify({ debug: true }));
  }
  if (url.pathname === "/api/save" || url.pathname === "/api/invite") {
    return send(res, 204, {}, "");
  }

  let filePath = path.join(dist, url.pathname === "/" ? "index.html" : url.pathname);
  if (!filePath.startsWith(dist)) {
    return send(res, 403, { "Content-Type": "text/plain" }, "forbidden");
  }
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    filePath = path.join(dist, "index.html");
  }
  const ext = path.extname(filePath);
  const body = fs.readFileSync(filePath);
  send(res, 200, { "Content-Type": mime[ext] || "application/octet-stream" }, body);
});

server.listen(port, "0.0.0.0", () => {
  console.log(`app2 listening on ${port}`);
});
