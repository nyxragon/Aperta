// Proof: the bypass wave flips gated endpoints via real authz-bypass transforms.
// Inline server: /api/v2/secret is gated but legacy /api/v1/secret is open (version-downgrade);
// GET /api/admin is gated but POST /api/admin is open (verb-swap). node:http, no deps.
import http from "node:http";
import { probeBypasses } from "../src/bypass.mjs";

const server = http.createServer((req, res) => {
  const p = req.url.split("?")[0];
  const send = (code) => { res.statusCode = code; res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ ok: code === 200 })); };
  if (p === "/api/v2/secret") return send(403);        // hardened current version
  if (p === "/api/v1/secret") return send(200);        // legacy version left open -> downgrade bypass
  if (p === "/api/admin" && req.method === "GET") return send(403);  // guard on GET only
  if (p === "/api/admin" && req.method === "POST") return send(200); // verb-swap bypass
  return send(404);
});

await new Promise((r) => server.listen(0, r));
const base = `http://localhost:${server.address().port}`;
let pass = 0, fail = 0;
const check = (c, m) => (c ? pass++ : (fail++, console.error("FAIL:", m)));

try {
  const gated = [{ method: "GET", path: "/api/v2/secret" }, { method: "GET", path: "/api/admin" }];
  const findings = await probeBypasses(base, gated, { headers: {} });
  check(findings.some((f) => f.technique.startsWith("version-downgrade") && f.variant.includes("/api/v1/secret")), "version-downgrade v2->v1 bypass found");
  check(findings.some((f) => f.technique.startsWith("verb-swap") && f.variant.startsWith("POST /api/admin")), "verb-swap GET->POST bypass found");
  check(findings.every((f) => f.status === 200), "every reported bypass actually reached (200)");
  console.log(`bypass e2e: ${pass} passed, ${fail} failed`);
} finally {
  server.close();
}
process.exit(fail ? 1 : 0);
