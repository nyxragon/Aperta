// Proof: live-verify marks reconstructed endpoints that resolve vs dead ones, incl. a HEAD->GET
// fallback when the server 404s a HEAD it would answer on GET. node:http, no deps.
import http from "node:http";
import { verifyEndpoints } from "../src/verify.mjs";

const server = http.createServer((req, res) => {
  const p = req.url.split("?")[0];
  const end = (code) => { res.statusCode = code; res.end(); };
  if (p === "/api/real") return end(200);                        // exists on any method
  if (p === "/api/gated") return end(403);                       // exists but gated -> still "exists"
  if (p === "/api/headless") return req.method === "HEAD" ? end(405) : end(200); // HEAD 405, GET 200 -> fallback
  return end(404);                                               // everything else missing
});

await new Promise((r) => server.listen(0, r));
const base = `http://localhost:${server.address().port}`;
let pass = 0, fail = 0;
const check = (c, m) => (c ? pass++ : (fail++, console.error("FAIL:", m)));

try {
  const results = await verifyEndpoints(base, [
    { method: "GET", path: "/api/real" },
    { method: "GET", path: "/api/gated" },
    { method: "GET", path: "/api/headless" },
    { method: "GET", path: "/api/ghost" },
  ]);
  const by = Object.fromEntries(results.map((r) => [r.path, r.exists]));
  check(by["/api/real"] === "exists", "real route exists");
  check(by["/api/gated"] === "exists", "gated route still counts as existing");
  check(by["/api/headless"] === "exists", "HEAD->GET fallback finds a route the HEAD 404/405'd");
  check(by["/api/ghost"] === "missing", "dead route marked missing");
  console.log(`verify e2e: ${pass} passed, ${fail} failed`);
} finally {
  server.close();
}
process.exit(fail ? 1 : 0);
