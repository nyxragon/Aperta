// Proof: the sibling-endpoint oracle confirms BOLA on NON-GUESSABLE ids (UUIDs), deterministically,
// with no id enumeration. This refutes the common "only works on sequential integer ids" critique:
// the oracle sources the victim's REAL object ids from the victim's OWN list endpoint, so the id
// format (uuid / slug / int / GraphQL GID) is irrelevant to confirmation.
//
// Self-contained: a tiny node:http server (no express, no deps), the real oracle, assertions.
import http from "node:http";
import { siblingOracleBOLA } from "../src/oracle.mjs";

// opaque, unguessable ids
const OBJECTS = [
  { id: "7b1f9c2e-0a44-4e21-9b3a-9f0c1d2e3f40", owner: "alice", item: "Keyboard" },
  { id: "c4d5e6f7-1122-4333-8444-556677889900", owner: "bob", item: "Secret briefcase" },
];
const TOKENS = { "tok-alice": "alice", "tok-bob": "bob" };

function who(req) {
  const h = req.headers.authorization || "";
  const t = h.startsWith("Bearer ") ? h.slice(7) : null;
  return TOKENS[t] || null;
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  const u = who(req);
  res.setHeader("content-type", "application/json");
  if (!u) { res.statusCode = 401; return res.end(JSON.stringify({ error: "unauth" })); }
  // sibling: the caller's OWN things (the ownership oracle)
  if (url.pathname === "/api/me/things") {
    return res.end(JSON.stringify({ things: OBJECTS.filter((o) => o.owner === u) }));
  }
  // object fetch by opaque id: BOLA, no owner check
  const m = url.pathname.match(/^\/api\/things\/(.+)$/);
  if (m) {
    const o = OBJECTS.find((x) => x.id === decodeURIComponent(m[1]));
    if (!o) { res.statusCode = 404; return res.end(JSON.stringify({ error: "no such thing" })); }
    return res.end(JSON.stringify(o)); // <-- missing o.owner === u check
  }
  res.statusCode = 404; res.end(JSON.stringify({ error: "not found" }));
});

await new Promise((r) => server.listen(0, r));
const base = `http://localhost:${server.address().port}`;
let pass = 0, fail = 0;
const check = (c, m) => (c ? pass++ : (fail++, console.error("FAIL:", m)));

try {
  const res = await siblingOracleBOLA(base, {
    objectTemplate: "/api/things/{param}",
    siblingPath: "/api/me/things",
    collection: "things",
    idKey: "id",
    attacker: { name: "alice", headers: { Authorization: "Bearer tok-alice" } },
    victim: { name: "bob", headers: { Authorization: "Bearer tok-bob" } },
  });
  check(res.verdict === "CONFIRMED", "UUID BOLA confirmed deterministically");
  check(res.evidence.reproductions === "3/3", "break reproduced 3/3 times");
  check(res.confidence === "high", "confidence tier high");
  check(res.evidence.foreign_id_tested === "c4d5e6f7-1122-4333-8444-556677889900", "the real victim UUID was sourced from the victim's own list (not guessed)");
  check(!/^\d+$/.test(res.evidence.foreign_id_tested), "the confirmed id is non-numeric (opaque UUID)");
  check(res.evidence.control_nonexistent_result.status === 404, "nonexistent-id control holds (404)");
  check(res.evidence.control_own_result.status === 200, "own-id control holds (200)");
  console.log(`uuid-bola e2e: ${pass} passed, ${fail} failed`);
} finally {
  server.close();
}
process.exit(fail ? 1 : 0);
