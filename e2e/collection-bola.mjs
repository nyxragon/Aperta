// e2e: the unfiltered-collection over-return oracle. A bare GET /api/things returns EVERY user's
// rows (the bug); the self-scoped GET /api/me/things returns only the caller's (the ownership
// statement). node:http, no deps. Also asserts a correctly-scoped list and a public row do NOT
// confirm.
import http from "node:http";
import { collectionOverReturnBOLA } from "../src/oracle_collection.mjs";

const THINGS = [
  { id: "t1", owner: "alice", item: "Keyboard" },
  { id: "t2", owner: "alice", item: "Mouse" },
  { id: "t3", owner: "bob", item: "Secret briefcase" },
  { id: "t4", owner: "bob", item: "Monitor", visibility: "public" },
];
const who = (req) => (req.headers.authorization || "").replace(/^Bearer\s+/i, "") || null;
const json = (res, code, obj) => { res.statusCode = code; res.setHeader("content-type", "application/json"); res.end(JSON.stringify(obj)); };

function server(bareMode) {
  // bareMode: "overreturn" (returns all), "scoped" (returns only own), "public-only-foreign"
  return http.createServer((req, res) => {
    const u = who(req); if (!u) return json(res, 401, { error: "unauth" });
    const url = new URL(req.url, "http://x");
    if (url.pathname === "/api/me/things") return json(res, 200, { things: THINGS.filter((o) => o.owner === u) });
    if (url.pathname === "/api/things") {
      if (bareMode === "scoped") return json(res, 200, { things: THINGS.filter((o) => o.owner === u) });
      if (bareMode === "public-only-foreign") return json(res, 200, { things: [...THINGS.filter((o) => o.owner === u), THINGS[3]] }); // own + a public one
      return json(res, 200, { things: THINGS }); // over-return: everyone's rows
    }
    return json(res, 404, { error: "nf" });
  });
}
async function withServer(mode, run) {
  const s = server(mode); await new Promise((r) => s.listen(0, r));
  try { return await run(`http://localhost:${s.address().port}`); } finally { s.close(); }
}
const cfg = () => ({ collectionPath: "/api/things", siblingPath: "/api/me/things", collection: "things", idKey: "id",
  attacker: { name: "alice", headers: { Authorization: "Bearer alice" } } });

let pass = 0, fail = 0;
const check = (c, m) => (c ? pass++ : (fail++, console.error("FAIL:", m)));

await withServer("overreturn", async (base) => {
  const r = await collectionOverReturnBOLA(base, cfg());
  check(r.verdict === "CONFIRMED", "over-returning collection is CONFIRMED");
  check(r.reportable === true, "a confirmed over-return is reportable");
  check(r.evidence.foreign_count >= 1 && r.evidence.foreign_rows.some((f) => f.owner === "bob"), "bob's row is identified as foreign in alice's own list");
  check(r.evidence.foreign_rows.every((f) => f.owner !== "bob" || true) && !r.evidence.foreign_rows.some((f) => f.id === "t4"), "the public row (t4) is NOT counted as a leak");
  check(r.evidence.reproductions === "3/3", "over-return reproduced 3/3");
});

await withServer("scoped", async (base) => {
  const r = await collectionOverReturnBOLA(base, cfg());
  check(r.verdict !== "CONFIRMED", "a correctly-scoped bare list is NOT confirmed");
});

await withServer("public-only-foreign", async (base) => {
  const r = await collectionOverReturnBOLA(base, cfg());
  check(r.verdict !== "CONFIRMED", "a list whose only extra row is public is NOT a leak");
});

console.log(`collection-bola e2e: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
