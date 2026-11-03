// Adversarial oracle e2e: the regression net for the correctness hardening.
//
// Each scenario is a self-contained node:http server (no deps) exercising a way the oracle could be
// fooled or could crash. The whole value of a CONFIRMED verdict is that it cannot be explained away,
// so these assert the oracle REFUSES to confirm when there is no real cross-user data contradiction,
// SURVIVES a non-JSON sibling instead of throwing, still CONFIRMS a real break behind a wrapped list,
// and emits an earned CORRECTLY-SCOPED negative when the endpoint enforces object authz.
import http from "node:http";
import { siblingOracleBOLA } from "../src/oracle.mjs";

let pass = 0, fail = 0;
const check = (c, m) => (c ? pass++ : (fail++, console.error("FAIL:", m)));

const DATA = [
  { id: "a1", owner: "alice", item: "Keyboard", total: 10 },
  { id: "b1", owner: "bob", item: "Secret briefcase", total: 99999 },
];
const who = (req) => (req.headers.authorization || "").replace(/^Bearer\s+/i, "") || null;
const json = (res, code, obj) => { res.statusCode = code; res.setHeader("content-type", "application/json"); res.end(JSON.stringify(obj)); };

async function withServer(handler, run) {
  const server = http.createServer(handler);
  await new Promise((r) => server.listen(0, r));
  const base = `http://localhost:${server.address().port}`;
  try {
    return await run(base);
  } finally { server.close(); }
}
const cfg = (extra = {}) => ({
  objectTemplate: "/api/things/{param}", siblingPath: "/api/me/things", collection: "things", idKey: "id",
  attacker: { name: "alice", headers: { Authorization: "Bearer alice" } },
  victim: { name: "bob", headers: { Authorization: "Bearer bob" } }, ...extra,
});
const sibling = (res, u) => json(res, 200, { things: DATA.filter((o) => o.owner === u) });

// A) id-echo / existence stub: returns {id} for any id. No real record -> must NOT confirm.
await withServer((req, res) => {
  const u = who(req); if (!u) return json(res, 401, { error: "unauth" });
  const url = new URL(req.url, "http://x");
  if (url.pathname === "/api/me/things") return sibling(res, u);
  const m = url.pathname.match(/^\/api\/things\/(.+)$/);
  if (m) return json(res, 200, { id: decodeURIComponent(m[1]) }); // echo only
  return json(res, 404, { error: "nf" });
}, async (base) => {
  const r = await siblingOracleBOLA(base, cfg());
  check(r.verdict !== "CONFIRMED", "A: id-echo stub is NOT confirmed (no non-trivial cross-user data)");
  check(r.gates.find((g) => g.id === "attacker_reads_foreign")?.pass === false, "A: the non-trivial-read gate is the one that fails");
});

// B) catch-all: returns a full object for ANY id (incl. nonexistent). The 200 is not ownership-gated.
await withServer((req, res) => {
  const u = who(req); if (!u) return json(res, 401, { error: "unauth" });
  const url = new URL(req.url, "http://x");
  if (url.pathname === "/api/me/things") return sibling(res, u);
  if (/^\/api\/things\//.test(url.pathname)) return json(res, 200, { id: "b1", owner: "bob", item: "Secret briefcase" });
  return json(res, 404, { error: "nf" });
}, async (base) => {
  const r = await siblingOracleBOLA(base, cfg());
  check(r.verdict !== "CONFIRMED", "B: catch-all (any id -> 200 object) is NOT confirmed");
  check(r.gates.find((g) => g.id === "control_nonexistent")?.pass === false, "B: the nonexistent-id control is the gate that fails");
});

// C) real BOLA behind a WRAPPED list envelope {data:{things}} -> tolerant extraction must still CONFIRM.
await withServer((req, res) => {
  const u = who(req); if (!u) return json(res, 401, { error: "unauth" });
  const url = new URL(req.url, "http://x");
  if (url.pathname === "/api/me/things") return json(res, 200, { data: { things: DATA.filter((o) => o.owner === u) } });
  const m = url.pathname.match(/^\/api\/things\/(.+)$/);
  if (m) { const o = DATA.find((x) => x.id === decodeURIComponent(m[1])); return o ? json(res, 200, o) : json(res, 404, { error: "nf" }); }
  return json(res, 404, { error: "nf" });
}, async (base) => {
  const r = await siblingOracleBOLA(base, cfg());
  check(r.verdict === "CONFIRMED", "C: real BOLA behind a wrapped {data:{things}} list IS confirmed (tolerant extraction)");
  check(r.evidence.data_matches_victim === true, "C: confirmation carries the cross-user data match");
});

// D) non-JSON sibling (expired session -> 200 HTML login shell): must be INAPPLICABLE, never throw.
let threw = false;
await withServer((req, res) => {
  const u = who(req); if (!u) return json(res, 401, { error: "unauth" });
  const url = new URL(req.url, "http://x");
  if (url.pathname === "/api/me/things") { res.statusCode = 200; res.setHeader("content-type", "text/html"); return res.end("<!doctype html><title>Login</title>"); }
  return json(res, 404, { error: "nf" });
}, async (base) => {
  let r;
  try { r = await siblingOracleBOLA(base, cfg()); } catch { threw = true; }
  check(!threw, "D: non-JSON sibling does not throw (no run-aborting crash)");
  check(r && r.verdict === "INAPPLICABLE", "D: non-JSON sibling -> INAPPLICABLE verdict");
});

// E) correctly-scoped endpoint: attacker denied on foreign, own works, object exists for victim.
await withServer((req, res) => {
  const u = who(req); if (!u) return json(res, 401, { error: "unauth" });
  const url = new URL(req.url, "http://x");
  if (url.pathname === "/api/me/things") return sibling(res, u);
  const m = url.pathname.match(/^\/api\/things\/(.+)$/);
  if (m) { const o = DATA.find((x) => x.id === decodeURIComponent(m[1])); if (!o) return json(res, 404, { error: "nf" }); if (o.owner !== u) return json(res, 403, { error: "forbidden" }); return json(res, 200, o); }
  return json(res, 404, { error: "nf" });
}, async (base) => {
  const r = await siblingOracleBOLA(base, cfg());
  check(r.verdict === "CORRECTLY-SCOPED", "E: an endpoint that enforces object authz earns CORRECTLY-SCOPED, not a false positive");
  check(r.reportable === false, "E: an earned negative is not reportable");
});

console.log(`oracle-negatives e2e: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
