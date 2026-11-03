// e2e: the single-identity owner-field oracle. One attacker session + one own id + one foreign id.
// No victim session. node:http, no deps. Asserts: a real BOLA CONFIRMS; a correctly-scoped endpoint
// does not; and a PERSONALIZED catch-all (returns owner=caller for any id) does NOT false-positive
// (the calibration from the attacker's own object prevents a username/id space mismatch).
import http from "node:http";
import { ownerFieldOracleBOLA } from "../src/oracle_owner.mjs";

const DATA = [
  { id: "a1", owner: "alice", item: "Keyboard" },
  { id: "b1", owner: "bob", item: "Secret briefcase" },
];
const who = (req) => (req.headers.authorization || "").replace(/^Bearer\s+/i, "") || null;
const json = (res, code, obj) => { res.statusCode = code; res.setHeader("content-type", "application/json"); res.end(JSON.stringify(obj)); };

function server(mode) {
  return http.createServer((req, res) => {
    const u = who(req); if (!u) return json(res, 401, { error: "unauth" });
    const m = req.url.split("?")[0].match(/^\/api\/things\/(.+)$/);
    if (!m) return json(res, 404, { error: "nf" });
    const id = decodeURIComponent(m[1]);
    if (mode === "personalized") return json(res, 200, { id, owner: u, item: "yours" }); // catch-all: always the caller's
    const o = DATA.find((x) => x.id === id);
    if (!o) return json(res, 404, { error: "no such thing" });
    if (mode === "scoped" && o.owner !== u) return json(res, 403, { error: "forbidden" });
    return json(res, 200, o); // bola mode: no owner check
  });
}
async function withServer(mode, run) {
  const s = server(mode); await new Promise((r) => s.listen(0, r));
  try { return await run(`http://localhost:${s.address().port}`); } finally { s.close(); }
}
const cfg = () => ({ objectTemplate: "/api/things/{param}", ownId: "a1", foreignIds: ["b1", "b2-missing"], attacker: { name: "alice", headers: { Authorization: "Bearer alice" } } });

let pass = 0, fail = 0;
const check = (c, m) => (c ? pass++ : (fail++, console.error("FAIL:", m)));

await withServer("bola", async (base) => {
  const r = await ownerFieldOracleBOLA(base, cfg());
  check(r.verdict === "CONFIRMED", "single-identity owner-field BOLA is CONFIRMED (no victim session)");
  check(r.reportable === true && r.evidence.foreign_id_tested === "b1", "the foreign object (bob's b1) is the confirmed break");
  check(r.evidence.attacker_owner_value === "alice", "the attacker owner value was calibrated from their own object");
  check(r.evidence.reproductions === "3/3", "reproduced 3/3");
});

await withServer("scoped", async (base) => {
  const r = await ownerFieldOracleBOLA(base, cfg());
  check(r.verdict !== "CONFIRMED", "a correctly-scoped endpoint (403 on foreign) is NOT confirmed");
});

await withServer("personalized", async (base) => {
  const r = await ownerFieldOracleBOLA(base, cfg());
  check(r.verdict !== "CONFIRMED", "a personalized catch-all (owner always = caller) does NOT false-positive");
});

console.log(`owner-field-bola e2e: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
