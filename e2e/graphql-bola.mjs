// Proof: the sibling oracle confirms BOLA over GraphQL global-ids, deterministically.
// Self-contained node:http GraphQL-ish endpoint (no deps), the real graphqlOracleBOLA, assertions.
import http from "node:http";
import { graphqlOracleBOLA } from "../src/oracle_graphql.mjs";

const OBJECTS = [
  { id: "T3JkZXI6YWxpY2Ux", owner: "alice", item: "Keyboard" },   // base64-ish opaque Relay-style GIDs
  { id: "T3JkZXI6Ym9iMQ==", owner: "bob", item: "Secret briefcase" },
];
const TOKENS = { "tok-alice": "alice", "tok-bob": "bob" };
const who = (req) => TOKENS[(req.headers.authorization || "").replace("Bearer ", "")] || null;

function body(req) {
  return new Promise((res) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => res(b)); });
}

const server = http.createServer(async (req, res) => {
  res.setHeader("content-type", "application/json");
  const u = who(req);
  if (!u) { res.statusCode = 200; return res.end(JSON.stringify({ errors: [{ message: "unauthenticated" }] })); }
  let q = {};
  try { q = JSON.parse(await body(req)); } catch {}
  const query = q.query || "";
  // sibling: the caller's OWN orders (ownership oracle)
  if (/myOrders/.test(query)) {
    return res.end(JSON.stringify({ data: { myOrders: OBJECTS.filter((o) => o.owner === u).map((o) => ({ id: o.id })) } }));
  }
  // object by global id: BOLA, no owner check
  if (/order\s*\(\s*id/.test(query)) {
    const o = OBJECTS.find((x) => x.id === q.variables?.id);
    return res.end(JSON.stringify({ data: { order: o ? { id: o.id, owner: o.owner, item: o.item } : null } }));
  }
  res.end(JSON.stringify({ data: null, errors: [{ message: "unknown query" }] }));
});

await new Promise((r) => server.listen(0, r));
const base = `http://localhost:${server.address().port}`;
let pass = 0, fail = 0;
const check = (c, m) => (c ? pass++ : (fail++, console.error("FAIL:", m)));

try {
  const res = await graphqlOracleBOLA(base, {
    endpoint: "/graphql",
    objectQuery: "query($id:ID!){ order(id:$id){ id owner item } }",
    objectPath: "order",
    siblingQuery: "query{ myOrders{ id } }",
    collectionPath: "myOrders",
    idField: "id",
    attacker: { name: "alice", headers: { Authorization: "Bearer tok-alice" } },
    victim: { name: "bob", headers: { Authorization: "Bearer tok-bob" } },
  });
  check(res.verdict === "CONFIRMED", "GraphQL BOLA confirmed deterministically");
  check(res.evidence.reproductions === "3/3", "break reproduced 3/3 times");
  check(res.confidence === "high", "confidence tier high");
  check(res.transport === "graphql", "result marked graphql transport");
  check(res.evidence.foreign_id_tested === "T3JkZXI6Ym9iMQ==", "victim's real opaque GID sourced from the victim's own query (not guessed)");
  check(res.evidence.control_own_present === true, "own-id control present");
  check(res.evidence.control_nonexistent_present === false, "nonexistent-id control absent (not a catch-all)");
  console.log(`graphql-bola e2e: ${pass} passed, ${fail} failed`);
} finally {
  server.close();
}
process.exit(fail ? 1 : 0);
