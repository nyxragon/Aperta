// The sibling-endpoint oracle for GraphQL-first APIs.
//
// Modern SPAs fetch objects by opaque global id: `query($id:ID!){ node(id:$id){...} }` or a typed
// `order(id:$id){...}`. The ownership oracle is the caller's own list query (`viewer{ orders{ id } }`
// or `myOrders{ id }`): the app's own statement of which ids belong to the caller. A BOLA is proven
// exactly as in REST (src/oracle.mjs): the victim's REAL global ids are read from the victim's own
// list query, the attacker requests one, and a contradiction with controls (own=present,
// nonexistent=absent) holding in the same run confirms the break. No id guessing, no response-diff,
// no LLM. Deterministic on opaque GraphQL global ids, which is exactly where REST-id tools give up.

// Read a value at a dot path ("viewer.orders" / "data.myOrders") from an object; "" => the object.
export function atPath(obj, path) {
  if (!path) return obj;
  return path.split(".").reduce((o, k) => (o == null ? o : o[k]), obj);
}

// Normalize a GraphQL list result (array of nodes, or a Relay connection {edges:[{node}]}) to nodes.
export function listNodes(val) {
  if (Array.isArray(val)) return val;
  if (val && Array.isArray(val.edges)) return val.edges.map((e) => e && e.node).filter(Boolean);
  if (val && Array.isArray(val.nodes)) return val.nodes;
  return [];
}

async function gqlPost(base, endpoint, headers, query, variables) {
  try {
    const r = await fetch(base.replace(/\/$/, "") + endpoint, {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
      body: JSON.stringify({ query, variables }),
    });
    let json = null;
    try { json = await r.json(); } catch {}
    return { status: r.status, json };
  } catch {
    return { status: 0, json: null };
  }
}

// The caller's own object global-ids, from their own list query (the ownership statement).
async function ownedGIDs(base, endpoint, headers, siblingQuery, collectionPath, idField) {
  const r = await gqlPost(base, endpoint, headers, siblingQuery, {});
  const nodes = listNodes(atPath(r.json?.data, collectionPath));
  return new Set(nodes.map((n) => n && n[idField]).filter((v) => v != null).map(String));
}

// Fetch one object by global-id with the object query; returns {present, body, status}.
async function getObjectGQL(base, endpoint, headers, objectQuery, id, objectPath) {
  const r = await gqlPost(base, endpoint, headers, objectQuery, { id });
  const obj = atPath(r.json?.data, objectPath);
  // present = the server returned a non-null object node for this id (not an auth error / null)
  const present = obj != null && typeof obj === "object" && !Array.isArray(obj);
  return { present, body: obj ?? null, status: r.status, errors: r.json?.errors || null };
}

/**
 * cfg = {
 *   endpoint,            // "/graphql"
 *   objectQuery,         // query with an $id:ID! variable, e.g. `query($id:ID!){ node(id:$id){ id owner } }`
 *   objectPath,          // dot path to the object node in data, e.g. "node" or "order"
 *   siblingQuery,        // `query{ viewer{ orders{ id } } }`
 *   collectionPath,      // dot path to the caller's list in data, e.g. "viewer.orders" or "myOrders"
 *   idField = "id",      // the field carrying the global id on each node/object
 *   attacker:{name,headers}, victim:{name,headers}
 * }
 */
export async function graphqlOracleBOLA(base, cfg) {
  const idField = cfg.idField || "id";
  const aH = cfg.attacker.headers || {};
  const vH = cfg.victim.headers || {};

  const attackerOwned = await ownedGIDs(base, cfg.endpoint, aH, cfg.siblingQuery, cfg.collectionPath, idField);
  const victimOwned = await ownedGIDs(base, cfg.endpoint, vH, cfg.siblingQuery, cfg.collectionPath, idField);

  const foreignId = [...victimOwned].find((id) => !attackerOwned.has(id)) || null;
  const ownId = [...attackerOwned][0] || null;
  const nonexistentId = "aperta-nonexistent-gid-00000000";

  const repeat = Math.max(1, cfg.repeat || 3);
  let reproduced = 0, attackerGetsForeign = null;
  if (foreignId) {
    for (let i = 0; i < repeat; i++) {
      const r = await getObjectGQL(base, cfg.endpoint, aH, cfg.objectQuery, foreignId, cfg.objectPath);
      attackerGetsForeign = r;
      if (r.present && String(r.body?.[idField]) === String(foreignId)) reproduced++;
    }
  }
  const controlOwn = ownId ? await getObjectGQL(base, cfg.endpoint, aH, cfg.objectQuery, ownId, cfg.objectPath) : null;
  const controlMissing = await getObjectGQL(base, cfg.endpoint, aH, cfg.objectQuery, nonexistentId, cfg.objectPath);

  const bodyIsForeign = foreignId && reproduced === repeat;
  const controlOwnOk = controlOwn && controlOwn.present;
  const notCatchAll = controlMissing && !controlMissing.present;

  const confirmed = Boolean(foreignId && bodyIsForeign && controlOwnOk && notCatchAll);

  return {
    verdict: confirmed ? "CONFIRMED" : "NOT-CONFIRMED",
    class: "BOLA",
    confidence: confirmed ? "high" : "none",
    method: "POST",
    transport: "graphql",
    idKey: idField,
    endpoint: `${cfg.endpoint} ${cfg.objectPath}(id:)`,
    oracle: `graphql sibling query ${cfg.collectionPath} (the app's own ownership statement)`,
    attacker: cfg.attacker.name,
    victim: cfg.victim.name,
    evidence: {
      attacker_owned: [...attackerOwned],
      victim_owned: [...victimOwned],
      foreign_id_tested: foreignId,
      reproductions: `${reproduced}/${repeat}`,
      attacker_get_foreign: attackerGetsForeign,
      control_own_id: ownId,
      control_own_present: controlOwn && controlOwn.present,
      control_nonexistent_present: controlMissing && controlMissing.present,
    },
    reason: confirmed
      ? `${cfg.attacker.name} fetched global-id ${foreignId}, which ${cfg.collectionPath} attributes to ${cfg.victim.name} and not to ${cfg.attacker.name}, a contradiction in the app's own authorization, with own-id present and nonexistent absent controls holding.`
      : "No sibling contradiction with controls held.",
  };
}

// --- self-test (offline: pure helpers only; full confirm is e2e/graphql-bola.mjs) --------
function selfTest() {
  let pass = 0, fail = 0;
  const check = (c, m) => (c ? pass++ : (fail++, console.error("FAIL:", m)));

  check(atPath({ a: { b: { c: 7 } } }, "a.b.c") === 7, "atPath walks a dot path");
  check(atPath({ x: 1 }, "") && atPath({ x: 1 }, "").x === 1, "empty path returns the object");
  check(atPath({ a: null }, "a.b") === null, "atPath stops at null safely");

  // plain array of nodes
  check(JSON.stringify(listNodes([{ id: "A" }, { id: "B" }])) === JSON.stringify([{ id: "A" }, { id: "B" }]), "listNodes passes a plain array");
  // Relay connection {edges:[{node}]}
  const conn = { edges: [{ node: { id: "A" } }, { node: { id: "B" } }] };
  check(listNodes(conn).map((n) => n.id).join(",") === "A,B", "listNodes unwraps a Relay connection");
  // {nodes:[...]}
  check(listNodes({ nodes: [{ id: "Z" }] })[0].id === "Z", "listNodes handles a nodes array");
  check(listNodes(null).length === 0 && listNodes({}).length === 0, "listNodes is empty-safe");

  console.log(`oracle_graphql self-test: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

if (process.argv[1] && process.argv[1].endsWith("oracle_graphql.mjs") && process.argv.includes("--self-test")) selfTest();
