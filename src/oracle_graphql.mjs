// The sibling-endpoint oracle for GraphQL-first APIs.
//
// Modern SPAs fetch objects by opaque global id: `query($id:ID!){ node(id:$id){...} }` or a typed
// `order(id:$id){...}`. The ownership oracle is the caller's own list query (`viewer{ orders{ id } }`
// or `myOrders{ id }`): the app's own statement of which ids belong to the caller. A BOLA is proven
// exactly as in REST (src/oracle.mjs): the victim's REAL global ids are read from the victim's own
// list query, the attacker requests one, and a contradiction with controls (own=present,
// nonexistent=absent) holding in the same run confirms the break. No id guessing, no response-diff,
// no probabilistic guess in the decision. Deterministic on opaque GraphQL global ids, which is exactly where REST-id tools give up.
//
// As in the REST oracle, confirmation is gated on a real cross-user DATA contradiction (the attacker
// receives the SAME non-trivial node the victim legitimately sees), never on id-equality alone, so an
// id-echo stub cannot confirm. The nonexistent control uses a format-preserving derived gid.

import { isNonTrivialObject, bodiesEqual, deriveNonexistentId, detectOwnerKey, detectSharing } from "./oracle.mjs";

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
  const base_evidence = { attacker_owned: [...attackerOwned], victim_owned: [...victimOwned] };

  if (attackerOwned.size === 0 && victimOwned.size === 0) return gqlInapplicable(cfg, base_evidence, "both sibling list queries returned no nodes (invalid sessions, wrong collectionPath, or empty lists).");
  const foreignId = [...victimOwned].find((id) => !attackerOwned.has(id)) || null;
  const ownId = [...attackerOwned][0] || null;
  if (!foreignId) return gqlInapplicable(cfg, base_evidence, "no victim-owned global-id is absent from the attacker's own list.");
  if (!ownId) return gqlInapplicable(cfg, base_evidence, "the attacker's own list is empty, so the own-id control cannot be established.");
  const nonexistentId = deriveNonexistentId(foreignId);

  // the record the VICTIM legitimately sees for this id (the ground truth the attacker must match)
  const victimForeign = await getObjectGQL(base, cfg.endpoint, vH, cfg.objectQuery, foreignId, cfg.objectPath);

  const repeat = Math.max(1, cfg.repeat || 3);
  let reads = 0, attackerGetsForeign = null;
  for (let i = 0; i < repeat; i++) {
    const r = await getObjectGQL(base, cfg.endpoint, aH, cfg.objectQuery, foreignId, cfg.objectPath);
    attackerGetsForeign = r;
    if (r.present && isNonTrivialObject(r.body, idField) && String(r.body?.[idField]) === String(foreignId)) reads++;
  }
  const controlOwn = await getObjectGQL(base, cfg.endpoint, aH, cfg.objectQuery, ownId, cfg.objectPath);
  const controlMissing = await getObjectGQL(base, cfg.endpoint, aH, cfg.objectQuery, nonexistentId, cfg.objectPath);

  const dataMatches = attackerGetsForeign && attackerGetsForeign.present && isNonTrivialObject(attackerGetsForeign.body, idField) &&
    victimForeign.present && isNonTrivialObject(victimForeign.body, idField) && bodiesEqual(attackerGetsForeign.body, victimForeign.body);

  const ownerKey = cfg.ownerKey || detectOwnerKey(attackerGetsForeign && attackerGetsForeign.body);
  const vOwn = ownerKey && victimForeign.body ? victimForeign.body[ownerKey] : null;
  const aVal = ownerKey && attackerGetsForeign && attackerGetsForeign.body ? attackerGetsForeign.body[ownerKey] : null;
  const ownerApplicable = Boolean(ownerKey && vOwn != null && typeof vOwn !== "object" && aVal != null && typeof aVal !== "object");
  const sharing = detectSharing(attackerGetsForeign && attackerGetsForeign.body, null);

  const gates = [
    { id: "foreign_sourced", label: `sibling attributes gid ${foreignId} to ${cfg.victim.name}, not ${cfg.attacker.name}`, expected: "victim-owned gid absent from attacker list", observed: `${foreignId}`, pass: true },
    { id: "attacker_reads_foreign", label: `${cfg.attacker.name} reads gid ${foreignId} ${repeat}/${repeat}`, expected: `present + non-trivial node ${repeat}/${repeat}`, observed: `${reads}/${repeat}`, pass: reads === repeat },
    { id: "data_matches_victim", label: "the attacker's node equals the node the victim legitimately sees", expected: "attacker node == victim node (non-trivial)", observed: dataMatches ? "equal" : "differs/absent/trivial", pass: Boolean(dataMatches) },
    { id: "control_own", label: `${cfg.attacker.name} reads own gid ${ownId}`, expected: "present", observed: controlOwn.present ? "present" : "absent", pass: Boolean(controlOwn.present) },
    { id: "control_nonexistent", label: "catch-all ruled out (format-valid unowned gid returns null)", expected: `absent for ${nonexistentId}`, observed: controlMissing.present ? "present" : "absent", pass: !controlMissing.present },
    { id: "not_shared", label: "the node is not shared/public to the attacker (would be legitimate access)", expected: "no sharing/visibility signal granting the attacker access", observed: sharing || "none", pass: !sharing },
  ];
  if (ownerApplicable) gates.push({ id: "owner_field", label: `the node's '${ownerKey}' names ${cfg.victim.name}`, expected: `${ownerKey}=${vOwn}`, observed: `${ownerKey}=${aVal}`, pass: String(aVal) === String(vOwn) });

  const confirmed = gates.every((g) => g.pass);
  const attackerDenied = reads === 0 && attackerGetsForeign && !attackerGetsForeign.present;
  const correctlyScoped = !confirmed && attackerDenied && victimForeign.present && isNonTrivialObject(victimForeign.body, idField) && controlOwn.present && !controlMissing.present;
  const verdict = confirmed ? "CONFIRMED" : correctlyScoped ? "CORRECTLY-SCOPED" : "NOT-CONFIRMED";
  const failed = gates.find((g) => !g.pass);

  return {
    verdict, class: "BOLA", confidence: confirmed || correctlyScoped ? "high" : "none", reportable: confirmed,
    method: "POST", transport: "graphql", idKey: idField,
    endpoint: `${cfg.endpoint} ${cfg.objectPath}(id:)`,
    oracle: `graphql sibling query ${cfg.collectionPath} (the app's own ownership statement)`,
    attacker: cfg.attacker.name, victim: cfg.victim.name, gates,
    evidence: {
      ...base_evidence,
      foreign_id_tested: foreignId,
      reproductions: `${reads}/${repeat}`,
      attacker_get_foreign: attackerGetsForeign,
      victim_get_foreign: { present: victimForeign.present, body: victimForeign.body },
      data_matches_victim: Boolean(dataMatches),
      owner_field: ownerApplicable ? { key: ownerKey, observed: attackerGetsForeign.body[ownerKey], victim: vOwn } : null,
      control_own_id: ownId,
      control_own_present: controlOwn.present,
      control_nonexistent_id: nonexistentId,
      control_nonexistent_present: controlMissing.present,
    },
    reason: confirmed
      ? `${cfg.attacker.name} fetched global-id ${foreignId}, the SAME node ${cfg.collectionPath} and the object query give ${cfg.victim.name}, reproduced ${reads}/${repeat} with own-id present and nonexistent (${nonexistentId}) absent controls holding.`
      : correctlyScoped
        ? `Earned negative: gid ${foreignId} exists and is ${cfg.victim.name}'s, but ${cfg.attacker.name} is denied every time. The resolver enforces object-level authorization.`
        : `Not confirmed (lead, keep digging). First unmet gate: ${failed ? failed.id + " (" + failed.observed + ")" : "unknown"}.`,
  };
}

function gqlInapplicable(cfg, evidence, why) {
  return {
    verdict: "INAPPLICABLE", class: "BOLA", confidence: "none", reportable: false, method: "POST", transport: "graphql",
    idKey: cfg.idField || "id", endpoint: `${cfg.endpoint} ${cfg.objectPath}(id:)`,
    oracle: `graphql sibling query ${cfg.collectionPath} (the app's own ownership statement)`,
    attacker: cfg.attacker.name, victim: cfg.victim.name, gates: [], evidence, reason: `Oracle inapplicable: ${why}`,
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
