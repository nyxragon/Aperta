// The unfiltered-collection over-return oracle.
//
// The sibling-endpoint oracle (src/oracle.mjs) proves a per-object BOLA: GET /api/orders/{id} with no
// owner check. But the more common and more severe modern leak is a COLLECTION endpoint that forgot
// its owner scope - GET /api/orders returns EVERY user's rows, not just the caller's. This oracle
// proves that deterministically, and it needs NEITHER a per-object endpoint NOR any id guessing: the
// attacker's OWN unfiltered-list response IS the evidence.
//
// The contradiction (all app-stated facts, no response-diff, no threshold, no guesswork in the decision):
//   - the app's self-scoped sibling (GET /api/me/orders) returns ONLY the caller's rows, which is the
//     app's own statement of "what is mine" (and proves the app CAN scope this collection);
//   - yet the attacker's bare GET /api/orders returns a row the app attributes to someone else -
//     either its owner field names another identity, or its id is in the VICTIM's own list.
//   - controls in-run: the attacker's own rows also appear in the bare list (it is a working list,
//     not empty/foreign-only), and genuinely shared/public rows are excluded (reuse detectSharing).
// Read-only: GET only, no state change.

import { extractCollection, constOwnerValue, detectOwnerKey, detectSharing } from "./oracle.mjs";

async function fetchList(base, path, headers, collection, collectionPath) {
  try {
    const r = await fetch(`${base}${path}`, { headers });
    if (r.status < 200 || r.status >= 300) return { ok: false, status: r.status, objects: [] };
    let j = null; try { j = await r.json(); } catch { return { ok: false, status: r.status, objects: [] }; }
    return { ok: true, status: r.status, objects: extractCollection(j, collection, collectionPath) };
  } catch { return { ok: false, status: 0, objects: [] }; }
}

// Pure decision core: given the attacker's bare-collection objects and the attacker's self-scoped
// sibling objects (and optionally the victim's own ids), return which bare rows are FOREIGN to the
// attacker. Decision is membership / scalar inequality only.
export function findOverReturned({ bareObjects, siblingObjects, idKey = "id", ownerKey = null, victimIds = null }) {
  const sibIds = new Set((siblingObjects || []).map((o) => (o && o[idKey] != null ? String(o[idKey]) : null)).filter((v) => v != null));
  const key = ownerKey || detectOwnerKey((bareObjects || [])[0] || {}) || detectOwnerKey((siblingObjects || [])[0] || {});
  const attackerOwner = key ? constOwnerValue(siblingObjects || [], key) : null;
  const foreign = []; let ownInBare = 0;
  for (const o of bareObjects || []) {
    if (!o || typeof o !== "object") continue;
    const oid = o[idKey] != null ? String(o[idKey]) : null;
    const ownById = oid && sibIds.has(oid);
    const ownByOwner = key && attackerOwner != null && o[key] != null && typeof o[key] !== "object" && String(o[key]) === String(attackerOwner);
    if (ownById || ownByOwner) { ownInBare++; continue; }           // the attacker's own row (expected)
    if (detectSharing(o, attackerOwner)) continue;                   // shared/public -> legitimate
    if (key && attackerOwner != null && o[key] != null && typeof o[key] !== "object" && String(o[key]) !== String(attackerOwner)) {
      foreign.push({ id: oid, ownerKey: key, owner: String(o[key]) }); continue;
    }
    if (victimIds && oid && victimIds.has(oid)) { foreign.push({ id: oid, by: "victim-owned-id" }); continue; }
  }
  return { foreign, ownInBare, ownerKey: key, attackerOwner };
}

/**
 * cfg = { collectionPath (bare list), siblingPath (self-scoped), collection, idKey, ownerKey?,
 *         collectionPathDot?, repeat?, attacker:{name,headers}, victim?:{name,headers} }
 * verdict: CONFIRMED / NOT-CONFIRMED / INAPPLICABLE, as a fold over an observable gate tape.
 */
export async function collectionOverReturnBOLA(base, cfg) {
  const idKey = cfg.idKey || "id";
  const aH = cfg.attacker.headers || {};
  const sib = await fetchList(base, cfg.siblingPath, aH, cfg.collection, cfg.collectionPathDot);
  const bare = await fetchList(base, cfg.collectionPath, aH, cfg.collection, cfg.collectionPathDot);
  const vic = cfg.victim ? await fetchList(base, cfg.siblingPath, cfg.victim.headers || {}, cfg.collection, cfg.collectionPathDot) : null;
  const ev = { self_scoped_count: sib.objects.length, bare_collection_count: bare.objects.length };

  if (!sib.ok || !bare.ok) return inapplicable(cfg, ev, `self-scoped sibling or bare collection returned non-JSON/non-2xx (sibling=${sib.status}, bare=${bare.status}).`);
  if (!bare.objects.length) return inapplicable(cfg, ev, "the bare collection returned no objects.");
  if (!sib.objects.length) return inapplicable(cfg, ev, "the self-scoped sibling returned no objects, so the attacker's own scope cannot be established.");

  const victimIds = vic && vic.ok ? new Set(vic.objects.map((o) => (o[idKey] != null ? String(o[idKey]) : null)).filter((v) => v != null)) : null;

  // reproduce the over-return N times (default 3): a one-off could be a transient/cache artifact
  const repeat = Math.max(1, cfg.repeat || 3);
  let reproduced = 0, last = null;
  for (let i = 0; i < repeat; i++) {
    const b = i === 0 ? bare : await fetchList(base, cfg.collectionPath, aH, cfg.collection, cfg.collectionPathDot);
    const r = findOverReturned({ bareObjects: b.objects, siblingObjects: sib.objects, idKey, ownerKey: cfg.ownerKey, victimIds });
    last = r;
    if (r.foreign.length > 0) reproduced++;
  }
  const foreign = last.foreign;
  const ownerKey = last.ownerKey;

  const gates = [
    { id: "over_return_sourced", label: "the attacker's unscoped list returns a row the app attributes to someone else",
      expected: "at least one foreign row (owner != attacker, or id in victim's list)", observed: `${foreign.length} foreign`, pass: foreign.length > 0 },
    { id: "reproduced", label: `the over-return is stable across ${repeat} fetches`,
      expected: `${repeat}/${repeat}`, observed: `${reproduced}/${repeat}`, pass: reproduced === repeat },
    { id: "control_own_present", label: "the attacker's OWN rows also appear in the list (a working list, not foreign-only)",
      expected: ">=1 own row", observed: `${last.ownInBare} own`, pass: last.ownInBare > 0 },
    { id: "control_sibling_scoped", label: "the self-scoped sibling is correctly scoped (proves the app CAN scope this collection)",
      expected: "sibling smaller than the bare list / all rows the attacker's own", observed: `sibling ${sib.objects.length} vs bare ${bare.objects.length}`,
      pass: sib.objects.length < bare.objects.length },
  ];
  const confirmed = gates.every((g) => g.pass);
  const failed = gates.find((g) => !g.pass);

  return {
    verdict: confirmed ? "CONFIRMED" : "NOT-CONFIRMED",
    class: "BOLA", subclass: "collection-over-return",
    confidence: confirmed ? "high" : "none", reportable: confirmed, method: "GET", idKey,
    endpoint: cfg.collectionPath,
    oracle: `self-scoped sibling ${cfg.siblingPath} (the app's own ownership statement) vs the unscoped ${cfg.collectionPath}`,
    attacker: cfg.attacker.name, victim: cfg.victim ? cfg.victim.name : null, gates,
    evidence: {
      ...ev,
      owner_field: ownerKey || null,
      foreign_rows: foreign.slice(0, 20),
      foreign_count: foreign.length,
      reproductions: `${reproduced}/${repeat}`,
    },
    reason: confirmed
      ? `${cfg.attacker.name}'s own GET ${cfg.collectionPath} returned ${foreign.length} row(s) the app attributes to other users, while the self-scoped ${cfg.siblingPath} correctly returns only ${sib.objects.length} of the attacker's own - the collection endpoint is missing its owner scope. Reproduced ${reproduced}/${repeat}.`
      : `Not confirmed (lead). First unmet gate: ${failed ? failed.id + " (" + failed.observed + ")" : "unknown"}.`,
  };
}

function inapplicable(cfg, evidence, why) {
  return {
    verdict: "INAPPLICABLE", class: "BOLA", subclass: "collection-over-return", confidence: "none", reportable: false,
    method: "GET", idKey: cfg.idKey || "id", endpoint: cfg.collectionPath,
    oracle: `self-scoped sibling ${cfg.siblingPath} vs the unscoped ${cfg.collectionPath}`,
    attacker: cfg.attacker.name, victim: cfg.victim ? cfg.victim.name : null, gates: [], evidence, reason: `Oracle inapplicable: ${why}`,
  };
}

// --- self-test (offline: the pure decision core) ----------------------------------------
function selfTest() {
  let pass = 0, fail = 0;
  const check = (c, m) => (c ? pass++ : (fail++, console.error("FAIL:", m)));

  const sibling = [{ id: 1, owner: "alice" }, { id: 2, owner: "alice" }]; // attacker's own, correctly scoped

  // over-return: bare list contains bob's rows -> foreign by owner
  let r = findOverReturned({ bareObjects: [{ id: 1, owner: "alice" }, { id: 9, owner: "bob" }, { id: 10, owner: "carol" }], siblingObjects: sibling });
  check(r.foreign.length === 2 && r.ownInBare === 1, "over-return detected by owner field (2 foreign, 1 own)");
  check(r.attackerOwner === "alice" && r.ownerKey === "owner", "attacker owner value derived from the scoped sibling");

  // correctly-scoped bare list: only the attacker's own rows -> no foreign
  r = findOverReturned({ bareObjects: [{ id: 1, owner: "alice" }, { id: 2, owner: "alice" }], siblingObjects: sibling });
  check(r.foreign.length === 0, "a correctly-scoped bare list yields no foreign rows");

  // shared/public rows are NOT foreign
  r = findOverReturned({ bareObjects: [{ id: 1, owner: "alice" }, { id: 7, owner: "bob", visibility: "public" }], siblingObjects: sibling });
  check(r.foreign.length === 0, "a public row in the list is legitimate, not a leak");

  // id-based foreignness when no owner field but a victim list is known
  r = findOverReturned({ bareObjects: [{ id: "u1" }, { id: "v9" }], siblingObjects: [{ id: "u1" }], victimIds: new Set(["v9"]) });
  check(r.foreign.length === 1 && r.foreign[0].id === "v9", "foreign row detected by victim-owned id when no owner field");

  console.log(`oracle_collection self-test: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

if (process.argv[1] && process.argv[1].endsWith("oracle_collection.mjs") && process.argv.includes("--self-test")) selfTest();
