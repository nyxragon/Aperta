// Stage 3, the sibling-endpoint oracle ("the app is its own oracle").
//
// An object endpoint (GET /api/orders/{id}) has no owner check = BOLA. We confirm it NOT with a
// tuned response-diff, but with a CONTRADICTION inside the app: the sibling GET /api/me/orders
// returns only the caller's own objects, so it is the app's own statement of who owns what.
// A BOLA is proven when an attacker retrieves the SAME record the victim legitimately sees, which
// the sibling attributes to the victim and NOT to the attacker, with controls (own-id=200,
// format-valid nonexistent id NOT 200) holding in-run.
//
// Confirmation is gated on an actual cross-user DATA contradiction, never on id-equality alone:
//  - the attacker's foreign object must be a NON-TRIVIAL body (fields beyond the id), and
//  - it must match the record the VICTIM gets for the same id (the victim's own legitimate view),
//  - and, when the body carries an owner/tenant field, that field must name the victim not the
//    attacker.
// This refuses the "id-echo / existence stub" false positive, where an endpoint returns {id:<echo>}
// for any well-formed id with no real record behind it.

const OWNER_KEYS = ["owner", "ownerId", "owner_id", "userId", "user_id", "accountId", "account_id",
  "account", "tenantId", "tenant_id", "tenant", "orgId", "org_id", "org", "createdBy", "created_by", "user"];
const COLLECTION_WRAPPERS = ["results", "items", "data", "nodes", "list", "records", "rows", "content"];

// Guarded JSON fetch: never throws on a non-JSON body (expired-session HTML login shell, 500 page,
// WAF block, redirect). Returns { ok, status, json } with json=null when the body is not JSON.
async function safeJson(url, headers) {
  try {
    const r = await fetch(url, { headers });
    let json = null;
    try { json = await r.json(); } catch {}
    return { ok: r.status >= 200 && r.status < 300, status: r.status, json };
  } catch {
    return { ok: false, status: 0, json: null };
  }
}

// Tolerant extraction of a list of objects from a sibling response, regardless of envelope shape:
// bare array, { collection:[...] }, { data:{ collection:[...] } }, { results|items|... }, a Relay
// connection { edges:[{node}] }, or { nodes:[...] }. Returns an array of objects (possibly empty).
export function extractCollection(json, collection, collectionPath) {
  if (json == null) return [];
  // explicit dot path wins (e.g. "operation.Details" for enterprise JSON)
  if (collectionPath) {
    const v = collectionPath.split(".").reduce((o, k) => (o == null ? o : o[k]), json);
    return normalizeNodes(v);
  }
  if (Array.isArray(json)) return normalizeNodes(json);
  if (Array.isArray(json.edges) || Array.isArray(json.nodes)) return normalizeNodes(json); // top-level Relay connection
  if (collection && json[collection] != null) return normalizeNodes(json[collection]);
  if (json.data != null) {
    if (collection && json.data[collection] != null) return normalizeNodes(json.data[collection]);
    if (Array.isArray(json.data)) return normalizeNodes(json.data);
  }
  for (const w of COLLECTION_WRAPPERS) {
    if (json[w] != null) { const n = normalizeNodes(json[w]); if (n.length) return n; }
  }
  return [];
}

function normalizeNodes(val) {
  if (Array.isArray(val)) return val.filter((o) => o && typeof o === "object");
  if (val && Array.isArray(val.edges)) return val.edges.map((e) => e && e.node).filter((o) => o && typeof o === "object");
  if (val && Array.isArray(val.nodes)) return val.nodes.filter((o) => o && typeof o === "object");
  return [];
}

// A follow-the-cursor URL on a paginated list, if the response advertises one. Bounded by the caller.
function nextPage(json) {
  if (!json || typeof json !== "object") return null;
  const cand = json.next || json.nextPage || json.nextPageUrl || json.next_page_url ||
    (json.links && json.links.next) || (json.paging && json.paging.next) || null;
  return typeof cand === "string" && cand ? cand : null;
}

// The app's own statement of ownership for this identity (uses caller-supplied auth headers).
// Follows up to `maxPages` of a cursor-paginated list so a real owned id on page 2 is not mistaken
// for a foreign one. Returns { ids:Set, objects:[...], ok, pages, status }.
async function ownedIds(base, headers, siblingPath, collection, idKey, collectionPath, maxPages = 10) {
  let url = `${base}${siblingPath}`;
  const ids = new Set(); const objects = []; let pages = 0; let firstStatus = 0; let anyOk = false;
  for (let i = 0; i < maxPages; i++) {
    const r = await safeJson(url, headers);
    if (i === 0) firstStatus = r.status;
    if (!r.ok || r.json == null) break;
    anyOk = true; pages++;
    for (const o of extractCollection(r.json, collection, collectionPath)) {
      if (o[idKey] != null) { ids.add(String(o[idKey])); objects.push(o); }
    }
    const nxt = nextPage(r.json);
    if (!nxt) break;
    url = /^https?:\/\//.test(nxt) ? nxt : `${base}${nxt.startsWith("/") ? "" : "/"}${nxt}`;
  }
  return { ids, objects, ok: anyOk, pages, status: firstStatus };
}

async function getObject(base, headers, template, id) {
  try {
    const r = await fetch(`${base}${template.replace("{param}", encodeURIComponent(id))}`, { headers });
    let body = null;
    try { body = await r.json(); } catch {}
    return { status: r.status, body };
  } catch {
    return { status: 0, body: null };
  }
}

// An object body with at least one field beyond the id. An id-echo / existence stub (just {id})
// is NOT non-trivial and can never confirm a BOLA (no real cross-user data was disclosed).
export function isNonTrivialObject(body, idKey) {
  if (!body || typeof body !== "object" || Array.isArray(body)) return false;
  return Object.keys(body).some((k) => k !== idKey && body[k] != null);
}

// Canonical JSON (stable key order) for a content-equality comparison between two bodies.
export function canonical(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(",")}}`;
}
export const bodiesEqual = (a, b) => canonical(a) === canonical(b);

// A format-preserving id that is (almost surely) nonexistent, so the "nonexistent control" proves the
// 200 is ownership-gated and not a catch-all that 200s any well-formed id. Fail-closed: if the
// mutation happens to collide with a real id, the control simply returns 200 and we refuse to confirm.
export function deriveNonexistentId(realId) {
  const s = String(realId);
  if (/^\d+$/.test(s)) return s + "000";                                  // numeric: huge, unlikely to exist
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s)) {
    const c = s[0]; const repl = c.toLowerCase() === "0" ? "1" : "0";     // UUID: flip the first nibble
    return repl + s.slice(1);
  }
  return s + "-aperta404";                                                // slug/opaque: unused suffix
}

// The single owner/tenant field present in a body, if any, and the constant value the app assigns it
// across an identity's own objects (its self-declared owner value). Returns null when undeterminable.
export function detectOwnerKey(body) {
  if (!body || typeof body !== "object") return null;
  return OWNER_KEYS.find((k) => body[k] != null) || null;
}
function constOwnerValue(objects, key) {
  if (!key) return null;
  const vals = new Set(objects
    .map((o) => (o[key] != null && typeof o[key] !== "object" ? String(o[key]) : null)) // scalar owners only
    .filter((v) => v != null));
  return vals.size === 1 ? [...vals][0] : null; // only trust it when the app states ONE owner for the set
}

// Legitimate cross-user access (shared / public / collaborator) is NOT a BOLA, and it is the #1 false
// positive this oracle must resist: the object genuinely belongs to the victim, yet the attacker is
// allowed to read it by design. Detect the app's own sharing signals in the returned object. If the
// object is public, or shared with (or lists) the attacker, confirmation must NOT fire. Conservative:
// when a sharing list exists and the attacker's identity is unknown, treat it as possibly-shared
// (a lead), because a false CONFIRMED is worse than a missed one.
const SHARE_BOOL = ["public", "ispublic", "shared", "isshared", "global", "isglobal", "everyone"];
const SHARE_VIS_KEYS = ["visibility", "access", "accesslevel", "scope", "privacy", "sharing"];
const SHARE_PUBLIC_VALS = new Set(["public", "shared", "global", "everyone", "org", "organization", "team", "all", "anyone", "unlisted"]);
const SHARE_LIST_KEYS = ["sharedwith", "shared_with", "collaborators", "members", "viewers", "editors", "acl", "participants", "guests", "contributors", "shares"];

export function detectSharing(body, attackerId) {
  if (!body || typeof body !== "object" || Array.isArray(body)) return null;
  for (const k of Object.keys(body)) {
    const lk = k.toLowerCase().replace(/[_-]/g, "");
    const v = body[k];
    if (SHARE_BOOL.includes(lk) && v === true) return `${k}=true (object is public/shared)`;
    if (SHARE_VIS_KEYS.includes(lk) && typeof v === "string" && SHARE_PUBLIC_VALS.has(v.toLowerCase())) return `${k}="${v}" (not private)`;
    if (SHARE_LIST_KEYS.includes(lk) && Array.isArray(v) && v.length) {
      const members = v.map((x) => (x && typeof x === "object" ? String(x.id ?? x.user ?? x.email ?? x.name ?? "") : String(x)));
      if (attackerId == null || members.includes(String(attackerId))) return `${k} shares this object (attacker may be authorized)`;
    }
  }
  return null;
}

/**
 * cfg = { objectTemplate, siblingPath, collection, idKey, collectionPath?, ownerKey?, repeat?,
 *         attacker:{name,headers}, victim:{name,headers} }
 * Aperta never logs in: the caller supplies each identity's auth headers (proxy or direct).
 *
 * verdict:
 *   CONFIRMED        - the attacker read the victim's real record, every gate held.
 *   CORRECTLY-SCOPED - an earned negative: the object exists and is the victim's, yet the attacker is
 *                      denied every time while own-id works (the endpoint enforces object authz).
 *   INAPPLICABLE     - the oracle could not run (no sibling data / no foreign id / no own id).
 *   NOT-CONFIRMED    - a lead, not a proof: something did not hold; keep digging.
 */
export async function siblingOracleBOLA(base, cfg) {
  const aH = cfg.attacker.headers || {};
  const vH = cfg.victim.headers || {};
  const idKey = cfg.idKey || "id";
  cfg.attacker.u = cfg.attacker.name; cfg.victim.u = cfg.victim.name;

  const attacker = await ownedIds(base, aH, cfg.siblingPath, cfg.collection, idKey, cfg.collectionPath);
  const victim = await ownedIds(base, vH, cfg.siblingPath, cfg.collection, idKey, cfg.collectionPath);

  const base_evidence = {
    attacker_owned: [...attacker.ids], victim_owned: [...victim.ids],
    sibling_pages_followed: { attacker: attacker.pages, victim: victim.pages },
  };

  // INAPPLICABLE: the oracle has no ground truth to reason from.
  if (!attacker.ok || !victim.ok) {
    return inapplicable(cfg, base_evidence,
      `sibling ${cfg.siblingPath} returned non-JSON/non-2xx for ${!attacker.ok ? cfg.attacker.u : cfg.victim.u} (session likely invalid or endpoint not a JSON list).`);
  }
  const foreignId = [...victim.ids].find((id) => !attacker.ids.has(id)) || null;
  const ownId = [...attacker.ids][0] || null;
  if (!foreignId) return inapplicable(cfg, base_evidence, "no victim-owned id is absent from the attacker's own list (identical identity, empty lists, or fully shared).");
  if (!ownId) return inapplicable(cfg, base_evidence, "the attacker's own list is empty, so the own-id control cannot be established.");

  const ownerKey = cfg.ownerKey || null;
  const victimOwnerVal = ownerKey ? constOwnerValue(victim.objects, ownerKey) : null;
  const attackerOwnerVal = ownerKey ? constOwnerValue(attacker.objects, ownerKey) : null;

  // The record the VICTIM legitimately sees for this id: the ground truth the attacker must match.
  const victimForeign = await getObject(base, vH, cfg.objectTemplate, foreignId);

  // Reproduce the attacker's read N times (default 3): a one-off could be a fluke/race.
  const repeat = Math.max(1, cfg.repeat || 3);
  let reads = 0, attackerGetsForeign = null;
  for (let i = 0; i < repeat; i++) {
    const r = await getObject(base, aH, cfg.objectTemplate, foreignId);
    attackerGetsForeign = r;
    if (r.status === 200 && isNonTrivialObject(r.body, idKey) && String(r.body[idKey]) === String(foreignId)) reads++;
  }
  const controlOwn = await getObject(base, aH, cfg.objectTemplate, ownId);                  // authorized baseline
  const nonexistentId = deriveNonexistentId(foreignId);
  const controlMissing = await getObject(base, aH, cfg.objectTemplate, nonexistentId);       // catch-all guard

  // Auto-detect an owner field from the body actually returned, if the caller did not name one.
  const autoOwnerKey = ownerKey || detectOwnerKey(attackerGetsForeign && attackerGetsForeign.body);
  const vOwn = autoOwnerKey ? (victimOwnerVal ?? constOwnerValue(victim.objects, autoOwnerKey)) : null;
  const aOwn = autoOwnerKey ? (attackerOwnerVal ?? constOwnerValue(attacker.objects, autoOwnerKey)) : null;
  // owner gate is applicable ONLY for a scalar owner value: a nested object owner (owner:{name:..})
  // stringifies to "[object Object]" for everyone and would wrongly fail the gate, suppressing a real
  // break. When the owner is non-scalar, skip the gate (data_matches_victim still carries the proof).
  const ownerVal = autoOwnerKey && attackerGetsForeign && attackerGetsForeign.body ? attackerGetsForeign.body[autoOwnerKey] : null;
  const ownerApplicable = Boolean(autoOwnerKey && vOwn != null && ownerVal != null && typeof ownerVal !== "object");
  const ownerObserved = ownerApplicable ? String(ownerVal) : null;
  // sharing / public / collaborator access = legitimate, not BOLA (the top false positive).
  const sharing = detectSharing(attackerGetsForeign && attackerGetsForeign.body, aOwn);

  const attackerBody = attackerGetsForeign && attackerGetsForeign.body;
  const dataMatches = attackerGetsForeign && attackerGetsForeign.status === 200 &&
    isNonTrivialObject(attackerBody, idKey) && victimForeign.status === 200 &&
    isNonTrivialObject(victimForeign.body, idKey) && bodiesEqual(attackerBody, victimForeign.body);

  // The oracle tape: every confirmation condition, observable, pass/fail. The verdict is a pure fold
  // over these gates, so CONFIRMED is impossible unless each one held, and a NOT-CONFIRMED names
  // exactly which gate broke (so an agent knows whether to re-propose or stop).
  const gates = [
    { id: "foreign_sourced", label: `sibling attributes id ${foreignId} to ${cfg.victim.u}, not ${cfg.attacker.u}`,
      expected: "a victim-owned id absent from the attacker's list", observed: `${foreignId}`, pass: true },
    { id: "attacker_reads_foreign", label: `${cfg.attacker.u} GET(${foreignId}) returns a real object ${repeat}/${repeat}`,
      expected: `200 + non-trivial body, id=${foreignId}, ${repeat}/${repeat}`, observed: `${reads}/${repeat} @ ${attackerGetsForeign ? attackerGetsForeign.status : 0}`, pass: reads === repeat },
    { id: "data_matches_victim", label: "the attacker's object equals the record the victim legitimately sees",
      expected: "attacker body == victim body (non-trivial)", observed: dataMatches ? "equal" : "differs/absent/trivial", pass: Boolean(dataMatches) },
    { id: "control_own", label: `${cfg.attacker.u} GET(own id ${ownId}) authorized`,
      expected: "200 + id matches", observed: `${controlOwn.status}`, pass: controlOwn.status === 200 && String(controlOwn.body && controlOwn.body[idKey]) === String(ownId) },
    { id: "control_nonexistent", label: "catch-all ruled out (format-valid unowned id is not served)",
      expected: `not 200 for ${nonexistentId}`, observed: `${controlMissing.status}`, pass: controlMissing.status !== 200 },
    { id: "not_shared", label: "the object is not shared/public to the attacker (would be legitimate access)",
      expected: "no sharing/visibility signal granting the attacker access", observed: sharing || "none", pass: !sharing },
  ];
  if (ownerApplicable) {
    gates.push({ id: "owner_field", label: `the object's own '${autoOwnerKey}' names ${cfg.victim.u}, not ${cfg.attacker.u}`,
      expected: `${autoOwnerKey}=${vOwn} (not ${aOwn})`, observed: `${autoOwnerKey}=${ownerObserved}`,
      pass: String(ownerObserved) === String(vOwn) && (aOwn == null || String(ownerObserved) !== String(aOwn)) });
  }

  const confirmed = gates.every((g) => g.pass);

  // An earned negative: the object provably exists and is the victim's, own-id works, no catch-all,
  // yet the attacker is denied every time. That triple is a deterministic proof of correct scoping.
  const attackerDenied = reads === 0 && attackerGetsForeign && attackerGetsForeign.status !== 200;
  const victimReadsIt = victimForeign.status === 200 && isNonTrivialObject(victimForeign.body, idKey);
  const correctlyScoped = !confirmed && attackerDenied && victimReadsIt &&
    controlOwn.status === 200 && controlMissing.status !== 200;

  const verdict = confirmed ? "CONFIRMED" : correctlyScoped ? "CORRECTLY-SCOPED" : "NOT-CONFIRMED";
  const failed = gates.find((g) => !g.pass);

  return {
    verdict,
    class: "BOLA",
    confidence: confirmed || correctlyScoped ? "high" : "none",
    reportable: confirmed,
    method: "GET",
    idKey,
    endpoint: cfg.objectTemplate,
    oracle: `sibling-endpoint ${cfg.siblingPath} (the app's own ownership statement)`,
    attacker: cfg.attacker.u,
    victim: cfg.victim.u,
    gates,
    evidence: {
      ...base_evidence,
      foreign_id_tested: foreignId,
      reproductions: `${reads}/${repeat}`,
      attacker_get_foreign: attackerGetsForeign,
      victim_get_foreign: { status: victimForeign.status, body: victimForeign.body },
      data_matches_victim: Boolean(dataMatches),
      owner_field: ownerApplicable ? { key: autoOwnerKey, observed: ownerObserved, victim: vOwn, attacker: aOwn } : null,
      control_own_id: ownId,
      control_own_result: { status: controlOwn.status },
      control_nonexistent_id: nonexistentId,
      control_nonexistent_result: { status: controlMissing.status },
    },
    reason: confirmed
      ? `${cfg.attacker.u} retrieved ${cfg.collection} ${foreignId}, the SAME record ${cfg.siblingPath} and the object endpoint give ${cfg.victim.u}, reproduced ${reads}/${repeat} with own-id=200 and nonexistent (${nonexistentId}) not-200 controls holding. A cross-user data contradiction in the app's own authorization.`
      : correctlyScoped
        ? `Earned negative: ${cfg.collection} ${foreignId} exists and is ${cfg.victim.u}'s, but ${cfg.attacker.u} is denied every time (own-id=200, no catch-all). The endpoint enforces object-level authorization.`
        : `Not confirmed (lead, keep digging). First unmet gate: ${failed ? failed.id + " (" + failed.observed + ")" : "unknown"}.`,
  };
}

function inapplicable(cfg, evidence, why) {
  return {
    verdict: "INAPPLICABLE", class: "BOLA", confidence: "none", reportable: false, method: "GET",
    idKey: cfg.idKey || "id", endpoint: cfg.objectTemplate,
    oracle: `sibling-endpoint ${cfg.siblingPath} (the app's own ownership statement)`,
    attacker: cfg.attacker.u, victim: cfg.victim.u, gates: [],
    evidence, reason: `Oracle inapplicable: ${why}`,
  };
}

// --- self-test (offline: pure helpers; full confirm is e2e/oracle*.mjs) ------------------
function selfTest() {
  let pass = 0, fail = 0;
  const check = (c, m) => (c ? pass++ : (fail++, console.error("FAIL:", m)));

  // extractCollection: every common envelope shape
  check(extractCollection([{ id: 1 }], "orders").length === 1, "bare array");
  check(extractCollection({ orders: [{ id: 1 }] }, "orders").length === 1, "{collection:[...]}");
  check(extractCollection({ data: { orders: [{ id: 1 }] } }, "orders").length === 1, "{data:{collection}}");
  check(extractCollection({ results: [{ id: 1 }, { id: 2 }] }, "orders").length === 2, "{results:[...]}");
  check(extractCollection({ items: [{ id: 1 }] }, "orders").length === 1, "{items:[...]}");
  check(extractCollection({ edges: [{ node: { id: 1 } }] }, "orders").length === 1, "Relay {edges:[{node}]}");
  check(extractCollection({ nodes: [{ id: 1 }] }, "orders").length === 1, "{nodes:[...]}");
  check(extractCollection({ operation: { Details: [{ RESOURCEID: 9 }] } }, "x", "operation.Details").length === 1, "explicit dot collectionPath (enterprise JSON)");
  check(extractCollection(null, "orders").length === 0 && extractCollection("<html>", "orders").length === 0, "non-JSON / null is empty-safe");

  // isNonTrivialObject: kills the id-echo stub
  check(isNonTrivialObject({ id: 1, owner: "bob" }, "id") === true, "non-trivial body");
  check(isNonTrivialObject({ id: 1 }, "id") === false, "id-echo stub is trivial");
  check(isNonTrivialObject({ id: 1, extra: null }, "id") === false, "null-only extra is trivial");
  check(isNonTrivialObject([1, 2], "id") === false && isNonTrivialObject(null, "id") === false, "array/null not non-trivial");

  // canonical equality is key-order independent
  check(bodiesEqual({ a: 1, b: 2 }, { b: 2, a: 1 }) === true, "canonical equal, key order independent");
  check(bodiesEqual({ a: 1 }, { a: 2 }) === false, "canonical unequal on value");

  // deriveNonexistentId: format-preserving, and different from the input
  check(deriveNonexistentId("2001") === "2001000", "numeric derive");
  const u = "c4d5e6f7-1122-4333-8444-556677889900";
  check(deriveNonexistentId(u) !== u && /^[0-9a-f-]{36}$/i.test(deriveNonexistentId(u)), "uuid derive keeps format, differs");
  check(deriveNonexistentId("abc") === "abc-aperta404", "opaque slug derive");

  // detectOwnerKey / constOwnerValue
  check(detectOwnerKey({ id: 1, owner: "bob" }) === "owner", "detect owner key");
  check(detectOwnerKey({ id: 1 }) === null, "no owner key");
  check(constOwnerValue([{ owner: "bob" }, { owner: "bob" }], "owner") === "bob", "constant owner value");
  check(constOwnerValue([{ owner: "bob" }, { owner: "x" }], "owner") === null, "mixed owner -> untrusted (null)");
  check(constOwnerValue([{ owner: { name: "bob" } }], "owner") === null, "non-scalar owner -> untrusted (null)");

  // detectSharing: legitimate cross-user access signals
  check(detectSharing({ id: 1, visibility: "public" }) !== null, "visibility:public is a sharing signal");
  check(detectSharing({ id: 1, isPublic: true }) !== null, "isPublic:true is a sharing signal");
  check(detectSharing({ id: 1, collaborators: ["alice"] }, "alice") !== null, "attacker in collaborators is a sharing signal");
  check(detectSharing({ id: 1, collaborators: ["carol"] }, "alice") === null, "attacker NOT in collaborators -> still a break (no signal)");
  check(detectSharing({ id: 1, owner: "bob", visibility: "private" }) === null, "a private owned object has no sharing signal");

  console.log(`oracle self-test: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

if (process.argv[1] && process.argv[1].endsWith("oracle.mjs") && process.argv.includes("--self-test")) selfTest();
