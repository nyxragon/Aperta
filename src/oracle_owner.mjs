// The owner-field oracle: a single-identity deterministic BOLA proof.
//
// The sibling oracle needs TWO sessions (attacker + victim) to source the victim's real ids. But a
// huge class of real APIs return the resource's OWNER inside the object body (owner/ownerId/userId/
// tenantId/...). When they do, the app ITSELF states who each object belongs to, so one attacker
// session is enough: the attacker fetches a foreign object (an id they observed or a neighbor id) and
// the app hands back an object whose OWN owner field names someone else. That is a self-contradiction
// the app authored - it served the caller an object it simultaneously labels as not the caller's.
//
// SOUNDNESS (why this is not a username-vs-id false positive): the attacker's owner value is
// CALIBRATED from one of the attacker's OWN objects (same value-space as the field being compared),
// never guessed or taken from a different endpoint's id space. If that calibration is unavailable the
// oracle is INAPPLICABLE, never a guess. Controls: own object reads 200 (authorized baseline), a
// format-derived nonexistent id is not served (no catch-all), shared/public objects are excluded.
// Read-only: GET only.

import { isNonTrivialObject, detectOwnerKey, detectSharing, deriveNonexistentId } from "./oracle.mjs";

async function getObj(base, headers, template, id) {
  try {
    const path = template.includes("{param}") ? template.replace(/\{param\}/g, encodeURIComponent(id)) : template;
    const r = await fetch(`${base}${path}`, { headers });
    let body = null; try { body = await r.json(); } catch {}
    return { status: r.status, body };
  } catch { return { status: 0, body: null }; }
}

/**
 * cfg = { objectTemplate, ownId (an id the attacker OWNS), foreignIds:[...] (ids to test),
 *         ownerKey?, idKey?, repeat?, attacker:{name,headers} }
 * verdict: CONFIRMED / NOT-CONFIRMED / INAPPLICABLE as a fold over an observable gate tape.
 */
export async function ownerFieldOracleBOLA(base, cfg) {
  const idKey = cfg.idKey || "id";
  const aH = cfg.attacker.headers || {};
  const ev = { own_id: cfg.ownId ?? null, foreign_ids_tested: (cfg.foreignIds || []).slice(0, 20) };

  if (cfg.ownId == null) return inapplicable(cfg, ev, "no --own-id: an object the attacker owns is required to calibrate the owner-field value space (otherwise a username-vs-id mismatch would false-positive).");
  if (!cfg.foreignIds || !cfg.foreignIds.length) return inapplicable(cfg, ev, "no --foreign-id: at least one other object id to test is required (an id you observed, or a neighbour).");

  // 1) calibrate: read the attacker's OWN object; its owner field value is the attacker's identity in
  // the SAME space as the field we will compare. This is also the own-id authorized control.
  const own = await getObj(base, aH, cfg.objectTemplate, cfg.ownId);
  const ownerKey = cfg.ownerKey || detectOwnerKey(own.body);
  if (own.status !== 200 || !isNonTrivialObject(own.body, idKey)) return inapplicable(cfg, ev, `the attacker's own object (${cfg.ownId}) did not read back as a real object (status ${own.status}).`);
  if (!ownerKey || own.body[ownerKey] == null || typeof own.body[ownerKey] === "object") return inapplicable(cfg, ev, "the object body carries no scalar owner/tenant field to reason from.");
  const attackerOwner = String(own.body[ownerKey]);
  ev.owner_field = ownerKey; ev.attacker_owner_value = attackerOwner;

  // 2) find a foreign object: served to the attacker, non-trivial, not shared, whose own owner field
  // names someone other than the (calibrated) attacker.
  const nonexistentId = deriveNonexistentId(cfg.foreignIds[0]);
  const repeat = Math.max(1, cfg.repeat || 3);
  let breakId = null, breakBody = null, reproduced = 0;
  for (const fid of cfg.foreignIds) {
    if (String(fid) === String(cfg.ownId)) continue;
    const r = await getObj(base, aH, cfg.objectTemplate, fid);
    if (r.status !== 200 || !isNonTrivialObject(r.body, idKey)) continue;
    if (r.body[ownerKey] == null || typeof r.body[ownerKey] === "object") continue;
    if (String(r.body[ownerKey]) === attackerOwner) continue;      // the attacker's own -> not a break
    if (detectSharing(r.body, attackerOwner)) continue;            // shared/public -> legitimate
    breakId = fid; breakBody = r.body; break;
  }
  if (breakId) {
    for (let i = 0; i < repeat; i++) {
      const r = await getObj(base, aH, cfg.objectTemplate, breakId);
      if (r.status === 200 && isNonTrivialObject(r.body, idKey) && String(r.body[ownerKey]) !== attackerOwner) reproduced++;
    }
  }
  const control = await getObj(base, aH, cfg.objectTemplate, nonexistentId);

  const gates = [
    { id: "own_calibrated", label: `the attacker's own object ${cfg.ownId} reads back with ${ownerKey}=${attackerOwner}`, expected: "200 + scalar owner field", observed: `200 ${ownerKey}=${attackerOwner}`, pass: true },
    { id: "owner_contradiction", label: `the attacker is served a foreign object whose own ${ownerKey} is NOT ${attackerOwner}`, expected: "a non-trivial, non-shared object owned by someone else", observed: breakId != null ? `id ${breakId} ${ownerKey}=${breakBody[ownerKey]}` : "none found", pass: breakId != null },
    { id: "reproduced", label: `the break is stable across ${repeat} reads`, expected: `${repeat}/${repeat}`, observed: `${reproduced}/${repeat}`, pass: breakId != null && reproduced === repeat },
    { id: "control_nonexistent", label: "catch-all ruled out (a format-valid unowned id is not served)", expected: `not 200 for ${nonexistentId}`, observed: `${control.status}`, pass: control.status !== 200 },
  ];
  const confirmed = gates.every((g) => g.pass);
  const failed = gates.find((g) => !g.pass);

  return {
    verdict: confirmed ? "CONFIRMED" : "NOT-CONFIRMED",
    class: "BOLA", subclass: "owner-field",
    confidence: confirmed ? "high" : "none", reportable: confirmed, method: "GET", idKey,
    endpoint: cfg.objectTemplate,
    oracle: `the object's own '${ownerKey}' field (the app's own ownership statement), single-identity`,
    attacker: cfg.attacker.name, victim: breakBody ? String(breakBody[ownerKey]) : null, gates,
    evidence: {
      ...ev,
      object_template: cfg.objectTemplate,
      foreign_id_tested: breakId,
      reproductions: `${reproduced}/${repeat}`,
      attacker_get_foreign: breakId != null ? { status: 200, body: breakBody } : null,
      control_own_id: cfg.ownId,
      control_own_result: { status: own.status },
      control_nonexistent_id: nonexistentId,
      control_nonexistent_result: { status: control.status },
    },
    reason: confirmed
      ? `${cfg.attacker.name} fetched ${cfg.objectTemplate.replace("{param}", breakId)} and the app returned an object whose own '${ownerKey}' is ${breakBody[ownerKey]} (not the attacker's ${attackerOwner}), reproduced ${reproduced}/${repeat} with the own-object control at 200 and nonexistent (${nonexistentId}) not served. A self-contradiction: the app served the caller an object it labels as another user's.`
      : `Not confirmed (lead). First unmet gate: ${failed ? failed.id + " (" + failed.observed + ")" : "unknown"}.`,
  };
}

function inapplicable(cfg, evidence, why) {
  return {
    verdict: "INAPPLICABLE", class: "BOLA", subclass: "owner-field", confidence: "none", reportable: false,
    method: "GET", idKey: cfg.idKey || "id", endpoint: cfg.objectTemplate,
    oracle: "the object's own owner field (single-identity)", attacker: cfg.attacker.name, victim: null,
    gates: [], evidence, reason: `Oracle inapplicable: ${why}`,
  };
}
