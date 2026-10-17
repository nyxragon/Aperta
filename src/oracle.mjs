// Stage 3, the sibling-endpoint oracle ("the app is its own oracle").
//
// An object endpoint (GET /api/orders/{id}) has no owner check = BOLA. We confirm it NOT with a
// tuned response-diff, but with a CONTRADICTION inside the app: the sibling GET /api/me/orders
// returns only the caller's own objects, so it is the app's own statement of who owns what.
// A BOLA is proven when an attacker retrieves an object the sibling attributes to the victim and
// NOT to the attacker, a self-contradiction, with controls (own-id 200, nonexistent 404) in-run.

// The app's own statement of ownership for this identity (uses caller-supplied auth headers).
async function ownedIds(base, headers, siblingPath, collection, idKey) {
  const r = await fetch(`${base}${siblingPath}`, { headers });
  const j = await r.json();
  return new Set((j[collection] || []).map((o) => String(o[idKey])));
}

async function getObject(base, headers, template, id) {
  const r = await fetch(`${base}${template.replace("{param}", id)}`, { headers });
  let body = null;
  try { body = await r.json(); } catch {}
  return { status: r.status, body };
}

/**
 * cfg = { objectTemplate, siblingPath, collection, idKey, attacker:{name,headers}, victim:{name,headers} }
 * Aperta never logs in: the caller supplies each identity's auth headers (proxy or direct).
 */
export async function siblingOracleBOLA(base, cfg) {
  const aH = cfg.attacker.headers || {};
  const vH = cfg.victim.headers || {};
  cfg.attacker.u = cfg.attacker.name; cfg.victim.u = cfg.victim.name; // keep message strings working

  const attackerOwned = await ownedIds(base, aH, cfg.siblingPath, cfg.collection, cfg.idKey);
  const victimOwned = await ownedIds(base, vH, cfg.siblingPath, cfg.collection, cfg.idKey);

  // a foreign object: the sibling says it is the victim's and NOT the attacker's
  const foreignId = [...victimOwned].find((id) => !attackerOwned.has(id));
  const ownId = [...attackerOwned][0];
  const nonexistentId = "999999999";

  // Reproduce the break N times (default 3, CLAUDE.md §6): a one-off 200 could be a fluke / race.
  const repeat = Math.max(1, cfg.repeat || 3);
  let reproduced = 0, attackerGetsForeign = null;
  if (foreignId) {
    for (let i = 0; i < repeat; i++) {
      const r = await getObject(base, aH, cfg.objectTemplate, foreignId);
      attackerGetsForeign = r; // keep the last for evidence
      if (r.status === 200 && r.body && String(r.body[cfg.idKey]) === String(foreignId)) reproduced++;
    }
  }
  const controlOwn = ownId ? await getObject(base, aH, cfg.objectTemplate, ownId) : null;        // authorized baseline
  const controlMissing = await getObject(base, aH, cfg.objectTemplate, nonexistentId);            // catch-all guard

  // Confirmation requires ALL of:
  //  - the sibling attributes foreignId to the victim, not the attacker (contradiction set up)
  //  - attacker GET(foreignId) returns the victim's object ALL `repeat` times (the break, reproduced)
  //  - control: attacker GET(ownId) is 200 (authorized access works, not a blanket allow/deny)
  //  - control: attacker GET(nonexistent) is 404 (the 200 is not a catch-all)
  const bodyIsForeign = foreignId && reproduced === repeat;
  const controlOwnOk = controlOwn && controlOwn.status === 200;
  const notCatchAll = controlMissing && controlMissing.status === 404;

  const confirmed = Boolean(foreignId && bodyIsForeign && controlOwnOk && notCatchAll);

  return {
    verdict: confirmed ? "CONFIRMED" : "NOT-CONFIRMED",
    class: "BOLA",
    confidence: confirmed ? "high" : "none",
    method: "GET",
    idKey: cfg.idKey,
    endpoint: cfg.objectTemplate,
    oracle: `sibling-endpoint ${cfg.siblingPath} (the app's own ownership statement)`,
    attacker: cfg.attacker.u,
    victim: cfg.victim.u,
    evidence: {
      attacker_owned: [...attackerOwned],
      victim_owned: [...victimOwned],
      foreign_id_tested: foreignId || null,
      reproductions: `${reproduced}/${repeat}`,
      attacker_get_foreign: attackerGetsForeign,
      control_own_id: ownId || null,
      control_own_result: controlOwn && { status: controlOwn.status },
      control_nonexistent_result: controlMissing && { status: controlMissing.status },
    },
    reason: confirmed
      ? `${cfg.attacker.u} retrieved ${cfg.collection} ${foreignId}, which ${cfg.siblingPath} attributes to ${cfg.victim.u} and not to ${cfg.attacker.u}, a contradiction in the app's own authorization reproduced ${reproduced}/${repeat} times, with own-id=200 and nonexistent=404 controls holding.`
      : "No sibling contradiction with controls held.",
  };
}
