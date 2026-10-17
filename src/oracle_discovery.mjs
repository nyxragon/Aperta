// Auto-discover sibling-oracle BOLA candidates from a reconstructed surface.
//
// The sibling-endpoint oracle (src/oracle.mjs) is Aperta's one deterministic, FP-resistant BOLA
// confirmation, but until now the operator had to hand-pick the object endpoint, its sibling, and
// the collection. That hid the single most honest metric about this technique: on how much of THIS
// surface does the oracle even apply? This module answers that automatically.
//
// An OBJECT endpoint is one that fetches a single record by id: `GET /api/orders/{param}`.
// Its ORACLE is a self-scoped SIBLING that lists the caller's OWN objects of the same collection,
// so the app itself states who owns what: `/api/me/orders`, `/api/my/orders`, or a bare collection
// list `GET /api/orders`. Match is by the collection token (the segment before `{param}`).
//
// Output includes an APPLICABILITY rate (object endpoints with a usable oracle / all object
// endpoints) so the tool reports where the technique applies and where it does not.

const SELF_SCOPES = ["me", "my", "mine", "self", "user", "users", "account", "current"];

function segs(path) {
  return path.split("/").filter(Boolean);
}

// Is this endpoint a single-object fetch? Returns the collection + the index of the id param.
export function objectEndpoint(e) {
  if (e.method !== "GET") return null;
  const s = segs(e.path);
  // find the LAST {param}; the collection is the segment immediately before it
  const idIdx = s.lastIndexOf("{param}");
  if (idIdx <= 0) return null;
  const collection = s[idIdx - 1];
  if (collection === "{param}") return null; // /{param}/{param} is not a collection/id shape
  return { collection, idIdx, method: e.method, path: e.path };
}

// A GET that lists a collection without taking an id. Classifies how self-scoped it looks.
function listEndpoint(e, collection) {
  if (e.method !== "GET") return null;
  if (e.path.includes("{param}")) return null;
  const s = segs(e.path);
  if (!s.includes(collection)) return null;
  // self-scoped if a scope token appears anywhere before the collection
  const ci = s.indexOf(collection);
  const scoped = s.slice(0, ci).some((seg) => SELF_SCOPES.includes(seg.toLowerCase()));
  return { path: e.path, scoped };
}

/**
 * discoverOracles(model) -> {
 *   objectEndpoints: [{method, path, collection}],
 *   pairs: [{ objectTemplate, collection, idKeyGuess, siblings:[{path,scoped}], best, confidence }],
 *   applicability: { objectEndpoints, withOracle, rate }
 * }
 * confidence: "high" when a self-scoped sibling (/me/x, /my/x) exists (it is a true ownership
 * statement); "medium" when only a bare collection list exists (it may or may not be self-scoped);
 * an object endpoint with no sibling is reported with no pair (counts against applicability).
 */
export function discoverOracles(model) {
  const endpoints = model.endpoints || [];
  const objects = [];
  for (const e of endpoints) {
    const o = objectEndpoint(e);
    if (o) objects.push(o);
  }
  const pairs = [];
  let withOracle = 0;
  for (const o of objects) {
    const siblings = [];
    for (const e of endpoints) {
      if (e.path === o.path) continue;
      const l = listEndpoint(e, o.collection);
      if (l) siblings.push(l);
    }
    // prefer a self-scoped sibling; dedupe by path
    const seen = new Set();
    const uniq = siblings.filter((s) => (seen.has(s.path) ? false : seen.add(s.path)));
    uniq.sort((a, b) => Number(b.scoped) - Number(a.scoped));
    const best = uniq[0] || null;
    if (best) withOracle++;
    pairs.push({
      objectTemplate: o.path,
      collection: o.collection,
      idKeyGuess: "id",
      siblings: uniq,
      best: best?.path || null,
      confidence: best ? (best.scoped ? "high" : "medium") : "none",
    });
  }
  const rate = objects.length ? withOracle / objects.length : 0;
  return {
    objectEndpoints: objects.map((o) => ({ method: o.method, path: o.path, collection: o.collection })),
    pairs,
    applicability: { objectEndpoints: objects.length, withOracle, rate: Number(rate.toFixed(3)) },
  };
}

// Human one-liner for the applicability metric (used by the CLI and report).
export function applicabilityLine(disc) {
  const a = disc.applicability;
  const pct = Math.round(a.rate * 100);
  return `sibling-oracle applies to ${a.withOracle}/${a.objectEndpoints} object endpoint(s) (${pct}%)`;
}

// --- self-test (offline) ----------------------------------------------------------------
function selfTest() {
  let pass = 0, fail = 0;
  const check = (c, m) => (c ? pass++ : (fail++, console.error("FAIL:", m)));

  const model = {
    endpoints: [
      { method: "GET", path: "/api/orders/{param}" },   // object, has self-scoped sibling
      { method: "GET", path: "/api/me/orders" },         // self-scoped sibling -> high
      { method: "GET", path: "/api/invoices/{param}" },  // object, only a bare list -> medium
      { method: "GET", path: "/api/invoices" },          // bare collection list
      { method: "GET", path: "/api/widgets/{param}" },   // object, NO sibling -> none
      { method: "POST", path: "/api/login" },            // not an object endpoint
      { method: "GET", path: "/api/admin/users/{param}" }, // object (collection=users), sibling /api/me/orders? no
    ],
  };
  const d = discoverOracles(model);
  check(d.objectEndpoints.length === 4, "4 object endpoints detected (orders, invoices, widgets, users)");
  const orders = d.pairs.find((p) => p.collection === "orders");
  check(orders && orders.best === "/api/me/orders" && orders.confidence === "high", "orders -> /api/me/orders high confidence");
  const inv = d.pairs.find((p) => p.collection === "invoices");
  check(inv && inv.best === "/api/invoices" && inv.confidence === "medium", "invoices -> bare list medium confidence");
  const widgets = d.pairs.find((p) => p.collection === "widgets");
  check(widgets && widgets.best === null && widgets.confidence === "none", "widgets -> no sibling");
  check(d.applicability.objectEndpoints === 4 && d.applicability.withOracle === 2, "applicability counts (2/4 have an oracle)");
  check(d.applicability.rate === 0.5, "applicability rate 0.5");
  check(applicabilityLine(d).includes("2/4") && applicabilityLine(d).includes("50%"), "applicability line");
  check(!d.pairs.some((p) => p.objectTemplate === "/api/login"), "POST /api/login is not an object endpoint");

  console.log(`oracle_discovery self-test: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

if (process.argv[1] && process.argv[1].endsWith("oracle_discovery.mjs") && process.argv.includes("--self-test")) selfTest();
