// Bypass-wave probing: for every endpoint gated from a low-priv identity, try a battery of known
// authorization-bypass transforms and report any that flip the SAME identity from gated to reached.
// This encodes the principle "a defense is a bypass hypothesis, not a verdict" as a
// deterministic, reproducible pass. A hit is an authz-BYPASS candidate (a wall moved); whether it
// reaches another user's data is then a job for the sibling oracle (prove) - impact, not reachability.
import { probe, isGated, buildGatingOpts } from "./authz_probe.mjs";

// State-changing verbs are never fired live unless the caller opts into unsafe (no-state-change rule).
const STATE_CHANGING = new Set(["POST", "PUT", "PATCH", "DELETE"]);

// Pure: the bypass variants for one (method, path). Each is {technique, method, path, headers}.
export function bypassTransforms(method, path) {
  const out = [];
  // API-version downgrade: a hardened /v2 while legacy /v1 stayed open (Akto-style).
  const vm = path.match(/\/v(\d+)(\/|$)/);
  if (vm && Number(vm[1]) >= 2) {
    const downs = [...new Set([1, Number(vm[1]) - 1])];
    for (const d of downs) {
      const p = path.replace(/\/v\d+(\/|$)/, `/v${d}$1`);
      if (p !== path) out.push({ technique: `version-downgrade v${vm[1]}->v${d}`, method, path: p, headers: {} });
    }
  }
  // Verb swap: the guard is on one method only.
  const swaps = { GET: ["POST"], POST: ["GET", "PUT"], PUT: ["POST", "PATCH"], PATCH: ["PUT"], DELETE: ["GET"] };
  for (const sm of swaps[method] || []) out.push({ technique: `verb-swap ${method}->${sm}`, method: sm, path, headers: {} });
  // Method-override header: framework honors X-HTTP-Method-Override over the real verb.
  out.push({ technique: "method-override X-HTTP-Method-Override:GET", method: "POST", path, headers: { "X-HTTP-Method-Override": "GET" } });
  // Trailing slash: route table and the guard disagree on the normalized path.
  if (!path.endsWith("/")) out.push({ technique: "trailing-slash", method, path: path + "/", headers: {} });
  // Case swap on the last segment: case-sensitive guard, case-insensitive router.
  const segs = path.split("/");
  const last = segs[segs.length - 1];
  if (/[a-z]/.test(last) && last !== "{param}") {
    const alt = [...segs]; alt[alt.length - 1] = last.toUpperCase();
    out.push({ technique: "case-swap", method, path: alt.join("/"), headers: {} });
  }
  // Parameter pollution on the id of an object endpoint.
  if (path.includes("{param}")) out.push({ technique: "param-pollution", method, path: path.replace(/\{param\}/g, "1") + "?id=1&id=1", headers: {} });
  return out;
}

// Make a reconstructed path concrete for probing (unresolved {param} -> 1).
function concrete(p) {
  let out = p.replace(/\{param\}/g, "1");
  if (!/^https?:\/\//.test(out) && !out.startsWith("/")) out = "/" + out;
  return out;
}

/**
 * probeBypasses(base, gatedEndpoints, session, rawOpts)
 *  gatedEndpoints: [{method, path}] that are gated from THIS identity (from the diff)
 *  returns [{ original, technique, variant, status }] for each transform that reached (flip = bypass)
 * Keep ≤1 req/s on live targets; this fans several requests per gated endpoint.
 */
export async function probeBypasses(base, gatedEndpoints, session, rawOpts = {}) {
  const opts = buildGatingOpts(rawOpts);
  const headers = session.headers || {};
  const findings = [];
  let skippedUnsafe = 0;

  // Baseline: what a guaranteed-miss looks like on this host (a soft-404 / SPA app-shell commonly
  // 200s every path). A variant whose response matches this shell is NOT a real reach, so a bypass
  // is only reported when it looks DIFFERENT from a known miss.
  const baseline = [];
  for (const p of ["/aperta-bypass-control-0a1b2c", "/nope/" + Math.random().toString(36).slice(2) + "/x"]) {
    const r = await probe(base, "GET", p, headers, true);
    baseline.push({ status: r.status, len: (r.body || "").length });
  }
  const looksLikeShell = (r) => baseline.some((b) => b.status === r.status && Math.abs((r.body || "").length - b.len) <= 48);

  for (const ep of gatedEndpoints) {
    for (const v of bypassTransforms(ep.method, ep.path)) {
      // SAFETY: a verb-swap / method-override to a state-changing verb would send a live mutating
      // request. Skip those unless --unsafe (lab / authorized). Read-only transforms still run.
      if (STATE_CHANGING.has(v.method) && !opts.unsafe) { skippedUnsafe++; continue; }
      const cp = concrete(v.path);
      const r = await probe(base, v.method, cp, { ...headers, ...v.headers }, true);
      // a bypass is a real SUCCESS (2xx), not merely "not 401/403"; apply content/deny markers (body
      // now fetched) and reject anything that is just the app-shell/soft-404 baseline.
      const reached = r.status >= 200 && r.status < 300 &&
        !isGated(r.status, { location: r.location, body: r.body }, opts) && !looksLikeShell(r);
      if (reached) {
        findings.push({ original: `${ep.method} ${ep.path}`, technique: v.technique, variant: `${v.method} ${cp}`, status: r.status });
      }
    }
  }
  findings.skippedUnsafe = skippedUnsafe; // state-changing transforms not fired (unless --unsafe)
  return findings;
}

// --- self-test (offline: pure transforms) -----------------------------------------------
function selfTest() {
  let pass = 0, fail = 0;
  const check = (c, m) => (c ? pass++ : (fail++, console.error("FAIL:", m)));
  const T = (method, path) => bypassTransforms(method, path).map((t) => t.technique);

  const v = bypassTransforms("GET", "/api/v2/admin/users");
  check(v.some((t) => t.technique === "version-downgrade v2->v1" && t.path === "/api/v1/admin/users"), "v2 downgrades to v1");
  check(T("GET", "/api/orders").includes("verb-swap GET->POST"), "GET gets a POST verb-swap");
  check(T("GET", "/api/orders").some((t) => t.startsWith("method-override")), "method-override variant present");
  check(T("GET", "/api/orders").includes("trailing-slash"), "trailing-slash variant");
  check(bypassTransforms("GET", "/api/Orders").some((t) => t.technique === "case-swap" && t.path === "/api/ORDERS"), "case-swap uppercases last segment");
  check(bypassTransforms("GET", "/api/orders/{param}").some((t) => t.technique === "param-pollution" && t.path.includes("?id=1&id=1")), "param-pollution on object endpoint");
  check(!T("GET", "/api/v1/x").some((t) => t.startsWith("version-downgrade")), "v1 has no downgrade");
  check(bypassTransforms("GET", "/api/users/{param}").every((t) => t.path !== "/api/users/{PARAM}"), "case-swap skips a {param} segment");

  console.log(`bypass self-test: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

if (process.argv[1] && process.argv[1].endsWith("bypass.mjs") && process.argv.includes("--self-test")) selfTest();
