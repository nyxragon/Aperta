// Live-verify reconstructed endpoints: a reconstructed path is a CLAIM from the JS until the live
// app confirms it resolves. An opt-in HEAD (GET fallback) per endpoint upgrades "I parsed this from
// the bundle" to "this endpoint exists" before any authz claim is made on it, and filters out dead
// routes left in the bundle. Unauthenticated by default; pass a session to verify behind auth. This
// never logs in and never changes state: it probes with HEAD then GET only, never the reconstructed
// write verb, so a DELETE/PUT/POST endpoint is existence-checked read-only. Keep <=1 req/s on targets.
import { probe } from "./authz_probe.mjs";

// Classify an endpoint's existence from its probed status.
export function classifyExistence(status) {
  if (status === 0) return "unknown";          // network error / unreachable
  if (status === 404 || status === 410) return "missing"; // not found / gone
  if (status >= 500) return "unknown";          // server erroring on everything is not evidence of a route
  return "exists";                              // 2xx/3xx/401/403/405... the route resolves to a handler
}

function concrete(path) {
  let p = path.replace(/\{param\}/g, "1");
  if (!/^https?:\/\//.test(p) && !p.startsWith("/")) p = "/" + p;
  return p;
}

// Probe 2-3 known-nonexistent paths. If they "exist", the host is a catch-all (SPA shell / soft-404),
// so a plain "exists" is meaningless and must not be read as a live endpoint.
async function detectCatchAll(base, headers) {
  const probes = ["/aperta-nonexistent-0a1b2c3d", "/this/path/does/not/exist-9z8y7x", "/__aperta_control__/x"];
  let hits = 0;
  for (const p of probes) {
    let r = await probe(base, "HEAD", p, headers, false);
    if ([404, 405, 501, 0].includes(r.status)) r = await probe(base, "GET", p, headers, false);
    if (classifyExistence(r.status) === "exists") hits++;
  }
  return hits >= 2; // majority of guaranteed-404 controls "exist" => catch-all
}

/**
 * verifyEndpoints(base, endpoints, headers, opts) -> [{method, path, status, exists}] (+ .catchAll)
 * HEAD first; on a method-not-allowed / not-implemented / 404-to-HEAD, fall back to GET (never the
 * reconstructed write verb). If the host is a catch-all, every "exists" is downgraded to "unknown".
 */
export async function verifyEndpoints(base, endpoints, headers = {}, opts = {}) {
  const catchAll = await detectCatchAll(base, headers);
  const out = [];
  for (const e of endpoints) {
    const cp = concrete(e.path);
    let r = await probe(base, "HEAD", cp, headers, false);
    if ([404, 405, 501, 0].includes(r.status)) {
      // SAFETY: fall back to GET only, never the reconstructed state-changing verb.
      const r2 = await probe(base, "GET", cp, headers, false);
      if (classifyExistence(r2.status) !== "missing" || r.status === 0) r = r2;
    }
    let exists = classifyExistence(r.status);
    if (catchAll && exists === "exists") exists = "unknown"; // host answers everything; not real evidence
    out.push({ method: e.method, path: e.path, status: r.status, exists });
  }
  out.catchAll = catchAll;
  return out;
}

export function verifyLine(results) {
  const n = (k) => results.filter((r) => r.exists === k).length;
  return `verified ${results.length} endpoint(s): ${n("exists")} exist, ${n("missing")} missing, ${n("unknown")} unknown`;
}

// --- self-test (offline) ----------------------------------------------------------------
function selfTest() {
  let pass = 0, fail = 0;
  const check = (c, m) => (c ? pass++ : (fail++, console.error("FAIL:", m)));

  check(classifyExistence(200) === "exists", "200 exists");
  check(classifyExistence(403) === "exists", "403 means the route resolves (gated, but exists)");
  check(classifyExistence(302) === "exists", "302 exists");
  check(classifyExistence(404) === "missing", "404 missing");
  check(classifyExistence(410) === "missing", "410 gone");
  check(classifyExistence(0) === "unknown", "0 unknown");
  check(classifyExistence(500) === "unknown", "500 is not evidence of a route (unknown)");
  check(classifyExistence(503) === "unknown", "503 unknown");

  const line = verifyLine([{ exists: "exists" }, { exists: "exists" }, { exists: "missing" }, { exists: "unknown" }]);
  check(line.includes("2 exist") && line.includes("1 missing") && line.includes("1 unknown"), "verify summary line");

  console.log(`verify self-test: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

if (process.argv[1] && process.argv[1].endsWith("verify.mjs") && process.argv.includes("--self-test")) selfTest();
