// Live-verify reconstructed endpoints: a reconstructed path is a CLAIM from the JS until the live
// app confirms it resolves. An opt-in HEAD (GET fallback) per endpoint upgrades "I parsed this from
// the bundle" to "this endpoint exists" before any authz claim is made on it, and filters out dead
// routes left in the bundle. Unauthenticated by default; pass a session to verify behind auth. This
// never logs in and never changes state (HEAD/GET only). Keep <=1 req/s on live targets.
import { probe } from "./authz_probe.mjs";

// Classify an endpoint's existence from its probed status.
export function classifyExistence(status) {
  if (status === 0) return "unknown";          // network error / unreachable
  if (status === 404 || status === 410) return "missing"; // not found / gone
  return "exists";                              // 2xx/3xx/401/403/405... the route resolves to a handler
}

function concrete(path) {
  let p = path.replace(/\{param\}/g, "1");
  if (!/^https?:\/\//.test(p) && !p.startsWith("/")) p = "/" + p;
  return p;
}

/**
 * verifyEndpoints(base, endpoints, headers, opts) -> [{method, path, status, exists}]
 * HEAD first; on a method-not-allowed / not-implemented / 404-to-HEAD, fall back to the real method.
 */
export async function verifyEndpoints(base, endpoints, headers = {}, opts = {}) {
  const out = [];
  for (const e of endpoints) {
    const cp = concrete(e.path);
    let r = await probe(base, "HEAD", cp, headers, false);
    if ([404, 405, 501, 0].includes(r.status)) {
      const r2 = await probe(base, e.method || "GET", cp, headers, false);
      // keep the more informative (a real GET 200/401/403 beats a HEAD 404/405)
      if (classifyExistence(r2.status) !== "missing" || r.status === 0) r = r2;
    }
    out.push({ method: e.method, path: e.path, status: r.status, exists: classifyExistence(r.status) });
  }
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

  const line = verifyLine([{ exists: "exists" }, { exists: "exists" }, { exists: "missing" }, { exists: "unknown" }]);
  check(line.includes("2 exist") && line.includes("1 missing") && line.includes("1 unknown"), "verify summary line");

  console.log(`verify self-test: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

if (process.argv[1] && process.argv[1].endsWith("verify.mjs") && process.argv.includes("--self-test")) selfTest();
