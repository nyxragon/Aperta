// Seed the surface from artifacts the hunter already has, so reconstruction quality does not depend
// on perfectly harvesting every minified chunk by hand:
//   - HAR / proxy export -> the API endpoints actually observed (merged into the reconstructed set)
//   - source map (.js.map) -> the ORIGINAL sources (sourcesContent), which reconstruct far better
//     than minified code (routes are not assembled from mangled variables there)
//   - asset-manifest / webpack manifest -> the full chunk URL list, so you know what is left to fetch
// Aperta still owns no recon: these parse artifacts you supply; fetching chunks stays your stage.
import { normalizePath, trafficEntries } from "./authz_probe.mjs";

// API endpoints observed in a HAR / proxy export, as [{method, path}] (normalized, deduped).
export function endpointsFromHar(har) {
  const seen = new Set();
  const out = [];
  for (const e of trafficEntries(har)) {
    let path;
    try { path = new URL(e.url).pathname; } catch { path = (e.url || "").split("?")[0]; }
    if (!/\/(api|graphql|v\d+|rest|rpc)(\/|$)/i.test(path)) continue; // API-like only
    const np = normalizePath(path);
    const key = `${e.method} ${np}`;
    if (!seen.has(key)) { seen.add(key); out.push({ method: e.method, path: np, file: "har" }); }
  }
  return out;
}

// A plain endpoint list -> [{method, path}]. One per line: "GET /api/orders/{param}" or "/api/x"
// (method defaults to GET). This is the hook an agent writes into after recovering the surface of an
// UNKNOWN framework any way it can (driving the app, a bespoke extractor), so the deterministic
// diff/prove stages still run. Blank lines and "#" comments are skipped.
export function endpointsFromList(text) {
  const seen = new Set();
  const out = [];
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = line.match(/^([A-Z]+)\s+(\/\S*)/) || line.match(/^(\/\S*)/);
    if (!m) continue;
    const method = m[2] ? m[1].toUpperCase() : "GET";
    const path = (m[2] || m[1]).split("?")[0];
    const key = `${method} ${path}`;
    if (!seen.has(key)) { seen.add(key); out.push({ method, path, file: "list" }); }
  }
  return out;
}

// Original sources carried inside a source map: [{path, content}].
export function sourcesFromSourceMap(mapJson) {
  const sources = mapJson?.sources || [];
  const contents = mapJson?.sourcesContent || [];
  const out = [];
  for (let i = 0; i < sources.length; i++) {
    const content = contents[i];
    if (typeof content === "string" && content.length) {
      out.push({ path: String(sources[i] || `source_${i}`).replace(/[^\w.\-/]/g, "_"), content });
    }
  }
  return out;
}

// JS chunk paths listed in an asset-manifest.json (CRA) or a webpack manifest, as string URLs.
export function chunksFromManifest(manifestJson) {
  const urls = new Set();
  const walk = (v) => {
    if (typeof v === "string") { if (/\.js(\?|$)/.test(v)) urls.add(v); return; }
    if (Array.isArray(v)) return v.forEach(walk);
    if (v && typeof v === "object") return Object.values(v).forEach(walk);
  };
  // CRA asset-manifest: { files:{...}, entrypoints:[...] }
  walk(manifestJson?.files ?? manifestJson);
  if (Array.isArray(manifestJson?.entrypoints)) manifestJson.entrypoints.forEach(walk);
  return [...urls];
}

// Union extra endpoints into a reconstructed model (dedup by METHOD+path).
export function mergeEndpoints(model, extra) {
  const have = new Set((model.endpoints || []).map((e) => `${e.method} ${e.path}`));
  const merged = [...(model.endpoints || [])];
  for (const e of extra) { const k = `${e.method} ${e.path}`; if (!have.has(k)) { have.add(k); merged.push(e); } }
  return { ...model, endpoints: merged.sort((a, b) => (a.path + a.method).localeCompare(b.path + b.method)) };
}

// --- self-test (offline) ----------------------------------------------------------------
function selfTest() {
  let pass = 0, fail = 0;
  const check = (c, m) => (c ? pass++ : (fail++, console.error("FAIL:", m)));

  const har = { log: { entries: [
    { request: { method: "GET", url: "https://app.x.com/api/orders/42" }, response: { status: 200 } },
    { request: { method: "POST", url: "https://app.x.com/api/orders" }, response: { status: 201 } },
    { request: { method: "GET", url: "https://app.x.com/static/logo.png" }, response: { status: 200 } }, // not API
  ] } };
  const eps = endpointsFromHar(har);
  check(eps.some((e) => e.method === "GET" && e.path === "/api/orders/{param}"), "HAR GET normalized to {param}");
  check(eps.some((e) => e.method === "POST" && e.path === "/api/orders"), "HAR POST endpoint");
  check(!eps.some((e) => e.path.includes("logo.png")), "non-API asset excluded");

  const map = { sources: ["webpack:///src/app.jsx", "webpack:///src/empty.js"], sourcesContent: ["const r=1;", ""] };
  const src = sourcesFromSourceMap(map);
  check(src.length === 1 && src[0].content === "const r=1;", "source map yields non-empty original sources");
  check(!/[:/]{2,}/.test(src[0].path.replace(/\//g, "")) && src[0].path.includes("app.jsx"), "source path sanitized");

  const manifest = { files: { "main.js": "/static/js/main.abc.js", "main.css": "/static/css/main.css" }, entrypoints: ["static/js/runtime.def.js"] };
  const chunks = chunksFromManifest(manifest);
  check(chunks.includes("/static/js/main.abc.js") && chunks.includes("static/js/runtime.def.js"), "manifest JS chunks listed");
  check(!chunks.some((c) => c.endsWith(".css")), "non-JS asset excluded from chunk list");

  const merged = mergeEndpoints({ endpoints: [{ method: "GET", path: "/api/me" }] }, eps);
  check(merged.endpoints.length === 3 && merged.endpoints.some((e) => e.path === "/api/me"), "merge unions HAR endpoints with reconstructed");

  const list = endpointsFromList("# agent-recovered surface\nGET /api/orders/{param}\nDELETE /api/orders/{param}\n/api/me/orders\n\n");
  check(list.length === 3, "endpoint list parsed (comment + blank skipped)");
  check(list.some((e) => e.method === "DELETE" && e.path === "/api/orders/{param}"), "explicit method parsed");
  check(list.some((e) => e.method === "GET" && e.path === "/api/me/orders"), "bare path defaults to GET");

  console.log(`ingest self-test: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

if (process.argv[1] && process.argv[1].endsWith("ingest.mjs") && process.argv.includes("--self-test")) selfTest();
