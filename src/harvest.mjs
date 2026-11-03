// Optional convenience: fetch the JS a page itself declares, so `reconstruct` has something to chew
// on without a separate crawler for the common case. This is NOT a crawler or a scanner and does not
// replace katana/getJS/a headless harvester (the thorough path for lazy/dynamic chunks) - it just
// follows what the app already points at: <script src>, <link rel=modulepreload/preload as=script>,
// and one level of same-origin chunk references found inside those bundles. Pure HTTP, no headless,
// no deps, same-origin only, bounded and polite.

import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";

// Script URLs a page declares, resolved against the page URL. Pure (HTML in -> absolute URLs out).
export function extractScriptUrls(html, baseUrl) {
  const urls = new Set();
  const add = (u) => { try { urls.add(new URL(u, baseUrl).href); } catch {} };
  for (const m of String(html).matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["']/gi)) add(m[1]);
  for (const m of String(html).matchAll(/<link\b[^>]*>/gi)) {
    const tag = m[0];
    if (/\brel=["'](?:modulepreload|preload)["']/i.test(tag) && (/\bas=["']script["']/i.test(tag) || /modulepreload/i.test(tag))) {
      const h = tag.match(/\bhref=["']([^"']+)["']/i);
      if (h) add(h[1]);
    }
  }
  return [...urls];
}

// Same-origin chunk references inside a bundle (one expansion level): string literals that look like
// a built JS chunk path. Conservative - only paths under a typical static/asset dir or with a hash,
// to avoid turning arbitrary strings into fetches.
export function extractChunkRefs(code, baseUrl) {
  const out = new Set();
  const add = (u) => { try { out.add(new URL(u, baseUrl).href); } catch {} };
  for (const m of String(code).matchAll(/["'`](\/?(?:[\w./-]*?(?:static|assets|_next|chunks|build)\/)[\w./-]*?\.m?js)["'`]/gi)) add(m[1]);
  for (const m of String(code).matchAll(/["'`]([\w./-]+\.[0-9a-f]{6,}\.(?:chunk\.)?m?js)["'`]/gi)) add(m[1]);
  // Vite/Rollup code-split chunk: a relative or bare `Name-<base64url hash>.js` (hash is not lowercase
  // hex). Resolve it against the BUNDLE's own URL (baseUrl), so `./Admin-Bt2N-p1k.js` next to
  // /assets/index-x.js becomes /assets/Admin-Bt2N-p1k.js, not /Admin-...js off the page root.
  for (const m of String(code).matchAll(/["'`](\.{0,2}\/[\w./-]*?[\w]+[-.][A-Za-z0-9_-]{6,}\.m?js)["'`]/g)) add(m[1]);
  return [...out];
}

async function get(url, headers) {
  try {
    const r = await fetch(url, { headers, redirect: "follow" });
    if (r.status < 200 || r.status >= 300) return { ok: false, status: r.status, body: "" };
    const ct = r.headers.get("content-type") || "";
    const body = await r.text();
    return { ok: true, status: r.status, body, ct };
  } catch { return { ok: false, status: 0, body: "" }; }
}

/**
 * harvest(pageUrl, { outDir, max=60, headers }) -> { dir, fetched:[{url,bytes}], bytes, pages }
 * Fetches the page, the JS it declares, and one level of same-origin chunk refs, into outDir.
 */
export async function harvest(pageUrl, { outDir, max = 60, headers = {} } = {}) {
  const origin = new URL(pageUrl).origin;
  mkdirSync(outDir, { recursive: true });
  const page = await get(pageUrl, headers);
  if (!page.ok) throw new Error(`could not fetch the page (${page.status}) - is it reachable / in scope / behind auth (pass --session)?`);

  const seen = new Set(); const fetched = []; let seq = 0;
  const sameOrigin = (u) => { try { return new URL(u).origin === origin; } catch { return false; } };
  const save = (code) => { const name = `b${seq++}.js`; writeFileSync(join(outDir, name), code); return name; };

  // level 0: scripts the page declares
  let queue = extractScriptUrls(page.body, pageUrl).filter(sameOrigin);
  const expand = [];
  for (const u of queue) {
    if (seen.has(u) || fetched.length >= max) continue; seen.add(u);
    const r = await get(u, headers);
    if (r.ok && /javascript|ecmascript|^$|text\/plain/i.test(r.ct || "") && r.body) { save(r.body); fetched.push({ url: u, bytes: r.body.length }); expand.push({ url: u, body: r.body }); }
  }
  // level 1: same-origin chunk refs found inside those bundles, resolved against EACH bundle's own URL
  // (so a relative `./chunk.js` lands in the bundle's dir, e.g. /assets/, not the page root).
  const refs = new Set();
  for (const { url, body } of expand) for (const u of extractChunkRefs(body, url)) if (sameOrigin(u)) refs.add(u);
  for (const u of refs) {
    if (seen.has(u) || fetched.length >= max) continue; seen.add(u);
    const r = await get(u, headers);
    if (r.ok && r.body) { save(r.body); fetched.push({ url: u, bytes: r.body.length }); }
  }
  const bytes = fetched.reduce((s, f) => s + f.bytes, 0);
  return { dir: outDir, fetched, bytes };
}

// --- self-test (offline: the pure extractors) -------------------------------------------
function selfTest() {
  let pass = 0, fail = 0;
  const check = (c, m) => (c ? pass++ : (fail++, console.error("FAIL:", m)));
  const base = "https://app.example.com/dashboard";

  const html = `<!doctype html><html><head>
    <link rel="modulepreload" href="/assets/index-abc.js">
    <link rel="preload" as="script" href="/assets/vendor-def.js">
    <link rel="stylesheet" href="/assets/x.css">
    <script src="/static/js/main.123.js"></script>
    <script src="https://cdn.other.com/thirdparty.js"></script>
    </head></html>`;
  const s = extractScriptUrls(html, base);
  check(s.includes("https://app.example.com/assets/index-abc.js"), "modulepreload href extracted + resolved");
  check(s.includes("https://app.example.com/assets/vendor-def.js"), "preload-as-script extracted");
  check(s.includes("https://app.example.com/static/js/main.123.js"), "script src extracted");
  check(s.includes("https://cdn.other.com/thirdparty.js"), "cross-origin script captured (origin filter is the fetch step's job)");
  check(!s.some((u) => u.endsWith(".css")), "stylesheet not treated as a script");

  const code = `a("/static/js/42.9f8e7d6c.chunk.js");b('/_next/static/chunks/pages/app.js');c("/assets/lazy-aa11bb22.js");notachunk("/api/orders")`;
  const refs = extractChunkRefs(code, base);
  check(refs.includes("https://app.example.com/static/js/42.9f8e7d6c.chunk.js"), "webpack chunk ref extracted");
  check(refs.includes("https://app.example.com/_next/static/chunks/pages/app.js"), "next chunk ref extracted");
  check(!refs.some((u) => u.includes("/api/orders")), "a non-chunk string is not harvested as a chunk");

  // Vite/Rollup: a relative `./Name-<base64url hash>.js` resolves against the BUNDLE's dir, not the page
  const vite = extractChunkRefs(`__vitePreload(()=>import("./Admin-Bt2N-p1k.js"),x);u("./util.js")`, "https://app.example.com/assets/index-CNec0UgK.js");
  check(vite.includes("https://app.example.com/assets/Admin-Bt2N-p1k.js"), "vite code-split chunk resolved into the bundle's /assets dir");
  check(!vite.some((u) => u.endsWith("/util.js")), "a plain relative import without a hash is not harvested (noise control)");

  console.log(`harvest self-test: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

if (process.argv[1] && process.argv[1].endsWith("harvest.mjs") && process.argv.includes("--self-test")) selfTest();
