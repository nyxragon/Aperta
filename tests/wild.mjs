// Real-world generalization test: fetch public JS from real SPAs, reconstruct, measure success.
// Read-only GETs of public static assets only (no APIs/auth/state). Measures (1) can we access the
// bundles, (2) does reconstruction recover a surface (framework + routes/endpoints/graphql ops).
import { mkdirSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { reconstruct, fingerprint } from "../src/reconstruct.mjs";
import { discoverOracles } from "../src/oracle_discovery.mjs";

const OUT = "/tmp/aperta-wild";
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36";
const MAX_JS = 40, MAX_BYTES = 60_000_000;

// Diverse real SPAs whose login/app-shell bundles are served publicly.
const SITES = process.argv.slice(2).length ? process.argv.slice(2) : [
  "https://linear.app", "https://vercel.com", "https://app.netlify.com", "https://notion.so",
  "https://trello.com", "https://airtable.com", "https://app.asana.com", "https://calendly.com",
  "https://miro.com", "https://canva.com", "https://posthog.com", "https://supabase.com",
  "https://railway.app", "https://render.com", "https://retool.com", "https://gitpod.io",
  "https://replit.com", "https://codesandbox.io", "https://stackblitz.com", "https://sentry.io",
  "https://grafana.com", "https://gitlab.com", "https://about.sourcegraph.com", "https://sourcegraph.com",
  "https://circleci.com", "https://app.clickup.com", "https://monday.com", "https://typeform.com",
  "https://webflow.com", "https://framer.com", "https://loom.com", "https://discord.com",
  "https://www.shuffler.io", "https://app.harness.io", "https://cloud.mongodb.com", "https://auth0.com",
  "https://okta.com", "https://1password.com", "https://dashboard.stripe.com", "https://buffer.com",
];

async function get(url, timeout = 15000) {
  const ctl = AbortSignal.timeout(timeout);
  const r = await fetch(url, { headers: { "User-Agent": UA }, redirect: "follow", signal: ctl });
  return r;
}

function jsUrlsFrom(html, baseUrl) {
  const urls = new Set();
  const base = new URL(baseUrl);
  for (const m of html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) {
    try { urls.add(new URL(m[1], base).href); } catch {}
  }
  // modulepreload / link rel for chunk hints
  for (const m of html.matchAll(/<link[^>]+href=["']([^"']+\.js)["']/gi)) {
    try { urls.add(new URL(m[1], base).href); } catch {}
  }
  return [...urls];
}

function chunkUrlsFrom(code, baseUrl) {
  const urls = new Set();
  const base = new URL(baseUrl);
  for (const m of code.matchAll(/["'`]([^"'`]*\/(?:assets|static|_next\/static|js)\/[^"'`]+\.js)["'`]/g)) {
    try { urls.add(new URL(m[1], base).href); } catch {}
  }
  return [...urls].slice(0, 30);
}

async function harvest(site) {
  const host = new URL(site).hostname.replace(/[^\w.-]/g, "_");
  const dir = join(OUT, host);
  mkdirSync(dir, { recursive: true });
  let htmlStatus = 0, bytes = 0, n = 0;
  const seen = new Set();
  try {
    const r = await get(site);
    htmlStatus = r.status;
    if (!r.ok) return { host, htmlStatus, dir, jsFiles: 0 };
    const html = await r.text();
    let queue = jsUrlsFrom(html, r.url);
    let depth1 = true;
    while (queue.length && n < MAX_JS && bytes < MAX_BYTES) {
      const u = queue.shift();
      if (seen.has(u)) continue; seen.add(u);
      try {
        const jr = await get(u, 20000);
        if (!jr.ok) continue;
        const code = await jr.text();
        if (!code.includes("function") && !code.includes("=>")) continue;
        bytes += code.length;
        writeFileSync(join(dir, `f${n}.js`), code);
        n++;
        // discover chunk URLs from EVERY file (the router/API chunk is usually lazy-loaded)
        for (const cu of chunkUrlsFrom(code, u)) if (!seen.has(cu) && queue.length < 200) queue.push(cu);
      } catch {}
    }
  } catch (e) {
    return { host, htmlStatus: htmlStatus || 0, dir, jsFiles: 0, err: String(e).slice(0, 30) };
  }
  return { host, htmlStatus, dir, jsFiles: n };
}

const pad = (s, n) => String(s).slice(0, n).padEnd(n);
console.log(pad("host", 26), pad("http", 5), pad("js", 4), pad("fw", 10), pad("routes", 7), pad("eps", 5), pad("gql", 5), pad("obj", 4), pad("orc", 4), "ok");
console.log("-".repeat(90));

let accessed = 0, success = 0, total = 0;
let objTotal = 0, orcTotal = 0, sitesWithObjects = 0, sitesWithOracle = 0;
for (const site of SITES) {
  total++;
  const h = await harvest(site);
  let fw = "-", routes = 0, eps = 0, ops = 0, obj = 0, orc = 0, ok = "";
  if (h.jsFiles > 0) {
    accessed++;
    try {
      fw = fingerprint(h.dir).framework;
      const m = reconstruct(h.dir);
      routes = m.routes.length;
      eps = m.endpoints.length; ops = m.operations.length;
      if (routes > 0 || eps > 0 || ops > 0) { success++; ok = "YES"; }
      // oracle applicability: object endpoints that have a self-scoped sibling list endpoint
      const d = discoverOracles(m);
      obj = d.applicability.objectEndpoints; orc = d.applicability.withOracle;
      objTotal += obj; orcTotal += orc;
      if (obj > 0) sitesWithObjects++;
      if (orc > 0) sitesWithOracle++;
    } catch (e) { ok = "ERR"; }
  } else ok = h.htmlStatus >= 400 || h.htmlStatus === 0 ? "no-access" : "no-js";
  console.log(pad(h.host, 26), pad(h.htmlStatus, 5), pad(h.jsFiles, 4), pad(fw, 10), pad(routes, 7), pad(eps, 5), pad(ops, 5), pad(obj, 4), pad(orc, 4), ok);
  await new Promise((r) => setTimeout(r, 600)); // polite inter-site pause
}
console.log("-".repeat(90));
console.log(`accessed ${accessed}/${total} (${Math.round(100 * accessed / total)}%) · reconstruction-success ${success}/${total} (${Math.round(100 * success / total)}%) · of-accessed ${success}/${accessed} (${accessed ? Math.round(100 * success / accessed) : 0}%)`);
console.log(`ORACLE APPLICABILITY: ${orcTotal}/${objTotal} object endpoints have a self-scoped sibling (${objTotal ? Math.round(100 * orcTotal / objTotal) : 0}%) · ${sitesWithOracle}/${sitesWithObjects} sites with object endpoints have at least one usable oracle`);
