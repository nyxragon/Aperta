// Engine core, the runtime-authoritative, framework-agnostic privilege diff.
//
// Pure HTTP: given the reconstructed endpoints and a list of caller-supplied SESSIONS
// (each just auth headers, Aperta never logs in), probe each endpoint as each identity and
// read the AUTHORIZATION response. The hidden surface for a low-priv session = endpoints it is
// gated from (401/403) that a higher-priv session reaches. No browser, no framework coupling, // it works identically on React, Angular, Vue, anything, because it only speaks HTTP.
//
// RUNTIME-AUTHORITATIVE: frameworks like Angular assemble the API base URL at runtime
// (this.baseUrl / environment config), so the static reconstruct cannot know it and emits paths
// that begin with "{param}" (the unresolved runtime base). When a session carries observed
// `traffic` (a HAR / proxy export), Aperta (a) resolves the REAL base the app used at runtime and
// (b) trusts what the identity actually reached at runtime over a re-probe. That makes the diff
// runtime-vs-runtime per identity rather than static-vs-runtime.
//
// A session: { name, role?, headers: { Authorization?|Cookie?|... }, apiBase?, traffic? }
// (the caller builds these from their proxy history or direct input; see ARCHITECTURE.md).

const GATED = new Set([401, 403]);

// ---- gating model ----------------------------------------------------------------------
// By default an authorization DENY is a 401/403. But many apps (enterprise Java, ZOHO/AdventNet,
// most SPAs) never return those: they deny by REDIRECTING to a login page (302 -> /login) or by
// serving a soft 200 app-shell while the real auth check happens in a later AJAX call. Against
// those, a status-only model counts every endpoint as reachable for every identity and the diff
// silently produces zero signal. The caller can therefore extend the model:
//   gatedStatus   extra status codes that mean denied (e.g. add 302)
//   gatedRedirect a RegExp tested against a 3xx Location (match => denied)
//   denyMarker    a RegExp whose presence in the body means denied (e.g. j_security_check)
//   contentMarker a RegExp that MUST be present in a 2xx/3xx body for it to count as reached
export function buildGatingOpts(opts = {}) {
  const gatedStatus =
    opts.gatedStatus instanceof Set ? opts.gatedStatus : new Set(opts.gatedStatus || GATED);
  return {
    gatedStatus,
    gatedRedirect: opts.gatedRedirect || null,
    denyMarker: opts.denyMarker || null,
    contentMarker: opts.contentMarker || null,
  };
}

// Is this response an authorization DENY under the active gating model?
// `meta` carries { location, body } captured at probe time (empty for traffic-observed statuses).
export function isGated(status, meta, opts) {
  if (opts.gatedStatus.has(status)) return true;
  if (status >= 300 && status < 400 && opts.gatedRedirect && meta?.location && opts.gatedRedirect.test(meta.location)) return true;
  if (opts.denyMarker && meta?.body != null && opts.denyMarker.test(meta.body)) return true;
  if (opts.contentMarker && status >= 200 && status < 400 && meta?.body != null && !opts.contentMarker.test(meta.body)) return true;
  return false;
}
function isReachable(status, meta, opts) {
  return status !== 0 && !isGated(status, meta, opts);
}

// Detect the degenerate "no signal" diff and tell the caller WHY, instead of returning a silent
// empty result. The #1 real-world failure (observed on ManageEngine PMP): the default model sees
// no delta because gating is redirect- or content-based, and the user is left thinking the app is
// flat. Returns human-readable warning strings for the CLI/MCP to surface prominently.
export function computeWarnings(rows, sessions, perSession, opts) {
  const w = [];
  if (!rows.length || sessions.length < 2) return w;
  const anyHidden = sessions.some((s) => perSession[s.name].hidden.length > 0);
  const statusVector = (s) => rows.map((r) => r.status[s.name]).join(",");
  const identical = new Set(sessions.map(statusVector)).size === 1;
  let threexx = 0, nonzero = 0;
  for (const r of rows) for (const s of sessions) { const st = r.status[s.name]; if (st) { nonzero++; if (st >= 300 && st < 400) threexx++; } }
  const redirectShare = nonzero ? threexx / nonzero : 0;
  if (!anyHidden) {
    if (identical) {
      w.push("NO PRIVILEGE DELTA: every identity returned an identical response on every endpoint. If the app denies access by redirecting to login or by serving a soft 200 app-shell, the default 401/403 gating model cannot see it. Re-run with --gated-redirect '<login-path-regex>' and/or --content-marker '<authed-only-regex>'. Also confirm the sessions actually carry auth (HttpOnly cookies are easy to drop; build sessions with 'aperta session --cookie-jar' / '--from-har').");
    } else {
      w.push("No hidden surface for any identity, despite differing responses. If you expected a role delta, check session validity and the gating model (--gated-redirect / --content-marker / --gated-status).");
    }
  }
  if (redirectShare > 0.5 && !opts.gatedRedirect && !opts.gatedStatus.has(302)) {
    w.push(`${Math.round(redirectShare * 100)}% of probes returned a 3xx redirect, counted as REACHABLE by default. Deny-by-redirect (302 to /login) is common in enterprise apps; pass --gated-redirect '<regex>' or --gated-status 302 to treat those as gated.`);
  }
  return w;
}

// ---- traffic parsing (HAR / proxy export / plain array) --------------------------------
// Normalize whatever the caller captured into [{ method, url, status }].
export function trafficEntries(traffic) {
  if (!traffic) return [];
  if (Array.isArray(traffic)) {
    return traffic.map((e) => ({ method: (e.method || "GET").toUpperCase(), url: e.url, status: e.status || 0 }))
      .filter((e) => e.url);
  }
  if (traffic.log && Array.isArray(traffic.log.entries)) {
    return traffic.log.entries.map((e) => ({
      method: (e.request?.method || "GET").toUpperCase(),
      url: e.request?.url,
      status: e.response?.status || 0,
    })).filter((e) => e.url);
  }
  return [];
}

function pathnameOf(url) {
  try { return new URL(url).pathname; } catch { return url.startsWith("/") ? url.split("?")[0] : "/" + url.split("?")[0]; }
}

// Replace id-like path segments with {param} so an observed concrete URL matches a template.
export function normalizePath(pathname) {
  return pathname
    .split("/")
    .map((seg) =>
      /^\d+$/.test(seg) ||                                   // numeric id
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg) || // uuid
      /^[0-9a-f]{16,}$/i.test(seg)                           // long hex / token
        ? "{param}"
        : seg
    )
    .join("/");
}

// Resolve the API base the app actually used at runtime, from observed traffic.
// Returns { origin, basePath } or null. basePath is the longest common directory prefix of the
// API-looking requests (those under /api, /v1.., or a GraphQL endpoint), origin is their host.
export function resolveRuntimeApiBase(traffic) {
  const entries = trafficEntries(traffic);
  if (!entries.length) return null;
  const apiLike = entries.filter((e) => /\/(api|graphql|v\d+|rest|rpc)(\/|$)/i.test(pathnameOf(e.url)));
  const pool = apiLike.length ? apiLike : entries;
  // dominant origin
  const originCount = {};
  for (const e of pool) { try { const o = new URL(e.url).origin; originCount[o] = (originCount[o] || 0) + 1; } catch {} }
  const origin = Object.entries(originCount).sort((a, b) => b[1] - a[1])[0]?.[0] || null;
  const paths = pool
    .filter((e) => { try { return new URL(e.url).origin === origin; } catch { return true; } })
    .map((e) => pathnameOf(e.url).split("/"));
  if (!paths.length) return origin ? { origin, basePath: "" } : null;

  // The base is the mount prefix, anchored at the last API-marker segment (api|v\d+|graphql|...).
  // Using the marker (not the raw common prefix) means a SINGLE sample resolves correctly instead
  // of swallowing the endpoint tail into the base.
  const isMarker = (seg) => /^(api|graphql|v\d+|rest|rpc)$/i.test(seg);
  const baseOf = (segs) => {
    let markerIdx = -1;
    for (let i = 0; i < segs.length; i++) if (isMarker(segs[i])) markerIdx = i;
    return markerIdx >= 0 ? segs.slice(0, markerIdx + 1).join("/") : null;
  };
  const candidates = paths.map(baseOf).filter(Boolean);
  let basePath;
  if (candidates.length) {
    const freq = {};
    for (const c of candidates) freq[c] = (freq[c] || 0) + 1;
    basePath = Object.entries(freq).sort((a, b) => b[1] - a[1])[0][0];
  } else {
    // no marker: longest common directory prefix, minus the final (resource) segment
    const first = paths[0];
    const prefix = [];
    for (let i = 0; i < first.length - 1; i++) {
      const seg = first[i];
      if (normalizePath(seg) === "{param}") break;
      if (paths.every((p) => p[i] === seg)) prefix.push(seg); else break;
    }
    basePath = prefix.join("/");
  }
  return { origin, basePath: basePath.replace(/\/$/, "") };
}

// Observed reachability from traffic: Map "METHOD normalizedPath" -> best (non-gated preferred) status.
export function observedReach(traffic) {
  const map = new Map();
  for (const e of trafficEntries(traffic)) {
    const key = `${e.method} ${normalizePath(pathnameOf(e.url))}`;
    const prev = map.get(key);
    // prefer a non-gated, non-zero observation
    if (prev === undefined || (GATED.has(prev) && !GATED.has(e.status)) || (prev === 0 && e.status)) map.set(key, e.status);
  }
  return map;
}

// ---- probing ---------------------------------------------------------------------------
// Turn a reconstructed path into a concrete probe target. `base` may be a relative mount
// ("/api", "/api/v2") OR an absolute URL ("https://api.example.com/v2") when resolved from
// runtime traffic. A leading "{param}" is the runtime base placeholder -> replace with `base`.
function concretePath(path, base) {
  let p = path;
  if (p.startsWith("{param}")) p = base.replace(/\/$/, "") + p.slice("{param}".length);
  p = p.replace(/\{param\}/g, "1");
  if (!/^https?:\/\//.test(p) && !p.startsWith("/")) p = "/" + p;
  return p;
}

export async function probe(baseURL, method, pathOrUrl, headers, needBody = false) {
  const url = /^https?:\/\//.test(pathOrUrl) ? pathOrUrl : baseURL.replace(/\/$/, "") + pathOrUrl;
  try {
    const r = await fetch(url, {
      method,
      headers,
      redirect: "manual",
      ...(["POST", "PUT", "PATCH"].includes(method) ? { body: "{}" } : {}),
    });
    let body = null;
    if (needBody) { try { body = await r.text(); } catch {} }
    return { status: r.status, location: r.headers.get("location") || null, body };
  } catch {
    return { status: 0, location: null, body: null };
  }
}

/**
 * @param {string} baseURL  origin of the target
 * @param {Array}  endpoints  reconstructed endpoints [{method, path}]
 * @param {Array}  sessions   [{name, role?, headers, apiBase?, traffic?}]
 * @returns matrix + per-session { reachable, gated, hidden } (hidden = gated here, reached by another)
 */
export async function authzDiff(baseURL, endpoints, sessions, defaultApiBase = "/api", rawOpts = {}) {
  const opts = buildGatingOpts(rawOpts);
  const needBody = !!(opts.contentMarker || opts.denyMarker);
  // per-session: resolve runtime base + observed reachability once
  const ctx = {};
  for (const s of sessions) {
    const runtime = resolveRuntimeApiBase(s.traffic);
    const base =
      s.apiBase ||
      (runtime ? (runtime.origin && runtime.origin !== new URL(baseURL).origin ? runtime.origin + runtime.basePath : runtime.basePath || defaultApiBase) : defaultApiBase);
    ctx[s.name] = { base, observed: observedReach(s.traffic), source: {} };
  }

  const rows = [];
  for (const e of endpoints) {
    const row = { method: e.method, path: e.path, status: {}, meta: {}, source: {} };
    for (const s of sessions) {
      const c = ctx[s.name];
      const cp = concretePath(e.path, c.base);
      const obsKey = `${e.method} ${normalizePath(pathnameOf(cp))}`;
      if (c.observed.has(obsKey)) {
        // runtime-authoritative: the identity actually hit this at runtime, trust it
        row.status[s.name] = c.observed.get(obsKey);
        row.meta[s.name] = {};
        row.source[s.name] = "observed";
      } else {
        const r = await probe(baseURL, e.method, cp, s.headers || {}, needBody);
        row.status[s.name] = r.status;
        row.meta[s.name] = { location: r.location, body: r.body };
        row.source[s.name] = "probed";
      }
    }
    rows.push(row);
  }

  const perSession = {};
  for (const s of sessions) {
    const reachable = [], gated = [], hidden = [];
    for (const row of rows) {
      const mine = row.status[s.name];
      const mineGated = isGated(mine, row.meta[s.name], opts);
      const reachedByOther = sessions.some((o) => o.name !== s.name && isReachable(row.status[o.name], row.meta[o.name], opts));
      const label = `${row.method} ${row.path}`;
      if (mineGated) {
        gated.push(label);
        if (reachedByOther) hidden.push(label); // the money: gated from me, reachable by a higher role
      } else if (mine !== 0) {
        reachable.push(label);
      }
    }
    perSession[s.name] = { role: s.role, base: ctx[s.name].base, reachable, gated, hidden };
  }
  const warnings = computeWarnings(rows, sessions, perSession, opts);
  return { matrix: rows, perSession, warnings };
}

// JSONL emitter for the hidden surface (pipe-friendly, anew-diffable).
export function hiddenToJSONL(diff, sessionName) {
  const p = diff.perSession[sessionName];
  return (p?.hidden || []).map((h) => JSON.stringify({ session: sessionName, hidden: h })).join("\n");
}

// ---- self-test (offline: no network) ---------------------------------------------------
function selfTest() {
  let pass = 0, fail = 0;
  const check = (cond, msg) => (cond ? pass++ : (fail++, console.error("FAIL:", msg)));

  // normalizePath collapses ids
  check(normalizePath("/api/orders/2001") === "/api/orders/{param}", "numeric id -> {param}");
  check(normalizePath("/api/users/3f2504e0-4f89-41d3-9a0c-0305e82c3301") === "/api/users/{param}", "uuid -> {param}");

  // Angular case: runtime base is an ABSOLUTE host different from the SPA origin
  const har = { log: { entries: [
    { request: { method: "GET", url: "https://api.acme.io/v2/me/orders" }, response: { status: 200 } },
    { request: { method: "GET", url: "https://api.acme.io/v2/orders/2001" }, response: { status: 200 } },
  ] } };
  const rb = resolveRuntimeApiBase(har);
  check(rb && rb.origin === "https://api.acme.io", "resolved runtime origin from traffic");
  check(rb && rb.basePath === "/v2", "resolved runtime basePath from traffic (common prefix)");

  // observed reachability keys normalize ids
  const obs = observedReach(har);
  check(obs.get("GET /v2/orders/{param}") === 200, "observed reachability keyed by normalized path");

  // concretePath substitutes a leading {param} runtime base (absolute) and produces an absolute URL
  const cp = concretePath("{param}/orders/{param}", "https://api.acme.io/v2");
  check(cp === "https://api.acme.io/v2/orders/1", "concretePath resolves absolute runtime base");

  // gating model: default is 401/403 only; a 302 is NOT gated by default
  const def = buildGatingOpts();
  check(isGated(403, {}, def) === true, "default: 403 is gated");
  check(isGated(302, { location: "/login" }, def) === false, "default: 302 is NOT gated");
  // --gated-status 302 extends the set
  check(isGated(302, {}, buildGatingOpts({ gatedStatus: new Set([401, 403, 302]) })) === true, "gatedStatus: 302 added -> gated");
  // --gated-redirect classifies a 3xx-to-login as gated, but leaves a 3xx elsewhere reachable
  const gr = buildGatingOpts({ gatedRedirect: /\/(login|signin)(\?|$|\/)/ });
  check(isGated(302, { location: "/login?from=/admin" }, gr) === true, "gatedRedirect: 302 -> /login is gated");
  check(isGated(302, { location: "/dashboard" }, gr) === false, "gatedRedirect: 302 -> /dashboard not gated");
  // --deny-marker / --content-marker on soft-200 bodies
  const dm = buildGatingOpts({ denyMarker: /j_security_check|ACCESS DENIED/ });
  check(isGated(200, { body: "<form action=j_security_check>" }, dm) === true, "denyMarker: soft-200 login shell is gated");
  const cm = buildGatingOpts({ contentMarker: /"orders"\s*:/ });
  check(isGated(200, { body: '{"shell":true}' }, cm) === true, "contentMarker absent in 200 -> gated");
  check(isGated(200, { body: '{"orders":[]}' }, cm) === false, "contentMarker present in 200 -> reachable");

  // computeWarnings: identical-across-identities => NO PRIVILEGE DELTA warning
  const flatRows = [
    { method: "GET", path: "/a", status: { alice: 302, admin: 302 }, meta: { alice: {}, admin: {} } },
    { method: "GET", path: "/b", status: { alice: 302, admin: 302 }, meta: { alice: {}, admin: {} } },
  ];
  const flatPer = { alice: { hidden: [] }, admin: { hidden: [] } };
  const flatWarn = computeWarnings(flatRows, [{ name: "alice" }, { name: "admin" }], flatPer, def);
  check(flatWarn.some((x) => x.includes("NO PRIVILEGE DELTA")), "warning: identical responses -> no-delta");
  check(flatWarn.some((x) => x.includes("3xx redirect")), "warning: redirect-dominant -> suggest --gated-redirect");
  // a healthy diff (alice has hidden surface) emits no no-delta warning
  const okPer = { alice: { hidden: ["GET /admin"] }, admin: { hidden: [] } };
  const okRows = [{ method: "GET", path: "/admin", status: { alice: 403, admin: 200 }, meta: { alice: {}, admin: {} } }];
  check(computeWarnings(okRows, [{ name: "alice" }, { name: "admin" }], okPer, def).length === 0, "no warning when a delta exists");

  // runtime-authoritative diff with NO network: both endpoints observed for 'alice' (user) and
  // one of them NOT observed/gated so 'admin' reaches it -> hidden surface falls out from traffic.
  const endpoints = [
    { method: "GET", path: "{param}/orders/{param}" },
    { method: "GET", path: "{param}/admin/users" },
  ];
  const sessions = [
    { name: "alice", role: "user", headers: {}, traffic: har },     // saw orders, never admin
    { name: "admin", role: "admin", headers: {}, traffic: { log: { entries: [
      { request: { method: "GET", url: "https://api.acme.io/v2/admin/users" }, response: { status: 200 } },
    ] } } },
  ];
  authzDiff("https://app.acme.io", endpoints, sessions).then((diff) => {
    const a = diff.perSession.alice;
    check(a.reachable.includes("GET {param}/orders/{param}"), "alice reachable from observed traffic (no probe)");
    check(a.base === "https://api.acme.io/v2", "alice base resolved to runtime absolute host");
    // alice never observed admin/users and (offline) probe returns 0, admin observed 200 ->
    // alice's admin endpoint is status 0 (not gated), so it is NOT counted hidden here (honest:
    // offline we cannot probe; with a live base a 403 would make it hidden). Assert admin reached it:
    check(diff.perSession.admin.reachable.includes("GET {param}/admin/users"), "admin reachable for admin/users from traffic");
    console.log(`authz_probe self-test: ${pass} passed, ${fail} failed`);
    process.exit(fail ? 1 : 0);
  });
}

if (process.argv[1] && process.argv[1].endsWith("authz_probe.mjs") && process.argv.includes("--self-test")) selfTest();
