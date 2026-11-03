// Build an Aperta session JSON from a real login, without the usual footgun.
//
// A session is just { name, role?, headers:{Cookie|Authorization|...}, apiBase?, traffic? }, the
// caller supplies auth, Aperta never logs in. Hand-building that from a curl/browser export is
// error-prone in exactly one way that silently ruins the diff: the Netscape cookie jar writes
// HttpOnly cookies as `#HttpOnly_<domain>\t...` lines, so a naive `grep -v '^#'` DROPS the session
// cookie and you get an unauthenticated session that looks fine and produces a meaningless diff
// (observed live on ManageEngine PMP). This module parses the jar correctly, HttpOnly included.

// Parse a Netscape/Mozilla cookie jar (curl -c / browser export). Returns [{domain,path,secure,
// expiry,name,value,httpOnly}]. Real comment lines are skipped; `#HttpOnly_` lines are NOT.
export function parseNetscapeJar(text) {
  const cookies = [];
  for (const raw of String(text).split(/\r?\n/)) {
    let line = raw;
    if (!line.trim()) continue;
    const httpOnly = line.startsWith("#HttpOnly_");
    if (line.startsWith("#") && !httpOnly) continue; // genuine comment
    if (httpOnly) line = line.slice("#HttpOnly_".length);
    const f = line.split("\t");
    if (f.length < 7) continue;
    const [domain, , path, secure, expiry, name, value] = f;
    cookies.push({
      domain, path,
      secure: secure === "TRUE",
      expiry: Number(expiry) || 0,
      name, value, httpOnly,
    });
  }
  return cookies;
}

// A host matches a jar domain if it equals it or is a subdomain of it (leading dot optional).
function hostMatchesDomain(host, domain) {
  const d = domain.replace(/^\./, "").toLowerCase();
  const h = host.toLowerCase();
  return h === d || h.endsWith("." + d);
}

// Collapse parsed cookies into a single Cookie header value. If `host` is given, only cookies
// scoped to it are included; otherwise all are sent. Last value for a name wins. Values are stripped
// of `;`/CR/LF so a crafted jar value cannot inject an extra cookie into the header.
const cookieSafe = (s) => String(s).replace(/[;\r\n]/g, "");
export function cookieHeader(cookies, { host } = {}) {
  const scoped = host ? cookies.filter((c) => hostMatchesDomain(host, c.domain)) : cookies;
  const byName = new Map();
  for (const c of scoped) byName.set(cookieSafe(c.name), cookieSafe(c.value));
  return [...byName].map(([n, v]) => `${n}=${v}`).join("; ");
}

// Auth / CSRF request headers Aperta should carry on a session (so a token-auth app is not left
// silently unauthenticated when its auth lives in a header rather than a cookie).
const AUTH_HEADER_RE = /^(authorization|x-csrf-token|x-xsrf-token|x-csrftoken|x-auth-token|x-access-token|x-api-key|api-key|x-session-token|cookie)$/i;
export function authHeadersFromHar(har) {
  const entries = har?.log?.entries || (Array.isArray(har) ? har : []);
  const out = {};
  for (const e of entries) {
    const hit = {};
    for (const h of e.request?.headers || []) {
      const n = (h.name || "").toLowerCase();
      if (n === "cookie") continue; // cookies handled separately
      if (AUTH_HEADER_RE.test(n) && h.value && !(h.name in out)) hit[h.name] = h.value;
    }
    Object.assign(out, hit);
    if (Object.keys(out).length) break; // first request that carries auth wins
  }
  return out;
}

// Pull the Cookie header the browser actually sent from a HAR (fallback when no jar is supplied).
export function cookieFromHar(har) {
  const entries = har?.log?.entries || (Array.isArray(har) ? har : []);
  for (const e of entries) {
    const hdrs = e.request?.headers || [];
    const ck = hdrs.find((h) => (h.name || "").toLowerCase() === "cookie");
    if (ck?.value) return ck.value;
    // some HARs model cookies as a structured array
    if (Array.isArray(e.request?.cookies) && e.request.cookies.length) {
      return e.request.cookies.map((c) => `${c.name}=${c.value}`).join("; ");
    }
  }
  return "";
}

// Request headers that are browser noise, not auth/identity: dropped from a copy-as-cURL import so
// the session carries only what identifies the caller.
const CURL_NOISE_HEADER = /^(accept|accept-encoding|accept-language|user-agent|sec-[a-z-]+|connection|referer|origin|cache-control|pragma|upgrade-insecure-requests|dnt|te|host|content-length|priority|if-none-match|if-modified-since)$/i;

// Tokenize a shell command honoring single/double quotes and backslash line-continuations. Good enough
// for a browser "Copy as cURL" string; not a full shell.
function shellTokens(s) {
  const out = []; let cur = "", q = null, started = false;
  const src = String(s).replace(/\\\r?\n/g, " ");
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (q) { if (c === q) q = null; else cur += c; continue; }
    if (c === "'" || c === '"') { q = c; started = true; continue; }
    if (c === "\\" && i + 1 < src.length) { cur += src[++i]; started = true; continue; }
    if (/\s/.test(c)) { if (started) { out.push(cur); cur = ""; started = false; } continue; }
    cur += c; started = true;
  }
  if (started) out.push(cur);
  return out;
}

// Build a session from a browser/devtools "Copy as cURL" command. The single highest-friction step in
// using Aperta is producing the session JSON by hand; a hunter already has the cURL on their clipboard.
// Keeps the URL's origin for apiBase hinting, the Cookie, and every auth/identity header; drops noise.
export function sessionFromCurl(curlText, { name, role } = {}) {
  if (!name) throw new Error("session needs a --name");
  // flags that CONSUME the next token (so it is not mistaken for the URL)
  const TAKES_ARG = new Set(["-X", "--request", "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
    "-A", "--user-agent", "-e", "--referer", "-u", "--user", "--connect-to", "--resolve", "-m", "--max-time",
    "--retry", "-o", "--output", "-w", "--write-out", "-c", "--cookie-jar", "--proxy", "-x"]);
  const toks = shellTokens(curlText);
  const headers = {}; let url = null;
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t === "-H" || t === "--header") {
      const h = toks[++i] || ""; const idx = h.indexOf(":");
      if (idx > 0) { const n = h.slice(0, idx).trim(); const v = h.slice(idx + 1).trim(); if (n && !CURL_NOISE_HEADER.test(n)) headers[n] = v; }
    } else if (t === "-b" || t === "--cookie") {
      const v = toks[++i]; if (v && v.includes("=")) headers.Cookie = v; // a value, not a jar file
    } else if (t === "--url") { url = toks[++i]; }
    else if (/^https?:\/\//.test(t) && !url) { url = t; }
    else if (TAKES_ARG.has(t)) { i++; } // skip the flag's argument
  }
  const session = { name };
  if (role) session.role = role;
  session.headers = headers;
  try { if (url) { const u = new URL(url); if (/\/(api|graphql|v\d+|rest|rpc)(\/|$)/i.test(u.pathname)) session.apiBase = u.pathname.replace(/\/[^/]*$/, "") || "/"; } } catch {}
  return session;
}

// Assemble a session object. `host` scopes the jar; a HAR, if supplied, is attached as `traffic`
// so the diff can run runtime-authoritatively (and seeds the Cookie if no jar is given).
export function buildSession({ name, role, jarText, har, apiBase, host, extraHeaders } = {}) {
  if (!name) throw new Error("session needs a --name");
  const session = { name };
  if (role) session.role = role;
  const headers = {};
  if (jarText) {
    const c = cookieHeader(parseNetscapeJar(jarText), { host });
    if (c) headers.Cookie = c;
  } else if (har) {
    const c = cookieFromHar(har);
    if (c) headers.Cookie = c;
  }
  // carry header-borne auth (Bearer / CSRF / API key) from the HAR, else a token-auth app yields a
  // silently-unauthenticated session and a meaningless diff (the same footgun as a dropped cookie).
  if (har) for (const [k, v] of Object.entries(authHeadersFromHar(har))) if (!(k in headers)) headers[k] = v;
  if (extraHeaders) for (const [k, v] of Object.entries(extraHeaders)) headers[k] = v; // caller override wins
  session.headers = headers;
  if (apiBase) session.apiBase = apiBase;
  if (har) session.traffic = har;
  return session;
}

// ---- self-test (offline) ---------------------------------------------------------------
function selfTest() {
  let pass = 0, fail = 0;
  const check = (cond, msg) => (cond ? pass++ : (fail++, console.error("FAIL:", msg)));

  const jar = [
    "# Netscape HTTP Cookie File",
    "# a genuine comment line",
    "#HttpOnly_app.example.com\tFALSE\t/\tTRUE\t0\tJSESSIONID\tSECRET123",
    "app.example.com\tFALSE\t/\tFALSE\t0\tcsrf\ttok456",
    ".other.com\tTRUE\t/\tFALSE\t0\tstray\tnope",
  ].join("\n");

  const cookies = parseNetscapeJar(jar);
  check(cookies.length === 3, "parses 3 cookies, skips the real comment");
  check(cookies.some((c) => c.name === "JSESSIONID" && c.httpOnly), "HttpOnly session cookie is NOT dropped");

  const hdr = cookieHeader(cookies, { host: "app.example.com" });
  check(/JSESSIONID=SECRET123/.test(hdr), "cookie header includes the HttpOnly session cookie");
  check(/csrf=tok456/.test(hdr), "cookie header includes the normal cookie");
  check(!/stray/.test(hdr), "host-scoping excludes an unrelated-domain cookie");

  const s = buildSession({ name: "alice", role: "user", jarText: jar, host: "app.example.com", apiBase: "/api" });
  check(s.name === "alice" && s.role === "user" && s.apiBase === "/api", "session carries name/role/apiBase");
  check(/JSESSIONID=SECRET123/.test(s.headers.Cookie), "built session is authenticated (HttpOnly preserved)");

  const har = { log: { entries: [{ request: { method: "GET", url: "https://app.example.com/api/me", headers: [{ name: "Cookie", value: "JSESSIONID=FROMHAR" }] } } ] } };
  const s2 = buildSession({ name: "bob", har });
  check(s2.headers.Cookie === "JSESSIONID=FROMHAR", "HAR fallback seeds the Cookie header");
  check(s2.traffic === har, "HAR is attached as traffic for runtime-authoritative diff");

  // header-borne auth (Bearer / CSRF) must be carried, not silently dropped
  const harTok = { log: { entries: [{ request: { method: "GET", url: "https://app.example.com/api/me", headers: [
    { name: "Authorization", value: "Bearer SECRETTOKEN" }, { name: "X-CSRF-Token", value: "csrf123" }, { name: "Accept", value: "*/*" },
  ] } }] } };
  const s3 = buildSession({ name: "carol", har: harTok });
  check(s3.headers.Authorization === "Bearer SECRETTOKEN", "Bearer auth header lifted from HAR");
  check(s3.headers["X-CSRF-Token"] === "csrf123", "CSRF header lifted from HAR");
  check(s3.headers.Accept === undefined, "a non-auth header is not carried");

  // cookie value injection is neutralized (a value with ';' cannot add a second cookie)
  const inj = cookieHeader([{ name: "SID", value: "abc; admin=true", domain: "x", path: "/" }]);
  check(!inj.includes(";"), "cookie value with ';' cannot inject a second cookie");

  // sessionFromCurl: a browser "Copy as cURL" becomes a ready session (the lowest-friction path)
  const curl = `curl 'https://app.example.com/api/me/orders' \\
    -X GET \\
    -H 'accept: application/json' \\
    -H 'Authorization: Bearer TOK123' \\
    -H 'X-CSRF-Token: csrf9' \\
    -H 'user-agent: Mozilla/5.0' \\
    -b 'session=abc; theme=dark' \\
    --compressed`;
  const sc = sessionFromCurl(curl, { name: "alice", role: "user" });
  check(sc.name === "alice" && sc.role === "user", "curl session carries name/role");
  check(sc.headers.Authorization === "Bearer TOK123" && sc.headers["X-CSRF-Token"] === "csrf9", "auth + CSRF headers kept from cURL");
  check(sc.headers.Cookie === "session=abc; theme=dark", "cookie kept from -b");
  check(!("accept" in sc.headers) && !("user-agent" in sc.headers), "browser-noise headers dropped");
  check(sc.apiBase === "/api/me", "apiBase hinted from the request path");
  const scX = sessionFromCurl(`curl -X POST --data '{"x":1}' -H 'Cookie: s=1' https://h/api/x`, { name: "b" });
  check(scX.headers.Cookie === "s=1" && !("-X" in scX.headers), "flags with arguments are consumed, not mistaken for the URL/headers");

  console.log(`session_import self-test: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

if (process.argv[1] && process.argv[1].endsWith("session_import.mjs") && process.argv.includes("--self-test")) selfTest();
