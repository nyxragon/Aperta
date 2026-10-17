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
// scoped to it are included; otherwise all are sent. Last value for a name wins.
export function cookieHeader(cookies, { host } = {}) {
  const scoped = host ? cookies.filter((c) => hostMatchesDomain(host, c.domain)) : cookies;
  const byName = new Map();
  for (const c of scoped) byName.set(c.name, c.value);
  return [...byName].map(([n, v]) => `${n}=${v}`).join("; ");
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

// Assemble a session object. `host` scopes the jar; a HAR, if supplied, is attached as `traffic`
// so the diff can run runtime-authoritatively (and seeds the Cookie if no jar is given).
export function buildSession({ name, role, jarText, har, apiBase, host } = {}) {
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

  console.log(`session_import self-test: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

if (process.argv[1] && process.argv[1].endsWith("session_import.mjs") && process.argv.includes("--self-test")) selfTest();
