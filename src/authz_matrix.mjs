// Classify the full identity x endpoint matrix into concrete authz findings.
//
// The diff already computes, per identity, what is reachable / gated / hidden. This turns that matrix
// into named findings, including the class the hidden-surface view misses:
//
//   BFLA / vertical privilege escalation  -- a PRIVILEGED-looking endpoint (an /admin, /manage,
//     /internal ... path, or a route the bundle marked role-gated) REACHED by a NON-privileged or
//     anonymous identity. Unlike a BOLA candidate (needs an object-level test to prove impact), this
//     is a direct broken-function-level-authz signal: a low-priv user is calling a privileged route.
//
//   BOLA / hidden-surface candidate  -- gated from a lower identity, reached by a higher one. A
//     candidate: confirm object-level impact with the sibling oracle (prove).
//
// Deterministic: it reads the matrix the live diff produced; no new network, no heurist-y scoring.

const PRIV_ROLES = new Set(["admin", "administrator", "superadmin", "superuser", "owner", "root", "staff", "manager", "moderator"]);
const ANON_ROLES = new Set(["anon", "anonymous", "guest", "public", "unauth", "unauthenticated", "none", "", null, undefined]);

// A path that *looks* privileged by convention (function-level authz is expected here).
const PRIV_PATH_RE = /\/(admin|administration|manage|management|internal|superuser|staff|console|moderat|settings\/users|users\/\{param\}\/(ban|role|promote))(\/|$|s\b)/i;

export function isPrivRole(role) { return PRIV_ROLES.has(String(role ?? "").toLowerCase()); }
export function isAnonRole(role) { return ANON_ROLES.has(role === null || role === undefined ? role : String(role).toLowerCase()); }
export function looksPrivileged(path) { return PRIV_PATH_RE.test(path); }

// cell reachable? (from the authoritative per-session lists)
function reaches(perSession, name, label) {
  return !!perSession[name] && perSession[name].reachable.includes(label);
}

/**
 * classifyFindings(diff) -> { bfla:[], bolaCandidates:[], anonReach:[] }
 *  bfla:           { endpoint, reachedBy:[{name,role}], severity }  privileged endpoint reached by non-priv
 *  anonReach:      { endpoint, reachedBy:[names] }                  privileged endpoint reached by an anon identity
 *  bolaCandidates: { endpoint, hiddenFrom:[names], reachedBy:[names] }  gated-from-lower / reached-by-higher
 */
export function classifyFindings(diff) {
  const names = Object.keys(diff.perSession);
  const roleOf = (n) => diff.perSession[n].role;
  const bfla = [], anonReach = [], bolaCandidates = [];

  for (const row of diff.matrix) {
    const label = `${row.method} ${row.path}`;
    const reachers = names.filter((n) => reaches(diff.perSession, n, label));
    const priv = looksPrivileged(row.path);

    if (priv) {
      const nonPriv = reachers.filter((n) => !isPrivRole(roleOf(n)));
      const anon = reachers.filter((n) => isAnonRole(roleOf(n)));
      if (anon.length) anonReach.push({ endpoint: label, reachedBy: anon });
      if (nonPriv.length) {
        const anonHit = nonPriv.some((n) => isAnonRole(roleOf(n)));
        bfla.push({ endpoint: label, reachedBy: nonPriv.map((n) => ({ name: n, role: roleOf(n) ?? null })), severity: anonHit ? "critical" : "high" });
      }
    }

    // BOLA candidate: gated from at least one identity, reached by at least one OTHER (a higher role).
    const gatedFrom = names.filter((n) => diff.perSession[n].gated.includes(label));
    if (gatedFrom.length && reachers.length) {
      bolaCandidates.push({ endpoint: label, hiddenFrom: gatedFrom, reachedBy: reachers });
    }
  }
  return { bfla, anonReach, bolaCandidates };
}

// One-line summary for the CLI.
export function findingsLine(f) {
  return `findings: ${f.bfla.length} BFLA/vertical-priv-esc, ${f.bolaCandidates.length} BOLA candidate(s), ${f.anonReach.length} anon-reach`;
}

// --- self-test (offline) ----------------------------------------------------------------
function selfTest() {
  let pass = 0, fail = 0;
  const check = (c, m) => (c ? pass++ : (fail++, console.error("FAIL:", m)));

  check(isPrivRole("admin") && isPrivRole("Owner") && !isPrivRole("user"), "priv-role set");
  check(isAnonRole("anon") && isAnonRole(null) && !isAnonRole("user"), "anon-role set");
  check(looksPrivileged("/api/admin/users") && looksPrivileged("/api/internal/flags") && !looksPrivileged("/api/orders"), "privileged-path heuristic");

  const diff = {
    matrix: [
      { method: "GET", path: "/api/admin/users" },     // privileged, reached by low-priv alice -> BFLA
      { method: "GET", path: "/api/internal/flags" },  // privileged, reached by anon -> anon-reach + critical BFLA
      { method: "GET", path: "/api/orders/{param}" },  // gated from alice, reached by admin -> BOLA candidate
    ],
    perSession: {
      anon:  { role: "anon",  reachable: ["GET /api/internal/flags"], gated: ["GET /api/admin/users", "GET /api/orders/{param}"], hidden: [] },
      alice: { role: "user",  reachable: ["GET /api/admin/users", "GET /api/internal/flags"], gated: ["GET /api/orders/{param}"], hidden: ["GET /api/orders/{param}"] },
      admin: { role: "admin", reachable: ["GET /api/admin/users", "GET /api/internal/flags", "GET /api/orders/{param}"], gated: [], hidden: [] },
    },
  };
  const f = classifyFindings(diff);
  const adminUsers = f.bfla.find((x) => x.endpoint === "GET /api/admin/users");
  check(adminUsers && adminUsers.reachedBy.some((r) => r.name === "alice") && adminUsers.severity === "high", "BFLA: low-priv alice reaches /admin/users (high)");
  const flags = f.bfla.find((x) => x.endpoint === "GET /api/internal/flags");
  check(flags && flags.severity === "critical", "BFLA reached by anon escalates to critical");
  check(f.anonReach.some((x) => x.endpoint === "GET /api/internal/flags" && x.reachedBy.includes("anon")), "anon-reach recorded");
  check(!f.bfla.some((x) => x.reachedBy.some((r) => r.name === "admin")), "admin reaching admin endpoint is NOT a BFLA");
  const bola = f.bolaCandidates.find((x) => x.endpoint === "GET /api/orders/{param}");
  check(bola && bola.hiddenFrom.includes("alice") && bola.reachedBy.includes("admin"), "BOLA candidate: orders gated from alice, reached by admin");
  check(findingsLine(f).includes("BFLA") && findingsLine(f).includes("BOLA candidate"), "findings line");

  console.log(`authz_matrix self-test: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

if (process.argv[1] && process.argv[1].endsWith("authz_matrix.mjs") && process.argv.includes("--self-test")) selfTest();
