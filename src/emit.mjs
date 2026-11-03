// Standard-format emitters. Aperta speaks what pipelines consume: SARIF for CI / code-scanning
// dashboards, nuclei templates for a detector flywheel. Pure data in -> string/object out, no I/O.

const SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

// The diff ({matrix, perSession}) -> flat findings for the given (low-priv) session.
// A finding = an endpoint gated from this identity but reachable by a higher-priv one = the
// hidden, role-gated surface (broken object/function-level authz candidate).
export function findingsFromDiff(diff, sessionName) {
  const p = diff.perSession[sessionName];
  if (!p) return [];
  // map each hidden "METHOD /path" to the role(s) that reached it, from the matrix
  return p.hidden.map((label) => {
    const [method, ...rest] = label.split(" ");
    const path = rest.join(" ");
    const row = diff.matrix.find((r) => r.method === method && r.path === path);
    const reachedBy = row
      ? Object.entries(row.status)
          .filter(([name, st]) => name !== sessionName && st !== 0 && st !== 401 && st !== 403)
          .map(([name]) => name)
      : [];
    return { method, path, label, hiddenFrom: sessionName, reachedBy };
  });
}

const RULE = {
  id: "aperta/hidden-authz-surface",
  name: "HiddenAuthorizationSurface",
  shortDescription: { text: "Endpoint reachable by a higher-privilege identity but gated from a lower one" },
  fullDescription: {
    text:
      "Aperta reconstructed this endpoint from the client bundle and observed, over live HTTP, that a " +
      "lower-privilege identity is denied (401/403) while a higher-privilege identity reaches it. This " +
      "is the role-gated surface a low-priv session never sees in the UI and a broken-object/function-" +
      "level-authorization candidate. Confirm impact with `aperta prove` (sibling-endpoint oracle).",
  },
  defaultConfiguration: { level: "warning" },
  properties: { tags: ["security", "access-control", "authorization", "BOLA", "BFLA"], "security-severity": "6.5" },
};

const BOLA_RULE = {
  id: "aperta/confirmed-bola",
  name: "ConfirmedBOLA",
  shortDescription: { text: "Broken Object Level Authorization confirmed by the app's own sibling endpoint" },
  fullDescription: {
    text:
      "An attacker identity retrieved an object the app's own sibling endpoint attributes to a different " +
      "user, with own-id=200 and nonexistent=404 controls holding in the same run. A self-contradiction " +
      "in the app's authorization, not a tuned response-diff.",
  },
  defaultConfiguration: { level: "error" },
  properties: { tags: ["security", "access-control", "BOLA", "IDOR"], "security-severity": "8.1" },
};

const SCOPED_RULE = {
  id: "aperta/scoped-authz-verified",
  name: "ScopedAuthorizationVerified",
  shortDescription: { text: "Object-level authorization deterministically verified (earned negative)" },
  fullDescription: {
    text:
      "Aperta proved this endpoint enforces object-level authorization: a known victim-owned object " +
      "exists and is denied to the attacker on every attempt, while the attacker's own object is " +
      "served and a nonexistent id is not. Pin this as a CI baseline and fail the build if it later " +
      "flips to a confirmed break.",
  },
  defaultConfiguration: { level: "note" },
  properties: { tags: ["security", "access-control", "authorization", "regression-baseline"], "security-severity": "0.0" },
};

const BFLA_RULE = {
  id: "aperta/broken-function-level-authz",
  name: "BrokenFunctionLevelAuthorization",
  shortDescription: { text: "Privileged-looking endpoint reached by a non-privileged or anonymous identity" },
  fullDescription: {
    text:
      "Aperta observed a non-privileged (or anonymous) identity reach an endpoint whose path or " +
      "bundle-declared route is privileged (admin/manage/internal). This is a direct broken-" +
      "function-level-authorization signal, not an object-level candidate.",
  },
  defaultConfiguration: { level: "error" },
  properties: { tags: ["security", "access-control", "BFLA", "privilege-escalation"], "security-severity": "8.2" },
};

// SARIF 2.1.0 log. `diff` may be null if only BOLA results are supplied.
// `findings` (from authz_matrix.classifyFindings) adds BFLA/vertical-priv-esc results when supplied.
export function toSARIF({ diff = null, session = null, bolas = [], findings = null } = {}) {
  const rules = [];
  const results = [];

  if (findings && findings.bfla && findings.bfla.length) {
    rules.push(BFLA_RULE);
    for (const b of findings.bfla) {
      results.push({
        ruleId: BFLA_RULE.id,
        level: "error",
        message: { text: `${b.endpoint} reached by ${b.reachedBy.map((r) => `'${r.name}'${r.role ? `/${r.role}` : ""}`).join(", ")}, which should not hold a privileged route (${b.severity}).` },
        locations: [{ logicalLocations: [{ fullyQualifiedName: b.endpoint, kind: "member" }] }],
        properties: { class: "BFLA", severity: b.severity, reachedBy: b.reachedBy },
      });
    }
  }

  if (diff && session) {
    rules.push(RULE);
    for (const f of findingsFromDiff(diff, session)) {
      results.push({
        ruleId: RULE.id,
        level: f.reachedBy.length ? "warning" : "note",
        message: {
          text:
            `${f.method} ${f.path} is gated from '${f.hiddenFrom}' but reachable by ` +
            `${f.reachedBy.length ? f.reachedBy.map((r) => `'${r}'`).join(", ") : "a higher-privilege identity"}.`,
        },
        locations: [
          { logicalLocations: [{ fullyQualifiedName: `${f.method} ${f.path}`, kind: "member" }] },
        ],
        properties: { method: f.method, path: f.path, hiddenFrom: f.hiddenFrom, reachedBy: f.reachedBy },
      });
    }
  }

  for (const b of bolas) {
    if (b.verdict === "CONFIRMED") {
      if (!rules.find((r) => r.id === BOLA_RULE.id)) rules.push(BOLA_RULE);
      results.push({
        ruleId: BOLA_RULE.id,
        level: "error",
        message: { text: b.reason || `Confirmed BOLA in ${b.endpoint || "object endpoint"} via the sibling-endpoint oracle.` },
        locations: [{ logicalLocations: [{ fullyQualifiedName: b.endpoint, kind: "member" }] }],
        properties: { class: "BOLA", attacker: b.attacker, victim: b.victim, oracle: b.oracle },
      });
    } else if (b.verdict === "CORRECTLY-SCOPED") {
      // a deterministic POSITIVE assertion: the app PROVED it enforces object-level authz here. Useful
      // as a CI regression baseline (fail the build if this endpoint later flips to CONFIRMED).
      if (!rules.find((r) => r.id === SCOPED_RULE.id)) rules.push(SCOPED_RULE);
      results.push({
        ruleId: SCOPED_RULE.id,
        level: "note",
        message: { text: b.reason || `Object-level authorization verified at ${b.endpoint}: the attacker is denied the victim's object while own-id works.` },
        locations: [{ logicalLocations: [{ fullyQualifiedName: b.endpoint, kind: "member" }] }],
        properties: { class: "scoped-authz-verified", attacker: b.attacker, victim: b.victim, oracle: b.oracle },
      });
    }
  }

  return {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "Aperta", informationUri: "https://github.com/nyxragon/Aperta", rules } },
        results,
      },
    ],
  };
}

// nuclei template for a CONFIRMED BOLA, a reusable detector for a detector flywheel.
// A cross-user oracle can't live in a static template, so this emits a reachability detector:
// request the object endpoint (with a low-priv session the operator supplies via -H) and flag a
// 200 that returns an object body. Re-run fleet-wide to catch the same pattern on other hosts.
export function toNucleiTemplate(bola, { exampleId } = {}) {
  if (bola.verdict !== "CONFIRMED") throw new Error("nuclei template is only emitted for a CONFIRMED finding");
  // Every interpolated value below originates from the live target (untrusted) and this template is
  // re-run fleet-wide by the detector flywheel, so an unescaped value would be a template-injection
  // that fires attacker-influenced requests at every host. Harden: slugify the id-derived name,
  // single-line + length-cap the example id, and emit every value as a JSON-quoted scalar (valid YAML)
  // so quotes/colons/newlines cannot break out of their field.
  const q = (v) => JSON.stringify(String(v));                                   // valid double-quoted YAML scalar
  const slug = (v) => String(v).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60) || "object";
  const oneLine = (v) => String(v).replace(/[\r\n\t]+/g, " ").slice(0, 256);    // no newlines, bounded
  // An id goes into a URL path: restrict it to safe id chars so it cannot add path segments ("/"),
  // nuclei interpolation ("{{"), quotes, or whitespace. It is only an EXAMPLE value anyway.
  const idSafe = (v) => (String(v).split(/[\r\n]/)[0].replace(/[^A-Za-z0-9._~:%=+-]/g, "").slice(0, 128) || "1");
  const collection = slug((bola.evidence && bola.endpoint.match(/\/([a-z0-9_-]+)\/\{param\}/i)?.[1]) || "object");
  const idval = idSafe(exampleId || (bola.evidence && bola.evidence.foreign_id_tested) || "1");
  const endpoint = oneLine(bola.endpoint);
  const path = endpoint.replace(/\{param\}/g, idval);
  const idKeyWord = `"${oneLine(bola.idKey || "id")}"`;
  const yaml = [
    `id: aperta-bola-${collection}`,
    ``,
    `info:`,
    `  name: ${q("Broken Object Level Authorization in " + endpoint)}`,
    `  author: nyxragon`,
    `  severity: high`,
    `  description: |`,
    `    Confirmed by Aperta via the sibling-endpoint oracle.`,
    `    An attacker identity retrieved an object the app attributes to another user.`,
    `    Supply a LOW-PRIV session for the detector run: nuclei -H 'Cookie: <attacker-session>'.`,
    `    The object id below is an example from the confirming run; point it at a victim-owned id.`,
    `  reference:`,
    `    - https://github.com/nyxragon/Aperta`,
    `  tags: bola,idor,access-control,authorization,aperta`,
    `  metadata:`,
    `    confirmed-by: aperta`,
    `    oracle: sibling-endpoint`,
    ``,
    `http:`,
    `  - method: ${/^[A-Z]+$/.test(bola.method || "") ? bola.method : "GET"}`,
    `    path:`,
    `      - ${q("{{BaseURL}}" + (path.startsWith("/") || /^https?:\/\//.test(path) ? path : "/" + path))}`,
    `    matchers-condition: and`,
    `    matchers:`,
    `      - type: status`,
    `        status:`,
    `          - 200`,
    `      - type: word`,
    `        part: body`,
    `        words:`,
    `          - ${q(idKeyWord)}`,
    ``,
  ].join("\n");
  return yaml;
}

// A self-contained reproduction script for a CONFIRMED finding. Unlike the nuclei template (which can
// only re-check reachability), this replays the actual cross-user CONTRADICTION the way a triager /
// vendor re-confirms it: victim's own list -> attacker reads the foreign object x3 -> own-id control
// -> nonexistent-id control. Session auth is a PLACEHOLDER (never embed a real token - evidence
// hygiene); the operator fills in the two identities and runs it.
export function toReproScript(bola) {
  if (bola.verdict !== "CONFIRMED") throw new Error("repro script is only emitted for a CONFIRMED finding");
  const sh = (s) => String(s).replace(/[\r\n]/g, " ");
  const ev = bola.evidence || {};
  const L = [
    "#!/usr/bin/env bash",
    `# Aperta reproduction - CONFIRMED ${sh(bola.class || "BOLA")}${bola.subclass ? " (" + sh(bola.subclass) + ")" : ""}`,
    `# Oracle: ${sh(bola.oracle || "the app's own ownership statement")}`,
    "# Fill in BASE and the two sessions, then run. Placeholders only: no real token is embedded.",
    "set -euo pipefail",
    'BASE="${BASE:-https://TARGET}"',
    'AUTH_HEADER="Authorization"          # or: Cookie',
    'ATTACKER_AUTH="PASTE_ATTACKER_SESSION"',
    'VICTIM_AUTH="PASTE_VICTIM_SESSION"',
    "",
  ];
  const G = (auth, path) => `curl -sS -H "$AUTH_HEADER: $${auth}" "$BASE${sh(path)}"`;
  const code = (auth, path) => `curl -sS -o /dev/null -w '%{http_code}\\n' -H "$AUTH_HEADER: $${auth}" "$BASE${sh(path)}"`;
  if (ev.sibling_path && ev.object_template && ev.foreign_id_tested != null) {
    const objFor = (id) => ev.object_template.replace(/\{param\}/g, encodeURIComponent(String(id)));
    L.push(`echo "[1] the victim's OWN list attributes object ${sh(ev.foreign_id_tested)} to the victim:"`, G("VICTIM_AUTH", ev.sibling_path), "");
    L.push(`echo "[2] the attacker reads that object 3x (the break; expect the victim's record each time):"`,
      `for i in 1 2 3; do ${code("ATTACKER_AUTH", objFor(ev.foreign_id_tested))}; done`, G("ATTACKER_AUTH", objFor(ev.foreign_id_tested)), "");
    if (ev.control_own_id != null) L.push(`echo "[3] control: the attacker's OWN id is authorized (expect 200):"`, code("ATTACKER_AUTH", objFor(ev.control_own_id)), "");
    if (ev.control_nonexistent_id != null) L.push(`echo "[4] control: a nonexistent id is not served (expect 404/!=200, rules out a catch-all):"`, code("ATTACKER_AUTH", objFor(ev.control_nonexistent_id)), "");
  } else if (bola.subclass === "collection-over-return" && ev.sibling_path) {
    L.push(`echo "[1] the attacker's self-scoped list (the app's statement of what is theirs):"`, G("ATTACKER_AUTH", ev.sibling_path), "");
    L.push(`echo "[2] the attacker's UNSCOPED list over-returns other users' rows (the leak):"`, G("ATTACKER_AUTH", bola.endpoint), "");
    L.push(`# foreign rows observed: ${sh(JSON.stringify((ev.foreign_rows || []).slice(0, 5)))}`, "");
  } else {
    L.push(`# transport: ${sh(bola.oracle || "")}`, `echo "See the Aperta evidence block; this finding uses a non-REST transport (e.g. GraphQL). Replay the object and sibling queries as the two identities."`, "");
  }
  L.push('echo "Reproduced: an attacker-authorized request returned data the app attributes to the victim."');
  return L.join("\n") + "\n";
}

// --- self-test --------------------------------------------------------------------------
function selfTest() {
  const diff = {
    matrix: [
      { method: "GET", path: "/api/admin/users", status: { alice: 403, admin: 200 } },
      { method: "GET", path: "/api/me/orders", status: { alice: 200, admin: 200 } },
    ],
    perSession: {
      alice: { role: "user", reachable: ["GET /api/me/orders"], gated: ["GET /api/admin/users"], hidden: ["GET /api/admin/users"] },
      admin: { role: "admin", reachable: ["GET /api/admin/users", "GET /api/me/orders"], gated: [], hidden: [] },
    },
  };
  const bola = { verdict: "CONFIRMED", class: "BOLA", method: "GET", idKey: "id",
    endpoint: "/api/orders/{param}", attacker: "alice", victim: "bob",
    oracle: "sibling-endpoint /api/me/orders", reason: "alice retrieved orders 2001 attributed to bob.",
    evidence: { foreign_id_tested: "2001" } };

  let pass = 0, fail = 0;
  const check = (cond, msg) => (cond ? pass++ : (fail++, console.error("FAIL:", msg)));

  const f = findingsFromDiff(diff, "alice");
  check(f.length === 1, "one hidden finding for alice");
  check(f[0].path === "/api/admin/users" && f[0].reachedBy.includes("admin"), "finding attributes reach to admin");

  const s = toSARIF({ diff, session: "alice", bolas: [bola] });
  check(s.version === "2.1.0" && s.$schema.includes("2.1.0"), "SARIF 2.1.0 version");
  check(s.runs[0].tool.driver.name === "Aperta", "driver name");
  check(s.runs[0].results.length === 2, "two results (1 hidden + 1 BOLA)");
  check(s.runs[0].tool.driver.rules.length === 2, "two rules registered");
  check(s.runs[0].results.every((r) => r.ruleId && r.message.text && r.locations.length), "results well-formed");
  check(s.runs[0].results.find((r) => r.ruleId === "aperta/confirmed-bola").level === "error", "BOLA is error-level");
  const sNoReason = toSARIF({ bolas: [{ verdict: "CONFIRMED", endpoint: "/api/x/{param}" }] });
  check(typeof sNoReason.runs[0].results[0].message.text === "string" && sNoReason.runs[0].results[0].message.text.length > 0, "SARIF result always has message.text (schema-required) even without a reason");
  // CORRECTLY-SCOPED emits a positive note-level result (the CI regression baseline), not an error
  const sScoped = toSARIF({ bolas: [{ verdict: "CORRECTLY-SCOPED", endpoint: "/api/orders/{param}", reason: "enforced" }] });
  const scopedRes = sScoped.runs[0].results.find((r) => r.ruleId === "aperta/scoped-authz-verified");
  check(scopedRes && scopedRes.level === "note", "CORRECTLY-SCOPED -> note-level scoped-authz-verified result");
  check(!sScoped.runs[0].results.some((r) => r.level === "error"), "a correctly-scoped verdict is NOT emitted as an error/finding");
  check(JSON.parse(JSON.stringify(s)), "SARIF is JSON-serializable");

  const tpl = toNucleiTemplate(bola);
  check(/^id: aperta-bola-orders$/m.test(tpl), "nuclei id derived from collection");
  check(tpl.includes("{{BaseURL}}/api/orders/2001"), "nuclei path uses BaseURL + example id");
  check(tpl.includes("severity: high"), "nuclei severity high");
  check(tpl.includes("author: nyxragon"), "nuclei author");
  check(/words:\s*\n\s*- "\\"id\\""/.test(tpl), "nuclei body matcher uses idKey as a quoted scalar");
  check(tpl.includes("tags: bola,idor,access-control,authorization,aperta"), "nuclei tags");
  let threw = false;
  try { toNucleiTemplate({ verdict: "NOT-CONFIRMED" }); } catch { threw = true; }
  check(threw, "nuclei refuses a non-confirmed finding");

  // repro script: self-contained, placeholder sessions, all four oracle steps, no embedded token
  const reproBola = { verdict: "CONFIRMED", class: "BOLA", method: "GET", idKey: "id", endpoint: "/api/orders/{param}", attacker: "alice", victim: "bob", oracle: "sibling /api/me/orders",
    evidence: { object_template: "/api/orders/{param}", sibling_path: "/api/me/orders", foreign_id_tested: "2001", control_own_id: "1001", control_nonexistent_id: "2001000" } };
  const repro = toReproScript(reproBola);
  check(repro.startsWith("#!/usr/bin/env bash"), "repro is a runnable bash script");
  check(repro.includes("/api/me/orders") && repro.includes("/api/orders/2001"), "repro replays the sibling list and the foreign-object read");
  check(repro.includes("/api/orders/1001") && repro.includes("/api/orders/2001000"), "repro includes the own-id and nonexistent-id controls");
  check(repro.includes("PASTE_ATTACKER_SESSION") && repro.includes("PASTE_VICTIM_SESSION") && !/Bearer\s+\w/.test(repro), "repro uses session placeholders, embeds no real token");
  let threw2 = false; try { toReproScript({ verdict: "NOT-CONFIRMED" }); } catch { threw2 = true; }
  check(threw2, "repro refuses a non-confirmed finding");

  // INJECTION: untrusted id/endpoint/idKey must not break out of their YAML field (flywheel re-runs this).
  const inj = toNucleiTemplate({ verdict: "CONFIRMED", method: "GET", idKey: "id", endpoint: "/api/orders/{param}",
    oracle: "s", reason: "r", evidence: { foreign_id_tested: '1\n    - "{{BaseURL}}/api/admin/delete_all"\n    headers:\n      X-Injected: pwned' } });
  check((inj.match(/\{\{BaseURL\}\}/g) || []).length === 1, "injected newline in id does NOT add a second request path");
  check(!inj.includes("/api/admin/delete_all") && !inj.includes("X-Injected"), "injected path/header are neutralized");
  const inj2 = toNucleiTemplate({ verdict: "CONFIRMED", method: "GET\nmalicious", idKey: 'id" evil', endpoint: '/api/x"y: z/{param}',
    oracle: "s", reason: "r", evidence: { foreign_id_tested: "1" } });
  check(/^  name: ".*"$/m.test(inj2), "endpoint goes into name as a quoted scalar (colon/quote safe)");
  check(/^  - method: GET$/m.test(inj2), "a non-A-Z method is rejected, falls back to GET");

  console.log(`emit self-test: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

if (process.argv[1] && process.argv[1].endsWith("emit.mjs") && process.argv.includes("--self-test")) selfTest();
