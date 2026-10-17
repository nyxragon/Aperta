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
    if (b.verdict !== "CONFIRMED") continue;
    if (!rules.find((r) => r.id === BOLA_RULE.id)) rules.push(BOLA_RULE);
    results.push({
      ruleId: BOLA_RULE.id,
      level: "error",
      message: { text: b.reason },
      locations: [{ logicalLocations: [{ fullyQualifiedName: b.endpoint, kind: "member" }] }],
      properties: { class: "BOLA", attacker: b.attacker, victim: b.victim, oracle: b.oracle },
    });
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
  const collection = (bola.evidence && bola.endpoint.match(/\/([a-z0-9_-]+)\/\{param\}/i)?.[1]) || "object";
  const idval = exampleId || (bola.evidence && bola.evidence.foreign_id_tested) || "1";
  const path = bola.endpoint.replace(/\{param\}/g, String(idval));
  const idKeyWord = `"${bola.idKey || "id"}"`;
  const yaml = [
    `id: aperta-bola-${collection}`,
    ``,
    `info:`,
    `  name: Broken Object Level Authorization in ${bola.endpoint}`,
    `  author: nyxragon`,
    `  severity: high`,
    `  description: |`,
    `    Confirmed by Aperta via the sibling-endpoint oracle (${bola.oracle}).`,
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
    `  - method: ${bola.method || "GET"}`,
    `    path:`,
    `      - "{{BaseURL}}${path}"`,
    `    matchers-condition: and`,
    `    matchers:`,
    `      - type: status`,
    `        status:`,
    `          - 200`,
    `      - type: word`,
    `        part: body`,
    `        words:`,
    `          - '${idKeyWord}'`,
    ``,
  ].join("\n");
  return yaml;
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
  check(JSON.parse(JSON.stringify(s)), "SARIF is JSON-serializable");

  const tpl = toNucleiTemplate(bola);
  check(/^id: aperta-bola-orders$/m.test(tpl), "nuclei id derived from collection");
  check(tpl.includes('"{{BaseURL}}/api/orders/2001"'.replace('"', '')) || tpl.includes("{{BaseURL}}/api/orders/2001"), "nuclei path uses BaseURL + example id");
  check(tpl.includes("severity: high"), "nuclei severity high");
  check(tpl.includes("author: nyxragon"), "nuclei author");
  check(tpl.includes("- '\"id\"'"), "nuclei body matcher uses idKey");
  check(tpl.includes("tags: bola,idor,access-control,authorization,aperta"), "nuclei tags");
  let threw = false;
  try { toNucleiTemplate({ verdict: "NOT-CONFIRMED" }); } catch { threw = true; }
  check(threw, "nuclei refuses a non-confirmed finding");

  console.log(`emit self-test: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

if (process.argv[1] && process.argv[1].endsWith("emit.mjs") && process.argv.includes("--self-test")) selfTest();
