// Per-framework extractor validation on representative fixtures.
//
// Real whole-app bundles are NOT committed (anti-overfit policy; corpus.mjs runs those locally
// from a gitignored corpus). This suite instead pins each framework extractor against a minimal,
// representative minified snippet so a regression in reconstruct/fingerprint is caught in CI with
// zero external data. It validates the SHAPE the extractor must recover, not a specific real app.
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { reconstruct, fingerprint } from "../src/reconstruct.mjs";

const dir = mkdtempSync(join(tmpdir(), "aperta-fx-"));
let pass = 0, fail = 0;
const check = (cond, msg) => (cond ? pass++ : (fail++, console.error("FAIL:", msg)));

function run(name, code) {
  const f = join(dir, name + ".js");
  writeFileSync(f, code);
  return { model: reconstruct(f), fp: fingerprint(f).framework };
}
const hasRoute = (m, p, role) => m.routes.some((r) => r.path === p && (role === undefined || r.role === role));
const hasEp = (m, key) => m.endpoints.some((e) => `${e.method} ${e.path}` === key);

// ---- React (react-router) --------------------------------------------------------------
{
  const { model, fp } = run("react", `
    var cr="/api";
    const routes=[{path:"/admin",element:Guard({need:"admin",children:0})},{path:"/dash",element:0}];
    function load(e){return fetch(\`\${cr}/orders/\${e}\`)}
    var k="react-router"; createBrowserRouter(routes);
  `);
  check(fp === "react", "react: fingerprint");
  check(hasRoute(model, "/admin", "admin"), "react: hidden /admin route with role from need: prop");
  check(hasEp(model, "GET /api/orders/{param}"), "react: endpoint from minified base var + template hole");
}

// ---- Angular (runtime baseUrl) ---------------------------------------------------------
{
  const { model, fp } = run("angular", `
    ɵɵdefineComponent({});
    const routes=[{path:"admin/users",component:C,canActivate:[AdminGuard]},{path:"home",component:H}];
    class S{ getUsers(){ return this.http.get(\`\${this.baseUrl}/admin/users\`) } }
  `);
  check(fp === "angular", "angular: fingerprint");
  check(hasRoute(model, "/admin/users", "AdminGuard"), "angular: role from canActivate guard");
  check(hasEp(model, "GET {param}/admin/users"), "angular: runtime-baseUrl endpoint -> {param}-prefixed");
}

// ---- Vue (vue-router + meta) -----------------------------------------------------------
{
  const { model, fp } = run("vue", `
    createRouter({routes:[{path:"/dashboard",component:D,meta:{requiresAuth:true,role:"admin"}},{path:"/public",component:P}]});
    var api=axios.create(); function f(){ return api.get("/api/vue/data") }
  `);
  check(fp === "vue", "vue: fingerprint");
  check(hasRoute(model, "/dashboard", "admin"), "vue: role from meta.role");
  check(hasEp(model, "GET /api/vue/data"), "vue: endpoint via axios instance");
}

// ---- Nuxt (vue-router records under __NUXT__) ------------------------------------------
{
  const { model, fp } = run("nuxt", `
    window.__NUXT__={serverRendered:true};
    const r=[{path:"/profile",component:Pr},{path:"/settings",component:St,meta:{role:"user"}}];
  `);
  check(fp === "nuxt", "nuxt: fingerprint (specificity over bare vue)");
  check(hasRoute(model, "/profile"), "nuxt: route record recovered");
  check(hasRoute(model, "/settings", "user"), "nuxt: role from meta.role");
}

// ---- AngularJS 1.x ($routeProvider / $resource / $http) --------------------------------
{
  const { model, fp } = run("angularjs", `
    angular.module("app",[]).config(function($routeProvider){ $routeProvider.when("/login",{}).when("/account",{}) });
    function svc($resource,$http){ var U=$resource("/api/users/:id"); $http({url:"/api/session",method:"GET"}) }
  `);
  check(fp === "angularjs", "angularjs: fingerprint");
  check(hasRoute(model, "/login") && hasRoute(model, "/account"), "angularjs: chained $routeProvider.when routes");
  check(hasEp(model, "GET /api/users/{param}"), "angularjs: $resource path with :id -> {param}");
  check(hasEp(model, "GET /api/session"), "angularjs: $http({url,method}) config object");
}

// ---- Salesforce Aura -------------------------------------------------------------------
// Honest gap: structured action/descriptor extraction (apex:// adapter) is NOT yet implemented.
// What IS validated: Aura is correctly fingerprinted (so the operator knows to use the right lens),
// and any literal endpoint strings are still recovered.
{
  const { model, fp } = run("aura", `
    $A.get("e.force:navigateToURL"); var d="markup://c:AdminPanel"; fetch("/sfsites/aura?r=1");
  `);
  check(fp === "aura", "aura: fingerprint (motivating case flagged for the apex:// lens)");
  check(model.endpoints.some((e) => e.path.includes("/sfsites/aura")), "aura: literal endpoint strings still recovered");
}

// ---- Next.js (chunk-path routes + _buildManifest) --------------------------------------
{
  const { model, fp } = run("next", `
    self.__next_f=[];
    var m={sortedPages:["/","/admin/settings","/_app"]};
    var c="chunks/app/dashboard/page-a1b2c3.js"; var c2="chunks/app/users/[id]/page-ffeedd.js";
  `);
  check(fp === "nextjs", "next: fingerprint (specificity over react)");
  check(hasRoute(model, "/dashboard"), "next: app-router chunk-path route");
  check(hasRoute(model, "/users/{param}"), "next: dynamic [id] segment -> {param}");
  check(hasRoute(model, "/admin/settings"), "next: _buildManifest sortedPages route");
}

rmSync(dir, { recursive: true, force: true });
console.log(`frameworks self-test: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
