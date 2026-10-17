---
name: aperta
description: >-
  Map a single-page app's hidden, role-gated attack surface and prove broken authorization on it.
  Use when hunting BOLA/IDOR/BFLA or broken access control on an SPA (React/Angular/Vue/Nuxt/Next/
  AngularJS/GraphQL), when you have collected the app's JS bundles and want the FULL route+API map
  including the admin/privileged surface a low-priv session never renders, or when you hold two
  identities and want a deterministic authorization proof. Composes with the adversarial-validator
  (/validate) before any report. Wraps the Aperta CLI; does no recon, proxy, or login itself.
---

# Aperta: reconstruct hidden surface, diff identities, prove authz

Aperta owns one thing: **reconstruct** the hidden surface from the bundle → **diff** it against a
low-priv session to isolate the role-gated surface → **prove** a BOLA with the app's own sibling
endpoint as the oracle. It speaks only HTTP + AST; recon, proxy, and login are YOUR pipeline's job.

Run it through the CLI (`node bin/aperta.mjs <cmd>` from the repo, or `aperta <cmd>` if linked).

**Your role vs the tool's (proposer / decider).** You do the fuzzy work: harvest the JS, handle an
unknown framework, propose which endpoints and which sibling pairs to test. Aperta makes the
*verdict* deterministically. Never overrule a `NOT-CONFIRMED` into a "probably vulnerable", and never
promote a `hidden` lead to a finding on your own judgment: if it is real, `prove` confirms it the
same way twice. Propose freely; let the oracle decide.

## When to reach for this
- You are testing an SPA for broken access control and want the surface the UI hides from your role.
- You collected JS bundles (getJS/katana/gau) and need routes + REST + GraphQL assembled from minified
  code, not just a regex string dump.
- You hold ≥2 identities (a low-priv and a higher-priv) and want the hidden delta or a proven break.

## Workflow

**0. Collect JS (your recon, Aperta does NOT fetch).** Pull the bundle + all code-split chunks for
the target into a dir. Reconstruction quality tracks chunk coverage, so harvest thoroughly.
```sh
getJS --url https://app.target.com | while read u; do curl -s "$u" -o "bundles/$(basename $u)"; done
# (through your proxy / container, in-scope only)
```

**1. Reconstruct the full surface (no session needed).**
```sh
aperta fingerprint bundles                       # which framework (picks your lens)
aperta reconstruct bundles --format endpoints    # human-readable
aperta reconstruct bundles --format openapi > surface.json   # machine, feeds the diff
```
Look at what came back that you have NOT seen in the UI, `/admin*`, `/api/admin/*`, privileged
GraphQL mutations. That is the lead. Then check where the BOLA oracle even applies, before spending
time:
```sh
aperta oracles --surface surface.json --format text   # object endpoints -> sibling oracle + applicability %
```

**If `fingerprint` says `unknown` (bespoke framework), reconstruct recovers nothing, that is your
job, not a dead end.** Recover the endpoint map yourself (drive the app and export a HAR, write a
one-off extractor for its router, read a source map) and feed it in; the deterministic stages run
unchanged:
```sh
aperta ingest --endpoints my-recovered-endpoints.txt > surface.json   # one "METHOD /path" per line
aperta ingest --har traffic.har > surface.json                        # or from observed traffic
aperta ingest --source-map app.js.map > surface.json                  # or original sources, if shipped
```

**2. Build sessions from YOUR proxy history (one per identity).** Aperta never logs in, you supply
auth. A session is JSON; `traffic` (a HAR / proxy export) is optional but makes the diff
runtime-authoritative (resolves Angular-style runtime baseUrls and trusts what the identity actually
reached):
```json
{ "name": "alice", "role": "user", "headers": { "Cookie": "session=..." }, "apiBase": "/api",
  "traffic": { "log": { "entries": [ /* optional HAR of what alice's session actually hit */ ] } } }
```

**3. Diff, isolate the hidden surface for the low-priv identity.**
```sh
aperta diff --base https://app.target.com --surface surface.json \
  --session alice.json --session admin.json --as alice --format jsonl   # hidden surface, anew-diffable
aperta diff ... --format sarif > findings.sarif                          # for a CI gate / dashboard
```
The `hidden` set = endpoints gated from alice (401/403) that admin reaches. Those are your BOLA/BFLA
candidates. Keep ≤1 req/s; the diff probes live.

**4. Prove, a deterministic BOLA via the sibling oracle.** Pick an object endpoint from the hidden
or reachable set and the sibling that filters to the caller's own objects:
```sh
aperta prove --base https://app.target.com \
  --object "/api/orders/{param}" --sibling "/api/me/orders" --collection orders \
  --attacker alice.json --victim bob.json
```
Or let Aperta discover and prove every candidate pair itself:
```sh
aperta prove --base https://app.target.com --surface surface.json --auto \
  --attacker alice.json --victim bob.json
```
`verdict: CONFIRMED` means the attacker pulled an object the sibling attributes to the victim, with
own-id=200 and nonexistent=404 controls holding, a contradiction in the app's own authorization, not
a tuned response-diff. Ids are sourced from the victim's own list, so this holds for UUIDs/slugs too.
Emit a detector for the flywheel: `aperta prove ... --format nuclei`. For a visual the operator can
read, emit the self-contained map: `aperta report --base ... --surface surface.json --session alice.json
--session admin.json --prove --attacker alice.json --victim bob.json > map.html`.

**5. Validate before you report (compose, don't self-confirm).** Hand the EVIDENCE (not your theory)
to the adversarial-validator:
```
/validate   # feed the prove output + the diff rows; let it try to DISCARD the finding
```
Only a finding that survives the validator and reaches real other-user data is a report.

## Output schema (so this chains)
- `reconstruct` → `{ framework, routes:[{path,role}], endpoints:[{method,path}], operations:[{type,name}] }`
- `diff` → JSONL `{ session, hidden }` per hidden endpoint (or SARIF 2.1.0)
- `prove` → `{ verdict, class, endpoint, oracle, attacker, victim, evidence, reason }` (or a nuclei template)

## Judgment
- A `hidden` endpoint is a **lead**, not a finding, reachability is not impact. Push to `prove` or a
  manual cross-user read before attaching severity.
- A `403→` that never reached data is not impact. The question is always "did the attacker reach
  something they shouldn't have?"
- Reconstruction missing routes usually means missing chunks, not a hardened app, harvest more JS and
  re-run before concluding.
- Next.js App Router routes mostly live server-side (RSC); low client-route recovery there is inherent
  to every tool, not an Aperta failure. The REST/GraphQL + diff/prove stages are unaffected.

## Related research terms
BOLA, BFLA, IDOR, broken object level authorization, broken function level authorization, mass
assignment, horizontal/vertical privilege escalation, role-gated route, lazy route, route guard
(canActivate/canLoad), react-router, vue-router, runtime baseUrl, OpenAPI, SARIF, sibling endpoint
oracle, differential authorization testing, source map, JS bundle reconstruction, shadow API.

## If this does not fit
If the CLI errors, the target is not a classic SPA, or the workflow does not match what you see, fall
back to your own exploration and creativity: read the bundle directly, reason about the trust
boundary, and keep going, the tool is a lever, not a cage.
