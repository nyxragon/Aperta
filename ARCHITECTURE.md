# Aperta architecture & integration contract

The design rules that keep Aperta plug-and-play, lean, and adoptable. These are decisions, not
suggestions, the whole value proposition depends on them.

## Design rules (non-negotiable)
1. **Aperta owns ONE thing:** reconstruct hidden surface → diff identities → prove authz. It owns
   **no recon, no proxy, no auth/login.** Those are the pipeline's job, already solved everywhere.
2. **Lean core:** the shipped tool is AST (Babel) + native `fetch` only. No browser, no recon bundled.
3. **Heavy bits are optional requisites**, never shipped: the browser-capture backend is an optional
   peer dep (install Playwright only if you use it); otherwise feed a HAR. Recon is the caller's.
4. **Interoperate via standard formats** on both ends, consume what pipelines produce, emit what
   they consume. Everything is a pipeable stage, not a system to adopt.
5. **Never dump raw surface into an LLM.** Shells return the delta + an artifact path; big data stays
   in files and in the engine process, out of context.

## I/O contract (the product)
**Inputs (caller already has these, Aperta fetches nothing by default):**
- JS: a directory of already-collected bundles (getJS/katana/gau output) or a URL list on stdin.
- Sessions: a list of identities, each supplied **by the researcher's automation via proxy or direct**:
  ```
  session = { name, role?, auth:{cookies?|headers?|bearer?}, traffic?: HAR|proxy-export }
  ```
  Aperta NEVER logs in. `auth` is required (for probing/oracle); `traffic` is optional (for the diff).

**Outputs (standard, drop into any tool):**
- OpenAPI/Swagger JSON (reconstructed surface) · SARIF (findings) · nuclei templates (confirmed BOLA,
  feeds a detector flywheel) · JSONL (anew-diffable) · plain endpoint list on stdout.

## Pipeline runs with no browser (the key consequence of session-as-input)
- **Oracle:** uses `auth` only → HTTP requests as each identity. No browser.
- **Diff:** (a) if `traffic` given → use the observed exercised-set; (b) else → probe the reconstructed
  endpoints with each identity's `auth` and read the authz response (2xx vs 401/403) → hidden surface
  falls out of who-can-reach-what. Pure HTTP; (c) browser backend only if neither is available.

## Pipeable subcommands
```
getJS -u $t | aperta reconstruct --format openapi > surface.json
aperta diff --surface surface.json --session alice.json --session admin.json > hidden.jsonl
aperta prove --surface surface.json --sessions alice.json,admin.json | tee findings.jsonl
```
Each subcommand is stdin→stdout; a researcher plugs in only the stage they need. Plus a **library mode**
(import the engine) so other tools embed it.

## Three thin shells over ONE engine (no logic drift)
- **CLI**, the engine. Terminal hunters, CI, any rig. Zero AI.
- **Skill (Claude Code)**, encodes the workflow + judgment, calls the CLI via Bash, and composes the
  loop: find hidden surface → prove → validate (hand the evidence to a separate adversarial-validator
  step before reporting). Ships in the `nyxragon-aperta` marketplace.
- **MCP server (`aperta mcp`)**, typed tools for any MCP client (Cursor/Desktop/Cline). Each tool returns
  a compact summary + artifact path, never the raw surface. Heavy work runs in the server process.

## How it slots into an existing rig, with zero new infra
A recon pipeline already collects JS, runs a proxy, and holds an identity matrix. Aperta is one stage:
it reads the JS recon already pulled, takes the proxy history per identity as the sessions, and emits
the hidden surface as JSONL and a confirmed BOLA as a nuclei template. No parallel browser, recon, or
proxy of its own.

## Build / contribution order
The engine (library + CLI) and its I/O contract come first: the multi-identity diff that consumes
caller-supplied sessions (auth +/- traffic), HTTP-only, emitting the hidden surface as JSONL/OpenAPI.
The skill and MCP server are thin wrappers over the same engine.
