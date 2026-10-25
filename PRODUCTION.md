# Going to production

You've run this locally, maybe through `docker compose up`, and you like it enough to point it
at something real. This is the checklist for that move - what changes, in what order, and why
each piece matters. Every item below is genuinely just configuration: nothing here requires
writing Go code or forking this project.

If you haven't yet, skim [`ARCHITECTURE.md`](ARCHITECTURE.md) for the "why" and
[`docs/REFERENCE.md`](docs/REFERENCE.md)'s **Roadmap: what's ahead** section for the honest list of what this
project doesn't do yet - this doc assumes you've already made peace with that list, not repeats
it.

## 1. Real identity: stop minting your own tokens

`cmd/devtoken` is explicitly a dev-only stand-in - it mints a JWT signed with a secret this proxy
also holds, which is fine for trying things out and means nothing once real people need to log
in. Swap to your actual IdP (Okta, Auth0, Azure AD, Google, anything that publishes a JWKS):

```yaml
jwt_jwks_url: "https://your-idp.example.com/.well-known/jwks.json"
jwt_issuer: "https://your-idp.example.com/"
# jwt_audience: "your-app-client-id"        # optional, but recommended if your IdP sets one
# jwt_user_claim: "email"                   # optional - defaults to "delegated_user"
# jwt_role_claim: "https://yourapp/role"    # optional - defaults to "delegated_role"
```

`jwt_issuer` is not optional in practice - the proxy refuses to start without it. Without issuer
validation, a token your IdP legitimately issued for a *different* application could be replayed
against this one; that's a real attack shape, not a theoretical one. `jwt_user_claim`/
`jwt_role_claim` exist because you don't control what your IdP names things - map its actual
claim names here rather than reconfiguring your IdP to match this project's defaults.

Once `jwt_jwks_url` is set, `jwt_secret` and `cmd/devtoken` tokens stop being accepted by this
proxy entirely - there's no way to mix the two modes, deliberately, so nobody ends up with a
"real" deployment that quietly still trusts a dev secret.

## 2. Real Vault: HA, and a real auth method

The `vault server -dev` you've been running (in-memory storage, unseals itself, one root token)
is a genuine single point of failure and a genuine standing credential with no expiry - fine for
a demo, not for anything you'd call production. Two separate things to fix:

- **Storage/availability**: run Vault in HA mode with a real storage backend (Raft integrated
  storage is the simplest modern default; Consul is the older, still-common choice) and real
  auto-unseal (a cloud KMS key, not a human typing unseal shares). This is standard Vault
  operations, not anything specific to this project - HashiCorp's own production hardening guide
  is the right reference, not this file.
- **How the proxy authenticates to Vault**: `vault_token` in `config.yaml` is a plain string -
  this proxy doesn't do its own Vault login flow (AppRole, Kubernetes service-account auth,
  etc.), it just uses whatever token you give it. Don't hand-type a root token here. Run **Vault
  Agent** (a standard, official HashiCorp tool) as a sidecar with auto-auth configured for
  whichever method fits your platform - AppRole for most things, Kubernetes auth if you're
  actually on Kubernetes - and have it write a short-lived token to a file. Your container's
  entrypoint reads that file and templates it into `config.yaml` before starting this proxy
  (`envsubst` against a `config.yaml.tmpl`, or an equivalent step your platform already has).
  The result: a scoped, auto-renewing, short-lived token instead of a permanent credential
  sitting in a config file.

Everything downstream of this - session-root minting via Transit, the biscuit signing keyring in
KV, real DB/AWS dynamic secrets if you use them - already works the same way against a real HA
Vault as it does against `-dev` mode. Nothing else changes.

## 3. More than one instance: the shared Postgres backend

By default, approval/hold/envelope state, saga state, and the audit log all live in a local
SQLite file plus a local JSONL file - correct and sufficient for exactly one running proxy
process. Run a second instance behind a load balancer without changing anything else, and you get
real, silent inconsistency: an approval created on instance A is invisible to instance B, and the
audit log splits into two disconnected chains.

One field fixes this:

```yaml
state_postgres_dsn: "postgres://user:pass@your-postgres-host:5432/rinwall?sslmode=require"
```

Set, every instance pointed at the same database behaves as one consistent system - approvals,
saga compensation, and the tamper-evident audit chain all work correctly across as many replicas
as you want to run. Unset (the default), you get exactly today's single-instance behavior. This
was live-verified with two real proxy processes: an approval created on one was completed on the
other, and a saga step recorded on one was correctly compensated by a denial on the other.

If you're only ever running one instance (a lot of real self-hosted deployments are), you can
skip this entirely - the SQLite/JSONL default is not a toy, it's a real, tested, working choice
for that shape of deployment.

## 4. Review your catalog before it's live

The realistic way to end up running an unreviewed tool catalog in production is the most
convenient one: `blastradius --mcp <url> --emit-registry > tools.yaml`, then straight into
`tools_path`, with nobody having actually read what the classifier decided. The classifier is
good (82-100% precision by class against hand-validated real-world tools), but "good" isn't the
same claim as "reviewed," and this is the one step in the whole pipeline that's actually about
your own judgment, not this project's.

```yaml
require_reviewed_tools: true
```

With this set, the proxy refuses to start unless **every** tool in the catalog carries a real
`reviewed_by`/`reviewed_at` - not just the ones the classifier flagged as uncertain, all of them,
including tools it's confident are read-only. Leaving `blastradius`'s own `TODO-...` placeholder
text in place doesn't count; the check rejects that specifically, not just an empty field.

```yaml
  - name: close_account
    reversibility_class: C
    reviewer_role: admin-lead
    reviewed_by: "jordan@yourcompany.com"
    reviewed_at: "2026-09-13"
    # ...
```

This is cheap insurance for a small catalog and a real forcing function for a large one - either
way, it's the only item on this list that can't be automated away, because reviewing the catalog
*is* the thing.

## 5. TLS: your ingress, not this proxy

This proxy deliberately never terminates TLS itself - that's not an oversight, it's the same
separation of concerns any reverse-proxy-shaped service makes. Put it behind whatever you already
use (nginx, an Envoy/Istio ingress, a cloud load balancer, Caddy) and terminate TLS there. If
you're running the `docker-compose.yml` reference stack as a starting point, that's the piece
you're adding on top of it, not something inside it.

## 6. Observability: what you get today, and what you have to add

`GET /metrics` returns a real JSON snapshot (`{"stages": {...}, "counters": {...}}`), every
decision lands in the audit log, and `GET /admin` now has a live activity feed (`GET
/admin/activity`, polled) showing that same decision stream in a browser, color-coded, in real
time - genuinely useful for watching one instance yourself, not yet a Prometheus/OTel export you
can scrape or a trace you can follow across services. There's no push-based shipping built in at
all: this proxy writes and serves locally, it doesn't send anything anywhere on its own.

Until that's built, the honest path is the one you'd use for any service that logs to stdout and
a local file: your platform's own log/metric collection (a Fluent Bit/Vector sidecar, a
Kubernetes DaemonSet, your cloud provider's agent) picking up the JSONL audit log and polling
`/metrics` on whatever interval you'd want a dashboard refreshed at. Not elegant, but real and
immediately available - don't wait on a native exporter to get visibility into a production
deployment.

## 7. Secrets hygiene, recapped

Every credential this project touches follows the same rule, and it's worth stating once in one
place: real secrets live in environment variables or a file your orchestration layer injects,
never in `config.yaml` itself. `ANTHROPIC_API_KEY` (the provenance judges), `mcp_upstream_auth_env`
(names an env var, never holds a value), `db_dsn_template` (the template has no credentials in
it - Vault mints those per session), the Vault token itself (§2 above) - all the same pattern.
`config.yaml` is safe to put in version control; nothing that actually authenticates you should
ever be in it.

## 8. What's still a known gap

Two things from the Roadmap in `docs/REFERENCE.md` are still true after everything above: AWS- and DB-backed
tools are read-only (a raw mutation's compensation semantics aren't designed yet), and
`internal/risk`'s scorer is a deterministic heuristic, not a trained model. Neither is a
configuration gap this doc can close - they're real, named scope boundaries, not oversights. See
the Roadmap section for the current, accurate list rather than trusting this paragraph to stay
up to date forever.

## Putting it together

A `config.yaml` with everything above applied at once - the actual shape of a real deployment,
not a toy:

```yaml
port: "8080"
upstream_url: "https://your-internal-api.example.com"
policy_path: "policies/tool_policy.rego"
tools_path: "tools.yaml"          # reviewed, not emitted-and-forgotten
require_reviewed_tools: true

audit_log_path: "/data/audit.log" # only read if state_postgres_dsn is unset
db_path: "/data/rinwall.db"   # only read if state_postgres_dsn is unset
state_postgres_dsn: "postgres://user:pass@postgres.internal:5432/rinwall?sslmode=require"

vault_addr: "https://vault.internal:8200"
vault_token: "${VAULT_TOKEN}"     # templated in from a Vault Agent auto-auth token file at startup - never hand-typed
vault_transit_key: "jit-session-root"

jwt_jwks_url: "https://your-idp.example.com/.well-known/jwks.json"
jwt_issuer: "https://your-idp.example.com/"
jwt_audience: "your-app-client-id"
```

(`${VAULT_TOKEN}` isn't native YAML interpolation - it's a placeholder for whatever templating
step your entrypoint already does; see §2.)

## One last honest note

Every claim in this document has been built and live-verified against a real running proxy -
real multi-instance Postgres state, a real JWKS-issued token, a real refusal to start on an
unreviewed catalog. What hasn't happened yet is a real design partner running this in their own
production environment, with their own IdP, their own Vault cluster, their own scale. Treat this
as a strong, tested scaffold to build your specific deployment on, not a substitute for your own
team's review of anything security-critical - the same honesty this project tries to hold itself
to everywhere else.
