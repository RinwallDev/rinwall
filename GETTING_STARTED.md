# Getting started

Two ways in, depending on what your agent talks to. Pick the one that matches what you have.

## 1. In front of an MCP server you already have

No configuration. RinWall reads the server's tool list, sorts every tool by whether it can be
undone, and starts:

```bash
go run ./cmd/rinwall --mcp https://your-server.example.com/mcp
```

(With a release download instead of a clone, it's `./rinwall --mcp ...`; the
[README](README.md) has the one-line install.)

It prints what it found, what it will hold for a person, and a reviewer token. Point your agent
at `http://127.0.0.1:8080/mcp` instead of the server; [`INTEGRATIONS.md`](INTEGRATIONS.md) has
the exact config for Claude Code, Claude Desktop, Cursor, and your own code. When the agent tries
something irreversible, open `http://127.0.0.1:8080/admin`, paste the token, and approve or deny.

If the server needs a token, keep it out of your shell history: put it in an environment variable
and pass the variable's name with `--mcp-auth-env`.

**No server handy?** Use the small one in this repository. It has one read, one undoable change,
and one irreversible action, which is enough to see all three behaviours:

```bash
go run ./cmd/mockupstream &
go run ./cmd/rinwall --mcp http://127.0.0.1:8000/mcp
```

To see what a server exposes before putting anything in front of it, the scanner lists and
classifies its tools without calling any of them: `go run ./cmd/blastradius --mcp <url>`.

## 2. In front of an HTTP API, with the full engine

An HTTP API doesn't publish a list of its tools the way an MCP server does, so here you describe
them in a short catalog file. Each entry names the endpoint and says what kind of action it is:

```yaml
- name: get_user
  description: "Look up a customer record by id"
  reversibility_class: B          # A = can be undone, B = read or safe to retry, C = can't be undone
  method: GET
  path: /users/{user_id}
  resource_arg: user_id
  args_schema:
    user_id: { type: string, required: true, pattern: "^[0-9]+$" }
```

[`examples/tools.yaml`](examples/tools.yaml) is a complete catalog with one tool of each kind,
including how a reversible change says what to restore and who approves an irreversible one.

This path also runs the full engine: a real secrets manager (Vault), signed identity for every
caller, and role-based policy. `docker compose` brings it all up, with a stand-in API to call:

```bash
docker compose up --build
```

Wait for it to settle (the proxy logs `listening on :8080`), then mint a token. Role matters
here: `policies/tool_policy.rego` gates each tool by role, and `admin` is the one role allowed to
attempt all three calls below (the **Basic test plan** further down shows the role gate saying no):

```bash
JWT=$(go run ./cmd/devtoken --user alex@example.com --role admin)
```

**Try it**, using that token and the example catalog:

```bash
# A read - executes immediately
curl -s -X POST localhost:8080/tool-call -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"   -d '{"agent_id":"a","tool":"get_user","args":{"user_id":"42"}}'

# A change that can be undone - executes, and would be reversed automatically if a later
# step in the same run failed (the test plan below shows that in full)
curl -s -X POST localhost:8080/tool-call -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"   -d '{"agent_id":"a","tool":"update_customer_tier","args":{"user_id":"42","tier":"gold"}}'

# Something irreversible - this one does NOT execute. It waits for a person.
curl -s -X POST localhost:8080/tool-call -H "Authorization: Bearer $JWT" -H "Content-Type: application/json"   -d '{"agent_id":"a","tool":"close_account","args":{"user_id":"42"}}'
```

That last call comes back `"status":"pending_approval"` with a `request_id` and `request_hash`.
It's routed to a specific reviewer role (`examples/tools.yaml` sets `close_account`'s to
`admin-lead`, a different person from whoever asked, which the approval step enforces). Mint an
`admin-lead` token and approve it:

```bash
LEAD=$(go run ./cmd/devtoken --user lead@example.com --role admin-lead)
curl -s -X POST localhost:8080/approvals/<request_id>/approve   -H "Authorization: Bearer $LEAD" -H "Content-Type: application/json" -d '{"hash":"<request_hash>"}'
```

*Now* it executes.

`docker compose down` stops it; add `-v` to also wipe the audit log and state for a clean
restart. To run the same engine without Docker, see **The manual way** in
[`docs/REFERENCE.md`](docs/REFERENCE.md).

## Basic test plan

A checklist, not a formality — each line is something you can actually verify yourself in a
couple of minutes against the `docker compose` stack from section 2.

- [ ] **A read executes with no friction.** The `get_user` call above returns
      `"status":"executed"` immediately.
- [ ] **The role gate is real, not decorative.** `update_customer_tier` needs `SalesManager` or
      `admin` - a `support` token gets denied outright, before reversibility class even enters
      the picture:
      ```bash
      SUPPORT=$(go run ./cmd/devtoken --user dana@example.com --role support)
      curl -s -X POST localhost:8080/tool-call -H "Authorization: Bearer $SUPPORT" -H "Content-Type: application/json" \
        -d '{"agent_id":"a","tool":"update_customer_tier","args":{"user_id":"42","tier":"gold"}}'
      # {"status":"denied","reason":"delegated_role=\"support\" is not authorized for tool=..."}
      ```
- [ ] **A reversible mutation executes, and is undone if something later fails.** `SalesManager`
      can change a tier but - unlike `admin` - can't close an account, which is exactly the
      natural denial that should trigger automatic reverse-order compensation on everything else
      in the same run:
      ```bash
      SM=$(go run ./cmd/devtoken --user jordan@example.com --role SalesManager)
      curl -s -X POST localhost:8080/tool-call -H "Authorization: Bearer $SM" -H "Content-Type: application/json" \
        -d '{"agent_id":"a","run_id":"test-1","tool":"update_customer_tier","args":{"user_id":"7","tier":"gold"}}'
      curl -s -X POST localhost:8080/tool-call -H "Authorization: Bearer $SM" -H "Content-Type: application/json" \
        -d '{"agent_id":"a","run_id":"test-1","tool":"close_account","args":{"user_id":"7"}}'
      # denied - SalesManager isn't allowed to close_account at all; re-read user 7 -
      # tier should already be back to what it was before this test, undone automatically
      curl -s -X POST localhost:8080/tool-call -H "Authorization: Bearer $SM" -H "Content-Type: application/json" \
        -d '{"agent_id":"a","tool":"get_user","args":{"user_id":"7"}}'
      ```
- [ ] **An irreversible action never executes without a human.** `close_account` (as `admin`,
      from section 2) comes back `pending_approval`, and nothing changed upstream until an
      `admin-lead` token approved it - a token with the wrong role, or the same identity that
      made the original request, both get rejected if you try them.
- [ ] **The audit log is tamper-evident, for real.** Pull it out, edit one byte, and watch it get
      caught at the exact line:
      ```bash
      docker compose cp proxy:/data/audit.log ./audit.log
      go run ./cmd/auditverify -path ./audit.log          # OK - hash chain intact
      sed -i 's/EXECUTED/EXECUTED_X/' ./audit.log          # tamper with one line
      go run ./cmd/auditverify -path ./audit.log          # TAMPERING DETECTED at that line
      ```
- [ ] **Key rotation actually propagates.** `mockupstream` fetches signing keys from the proxy
      and refreshes every 30s - rotate the key, then give it a moment and confirm a fresh call
      still verifies once that refresh lands:
      ```bash
      curl -s -X POST localhost:8080/admin/biscuit-keys/rotate -H "Authorization: Bearer $JWT"
      curl -s localhost:8080/biscuit-keys   # both the old (current:false) and new (current:true) key
      sleep 30
      curl -s -X POST localhost:8080/tool-call -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
        -d '{"agent_id":"a","tool":"get_user","args":{"user_id":"42"}}'   # still executes cleanly
      ```
- [ ] **The compliance report reflects real activity.** `GET /compliance/report` - `by_decision`
      and `by_reversibility_class` should match what you actually did above, and `audit_chain.ok`
      should be `true` (or `false`, correctly, if you left the tamper from the step above in
      place):
      ```bash
      curl -s "localhost:8080/compliance/report" -H "Authorization: Bearer $JWT" | python -m json.tool
      ```

If every box checks out, you've verified the actual claim this project makes: reversible actions
happen and can be undone, irreversible ones can't happen without a human, and the record of all
of it can't be quietly edited after the fact - not by reading the code and trusting it, by making
it happen and watching.

Watching is easier than curl, too: open `http://localhost:8080/admin`, paste an admin token, and
everything above - every read, every mutation, every denial, every auto-reversal - shows up in
the **Live Activity** feed in real time as you run the steps, no re-running curl to see what
happened.

## Where to go next

- **`ARCHITECTURE.md`** - if you just watched all this happen and want the "why," not only the
  "how": the threat model and what each piece is for.
- **`docs/REFERENCE.md`** - the full reference: every endpoint, every config option, and deeper
  walkthroughs (four-eyes approval, the model-based provenance judge, the visual provenance judge
  for screenshot-reasoning/computer-use agents, real Vault dynamic secrets for DB/AWS, benchmarks).
- **`INTEGRATIONS.md`** - paste-ready config to put the proxy in front of Claude Code, Claude
  Desktop, Cursor, or any other MCP client, over HTTP or stdio.
- **`go run ./cmd/blastradius --mcp <url>`** - point it at any MCP server (yours or someone
  else's) and get a report on how much of its tool catalog is irreversible, no setup required.
- **`docker-compose.yml` / `config/config.docker.yaml`** - what a real self-hosted deployment's
  config looks like, and what's simplified in this reference version vs. real production use
  (both files say so directly in their own comments).
- **`PRODUCTION.md`** - once this reference stack has proven itself to you, the checklist for
  actually going live: real identity, real Vault, running more than one instance, and reviewing
  your catalog before it's serving real traffic.
