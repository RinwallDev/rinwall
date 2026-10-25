# Changelog

Each entry says what changed, what you'll notice, and how to check it. Versions are
`v0.MINOR.PATCH` until 1.0; [`MAINTAINING.md`](MAINTAINING.md) describes when each part
moves.

## Unreleased

Nothing yet.

## v0.1.0

First public release.

**The gate.** RinWall sits between an agent and its tools and sorts every tool into one of
three classes: read-only, compensable (a change with a natural inverse) or irreversible.
Reads go through. Compensable calls go through after RinWall records the state they change,
and are reversed automatically if a later step in the same run fails; if that state can't
be read, the call is refused rather than run without a way back. Irreversible calls wait
until a person approves that exact request: the approval is bound by hash to the tool,
its arguments and who asked. A tool RinWall can't classify is treated as irreversible.

**Ways to run it.**

- Zero-config mode: `rinwall --mcp <url>` reads the server's tool list, classifies it and
  starts. It has no authentication, so it only listens on `127.0.0.1`.
- MCP over HTTP and over stdio (`--stdio`), for clients that launch a local server process.
  [`INTEGRATIONS.md`](INTEGRATIONS.md) has config for Claude Code, Claude Desktop, Cursor
  and your own agent code.
- A config-file mode for production: JWKS identity from your IdP, short-lived credentials
  minted per call from Vault so the agent never holds standing secrets, Postgres for state
  shared across replicas, a reviewed tool catalog, and policy in Rego.
  [`PRODUCTION.md`](PRODUCTION.md) covers it.

**Reviewing.** An admin console at `/admin` shows pending approvals, holds and a live feed
of every decision. A call held for approval returns a message written for the agent's user:
what happened, that nothing has run, where to approve, and not to call again. Every decision
is written to a tamper-evident audit log.

**Scanning.** `rinwall-blastradius` lists an MCP server's tools and classifies them without
calling any of them, printing the signals behind each verdict. `--emit-registry` writes the
result as a catalog you can review and pin. The research in
[`research/2026-10-public-mcp-scan.md`](research/2026-10-public-mcp-scan.md) was produced
with it.

**Check it:**

```bash
rinwall --version
go run ./cmd/mockupstream &
go run ./cmd/rinwall --mcp http://127.0.0.1:8000/mcp
```

The startup output should list one irreversible, one compensable and one read-only tool.

**Worth knowing.** Environment variables use the `JIT_` prefix (`JIT_JWT_SECRET`,
`JIT_STDIO_JWT`). [`THREAT_MODEL.md`](THREAT_MODEL.md) lists what RinWall defends against,
what it doesn't, and its known weak points. It hasn't had a third-party review yet.
