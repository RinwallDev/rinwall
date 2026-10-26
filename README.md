# RinWall

A firewall for what your AI agents are allowed to *do*.

RinWall sits between your agent and the tools it calls. Before any call goes through, it
asks one question: **can this be undone?**

- **Reads** go straight through.
- **Changes that can be undone** go through, and are rolled back automatically if a later
  step in the same run fails.
- **Actions that can't be undone** (sending, paying, deleting, publishing) wait until a
  person approves that exact request.

You don't have to label anything. RinWall reads your server's tool list and classifies each
tool itself, and treats any tool it can't classify as irreversible. We measured how often it
gets this right across 800 public MCP servers: [the write-up](research/2026-10-public-mcp-scan.md).

The agent never holds your credentials, and every decision is written to a tamper-evident
audit log.

![RinWall in front of an MCP server: scan, gate, approve, execute](docs/demo.svg)

*A real recording, not a mock-up: `scripts/record_demo.py` replays it against the real
binaries.*

> **Status: v0.1, a working reference implementation.** Built, tested, and verified against
> real clients and infrastructure, but not yet run in anyone's production except our own
> test stacks, and not yet reviewed by a third party. Issues get a
> response within three business days, security reports sooner ([`SECURITY.md`](SECURITY.md)).
> Apache-2.0.

## Try it in front of your MCP server

**1. Install.** One download, no dependencies. Pick your platform: `darwin_arm64` (Apple
Silicon), `darwin_amd64`, `linux_amd64`, `linux_arm64`, or `windows_amd64` (a `.zip`).

```bash
curl -fsSL https://github.com/RinwallDev/rinwall/releases/latest/download/rinwall_darwin_arm64.tar.gz | tar xz
cd rinwall_darwin_arm64
```

Or, with Go installed: `go install github.com/RinwallDev/rinwall/cmd/rinwall@latest`.

**2. Run it in front of your server.** Leave this terminal open; you'll need what it prints.

```bash
./rinwall --mcp https://your-server.example.com/mcp
```

If your server needs a token, put it in an environment variable and name the variable:
`--mcp-auth-env MY_SERVER_TOKEN`.

**3. Point your agent at RinWall instead of the server.** For Claude Code:

```bash
claude mcp add --transport http rinwall http://127.0.0.1:8080/mcp
```

Cursor, Claude Desktop, and your own agent code are in [`INTEGRATIONS.md`](INTEGRATIONS.md).

**What you'll see.** At startup RinWall lists your server's tools sorted by what can be
undone, and prints a reviewer token:

```
  Scanned 3 tools and classified them by what they can undo:

     1 irreversible        needs a human to approve, every time
         mcp_close_account
     1 compensable         executes, and is undone automatically if the run fails
         mcp_update_customer_tier
     1 read-only/retryable executes freely

  Review pending calls:  http://127.0.0.1:8080/admin
  To approve something, paste this reviewer token into that page:
    eyJhbGci...
```

Use your agent normally. When it tries something irreversible, the call waits and the agent
is told so. Open `http://127.0.0.1:8080/admin`, paste the token, and approve or deny.

This mode needs no configuration and is meant for trying RinWall out. It has no
authentication, so it only listens on your own machine (`127.0.0.1`) and refuses any other
address. [`PRODUCTION.md`](PRODUCTION.md) covers the real setup.

**No MCP server to try it on?** The repository includes a small one with a read, an undoable
change, and an irreversible action:

```bash
git clone https://github.com/RinwallDev/rinwall && cd rinwall
go run ./cmd/mockupstream &
go run ./cmd/rinwall --mcp http://127.0.0.1:8000/mcp
```

## Other setups

| Your agent... | What to do |
|---|---|
| calls MCP tools from your own code | Point its MCP client at `http://127.0.0.1:8080/mcp`, as in step 3. |
| calls an HTTP API | Describe the API's endpoints in a short catalog file; RinWall can't read them from the API itself yet. [`GETTING_STARTED.md`](GETTING_STARTED.md) has a worked example. |
| runs tools as functions inside its own code | Not supported directly yet: RinWall needs something on the network to sit in front of. Expose the functions as a small API or MCP server. A library that wraps functions in place is on the roadmap. |
| is going to production | [`PRODUCTION.md`](PRODUCTION.md): real identity, a secrets manager, multiple replicas, a reviewed catalog. All configuration, no code. |

## Check a server before you trust it

The scanner on its own answers "what could an agent do with this server?" without running
anything. It sends only the two requests that list tools, and calls none of them:

```bash
./rinwall-blastradius --mcp https://some-server.example.com/mcp
```

We ran it across 800 public MCP servers. More than one in four exposes at least one action that
can't be undone: [the write-up](research/2026-10-public-mcp-scan.md).

## Learn more

- [`ARCHITECTURE.md`](ARCHITECTURE.md): how it works and why, in plain English.
- [`THREAT_MODEL.md`](THREAT_MODEL.md): what it defends against, what it doesn't, and its known weak points.
- [`docs/REFERENCE.md`](docs/REFERENCE.md): every endpoint, option, and guarantee, with walkthroughs you can run.
- [`CHANGELOG.md`](CHANGELOG.md): what changed in each release, and how to check it.

## Contributing

Issues and pull requests are welcome; [`CONTRIBUTING.md`](CONTRIBUTING.md) explains what a
change needs. Report security issues privately, as [`SECURITY.md`](SECURITY.md) describes,
not in a public issue. Licensed under Apache-2.0.
