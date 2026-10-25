# Integrations: putting RinWall in front of your agent

The proxy is an MCP server. Any MCP client can use it - over HTTP (clients that connect to a
URL) or over stdio (clients that launch a local server process). Pick your client below;
each entry is a config you can paste, not a description.

Two ways to run the proxy, and the configs differ only in whether they carry a token:

- **Zero-config**: `go run ./cmd/rinwall --mcp http://localhost:3000/mcp` in front of an MCP
  server you already run. No token needed - requests with no credential run as a local
  identity, and the listener is loopback-only for exactly that reason.
- **Config file**: `go run ./cmd/rinwall -config config/config.yaml` (real Vault, real policy,
  real identity). Every request needs a JWT: `go run ./cmd/devtoken --user you@example.com
  --role admin --ttl 8h` for local use, your IdP's tokens in production (`PRODUCTION.md`).

If your client launches a process, it needs the binary: download it as the [README](README.md)
shows, or build it with `go build -o rinwall ./cmd/rinwall`.

## Claude Code

HTTP transport, native. Zero-config:

```bash
claude mcp add --transport http rinwall http://127.0.0.1:8080/mcp
```

Config-file mode, with a token:

```bash
JWT=$(go run ./cmd/devtoken --user you@example.com --role admin --ttl 8h)
claude mcp add --transport http rinwall http://127.0.0.1:8080/mcp --header "Authorization: Bearer $JWT"
```

Confirm with `claude mcp list` - it performs a real `initialize` and should show
`rinwall: ... - ✓ Connected`. Inside a session, `/mcp` lists the tools with their
descriptions. Remove with `claude mcp remove rinwall`.

## Claude Desktop

Claude Desktop launches local servers over stdio, so point it at the binary with `--stdio`.
In `claude_desktop_config.json` (Settings → Developer → Edit Config):

```json
{
  "mcpServers": {
    "rinwall": {
      "command": "/absolute/path/to/rinwall",
      "args": ["--mcp", "http://localhost:3000/mcp", "--stdio"]
    }
  }
}
```

Config-file mode needs an identity for the session, passed as an environment variable:

```json
{
  "mcpServers": {
    "rinwall": {
      "command": "/absolute/path/to/rinwall",
      "args": ["-config", "/absolute/path/to/config.yaml", "--stdio"],
      "env": { "JIT_STDIO_JWT": "<token from cmd/devtoken or your IdP>" }
    }
  }
}
```

Restart Claude Desktop; the tools appear under the hammer icon. The HTTP listener still runs
alongside stdio (default port 8080, `--port` to change it) - that's where the reviewer console
lives, see below.

**Where the approval token goes.** Because Claude Desktop starts RinWall itself, you never see
its startup output, including the reviewer token you need to approve an irreversible call.
Claude Desktop writes that output to its MCP log: on macOS under `~/Library/Logs/Claude/`, on
Windows under `%APPDATA%\Claude\logs\`, in the file named after the server. Look there for the
line starting `eyJ`. This is a known rough edge; a better way to hand you the token is being
worked on.

## Cursor

HTTP transport. In `.cursor/mcp.json` (project) or `~/.cursor/mcp.json` (global):

```json
{
  "mcpServers": {
    "rinwall": {
      "url": "http://127.0.0.1:8080/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

Drop the `headers` block for zero-config mode. Cursor can also launch the binary over stdio
with the same `command`/`args` shape as the Claude Desktop entry above.

## Any other client

- **Connects to a URL** (Streamable HTTP): `POST http://127.0.0.1:8080/mcp`, `Authorization:
  Bearer <token>` unless zero-config. Protocol versions 2024-11-05 through 2025-06-18.
- **Launches a process** (stdio): `rinwall --stdio` plus either `--mcp <upstream>` or
  `-config <file>` with `JIT_STDIO_JWT` set. Newline-delimited JSON-RPC on stdin/stdout; all
  logs go to stderr.
- **Your own code**: see the next section.

## Your own agent code

Where RinWall goes depends on where your agent's tools live:

- **Your agent calls MCP tools.** Point its MCP client at `http://127.0.0.1:8080/mcp` instead of
  the server, and run RinWall in front of the server. The official MCP SDKs work unchanged;
  `scripts/mcp_client_check.py` drives the Python SDK through the handshake and a call.
- **Your agent calls an HTTP API.** Describe the API's endpoints in a catalog file
  (`GETTING_STARTED.md`, section 2, shows one), run RinWall with it, and have your agent send
  each tool call to RinWall instead of the API:

  ```bash
  curl -s -X POST http://127.0.0.1:8080/tool-call -H "Authorization: Bearer $JWT"     -H "Content-Type: application/json"     -d '{"agent_id":"my-agent","tool":"get_user","args":{"user_id":"42"}}'
  ```

  RinWall checks the call, makes the real request to your API with a short-lived credential,
  and returns the result.
- **Your agent's tools are functions in its own code.** Not supported directly yet. RinWall works
  by sitting between the agent and something it reaches over the network, so in-process
  functions have nothing for it to sit in front of. The workaround today is to expose those
  functions as a small HTTP API or MCP server. A library that wraps a function in place, so
  RinWall decides before it runs, is on the roadmap.

## What your agent will see

`tools/list` returns the catalog with real descriptions, so the model can choose tools
normally. A `tools/call` comes back one of three ways:

- **executed** - the upstream result, as usual.
- **denied** - policy, validation, or a circuit breaker said no; `isError` is true and the
  text says why.
- **pending_approval** / **pending_hold** - the action needs a human. `isError` is false (the
  call didn't fail; it's waiting), and the text carries a `request_id`. Nothing has happened
  upstream yet.

The text of a held call is written for the person, since the agent usually relays it. For
example:

> Waiting for approval (request appr-1). This action can't be undone, so it needs a person's
> approval. Nothing has happened yet. To continue, approve or deny it at
> http://127.0.0.1:8080/admin. Approving it runs it, so don't call it again.

In zero-config mode it names the console's address. In a deployment with a config file it
names the reviewer role instead, because the console's address depends on how you expose it.

**Approving:** open the console, paste a token with the tool's `reviewer_role` (zero-config
prints one at startup), and approve. **The approval itself executes the action.** That's why
the message tells the agent not to call it again: a retry is a new request and would need a
second approval. (A client-side "wait for approval" is on the roadmap.)

## Sending what makes the firewall smarter

Everything above works with a plain `tools/call`. Three optional fields in the call's `_meta`
turn on the parts that need to know more than the arguments:

```json
"_meta": {
  "run_id": "task-7f3a",
  "context_window": [{"role": "user", "content": "..."}, {"role": "tool", "content": "..."}],
  "arg_provenance": {"tier": "tainted"}
}
```

- `run_id` groups calls into one run, so a later failure or denial automatically reverses
  the earlier compensable steps.
- `context_window` lets the provenance judge decide whether an argument came from the
  human or from something the agent read (needs `ANTHROPIC_API_KEY` on the proxy and
  `provenance_judge: true` on the tool).
- `arg_provenance` is the explicit version of the same signal, if your orchestrator already
  knows.

Framework middlewares that populate these automatically are the next integration step; until
then they are yours to send.
