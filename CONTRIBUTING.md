# Contributing

Thanks for looking. This is a small project with a specific thesis - every agent action is
classified by whether it can be undone, and the system behaves accordingly - so the most
useful contributions are the ones that strengthen that thesis against real tools and real
clients. Read `ARCHITECTURE.md` first; it is short and explains why each piece exists.

## Before you start

- **Bugs** - open an issue with the request (or sequence) that reproduces it. A failing test
  is even better; `internal/handler/handler_test.go` shows the shape.
- **Security** - do not open an issue. See `SECURITY.md`.
- **Features** - open an issue first for anything that adds a config field, a new upstream
  kind, or changes what a reversibility class means. Those decisions are deliberate and we
  would rather talk before you spend a weekend on it.
- **Integrations** are the most wanted contribution. Look for issues labelled
  `integration wanted` - a middleware for a framework that auto-sends `run_id` and
  `context_window` (see `INTEGRATIONS.md`) makes the whole Intent Integrity Plane real for
  that framework's users.

## Running it

```bash
go build ./... && go vet ./... && go test ./...
```

That's the whole default suite; it needs nothing external. Integration tests that need a
real backing service are gated by environment variables and skip otherwise:

| Variable | Needs | Exercises |
|---|---|---|
| `JIT_INTEGRATION_POSTGRES=1` | a local Postgres (see `internal/approval/postgres_test.go` for the DSN default) | the multi-instance state backends |
| `JIT_INTEGRATION_AWS=1` + `JIT_TEST_S3_BUCKET` | a real AWS account via Vault | the AWS dynamic-secrets path |

`GETTING_STARTED.md` runs the whole thing with `docker compose`.

## What a pull request needs

- A test that fails without the change. Security-relevant changes (anything under
  `internal/handler`, `internal/approval`, `internal/capability`, `internal/authn`,
  `internal/validate`, the admin console) need one that demonstrates the property, not just
  the code path - look at how existing tests are named.
- `gofmt`, `go vet`, and the full suite clean. CI runs them.
- A `CHANGELOG.md` entry under *Unreleased* written for someone testing the change: what
  changed, what they'll notice, how to confirm it.
- Comments that state invariants, not history. "This must hold because X" is good;
  "we used to do Y" belongs in the commit message.

## Style

Plain Go, standard library first, no cgo (the SQLite and Postgres drivers were chosen pure-Go
on purpose). One struct with internal branching is preferred over a new interface when a
second backend arrives - see `internal/approval` for the pattern. Fail closed: when a check
can't run, the answer is "no" or "ask a human," never "probably fine."

## Maintainers

`MAINTAINING.md` is the playbook for triage, security reports, reviews, and releases. It
is public on purpose, so contributors can see what to expect and when.

## Code of conduct

`CODE_OF_CONDUCT.md`. Short version: be direct about the work, decent to the people.

## License

By contributing you agree your contribution is licensed under the Apache License 2.0, like
the rest of the project.
