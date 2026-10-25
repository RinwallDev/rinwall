# Maintaining RinWall

This is the working playbook for whoever holds the maintainer role.
It is written so that the job can be done in a bounded weekly budget without the owner
(@knoor) in the loop for routine work, and so that it is always clear which decisions are
*not* routine and go to the owner.

The public promises this playbook exists to keep are in two places and must stay true:

- `README.md`: issues get a response within three business days.
- `SECURITY.md`: vulnerability reports are acknowledged within three business days, sooner
  for anything critical.

## Weekly rhythm

- **Every business day, one short triage pass** (ten to twenty minutes): new issues, new
  PRs, new private security advisories, CI status on `master`. Everything new gets a label
  and a first reply the same day it is seen. A first reply does not have to be an answer;
  "seen, reproducing, will update by <day>" keeps the promise.
- **One or two longer blocks per week**: reproduce bugs, review PRs, land small fixes, cut a
  release if one is due, send the weekly note (below).
- **The budget is 15 hours a week** (agreed with the owner, October 2026). The daily passes
  take one to two of those; the rest is the longer blocks. If a week needs more, say so in
  the weekly note rather than quietly absorbing it; if it needs less, that is fine.
- **Weekly note to the owner**, five lines or fewer: open issues by label, PRs waiting on
  whom, anything escalated, anything shipped, anything you need a decision on.

## Issue triage

Decision order, first match wins:

1. **Is it a vulnerability, or does it read like one?** Anything that lets an agent act
   without the gate it should have hit: bypassing an approval, forging or escaping a
   capability token, tampering with the audit chain undetected, script running in the
   reviewer console. Do not discuss it in the public issue. Reply with the canned
   *security redirect* below, open a private advisory yourself from the issue content
   (Security tab, "Report a vulnerability", then "Open a draft advisory"), and notify the
   owner the same day. Then follow the security section below.
2. **Is it a bug with a reproduction?** Label `bug`. Reproduce it against `master` with
   the shortest thing that works: usually `go test ./...` with a new case, or a zero-config
   run (`go run ./cmd/rinwall --mcp <url>`) plus one request. If it reproduces, say so and
   say what you will do. If it does not, label `needs repro` and ask for the exact request,
   config, and version (`rinwall --version`, or the first startup log line).
3. **Is it a bug without a reproduction?** Label `needs repro` and ask for the three
   things above. Close after two weeks of silence with a friendly note; reopen on reply.
4. **Is it a feature request?** Label `enhancement`. If it adds a config field, a new
   upstream kind, a new reversibility class, or changes what an existing class means,
   also label `needs design` and reply that the owner will weigh in. Those are the
   decisions `CONTRIBUTING.md` asks people to talk about first; do not accept or decline
   them yourself.
5. **Is it an integration?** (a middleware or SDK for a framework, a client config that
   does not work). Label `integration wanted`. These are the most wanted contributions;
   point at `INTEGRATIONS.md` and say so.
6. **Is it a question?** Label `question`. Answer from the docs and link the section.
   If the docs did not answer it, the docs have a bug: open a `documentation` issue or
   fix it in the same reply's PR.

Labels that must exist: `bug`, `enhancement`, `question`, `documentation`,
`good first issue`, `help wanted`, `wontfix`, `duplicate`, plus `needs repro`,
`needs design`, `integration wanted`, `security` (used only on the *redirected* public
issue, so it is findable later). Create the missing ones once:

```bash
gh label create "needs repro" --color e4e669 --description "Cannot reproduce yet; waiting on request, config, version"
gh label create "needs design" --color 5319e7 --description "Changes config, an upstream kind, or class semantics; owner decides"
gh label create "integration wanted" --color 0e8a16 --description "A framework middleware or client config we would like to exist"
gh label create "security" --color b60205 --description "Redirected to a private advisory; do not discuss here"
```

## Security reports

`SECURITY.md` is the public contract. Internally:

- **Acknowledge within one business day** when you can; three is the ceiling. The
  acknowledgement is "received, assessing against THREAT_MODEL.md, next update by <day>".
- **Assess against the guarantees** listed in `THREAT_MODEL.md`. A report that breaks one
  of them is real regardless of how exotic the setup is. A report that needs a compromised
  Vault, Postgres, or IdP is out of scope by the published policy; say so politely and
  point at the trust table.
- **Critical** means: a human gate bypassed, a capability token forged or widened, audit
  tampering undetected, script execution in the reviewer console. Tell the owner the same
  day, before any fix work. Everything else, tell the owner in the weekly note.
- **Fix in the advisory's private fork** with a regression test that demonstrates the
  property, a `CHANGELOG.md` entry that names the class of bug plainly, and a release.
  Publish the advisory when the release is out; request a CVE through GitHub if the
  reporter wants one or the issue is critical. Credit the reporter unless they decline.
- Never paste a reporter's proof-of-concept into a public issue, commit message, or the
  changelog. The changelog names the class ("a Class C tool could execute without
  approval when ..."), not the payload.

## Pull requests

Review against `CONTRIBUTING.md`, which contributors have already read:

- A test that fails without the change. For anything under `internal/handler`,
  `internal/approval`, `internal/capability`, `internal/authn`, `internal/validate`, or
  the admin console, the test must demonstrate the security property, not just cover the
  line. If you cannot tell what property a test proves from its name, ask.
- CI green. CI runs gofmt, build, vet, the suite, govulncheck, and a Docker build; a red
  govulncheck on a dependency the PR did not touch is not the contributor's problem, note
  it and handle it separately.
- A `CHANGELOG.md` entry under *Unreleased*, written for a tester.
- Comments state invariants, not history.
- No new dependency without the owner's OK. No change to `LICENSE`, `SECURITY.md`, or the
  README's status block without the owner's OK.
- Run `gitleaks detect --source . --no-git` on the PR checkout if it adds config,
  fixtures, or scripts. The repository history is clean and should stay that way.

Merge with "Squash and merge" so each PR is one commit on `master`. Thank the contributor
in the merge comment; it costs nothing and is most of what keeps people coming back.

Anything that stalls for two weeks waiting on the contributor gets one ping, then is
closed with "happy to reopen when you have time".

## Releases

Cut a release when *Unreleased* in `CHANGELOG.md` has a security fix (same day), or
otherwise roughly monthly when it has anything in it.

1. In `CHANGELOG.md`, rename *Unreleased* to the version and date, and start a fresh
   empty *Unreleased* above it. Versions are `v0.MINOR.PATCH` until the owner declares 1.0.
   A security fix or a bug fix bumps PATCH; anything that adds a config field or a flag
   bumps MINOR.
2. Commit, then tag and push the tag:

   ```bash
   git tag v0.1.1 && git push origin v0.1.1
   ```

3. `.github/workflows/release.yml` builds binaries for linux/darwin/windows on amd64 and
   arm64 (`rinwall`, `rinwall-blastradius`, `rinwall-devtoken`,
   `rinwall-auditverify`), writes `SHA256SUMS`, publishes a GitHub release with
   generated notes, and pushes `ghcr.io/rinwalldev/rinwall:<tag>`.
4. Smoke test: download the binary for your platform and run `rinwall --version`; it
   must print the tag, not `dev`. Pull the image and run it with `--help`.
5. Edit the generated release notes so the first paragraph is the changelog entry in plain
   words. The auto-generated PR list goes under it.

If the workflow fails, delete the tag (`git push origin :refs/tags/v0.1.1`), fix, retag.
Never force-push `master`.

## Running it locally

```bash
go build ./... && go vet ./... && go test ./...
```

needs nothing external. `GETTING_STARTED.md` has the `docker compose` stack with a real
Vault. `go run ./cmd/rinwall --mcp <url>` is zero-config mode against any MCP server.
Integration tests needing Postgres or AWS are gated by environment variables and skip
otherwise; see the table in `CONTRIBUTING.md`.

## Goes to the owner, always

- Anything critical under *Security reports*.
- Anything labelled `needs design`.
- New dependencies, license questions, the project name or trademark, anything that costs
  money (domains, CI minutes, a hosted anything).
- Press, podcast, partnership, acquisition, or investor contact of any kind. Reply
  "thanks, forwarding to the owner" and forward it.
- A request to make a public statement about a competitor, a vulnerability in someone
  else's product, or a named third-party MCP server from the ecosystem scan. The scan is
  published as aggregates and methodology on purpose; we do not name servers.

## Canned replies

**Security redirect** (on a public issue that reads like a vulnerability):

> Thanks for this. Because it may let an agent act without the gate it should hit, I've
> moved it to a private security advisory so it isn't public before a fix is out, and I've
> locked this issue. You'll get an invite to the advisory thread; everything continues
> there. Timeline is in SECURITY.md.

**Needs repro**:

> Thanks. I couldn't reproduce this yet. Could you share (1) the exact request or sequence
> that triggers it, (2) the config or catalog it needs with any secrets removed, and
> (3) the version (`rinwall --version`, or the first startup log line)? A failing test
> in the style of `internal/handler/handler_test.go` is the fastest route if you're up for it.

**Needs design**:

> Thanks for the proposal. This changes <a config field / an upstream kind / what a class
> means>, which is one of the decisions we talk about before anyone builds. I've labelled
> it and the owner will weigh in; expect a reply within a week.

**Out of scope by the threat model**:

> Thanks for the careful report. This one depends on <Vault / Postgres / the IdP> being
> compromised, which THREAT_MODEL.md lists as a trust boundary rather than something the
> proxy defends against. If you can get the same effect without that, it's absolutely in
> scope and I'd like to see it.
