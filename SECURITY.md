# Security policy

RinWall is a security control. A vulnerability in it is worse than a vulnerability in
most software, because it sits in the path of every action an agent takes and is trusted to
say no. Please report anything that lets an agent act without the gate it should have hit.

## Reporting

**Use GitHub's private vulnerability reporting** on this repository (Security tab → "Report
a vulnerability"). It opens a private advisory thread with the maintainers; nothing is
public until a fix is out. Please do not open a public issue for anything exploitable.

Include what you can: a request or sequence of requests that demonstrates the problem,
the config or catalog it needs, and which guarantee it breaks (see `THREAT_MODEL.md` for
the list of guarantees this project actually makes - a report against one of those gets
the fastest response).

## What to expect

- Acknowledgement within **3 business days**.
- A maintainer assesses impact against the threat model and keeps the
  thread updated. Anything that bypasses a human gate, forges or escapes a capability
  token, tampers with the audit chain undetected, or runs script in the reviewer console
  is treated as critical.
- A fix lands with a regression test and a `CHANGELOG.md` entry that names the class of
  bug plainly. Credit to the reporter by default, unless you'd rather not.

## In scope

The proxy (`cmd/rinwall`), every package under `internal/`, the admin console, the scanner
(`cmd/blastradius`), and the published container images and binaries.

## Out of scope

- Findings that require a compromised Vault, Postgres, or IdP - those are platform trust
  boundaries, stated as such in `THREAT_MODEL.md`.
- Zero-config mode exposed on a non-loopback address. It refuses to bind one; if you've
  patched that out, you've opted out of the guarantee.
- Denial of service against the listener itself beyond the per-user rate limit, which is a
  backstop against runaway agents, not a DoS defense.
- Prompt-injection payloads that merely lower the provenance judge's confidence. The judge
  is a signal that can only add friction, never remove it - `THREAT_MODEL.md` says so.
  A payload that gets a tainted argument *through* without step-up is in scope.

## Supported versions

The latest tagged release and `master`. There is no backport policy yet.
