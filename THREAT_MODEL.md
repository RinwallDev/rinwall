# Threat model

What this system is trying to stop, who it trusts, and where it is honestly weak. If you are
evaluating it for real use, this is the document to argue with.

## Who is trusted, and how much

| Party | Trust | Why |
|---|---|---|
| **The agent** (LLM + orchestrator loop) | **None.** | It reads attacker-controlled content by design. Every argument it sends is treated as potentially manufactured. Its `agent_id` is a label, not an identity. |
| **The delegated human** | Identity trusted, intent not assumed | Identity comes from a verified JWT (HS256 dev secret, or a real IdP via JWKS). What that human *actually asked for* is exactly what the provenance machinery tries to establish. |
| **The orchestrator integration** | Partially | It supplies `arg_provenance`, `run_id`, `context_window`, screenshots. A dishonest orchestrator can under-report taint; the model-based judge exists so the proxy can form its own view from the forwarded conversation rather than trusting a self-report. It cannot defend against an orchestrator that forwards a *fabricated* conversation. |
| **Reviewers / approvers** | Trusted humans | Verified identity, role-matched to the tool's `reviewer_role`, never the requester, two distinct people above the four-eyes threshold. Their browser is part of the trust boundary - see the admin console note below. |
| **Upstream services** | Trusted to act; not required to verify | A stock upstream ignores the forwarded capability token, so proxy-side enforcement is what binds. An upstream that verifies the token gets an independent second check (`cmd/mockupstream` shows how). |
| **Vault, Postgres, the IdP** | Infrastructure | Compromise of any of these is out of scope here and in scope for your platform's own hardening. |

## What it defends against

- **Confused deputy via injected content.** An agent that read an email, page, or tool result and
  was talked into a mutation. A tainted argument on a Class A or C tool forces human step-up
  regardless of role - a hard rule in Go, not a policy that can be misconfigured away.
- **Standing-credential theft.** The agent never holds an upstream credential. It gets a biscuit
  token scoped to one tool, one resource, and a ten-second expiry, attenuated locally from a
  per-session root. Upstream MCP credentials live in the proxy, never in the agent's context.
- **Irreversible actions with nobody looking.** Class C never executes without one of three
  human-authorized paths: a bounded pre-authorized envelope, a cancellable hold window, or a
  hash-bound routed approval.
- **A mutation that can't be put back.** Class A executes only after a pre-image snapshot is
  captured; if the snapshot fails, the mutation is refused rather than executed as silently
  irreversible. A later failure or denial in the same run walks compensable steps back in order,
  through policy, per resource.
- **Replay of a stale approval.** Approvals are bound to a hash of tool + args + resource +
  requester; a changed payload invalidates the pending approval.
- **Runaway agents.** Per-user rate limiting and identical-call loop detection, keyed on the
  verified user - not on anything the agent can vary.
- **Quiet after-the-fact edits to the record.** The audit log is a SHA-256 hash chain
  (`cmd/auditverify`), and the compliance report embeds its own verification result.

## What it explicitly does not defend against

- **A malicious or careless authorized human.** If the human really asked for it, the argument
  is genuinely theirs. That threat is handled by role policy, Class C tiering, four-eyes, and the
  audit trail - not by provenance.
- **An orchestrator that lies about the conversation.** The judge can only assess what it is
  shown. Forwarding a fabricated or edited context window defeats it.
- **Anything that never becomes a tool call.** A raw shell, a browser the agent drives directly,
  or an API it reaches without going through this proxy is invisible to it.
- **Denial of service beyond the per-user budget.** The rate limiter is a backstop against
  runaway agents, not a DoS defense for the listener itself.
- **Upstream side effects the catalog doesn't model.** Compensation restores declared fields via
  a declared reader on the same resource. Cascading effects in the upstream (a webhook it fired,
  a downstream sync) are not undone.

## Known weak points, stated plainly

1. **The provenance judge can be targeted.** It reads the same text the injection was planted
   in. The prompt fences every message as data, counts only `[user]` turns as the human, and
   treats in-band claims of authorization as evidence *of* injection - but this is hardening,
   not proof. A sufficiently clever payload can still move a confidence score. The mitigation
   that actually holds is structural: the judge can only *add* taint, so the worst a manipulated
   judge can do is fail to add friction, never remove it, and explicit `arg_provenance` from the
   orchestrator still applies. Treat the judge as one signal, not the gate.
2. **The reviewer's browser is in the trust boundary.** The admin console renders agent-supplied
   values; everything it renders is escaped, and a regression here would be a stored XSS in the
   session of the person approving irreversible actions. Keep it that way.
3. **Classification is a heuristic.** `blastradius` reads names, descriptions, and schemas. It
   fails closed (unknown → gated), and hand-validation across 800 real servers found no
   false-safe result - but "archive" that hard-deletes in your system is invisible to it. The
   `require_reviewed_tools` gate exists so an unreviewed catalog can't reach production.
4. **Compensation is a bounded subset of "undo."** Field restore from a captured pre-image, on
   the same resource, in reverse order, through policy. Real-world reversibility is wider than
   that; this is the part that is actually built and verified.
5. **HS256 is a dev secret.** Real deployments use `jwt_jwks_url` and a real IdP
   (`PRODUCTION.md`). There is no rotation story for the shared secret itself.
6. **The token forwarded to a stock upstream is advisory.** Enforcement binds at the proxy;
   an upstream that verifies the token gets defense in depth, one that doesn't gets none there.
7. **Single tenant per deployment.** One proxy serves one organization. Multi-tenant isolation
   is deliberately not attempted.
8. **No third-party security review has happened yet.** Everything above was built and tested by
   the people who wrote it.

## SOC 2 Trust Services Criteria - what is and isn't evidenced

A working reference, not a customer-facing attestation. Only what the running system actually
does is claimed.

| Criterion | What it asks | Evidenced by |
|---|---|---|
| CC6.1 logical access | Restrict access against unauthorized use | No standing credentials: verified delegated identity, per-call biscuit tokens scoped to one tool + resource + expiry |
| CC6.2 credential issuance | Register/authorize users before access | **Not claimed** - identity issuance is your IdP's job; this proxy verifies, it does not issue |
| CC6.3 least privilege | Access by job function | Per-tool `reviewer_role`, Rego role policy, tokens scoped to the single call they were minted for |
| CC6.6 external threats | Defend against threats from outside the boundary | Taint tracking and the provenance judges - the confused-deputy defense |
| CC6.7 data transmission | Control movement of information | Response field sanitization (`sanitize_fields`); partial, not a DLP claim |
| CC7.1/7.2 anomaly detection | Monitor and detect security-relevant anomalies | Loop breaker, per-user rate limit, per-stage metrics and discrete counters (e.g. `vault_unavailable`) |
| CC7.3 evaluate events | Assess whether an event indicates a failure | Risk scoring drives step-up/four-eyes before execution, not after |
| CC7.4 respond | Contain and remediate | Tiered human gates plus automatic reverse-order compensation on downstream failure |
| C1.x confidentiality | Protect designated confidential information | Sanitization; judge audit entries carry verdict and rationale only, never raw conversation or screenshots |
| A1.x availability | Meet availability commitments | **Not claimed** - HA is a deployment decision (`state_postgres_dsn`, real HA Vault), not something this code asserts |
| CC8.1 change management | Changes are authorized, tested, tracked | Test suite and commit history; a process claim, not a product feature |
