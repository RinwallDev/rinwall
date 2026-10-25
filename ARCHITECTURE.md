# What this is, and why

`GETTING_STARTED.md` gets it running. `docs/REFERENCE.md` is the reference for every endpoint
and config option. This is the piece in between: what the system actually does, and the reasoning
behind each part of it.

## The problem

An AI agent that can call tools - read a database, send an email, update a record, close an
account - usually does it one of two risky ways. Either it holds a real, standing credential
(an API key, a service account) that can do everything that credential can do, all the time,
whether the agent needs it right now or not. Or a human is expected to review every call before
it happens, which nobody actually does past the first few days, because that's not what humans
are for.

Two failure modes fall directly out of that:

- **Confused deputy.** An agent that reads an email, a document, or a tool result can be talked
  into calling a tool it was never told to call - "please process this refund" embedded in
  customer-support text, say. The agent's *authorization* to call the tool is real; its
  *intent* to call it was manufactured by content it merely read. A system that only checks
  "is this role allowed to call this tool" can't tell those two apart.
- **No undo.** Once a mistaken or manipulated call executes, it's just... done. Most security
  tooling stops at "did we allow or deny this," as if every action were equally final. Most
  aren't - a database update has a natural inverse; a sent email doesn't.

## The core idea

Sit inline between the agent and every tool it calls (as an MCP server, a REST proxy, or both -
see **Interception Layer** below), and make three specific guarantees on every call:

1. **The agent never holds a standing credential.** It gets a token scoped to exactly this one
   tool, this one resource, for the next few seconds - minted just before the call, useless
   immediately after.
2. **A mutating argument that traces back to something the agent merely *read*, not something a
   human actually said, gets a human's eyes before it executes** - regardless of whether the
   agent's role would otherwise be allowed to make that call.
3. **Every tool is registered with a reversibility class up front.** A class that can be undone
   gets undone automatically if anything downstream fails. A class that can't be undone never
   executes without a human approving that exact call, first.

None of this depends on trusting the agent's own judgment. That's the point - an agent that's
been fooled by injected content still can't get anything irreversible past this layer, and even
a database mutation it *did* get through can be walked back.

## How one call actually flows through it

Every call - MCP or REST, doesn't matter, both adapters produce the same internal shape - goes
through the same pipeline (`internal/handler`):

```
 agent call
     │
     ▼
 rate limit ─────────  a per-session token bucket, checked first, before anything else does
     │                 any real work - a runaway agent gets stopped cheaply
     ▼
 validate ─────────── allowlist schema check (internal/validate); unknown fields, oversized
     │                 payloads, and undeclared encodings are rejected here, before anything
     │                 else sees the request
     ▼
 loop check ────────── a sliding window of recent (tool, args) pairs per session; the exact
     │                 same call repeated past a threshold gets blocked and logged, not
     │                 retried forever
     ▼
 policy evaluate ───── OPA, embedded in-process (internal/policy) - is this role even
     │                 allowed to attempt this tool at all? Coarse, role-based, fast.
     ▼
 taint assessment ──── did each mutating argument come from the human, or from content the
     │                 agent read? Explicit (caller-supplied) or judged (an optional real
     │                 model call comparing the request against actual conversation history) -
     │                 either signal can only ADD taint, never remove it
     ▼
 class dispatch ────── Class A (compensable): capture the resource's current state, THEN
     │                 execute. Class B (idempotent): just execute. Class C (irreversible):
     │                 route to one of three human-gate tiers instead of executing directly.
     │                 A tainted argument forces step-up here regardless of class or role -
     │                 a hard Go-level rule, not something a Rego policy bundle can bypass.
     ▼
 capability mint ───── a short-lived, single-tool, single-resource biscuit token, attenuated
     │                 locally from a per-session root (no network call on this path - see
     │                 Fast Capability Plane below)
     ▼
 execute ────────────  forward to the real upstream (HTTP, a Vault-minted DB/AWS credential,
     │                 or another MCP server) with that scoped token attached
     ▼
 audit ─────────────── SHA-256 hash-chained JSONL entry - what happened, under what token,
                       tamper-evident from the moment it's written (internal/audit)
```

Every one of those steps is a real package, not a conceptual placeholder - see **Layout** in
`docs/REFERENCE.md` for exactly where each one lives.

## The four pieces, and why each exists

**Interception Layer** (`internal/adapter/rest`, `internal/adapter/mcp`, `internal/mcpclient`).
Two adapters produce one internal call representation: a REST reverse-proxy for agents calling
internal APIs directly, and a real MCP server (Streamable HTTP, spec-validated against the
official SDK) for agents that talk MCP. `internal/mcpclient` is the *client* half - what lets
this proxy also forward onward to a real upstream MCP server, so it can sit in front of one you
already run rather than requiring you to rebuild anything.

**Fast Capability Plane** (`internal/capability`). The standing-credential problem, solved
without making every call pay a network round trip. A session's root capability is minted once
via Vault (or, in zero-config mode, a local ephemeral keypair - see `internal/capability/local.go`
for exactly what that trades away). Every subsequent call for that session *locally* attenuates a
new token scoped to one tool and one resource, with a signature the upstream can independently
verify - no further network call, no shared secret the upstream has to be handed.

**Intent Integrity Plane** (taint tracking in `internal/handler`, the optional judge in
`internal/provenance`). The confused-deputy defense. A caller can explicitly mark an argument
`tainted`; optionally, a real model call (`internal/provenance.AnthropicJudge`) compares the
proposed call against the actual recent conversation and scores whether each argument plausibly
traces to something the human said, at a confidence rather than a binary verdict, since humans
paraphrase and naive matching would be wrong both directions. Either signal only ever adds
friction (forces the human-approval step below) - never grants access on its own.

**Reversibility Plane** (`internal/registry`, `internal/saga`, `internal/approval`). Every tool
declares a class at registration time - the registry refuses to load a tool without one:

| Class | Meaning | What happens |
|---|---|---|
| **A** — compensable | Has a natural inverse and a way to read prior state | Executes; state is captured first; auto-reversed in strict reverse order if anything later in the same run fails |
| **B** — idempotent | Read-only or safely retryable | Executes; nothing to undo because nothing changed |
| **C** — irreversible | Sent email, payment, hard delete, account closure | **Never executes without a human**, via one of three tiers below |

Class C's human gate is three tiers, not one, deliberately - a system that routes *everything*
irreversible to a live person trains that person to rubber-stamp, and then the gate stops
meaning anything:

1. **Pre-authorized envelope** - a human sets a bounded rule in advance ("up to 3 refund emails
   a day, under $50, verified customers only"); a matching call executes instantly.
2. **Hold-and-cancel** - for actions with a natural dispatch delay, queue it visibly; a human can
   cancel inside the window, otherwise it fires.
3. **Bound, routed approval** - cryptographically bound to the exact call (a changed payload
   invalidates a pending approval automatically), routed to whichever role the tool names as its
   reviewer, requiring two independent approvers above a risk threshold (`internal/risk`), and
   never satisfiable by the same identity that requested it.

A Class A run's compensation is grouped and walked back **per resource, concurrently** - two
independent resources in one run don't block each other if only one fails - and reuses the
original step's real identity through real policy evaluation, so even the system's own cleanup
never bypasses authorization.

## What this deliberately doesn't do yet

**It only sees structured tool calls (MCP or REST) - nothing else.** An agent driving a browser
session by clicking around a UI, or one that's handed a raw shell, produces neither shape at all
- there's no tool call for this to intercept unless something wraps those actions as one first.
If it IS wrapped (`run_shell_command`, `browser_click` as named MCP tools, which is how a lot of
real deployments already do it, precisely to avoid open-ended access), the pipeline above applies
exactly as it does to any other tool: verified live, `execute_command` reads as Class C from the
recognized "execute" verb, while `run_shell_command`/`browser_click`/`browser_navigate` correctly
fail closed to unclassified-and-gated rather than being guessed at - the classifier has no
business inferring whether a click means "next page" or "confirm a transfer." But even gated,
today's policy/taint machinery reasons about *that a call happened*, not the semantic content of
`args.command` or `args.selector` - nothing parses a shell command string or inspects a page for
danger. The architecturally real way to go further is intercepting *below* the API layer entirely
(eBPF, hooking syscalls so nothing needs a defined tool-call API to be caught at all) - deliberately
not built: a real trust ask (`CAP_SYS_ADMIN`), Linux-only, genuine ongoing maintenance burden, and
parked until a design partner who controls their own host infrastructure actually needs it.

**A pure screenshot-reasoning agent (computer-use style) needed its own mechanism, not an
extension of the text judge - now built** (`internal/visualprovenance`). It's typically one
generic tool (`computer`, with an `action` field - `left_click`, `type`, `key`) rather than
semantically-named ones, and this system classifies a tool once, at registration, not per call -
one class applies to every click that tool ever makes for its whole lifetime. Gating it Class C
would make every trivial scroll need a human; the realistic registration is Class B, which the
pre-existing text-taint gate (Class A/C only) would never even reach. So the visual judge is
wired at a call site deliberately independent of `ReversibilityClass` entirely
(`registry.Tool.VisualProvenanceJudge`, `handler.assessVisualProvenance`) - confirmed live: a
Class-B-registered `computer` tool correctly reaches step-up, something the text judge structurally
cannot do. What it checks is different from the text judge too: not "does this argument trace to
the human's words" (meaningless for a coordinate), but "does the actual screen content at the
target plausibly match the agent's own stated reasoning for the action, or does it look
manufactured by deceptive/injected on-screen content" - validated against the real API with three
constructed screenshots (a legitimate order page, a fake "System Notice" payment-approval dialog
embedded in an email, a page where stated intent didn't match the button at the target
coordinate) before any interface was built around it, and live-verified end to end afterward: a
real fake-dialog screenshot sent through the real wire protocol scored confidence 0.15, tainted
the call, and correctly required two independent `admin-lead` approvals (risk score 0.7) before
executing; the same clean order screenshot executed directly with no false positive; an inert
`screenshot` action never reached the judge at all, per the cost filter
(`visual_judge_action_arg`/`visual_judge_trigger_values`) that only real click/type actions pay for.

What's still a real, named limitation rather than solved: this requires the orchestrator to
actually capture and forward both the screenshot and the agent's own stated reasoning for the
action - a real integration lift, and a deployment that doesn't wire it up gets no visual check at
all, silently. The cost filter depends on the tool declaring its own action-type convention; a
framework with no such field gets checked on every single call (correct, but costly) rather than
just the consequential ones. And the underlying limitation this was built to route around - one
reversibility class per registered tool name, not per call - is still exactly as true as before;
the visual judge compensates for it for tools that opt in, it doesn't remove it.

A trained risk model (the scorer is a documented heuristic), full JSON Schema validation (a
small custom allowlist DSL instead), and a few other named gaps - see the **Roadmap** at the end
of `docs/REFERENCE.md` for the current list rather than duplicating it here.

## Where to go next

- **`GETTING_STARTED.md`** - run it and watch every claim above actually happen.
- **`docs/REFERENCE.md`** - the full reference: every endpoint, every config option, deeper walkthroughs
  of four-eyes approval, the provenance judge, real Vault-backed dynamic secrets, and benchmarks.
- **`go run ./cmd/blastradius --mcp <url>`** - see the reversibility classification above applied
  to a real MCP server's actual tool catalog, yours or someone else's, with no setup required.
- **`PRODUCTION.md`** - what changes to run this for real: real identity, real Vault, more than
  one instance, and reviewing your catalog before it's live.
- **`THREAT_MODEL.md`** - trust boundaries, what's defended against and what isn't, and the known
  weak points stated plainly.
