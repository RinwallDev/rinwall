// Package handler implements the six-step flow every intercepted tool call
// goes through, regardless of which adapter (REST or MCP) produced it:
// inspect/validate -> classify -> policy evaluate -> class-specific handling
// (Class A pre-image capture, Class C tiering) -> mint scoped token ->
// forward to upstream -> audit. This is the transport-agnostic core.
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/RinwallDev/rinwall/internal/approval"
	"github.com/RinwallDev/rinwall/internal/audit"
	"github.com/RinwallDev/rinwall/internal/capability"
	"github.com/RinwallDev/rinwall/internal/mcpclient"
	"github.com/RinwallDev/rinwall/internal/metrics"
	"github.com/RinwallDev/rinwall/internal/policy"
	"github.com/RinwallDev/rinwall/internal/provenance"
	"github.com/RinwallDev/rinwall/internal/proxytypes"
	"github.com/RinwallDev/rinwall/internal/registry"
	"github.com/RinwallDev/rinwall/internal/risk"
	"github.com/RinwallDev/rinwall/internal/saga"
	"github.com/RinwallDev/rinwall/internal/validate"
	"github.com/RinwallDev/rinwall/internal/visualprovenance"
)

// provenanceConfidenceThreshold: a judge assessment below this joins the
// same tainted-args set an explicit arg_provenance:"tainted" would - one
// threshold, one machinery, no parallel decision path.
const provenanceConfidenceThreshold = 0.5

const tokenTTL = 10 * time.Second

type Handler struct {
	Registry   *registry.Registry
	Policy     *policy.Engine
	Capability capability.RootIssuer
	Approvals  *approval.Store
	Audit      *audit.Logger
	Metrics    *metrics.Recorder
	Risk       risk.Scorer
	Sagas      *saga.Store
	// ProvenanceJudge is nil unless cmd/rinwall sets it - the model-based
	// provenance add-on is opt-in at the deployment level (a judge must be
	// configured at all) AND per-tool (registry.Tool.ProvenanceJudge), on
	// top of the caller supplying a context window for that specific call.
	// All three gates must be open; any one absent means the existing
	// self-reported-taint path is the only thing that runs, unchanged.
	ProvenanceJudge provenance.Judge
	// VisualProvenanceJudge is the screenshot-reasoning analog - nil
	// unless cmd/rinwall configures it, opt-in the same three-gate way
	// (deployment-level judge configured, registry.Tool.VisualProvenanceJudge
	// set, AND the caller supplies both a screenshot and stated intent for
	// this specific call). Checked at a call site independent of
	// ReversibilityClass - see assessVisualProvenance's own doc comment for
	// why that's deliberate, not an oversight matching ProvenanceJudge's
	// A/C-only gate.
	VisualProvenanceJudge visualprovenance.Judge
	UpstreamBase          string
	HTTPClient            *http.Client

	// ReviewURL is where a person approves or cancels a held call, when
	// cmd/rinwall knows it (zero-config mode: the loopback console). It
	// only shapes the message the agent relays to its user; it is never a
	// credential and grants nothing. Empty means "unknown" - a real
	// deployment's console may sit behind the operator's own ingress, so
	// the message names the reviewer role instead of guessing a URL.
	ReviewURL string

	// DBSecrets/DBDSNTemplate are nil/empty unless cmd/rinwall configures
	// them - the real Vault database dynamic-secrets path (see
	// dbquery.go) is opt-in the same way ProvenanceJudge is: a tool only
	// takes this path at all if registry.Tool.IsDBBacked() is true, and
	// that path only works if a minter is actually wired up here.
	// DBDSNTemplate is a printf-style DSN with two %s placeholders
	// (username, password) - everything else about the connection
	// (host/port/database/sslmode) is fixed per deployment, only the
	// per-session credential varies.
	DBSecrets     capability.DBCredentialMinter
	DBDSNTemplate string

	// AWSSecrets/AWSRegion are the AWS analog - nil/empty unless
	// cmd/rinwall configures them, opt-in the same way. AWSRegion is the
	// one piece of AWS SDK config that doesn't vary per credential (the
	// bucket a tool reads is registry.Tool.S3Bucket, per-tool, since
	// different aws-backed tools could plausibly target different
	// buckets).
	AWSSecrets capability.AWSCredentialMinter
	AWSRegion  string

	// MCPUpstream is the client half of MCP-to-MCP passthrough - nil
	// unless cmd/rinwall configures an upstream MCP server, opt-in the same
	// way the others are, and only reached by a tool that sets mcp_tool.
	// It holds the upstream's own credential, which is precisely what
	// keeps that credential out of the agent's context - see mcpcall.go.
	MCPUpstream *mcpclient.Client

	sagaMu    sync.Mutex
	preImages map[string]json.RawMessage // key: tool+"|"+resource - LastPreImage's cache, separate from the ordered per-run trace in Sagas

	loops   *loopGuard
	rates   *rateLimiter
	caps    *sessionCapabilityCache
	dbCache *sessionDBCache
}

func New(reg *registry.Registry, pol *policy.Engine, cap capability.RootIssuer, appr *approval.Store, aud *audit.Logger, sagas *saga.Store, upstreamBase string) *Handler {
	return &Handler{
		Registry:     reg,
		Policy:       pol,
		Capability:   cap,
		Approvals:    appr,
		Audit:        aud,
		Metrics:      metrics.New(),
		Risk:         risk.HeuristicScorer{},
		Sagas:        sagas,
		UpstreamBase: upstreamBase,
		HTTPClient:   &http.Client{Timeout: 5 * time.Second},
		preImages:    make(map[string]json.RawMessage),
		loops:        newLoopGuard(),
		rates:        newRateLimiter(),
		caps:         newSessionCapabilityCache(),
		dbCache:      newSessionDBCache(),
	}
}

// sessionKeyFor is the one place the session identity that scopes rate
// limiting, loop detection, AND the capability root cache is computed.
// It is the VERIFIED delegated user only. AgentID is a caller-supplied
// label with no verification behind it; keying on it would let an agent
// escape both circuit breakers, and force a fresh Vault root mint per
// call, simply by varying the label. Anything that gates or rate-limits
// must key on something the caller can't choose.
func sessionKeyFor(req proxytypes.CallRequest) string {
	return req.DelegatedUser
}

// Handle is the public entry point every adapter calls. It wraps
// handleInner with the saga compensation trigger: a denial or error within
// a tracked run (req.RunID set) walks that run's executed Class A steps in
// reverse and compensates them - see CompensateRun. handleInner has no
// knowledge of this; it just returns whatever the call's actual outcome
// was, same as every phase before this one.
func (h *Handler) Handle(ctx context.Context, req proxytypes.CallRequest) (proxytypes.CallResult, error) {
	result, err := h.handleInner(ctx, req)
	if err == nil && req.RunID != "" && (result.Status == "denied" || result.Status == "error") {
		h.CompensateRun(ctx, req.RunID, fmt.Sprintf("%s on %s returned %s: %s", req.Tool, req.RunID, result.Status, result.Reason))
	}
	return result, err
}

func (h *Handler) handleInner(ctx context.Context, req proxytypes.CallRequest) (proxytypes.CallResult, error) {
	defer h.Metrics.Timer("total")()

	sessionKey := sessionKeyFor(req)
	if !h.rates.Allow(sessionKey) {
		h.Audit.Write(map[string]any{"decision": "DENY", "tool": req.Tool, "delegated_role": req.DelegatedRole,
			"reason": "circuit breaker: rate limit exceeded for this session", "transport": req.Transport, "agent_id": req.AgentID})
		return proxytypes.CallResult{Status: "denied", Reason: "rate limit exceeded - too many tool calls in a short window"}, nil
	}

	tool, ok := h.Registry.Get(req.Tool)
	if !ok {
		h.Audit.Write(map[string]any{"decision": "DENY", "tool": req.Tool, "delegated_role": req.DelegatedRole,
			"reason": "unknown tool", "transport": req.Transport, "agent_id": req.AgentID})
		return proxytypes.CallResult{Status: "denied", Reason: "unknown tool"}, nil
	}

	validateDone := h.Metrics.Timer("validate")
	cleanArgs, err := validate.Validate(tool.ArgsSchema, req.Args)
	validateDone()
	if err != nil {
		h.Audit.Write(map[string]any{"decision": "DENY", "tool": req.Tool, "delegated_role": req.DelegatedRole,
			"reason": "validation: " + err.Error(), "transport": req.Transport, "agent_id": req.AgentID})
		return proxytypes.CallResult{Status: "denied", Reason: "validation failed: " + err.Error()}, nil
	}

	if h.loops.tooManyRepeats(sessionKey, req.Tool, cleanArgs) {
		h.Audit.Write(map[string]any{"decision": "DENY", "tool": req.Tool, "delegated_role": req.DelegatedRole,
			"reason":    "circuit breaker: identical call repeated too many times in a short window (possible loop/hallucination)",
			"transport": req.Transport, "agent_id": req.AgentID, "args": cleanArgs})
		return proxytypes.CallResult{Status: "denied", Reason: "circuit breaker: this exact call has repeated too many times recently"}, nil
	}

	policyDone := h.Metrics.Timer("policy")
	decision, err := h.Policy.Evaluate(ctx, map[string]any{
		"tool":                req.Tool,
		"delegated_role":      req.DelegatedRole,
		"reversibility_class": string(tool.ReversibilityClass),
		"args":                cleanArgs,
	})
	policyDone()
	if err != nil {
		return proxytypes.CallResult{}, fmt.Errorf("handler: policy evaluation: %w", err)
	}
	if !decision.Allow {
		h.Audit.Write(map[string]any{"decision": "DENY", "tool": req.Tool, "delegated_role": req.DelegatedRole,
			"reason": decision.Reason, "transport": req.Transport, "agent_id": req.AgentID, "args": cleanArgs})
		return proxytypes.CallResult{Status: "denied", Reason: decision.Reason}, nil
	}

	resource := ""
	if tool.ResourceArg != "" {
		resource = fmt.Sprintf("%v", cleanArgs[tool.ResourceArg])
	}

	// Intent Integrity Plane: a fully-authorized role is never sufficient
	// on its own for a tainted, mutating argument - this is a hard Go-level
	// rule, not a Rego policy, deliberately: a misconfigured or overly
	// permissive policy bundle must not be able to bypass it. Class B is
	// exempt by design (idempotent/retry-safe, not a real mutation in the
	// sense this check cares about); Class A and C both force the same
	// step-up path regardless of what policy or Class C's own tiering
	// would otherwise have allowed.
	if tool.ReversibilityClass == registry.ClassA || tool.ReversibilityClass == registry.ClassC {
		mergedProvenance := h.assessProvenance(ctx, tool, cleanArgs, req)
		if tainted := risk.TaintedArgs(mergedProvenance); len(tainted) > 0 {
			return h.stepUp(ctx, tool, cleanArgs, resource, req, tainted, mergedProvenance)
		}
	}

	// Visual provenance: deliberately INDEPENDENT of ReversibilityClass,
	// unlike the text check above - see assessVisualProvenance's own doc
	// comment and registry.Tool.VisualProvenanceJudge for why the A/C-only
	// gate would otherwise never reach this tool shape at all.
	if visualTainted, visualProvenance := h.assessVisualProvenance(ctx, tool, cleanArgs, req); len(visualTainted) > 0 {
		return h.stepUp(ctx, tool, cleanArgs, resource, req, visualTainted, visualProvenance)
	}

	switch tool.ReversibilityClass {
	case registry.ClassC:
		return h.handleClassC(ctx, tool, cleanArgs, resource, req)
	case registry.ClassA:
		return h.execute(ctx, tool, cleanArgs, resource, req, "class_a_direct")
	default: // ClassB
		return h.execute(ctx, tool, cleanArgs, resource, req, "class_b_direct")
	}
}

// assessProvenance returns the provenance map that actually governs this
// call's taint decision: the caller's explicit arg_provenance, OR-combined
// with the model-based judge's verdict when all three gates are open (a
// judge is configured, this tool opted in, and a context window was
// supplied for this call). OR-combined means the judge can only ADD taint,
// never remove an explicit one - consistent with every soft signal in this
// system only ever adding friction. If any gate is closed, this returns
// the caller's map unchanged and the existing self-reported path is the
// only thing that ran.
func (h *Handler) assessProvenance(ctx context.Context, tool registry.Tool, cleanArgs map[string]any, req proxytypes.CallRequest) map[string]proxytypes.Provenance {
	merged := make(map[string]proxytypes.Provenance, len(req.ArgProvenance))
	for k, v := range req.ArgProvenance {
		merged[k] = v
	}

	if h.ProvenanceJudge == nil || !tool.ProvenanceJudge || len(req.ContextWindow) == 0 {
		return merged
	}

	ctxWindow := make([]provenance.Message, len(req.ContextWindow))
	for i, m := range req.ContextWindow {
		ctxWindow[i] = provenance.Message{Role: m.Role, Content: m.Content}
	}

	assessments, usage, err := h.ProvenanceJudge.Assess(ctx, ctxWindow, tool.Name, cleanArgs)
	if err != nil {
		// A judge failure is not a security failure - it just means this
		// call falls back to whatever was explicitly reported, same as any
		// deployment without the add-on configured at all.
		h.Audit.Write(map[string]any{"decision": "PROVENANCE_JUDGE_ERROR", "tool": tool.Name,
			"reason": "judge call failed, falling back to explicit arg_provenance only: " + err.Error()})
		return merged
	}

	// One usage entry per CALL, not per argument - a single real API
	// request judges every argument in the call at once, so this is what
	// internal/usage's cost report bills against; the per-argument
	// PROVENANCE_JUDGED entries below stay unchanged (compliance.Generate
	// already counts those) and would double-count cost if reused for it.
	if usage.InputTokens > 0 || usage.OutputTokens > 0 {
		h.Audit.Write(map[string]any{"decision": "PROVENANCE_JUDGE_USAGE", "tool": tool.Name,
			"reason":       "real per-call token usage from the judge's API response",
			"input_tokens": usage.InputTokens, "output_tokens": usage.OutputTokens})
	}

	for arg, assessment := range assessments {
		h.Audit.Write(map[string]any{"decision": "PROVENANCE_JUDGED", "tool": tool.Name, "arg": arg,
			"reason": fmt.Sprintf("confidence=%.2f: %s", assessment.Confidence, assessment.Rationale)})
		if assessment.Confidence < provenanceConfidenceThreshold {
			merged[arg] = proxytypes.ProvenanceTainted
		}
	}
	return merged
}

// visualJudgeConfidenceThreshold mirrors provenanceConfidenceThreshold -
// same reasoning, different modality: below this, the action's target
// doesn't plausibly match the agent's own stated intent, or looks
// manufactured by deceptive/injected on-screen content.
const visualJudgeConfidenceThreshold = 0.5

// assessVisualProvenance is the screenshot-reasoning analog of
// assessProvenance, and deliberately NOT folded into it or into the A/C-only
// gate that calls assessProvenance. Two reasons, both load-bearing:
//
//  1. The question is different. assessProvenance asks whether an
//     argument's VALUE traces to the human's words - meaningless for a
//     coordinate. This asks whether the actual screen content at the
//     target plausibly matches the agent's OWN stated reasoning for the
//     action, or looks manufactured by deceptive/injected content -
//     validated against the real API before this function existed (see
//     internal/visualprovenance's package doc for the three real test
//     screenshots and how each scored).
//  2. The trigger has to be independent of ReversibilityClass. A pure
//     screenshot-reasoning ("computer use") tool is typically one generic
//     tool with an action discriminator, not semantically-named actions -
//     internal/classify correctly fails such a tool closed to
//     unclassifiable, but this system assigns a class once per registered
//     tool NAME, not per call. Class C makes every scroll need a human
//     (unusable); Class B - the realistic outcome - means the A/C-only
//     gate above would never even call this function. So this runs for
//     every class, gated on its own opt-in flag instead.
//
// Returns (nil, nil) whenever any gate is closed: no judge configured, the
// tool didn't opt in, or the caller didn't supply both a screenshot and a
// stated intent for this call - same "caller hasn't integrated it, keep
// today's behavior" compatibility default as everywhere else taint is
// optionally supplied.
func (h *Handler) assessVisualProvenance(ctx context.Context, tool registry.Tool, cleanArgs map[string]any, req proxytypes.CallRequest) ([]string, map[string]proxytypes.Provenance) {
	if h.VisualProvenanceJudge == nil || !tool.VisualProvenanceJudge || len(req.Screenshot) == 0 || req.StatedIntent == "" {
		return nil, nil
	}

	// Cost filter: a real multimodal model call on every scroll and
	// screenshot is a cost nobody wants, and most of a computer-use tool's
	// calls are exactly that - inert. Skip anything that isn't a
	// recognized consequential action, per the tool's own declared
	// discriminator. No configured filter means no skipping - the honest,
	// costlier default for a tool with no action-type convention at all.
	if tool.VisualJudgeActionArg != "" {
		actionVal, _ := cleanArgs[tool.VisualJudgeActionArg].(string)
		triggered := false
		for _, v := range tool.VisualJudgeTriggerValues {
			if v == actionVal {
				triggered = true
				break
			}
		}
		if !triggered {
			return nil, nil
		}
	}

	argsJSON, _ := json.Marshal(cleanArgs)
	actionDesc := fmt.Sprintf("%s(%s)", tool.Name, string(argsJSON))

	assessment, usage, err := h.VisualProvenanceJudge.Assess(ctx, req.Screenshot, req.StatedIntent, actionDesc)
	if err != nil {
		// Same posture as the text judge: a judge failure is not a
		// security failure - it just means this call falls back to
		// whatever role/policy would otherwise have decided, same as any
		// deployment without the add-on configured at all.
		h.Audit.Write(map[string]any{"decision": "VISUAL_PROVENANCE_JUDGE_ERROR", "tool": tool.Name,
			"reason": "visual judge call failed, proceeding without a visual check: " + err.Error()})
		return nil, nil
	}
	if usage.InputTokens > 0 || usage.OutputTokens > 0 {
		h.Audit.Write(map[string]any{"decision": "VISUAL_PROVENANCE_JUDGE_USAGE", "tool": tool.Name,
			"reason":       "real per-call token usage from the visual judge's API response",
			"input_tokens": usage.InputTokens, "output_tokens": usage.OutputTokens})
	}
	// The verdict and rationale are logged; the raw screenshot never is -
	// the same privacy-conscious default as the text judge never logging
	// raw conversation content, here mattering more, not less, since a
	// screenshot routinely contains far more than the one argument being
	// judged.
	h.Audit.Write(map[string]any{"decision": "VISUAL_PROVENANCE_JUDGED", "tool": tool.Name,
		"reason": fmt.Sprintf("confidence=%.2f: %s", assessment.Confidence, assessment.Rationale)})

	if assessment.Confidence >= visualJudgeConfidenceThreshold {
		return nil, nil
	}
	// Below threshold: the whole call is now suspect, not one specific
	// field - unlike text taint, there is no single argument this verdict
	// naturally attaches to (a coordinate pair isn't "the tainted part," the
	// ACTION is), so every argument present in this call is marked tainted.
	tainted := make(map[string]proxytypes.Provenance, len(cleanArgs))
	names := make([]string, 0, len(cleanArgs))
	for name := range cleanArgs {
		tainted[name] = proxytypes.ProvenanceTainted
		names = append(names, name)
	}
	if len(names) == 0 {
		// A call with no arguments at all still needs SOMETHING to name as
		// tainted, or risk.TaintedArgs would see an empty map and this
		// verdict would silently vanish instead of forcing step-up.
		names = []string{"_visual_action"}
		tainted["_visual_action"] = proxytypes.ProvenanceTainted
	}
	return names, tainted
}

// stepUp forces a call through bound, routed approval regardless of role
// authorization or (for Class C) whether a pre-authorized envelope would
// otherwise have matched - a tainted argument means the specific VALUE
// needs a human's eyes, not just confirmation that the role is allowed to
// use this tool in general. The risk score decides whether one approver is
// enough or whether four-eyes (two distinct, non-requester approvers) is
// required; it never decides whether to skip this step entirely.
func (h *Handler) stepUp(ctx context.Context, tool registry.Tool, cleanArgs map[string]any, resource string, req proxytypes.CallRequest, taintedArgs []string, mergedProvenance map[string]proxytypes.Provenance) (proxytypes.CallResult, error) {
	score := h.Risk.Score(tool.Name, tool.ReversibilityClass, mergedProvenance)
	required := risk.RequiredApprovals(score)

	pending, err := h.Approvals.CreateApproval(tool.Name, cleanArgs, resource, req.DelegatedUser, tool.ReviewerRole, 5*time.Minute, required, score, taintedArgs, req.RunID)
	if err != nil {
		return proxytypes.CallResult{}, fmt.Errorf("handler: create step-up approval: %w", err)
	}
	h.Audit.Write(map[string]any{"decision": "PENDING", "tool": tool.Name, "delegated_role": req.DelegatedRole,
		"reason": fmt.Sprintf("step-up: tainted args %v (risk_score=%.2f, requires %d approver(s)), routed to reviewer_role=%s, bound to hash %s",
			taintedArgs, score, required, tool.ReviewerRole, pending.Hash),
		"transport": req.Transport, "agent_id": req.AgentID, "args": cleanArgs})
	return proxytypes.CallResult{Status: "pending_approval", RequestID: pending.ID, RequestHash: pending.Hash,
		RiskScore: score, RequiredApprovals: required, TaintedArgs: taintedArgs,
		Reason: h.approvalMessage(
			fmt.Sprintf("%s came from content the agent read, not from the person it acts for, so this call needs %s.",
				argList(taintedArgs), approvalCount(required)),
			tool.ReviewerRole, pending.ID)}, nil
}

// --- Class A: capture a pre-image before the mutation ----------------------

// capturePreImage runs immediately before a Class A mutation, from inside
// execute() itself - the one choke point every Class A path (direct,
// step-up approved, tier-1 envelope) goes through. Returns nil on any
// failure, including a non-2xx upstream status: a 404 or 500 body is not a
// snapshot, and storing it as one would make a later compensation restore
// garbage. The read carries the same scoped capability token as the
// mutation it precedes, so an upstream that authenticates reads sees a
// valid token for exactly this tool and resource rather than nothing.
func (h *Handler) capturePreImage(ctx context.Context, tool registry.Tool, resource, token string) json.RawMessage {
	if tool.PreImage == nil {
		return nil
	}
	path := strings.ReplaceAll(tool.PreImage.Path, "{"+tool.ResourceArg+"}", resource)
	httpReq, err := http.NewRequestWithContext(ctx, tool.PreImage.Method, h.UpstreamBase+path, nil)
	if err != nil {
		return nil
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	resp, err := h.HTTPClient.Do(httpReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[saga] warning: could not capture pre-image for %s/%s: %v\n", tool.Name, resource, err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "[saga] warning: pre-image read for %s/%s returned HTTP %d\n", tool.Name, resource, resp.StatusCode)
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil || !json.Valid(body) {
		return nil
	}

	h.sagaMu.Lock()
	h.preImages[tool.Name+"|"+resource] = json.RawMessage(body)
	h.sagaMu.Unlock()

	h.Audit.Write(map[string]any{"decision": "SNAPSHOT", "tool": tool.Name, "resource": resource,
		"reason": "pre-image captured for possible compensation", "pre_image": json.RawMessage(body)})
	return json.RawMessage(body)
}

// LastPreImage exposes the most recent captured snapshot for a
// tool+resource - a diagnostic view. Automated compensation restores from
// the saga store's own copy, not from here.
func (h *Handler) LastPreImage(tool, resource string) (json.RawMessage, bool) {
	h.sagaMu.Lock()
	defer h.sagaMu.Unlock()
	v, ok := h.preImages[tool+"|"+resource]
	return v, ok
}

// --- Class C: three-tier gate ------------------------------------------------

func (h *Handler) handleClassC(ctx context.Context, tool registry.Tool, cleanArgs map[string]any, resource string, req proxytypes.CallRequest) (proxytypes.CallResult, error) {
	// Tier 1: pre-authorized envelope.
	if env, ok := h.Approvals.CheckPreAuth(tool.Name, cleanArgs); ok {
		h.Audit.Write(map[string]any{"decision": "ALLOW", "tool": tool.Name, "delegated_role": req.DelegatedRole,
			"reason": "tier1: matched pre-authorized envelope " + env.ID, "transport": req.Transport, "agent_id": req.AgentID})
		return h.execute(ctx, tool, cleanArgs, resource, req, "tier1_envelope:"+env.ID)
	}

	// Tier 2: hold-and-cancel window, for tools with a natural dispatch delay.
	if tool.Deferrable {
		hold, err := h.Approvals.EnqueueHold(tool.Name, cleanArgs, tool.HoldSeconds, req.DelegatedUser, req.DelegatedRole, req.AgentID, req.RunID, tool.ReviewerRole, func() {
			h.Audit.Write(map[string]any{"decision": "ALLOW", "tool": tool.Name, "delegated_role": req.DelegatedRole,
				"reason": "tier2: hold window elapsed uncancelled, firing", "transport": req.Transport, "agent_id": req.AgentID})
			if _, err := h.execute(context.Background(), tool, cleanArgs, resource, req, "tier2_hold_fired"); err != nil {
				fmt.Fprintf(os.Stderr, "[handler] hold-fired execution error: %v\n", err)
			}
		})
		if err != nil {
			return proxytypes.CallResult{}, fmt.Errorf("handler: enqueue hold: %w", err)
		}
		h.Audit.Write(map[string]any{"decision": "HOLD", "tool": tool.Name, "delegated_role": req.DelegatedRole,
			"reason":    fmt.Sprintf("tier2: queued, fires in %ds unless cancelled (hold %s)", tool.HoldSeconds, hold.ID),
			"transport": req.Transport, "agent_id": req.AgentID})
		return proxytypes.CallResult{Status: "pending_hold", HoldID: hold.ID, FiresInS: tool.HoldSeconds,
			Reason: h.holdMessage(tool.HoldSeconds, tool.ReviewerRole, hold.ID)}, nil
	}

	// Tier 3: bound, routed approval - the irreducible remainder. No taint
	// involved on this path (stepUp already intercepted that case before
	// handleClassC was ever called), so a single approver and a zero risk
	// score are correct here.
	pending, err := h.Approvals.CreateApproval(tool.Name, cleanArgs, resource, req.DelegatedUser, tool.ReviewerRole, 5*time.Minute, 1, 0, nil, req.RunID)
	if err != nil {
		return proxytypes.CallResult{}, fmt.Errorf("handler: create approval: %w", err)
	}
	h.Audit.Write(map[string]any{"decision": "PENDING", "tool": tool.Name, "delegated_role": req.DelegatedRole,
		"reason":    fmt.Sprintf("tier3: routed to reviewer_role=%s, bound to hash %s", tool.ReviewerRole, pending.Hash),
		"transport": req.Transport, "agent_id": req.AgentID, "args": cleanArgs})
	return proxytypes.CallResult{Status: "pending_approval", RequestID: pending.ID, RequestHash: pending.Hash,
		Reason: h.approvalMessage("This action can't be undone, so it needs a person's approval.",
			tool.ReviewerRole, pending.ID)}, nil
}

// The messages below are what an agent relays to the person it acts for
// when a call is held, so they are written for that person, not for an
// API client: what happened, where to act, and that retrying is wrong.
// Machine-readable detail (request_id, request_hash, required_approvals)
// stays in its own CallResult fields; nothing here is parsed by anything.
// The audit log keeps its own, differently-worded reasons, which is what
// internal/compliance reads.

// approvalMessage is the text for a call waiting on one or more approvals.
func (h *Handler) approvalMessage(why, reviewerRole, requestID string) string {
	where := fmt.Sprintf("a reviewer with the %q role can approve or deny it in the RinWall console", reviewerRole)
	if h.ReviewURL != "" {
		where = "approve or deny it at " + h.ReviewURL
	}
	return fmt.Sprintf("Waiting for approval (request %s). %s Nothing has happened yet. To continue, %s. "+
		"Approving it runs it, so don't call it again.", requestID, why, where)
}

// holdMessage is the text for a call that will run on its own unless cancelled.
func (h *Handler) holdMessage(seconds int, reviewerRole, holdID string) string {
	where := fmt.Sprintf("a reviewer with the %q role can cancel it in the RinWall console", reviewerRole)
	if h.ReviewURL != "" {
		where = "cancel it at " + h.ReviewURL
	}
	return fmt.Sprintf("Scheduled (hold %s). This action can't be undone, so it waits %ds before it runs, "+
		"in case someone wants to stop it. To stop it, %s. Don't call it again: it will run on its own.",
		holdID, seconds, where)
}

func argList(args []string) string {
	if len(args) == 0 {
		return "Part of this call"
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = fmt.Sprintf("%q", a)
	}
	if len(quoted) == 1 {
		return "The value for " + quoted[0]
	}
	return "The values for " + strings.Join(quoted, ", ")
}

func approvalCount(n int) string {
	if n <= 1 {
		return "a person's approval"
	}
	return fmt.Sprintf("approval from %d different people", n)
}

// ReplayHold resumes a Tier-2 hold that survived a restart via
// approval.Store's persistence (see internal/approval/persist.go). cmd/rinwall
// calls this once at startup for every ResumableHoldIDs() entry, wired as
// the onFire callback to ScheduleResumedHold.
func (h *Handler) ReplayHold(ctx context.Context, toolName string, args map[string]any, requestedBy, delegatedRole, agentID string) {
	tool, ok := h.Registry.Get(toolName)
	if !ok {
		fmt.Fprintf(os.Stderr, "[handler] warning: resumed hold references unknown tool %q, skipping\n", toolName)
		return
	}
	resource := ""
	if tool.ResourceArg != "" {
		resource = fmt.Sprintf("%v", args[tool.ResourceArg])
	}
	req := proxytypes.CallRequest{Transport: "resumed", AgentID: agentID, DelegatedUser: requestedBy, DelegatedRole: delegatedRole, Tool: toolName}
	h.Audit.Write(map[string]any{"decision": "ALLOW", "tool": toolName, "delegated_role": delegatedRole,
		"reason": "tier2: resumed after restart, hold window already elapsed or elapsing now", "transport": "resumed", "agent_id": agentID})
	if _, err := h.execute(ctx, tool, args, resource, req, "tier2_hold_resumed"); err != nil {
		fmt.Fprintf(os.Stderr, "[handler] resumed hold execution error: %v\n", err)
	}
}

// CompleteApproval is called by the /approvals/{id}/approve endpoint once
// the store has verified the hash still matches the original request.
func (h *Handler) CompleteApproval(ctx context.Context, p *approval.PendingApproval, req proxytypes.CallRequest) (proxytypes.CallResult, error) {
	tool, ok := h.Registry.Get(p.Tool)
	if !ok {
		return proxytypes.CallResult{}, fmt.Errorf("handler: approved request references unknown tool %q", p.Tool)
	}
	req.RunID = p.RunID // the pending record is the source of truth for which run this belongs to, not whatever the approver's ad-hoc request carried
	h.Audit.Write(map[string]any{"decision": "ALLOW", "tool": p.Tool, "delegated_role": req.DelegatedRole,
		"reason": "tier3: approved by reviewer, hash matched", "transport": req.Transport, "agent_id": req.AgentID})
	return h.execute(ctx, tool, p.Args, p.Resource, req, "tier3_approved:"+p.ID)
}

// CompensateRun compensates a run's executed Class A steps, grouped by
// RESOURCE rather than treated as one flat list. That grouping is the real
// dependency structure: two steps on the SAME resource may genuinely
// depend on each other (a later one may have been built on an earlier
// one's effect), so that pairing is still walked in strict REVERSE order,
// exactly as before. Two steps on DIFFERENT resources share nothing, so
// they have no real ordering dependency at all - each resource's chain is
// compensated independently and concurrently, and a failure in one
// resource's chain only stops THAT chain, never an unrelated one - see
// compensateResourceChain for why stopping still matters WITHIN one
// resource's chain.
//
// Called from two places: Handle's wrapper, when a call within a tracked
// run comes back denied or errored, and internal/adapter/rest's /deny
// endpoint, when a reviewer explicitly denies a pending approval that
// belongs to a tracked run. Both call sites just need a runID - this
// method is a no-op if the run has nothing compensable, so callers never
// need to check first.
func (h *Handler) CompensateRun(ctx context.Context, runID, triggerReason string) {
	if !h.Sagas.HasCompensableSteps(runID) {
		return
	}
	steps := h.Sagas.StepsFor(runID)

	// StepsFor returns oldest-first; grouping preserves that relative
	// order within each resource's slice, so each chain can still be
	// walked in reverse for its own steps.
	byResource := make(map[string][]*saga.Step, len(steps))
	var resourceOrder []string
	for _, step := range steps {
		if _, seen := byResource[step.Resource]; !seen {
			resourceOrder = append(resourceOrder, step.Resource)
		}
		byResource[step.Resource] = append(byResource[step.Resource], step)
	}

	var wg sync.WaitGroup
	for _, resource := range resourceOrder {
		resourceSteps := byResource[resource]
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.compensateResourceChain(ctx, runID, triggerReason, resourceSteps)
		}()
	}
	wg.Wait()
}

// compensateResourceChain walks ONE resource's steps in reverse execution
// order and stops - for that resource only - the first time a compensation
// itself fails, rather than skipping past it to try earlier steps on the
// SAME resource. Skipping past a failure could leave that resource's state
// MORE confused, not less: if step 2 can't be undone, blindly undoing step
// 1 first is a guess this system doesn't get to make silently. A stopped
// chain is surfaced via COMPENSATION_FAILED in the audit log for a human
// to look at, not retried automatically and not hidden - and other
// resources' chains in the same run are unaffected.
func (h *Handler) compensateResourceChain(ctx context.Context, runID, triggerReason string, steps []*saga.Step) {
	for i := len(steps) - 1; i >= 0; i-- {
		step := steps[i]
		if step.ReversibilityClass != string(registry.ClassA) || step.Compensated || step.CompensationFailed {
			continue
		}

		tool, ok := h.Registry.Get(step.Tool)
		if !ok {
			h.failCompensation(runID, step, fmt.Sprintf("tool %q no longer in registry", step.Tool))
			return
		}
		compensateToolName := tool.CompensateWith
		if compensateToolName == "" {
			compensateToolName = tool.Name
		}
		compTool, ok := h.Registry.Get(compensateToolName)
		if !ok {
			h.failCompensation(runID, step, fmt.Sprintf("compensating tool %q not in registry", compensateToolName))
			return
		}

		var preImage map[string]any
		if err := json.Unmarshal(step.PreImage, &preImage); err != nil {
			h.failCompensation(runID, step, "captured pre-image is not valid JSON: "+err.Error())
			return
		}
		compArgs := map[string]any{}
		if compTool.ResourceArg != "" {
			compArgs[compTool.ResourceArg] = step.Resource
		}
		for _, field := range tool.CompensateFields {
			if v, ok := preImage[field]; ok {
				compArgs[field] = v
			}
		}

		if _, err := validate.Validate(compTool.ArgsSchema, compArgs); err != nil {
			h.failCompensation(runID, step, "compensation args failed validation: "+err.Error())
			return
		}

		// Defense in depth: no action bypasses authorization, ever, not even
		// the system's own cleanup. Uses the ORIGINAL step's identity, since
		// a compensation is that same session undoing its own prior action,
		// not a new independent actor. Rate limiting and loop detection are
		// deliberately NOT applied here - those catch a misbehaving agent
		// deciding something new, and a system-triggered compensation isn't
		// that. Policy.Evaluate and execute() are both safe to call
		// concurrently across resource chains: OPA's PreparedEvalQuery.Eval
		// takes a value receiver and only reads compiled, immutable query
		// state, and this project's own concurrent-load testing already
		// exercised concurrent Policy.Evaluate calls from every parallel
		// /tool-call request without incident.
		decision, err := h.Policy.Evaluate(ctx, map[string]any{
			"tool": compTool.Name, "delegated_role": step.DelegatedRole,
			"reversibility_class": string(compTool.ReversibilityClass), "args": compArgs,
		})
		if err != nil {
			h.failCompensation(runID, step, "policy evaluation error: "+err.Error())
			return
		}
		if !decision.Allow {
			h.failCompensation(runID, step, "policy denied the compensating call: "+decision.Reason)
			return
		}

		compReq := proxytypes.CallRequest{
			Transport: compensationTransport, AgentID: step.AgentID,
			DelegatedUser: step.DelegatedUser, DelegatedRole: step.DelegatedRole, Tool: compTool.Name,
		}
		result, err := h.execute(ctx, compTool, compArgs, step.Resource, compReq, "saga_compensation:"+runID)
		if err != nil {
			h.failCompensation(runID, step, "compensation execution error: "+err.Error())
			return
		}
		if result.Status != "executed" {
			h.failCompensation(runID, step, "compensation did not execute: "+result.Reason)
			return
		}

		h.Sagas.MarkCompensated(runID, step.Seq)
		h.Audit.Write(map[string]any{"decision": "COMPENSATED", "tool": step.Tool, "resource": step.Resource,
			"reason":         fmt.Sprintf("saga %s (%s): restored %v on %s via %s", runID, triggerReason, tool.CompensateFields, step.Tool, compTool.Name),
			"delegated_role": step.DelegatedRole, "agent_id": step.AgentID})
	}
}

func (h *Handler) failCompensation(runID string, step *saga.Step, note string) {
	h.Sagas.MarkCompensationFailed(runID, step.Seq, note)
	h.Audit.Write(map[string]any{"decision": "COMPENSATION_FAILED", "tool": step.Tool, "resource": step.Resource,
		"reason":         fmt.Sprintf("saga %s: could not compensate step #%d (%s) on resource %q: %s - that resource's chain stopped here; other resources in this run, if any, are unaffected", runID, step.Seq, step.Tool, step.Resource, note),
		"delegated_role": step.DelegatedRole, "agent_id": step.AgentID})
}

// --- shared execution path: mint token, forward, sanitize, audit -----------

// isCompensationCall marks a synthetic execute() invocation made BY
// CompensateRun to undo a prior step - it must never itself capture a new
// pre-image (there's nothing to compensate a compensation with) or be
// recorded as a new saga step (that would let a run's trace grow forever
// undoing its own undos).
const compensationTransport = "saga-compensation"

func (h *Handler) execute(ctx context.Context, tool registry.Tool, args map[string]any, resource string, req proxytypes.CallRequest, path string) (proxytypes.CallResult, error) {
	if tool.IsDBBacked() {
		return h.executeDBQuery(ctx, tool, args, resource, req, path)
	}
	if tool.IsAWSBacked() {
		return h.executeAWSS3Get(ctx, tool, args, resource, req, path)
	}
	if tool.IsMCPBacked() {
		return h.executeMCPCall(ctx, tool, args, resource, req, path)
	}
	isCompensation := req.Transport == compensationTransport

	// Two very different costs, measured separately on purpose: a real
	// Vault round trip only happens on a session's first call (or after its
	// root expires) - everything else in the same session is a cache hit
	// that costs a mutex lock, not a network call. Blending them under one
	// "capability_issue" number would hide that almost every real call
	// should land in the cheap bucket - see internal/metrics's two labels.
	root, err := h.caps.getOrMint(ctx, h.Metrics, h.Capability, sessionKeyFor(req), req.DelegatedUser, req.DelegatedRole)
	if err != nil {
		return proxytypes.CallResult{}, fmt.Errorf("handler: get/mint root capability: %w", err)
	}

	attenuateDone := h.Metrics.Timer("capability_attenuate")
	token, err := root.Attenuate(tool.Name, resource, tokenTTL)
	attenuateDone()
	if err != nil {
		return proxytypes.CallResult{}, fmt.Errorf("handler: attenuate capability: %w", err)
	}

	// Class A means "we can put this back." If the snapshot can't be taken
	// there is nothing to put back, and executing anyway would make this
	// call irreversible in practice while the catalog still says otherwise -
	// the exact "compensable in name only" condition blastradius warns
	// about. So this fails closed. An earlier version warned and continued.
	var preImage json.RawMessage
	if tool.ReversibilityClass == registry.ClassA && !isCompensation {
		preImage = h.capturePreImage(ctx, tool, resource, token.Value)
		if preImage == nil {
			h.Audit.Write(map[string]any{"decision": "ERROR", "tool": tool.Name, "delegated_role": req.DelegatedRole,
				"reason":   "pre-image capture failed - refusing to execute a compensable mutation without a snapshot to restore from",
				"resource": resource, "path": path, "transport": req.Transport, "agent_id": req.AgentID})
			return proxytypes.CallResult{Status: "error", Reason: "pre-image capture failed - a compensable (class A) mutation is not executed without a snapshot to restore from"}, nil
		}
	}

	upstreamPath := tool.Path
	if tool.ResourceArg != "" {
		upstreamPath = strings.ReplaceAll(upstreamPath, "{"+tool.ResourceArg+"}", resource)
	}
	body, _ := json.Marshal(args)
	httpReq, err := http.NewRequestWithContext(ctx, tool.Method, h.UpstreamBase+upstreamPath, bytes.NewReader(body))
	if err != nil {
		return proxytypes.CallResult{}, fmt.Errorf("handler: build upstream request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token.Value)

	upstreamDone := h.Metrics.Timer("upstream_call")
	resp, err := h.HTTPClient.Do(httpReq)
	upstreamDone()
	if err != nil {
		h.Audit.Write(map[string]any{"decision": "ERROR", "tool": tool.Name, "delegated_role": req.DelegatedRole,
			"reason": "upstream call failed: " + err.Error(), "path": path})
		return proxytypes.CallResult{Status: "error", Reason: err.Error()}, nil
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(resp.Body)

	// Response sanitization: strip fields the tool definition marks as
	// internal-only before the response ever reaches the agent's context -
	// this is what stops the upstream API's own implementation details
	// (internal ids, other customers' data accidentally over-fetched by a
	// sloppy endpoint, etc.) from leaking into the LLM's prompt window.
	var parsed any
	_ = json.Unmarshal(rawBody, &parsed)
	if len(tool.SanitizeFields) > 0 {
		parsed = stripFields(parsed, tool.SanitizeFields)
	}

	h.Audit.Write(map[string]any{"decision": "EXECUTED", "tool": tool.Name, "delegated_role": req.DelegatedRole,
		"reason": path, "resource": resource, "upstream_status": resp.StatusCode, "transport": req.Transport,
		"agent_id": req.AgentID})

	// Saga trace: every class gets recorded for a human's full visibility
	// into the run, but only Class A steps are ever walked back - see
	// CompensateRun. A compensation call never reaches here (isCompensation
	// guards it) - undoing an undo isn't a thing this system does.
	if req.RunID != "" && !isCompensation {
		h.Sagas.RecordStep(&saga.Step{
			RunID: req.RunID, Tool: tool.Name, ReversibilityClass: string(tool.ReversibilityClass),
			Resource: resource, Args: args, PreImage: preImage,
			DelegatedUser: req.DelegatedUser, DelegatedRole: req.DelegatedRole, AgentID: req.AgentID,
			ExecutedAt: time.Now(),
		})
	}

	return proxytypes.CallResult{Status: "executed", UpstreamCode: resp.StatusCode, UpstreamBody: parsed}, nil
}

// stripFields deletes each dot-path (e.g. "user.ssn") from a decoded JSON
// value. Only descends through maps - a response shaped as a top-level
// array is left alone, which covers every tool registered so far; extend
// if a tool ever returns a bare array of records that itself needs
// per-element stripping.
func stripFields(v any, paths []string) any {
	for _, p := range paths {
		deleteAtPath(v, strings.Split(p, "."))
	}
	return v
}

func deleteAtPath(v any, path []string) {
	if len(path) == 0 {
		return
	}
	m, ok := v.(map[string]any)
	if !ok {
		return
	}
	if len(path) == 1 {
		delete(m, path[0])
		return
	}
	if child, ok := m[path[0]]; ok {
		deleteAtPath(child, path[1:])
	}
}
