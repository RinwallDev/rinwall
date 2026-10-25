// Package proxytypes is the transport-agnostic core representation an
// intercepted tool call is normalized into, regardless of whether it
// arrived over the REST adapter or the MCP adapter. Both adapters produce
// exactly this struct and hand it to the same handler: dual adapter,
// single core.
package proxytypes

// Provenance records where an argument's VALUE actually came from - not who
// is making the call (that's DelegatedUser/DelegatedRole), but whether this
// specific value was typed by that human or derived from content the agent
// merely read (a web page, an email, a prior tool result, a RAG chunk).
// This is the Intent Integrity Plane's core distinction: a fully-authorized
// role is not sufficient on its own for a tainted, mutating argument - see
// internal/handler's step-up logic.
type Provenance string

const (
	ProvenanceTrusted Provenance = "trusted" // human-typed, or otherwise verified
	ProvenanceTainted Provenance = "tainted" // derived from content the agent read
)

type CallRequest struct {
	Transport     string // "rest" | "mcp"
	AgentID       string
	DelegatedUser string
	DelegatedRole string
	Tool          string
	Args          map[string]any

	// ArgProvenance is populated by the orchestrator, not inferred by us -
	// we have no way to know where a value came from except being told.
	// An argument absent from this map is treated as trusted (unspecified,
	// not tainted) - this is a deliberate compatibility choice: an
	// orchestrator that hasn't integrated taint plumbing yet keeps today's
	// behavior rather than every call silently requiring step-up.
	ArgProvenance map[string]Provenance

	// RunID groups a sequence of tool calls into one logical multi-step
	// operation for the saga engine (internal/saga) - like ArgProvenance,
	// we cannot infer this ourselves, it has to be supplied by whatever is
	// orchestrating the agent. Empty means "not tracked": no step gets
	// recorded and no compensation can ever trigger for this call, which
	// is the deliberate default for callers that haven't integrated it.
	RunID string

	// ContextWindow is a bounded slice of the actual recent conversation,
	// supplied by the caller for tools with the model-based provenance
	// judge add-on enabled (registry.Tool.ProvenanceJudge) - see
	// internal/provenance. Deliberately a plain local type, not
	// provenance.Message: this package stays dependency-free, matching its
	// existing role as pure transport-agnostic data; the handler converts.
	// Absent or empty means the judge is never consulted for this call,
	// regardless of the tool's setting.
	ContextWindow []ContextMessage

	// Screenshot/StatedIntent are what the visual provenance judge
	// (registry.Tool.VisualProvenanceJudge, internal/visualprovenance)
	// needs - a raw screenshot (already decoded from the wire protocol's
	// base64 encoding) and the agent's own stated reasoning for the
	// proposed action it's about to take. Both required together; either
	// absent means the judge is never consulted for this call, same
	// compatibility pattern as ContextWindow - a caller that hasn't
	// integrated this keeps today's behavior.
	Screenshot   []byte
	StatedIntent string
}

type ContextMessage struct {
	Role    string
	Content string
}

type CallResult struct {
	Status       string `json:"status"` // "executed" | "denied" | "pending_approval" | "pending_hold" | "recorded" | "error"
	Reason       string `json:"reason,omitempty"`
	RequestID    string `json:"request_id,omitempty"`   // pending approval
	RequestHash  string `json:"request_hash,omitempty"` // pending approval
	HoldID       string `json:"hold_id,omitempty"`      // Class C tier 2 - pending hold
	FiresInS     int    `json:"fires_in_s,omitempty"`   // Class C tier 2
	UpstreamCode int    `json:"upstream_status,omitempty"`
	UpstreamBody any    `json:"upstream_body,omitempty"`

	// Populated when a call is escalated for step-up (tainted mutating
	// argument, or a Class C request routed to tier 3) - lets the caller
	// see up front how much scrutiny this specific request is getting,
	// rather than discovering it only after an approve/deny round trip.
	RiskScore         float64  `json:"risk_score,omitempty"`
	RequiredApprovals int      `json:"required_approvals,omitempty"`
	TaintedArgs       []string `json:"tainted_args,omitempty"`
}
