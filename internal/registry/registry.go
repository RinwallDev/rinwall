// Package registry holds the one contract every mutating tool must satisfy
// before an agent is ever allowed to call it: a declared reversibility class
// and an allowlist argument schema. A tool with neither does not load - this
// is deliberate, not an oversight; see ARCHITECTURE.md.
package registry

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type ReversibilityClass string

const (
	ClassA ReversibilityClass = "A" // compensable
	ClassB ReversibilityClass = "B" // idempotent / retry-safe
	ClassC ReversibilityClass = "C" // irreversible
)

// FieldSpec is a deliberately small, allowlist-only schema - not full JSON
// Schema. Type, required, enum, pattern and max length cover the shipped
// tools; a proper JSON Schema library can replace this without touching
// callers if a tool ever needs more.
type FieldSpec struct {
	Type      string   `yaml:"type"` // "string" | "number" | "bool"
	Required  bool     `yaml:"required"`
	Enum      []string `yaml:"enum,omitempty"`
	Pattern   string   `yaml:"pattern,omitempty"`
	MaxLength int      `yaml:"max_length,omitempty"`
	MaxValue  *float64 `yaml:"max_value,omitempty"` // numeric ceiling, e.g. caps a result-count/limit argument directly in the schema
}

// PreImage says how to read a Class A resource's prior state before it's
// mutated, so compensation has something to restore from. Two shapes, one
// per upstream kind: Method/Path for an HTTP upstream, MCPTool for an MCP
// one (called with a single argument, the tool's ResourceArg, set to the
// resource being mutated). Exactly one shape is set - see
// validateToolDefinition.
type PreImage struct {
	Method  string `yaml:"method,omitempty"`
	Path    string `yaml:"path,omitempty"`
	MCPTool string `yaml:"mcp_tool,omitempty"`
}

type Tool struct {
	Name string `yaml:"name"`
	// Description is what an agent sees in tools/list when this proxy
	// fronts an MCP server - carried through from the upstream's own
	// description. Without it an agent behind the proxy can't choose tools.
	Description        string               `yaml:"description,omitempty"`
	ReversibilityClass ReversibilityClass   `yaml:"reversibility_class"`
	Method             string               `yaml:"method"`
	Path               string               `yaml:"path"`
	ResourceArg        string               `yaml:"resource_arg"`
	ArgsSchema         map[string]FieldSpec `yaml:"args_schema"`
	SanitizeFields     []string             `yaml:"sanitize_fields,omitempty"`   // dot-paths stripped from the upstream response
	CompensateWith     string               `yaml:"compensate_with,omitempty"`   // Class A - empty means the tool re-issues itself
	CompensateFields   []string             `yaml:"compensate_fields,omitempty"` // Class A - arg names restored from the pre-image on compensation
	PreImage           *PreImage            `yaml:"pre_image,omitempty"`         // Class A
	Deferrable         bool                 `yaml:"deferrable,omitempty"`        // Class C tier 2
	HoldSeconds        int                  `yaml:"hold_seconds,omitempty"`      // Class C tier 2
	ReviewerRole       string               `yaml:"reviewer_role,omitempty"`     // Class C tier 3

	// ReviewedBy/ReviewedAt are purely informational in normal operation -
	// nothing in validateToolDefinition checks them, and a catalog missing
	// both loads exactly as it always has. They only become load-bearing
	// when a deployment opts into require_reviewed_tools (cmd/rinwall's
	// Config, checked via RequireReviewed below): the structural gate
	// against the one realistic way to end up running an unreviewed
	// catalog in production - piping `blastradius --emit-registry`
	// straight into service without a human ever looking at it. See
	// RequireReviewed's own doc comment for the full reasoning.
	ReviewedBy string `yaml:"reviewed_by,omitempty"`
	ReviewedAt string `yaml:"reviewed_at,omitempty"` // RFC3339 or YYYY-MM-DD

	// ProvenanceJudge opts this specific tool into the model-based
	// provenance add-on (internal/provenance) - off by default. An org
	// enables it per sensitive tool (close_account) while leaving
	// low-stakes ones on the cheaper self-reported/no-taint path. Only
	// takes effect when the caller also supplies a context window with
	// the call; the tool setting alone does nothing without that.
	ProvenanceJudge bool `yaml:"provenance_judge,omitempty"`

	// VisualProvenanceJudge opts this tool into the screenshot-reasoning
	// analog of ProvenanceJudge (internal/visualprovenance) - for the
	// "computer use" tool shape (one generic tool, an action
	// discriminator, no semantic tool name to classify) rather than the
	// text judge's confused-deputy check. Deliberately triggered
	// INDEPENDENT of ReversibilityClass in internal/handler, not folded
	// into the existing A/C-only taint gate - that gate would silently
	// never reach a Class-B-registered "computer" tool, which is the
	// realistic outcome for a tool whose danger varies per call rather
	// than by name. Requires the caller to supply a screenshot AND their
	// own stated reasoning for the action alongside the call; absent
	// either, this setting does nothing, same as ProvenanceJudge without
	// a context window.
	VisualProvenanceJudge bool `yaml:"visual_provenance_judge,omitempty"`

	// VisualJudgeActionArg/VisualJudgeTriggerValues are the cost filter: a
	// real multimodal model call on every scroll and screenshot is a cost
	// nobody wants, and most of a computer-use tool's calls are exactly
	// that - inert. VisualJudgeActionArg names which argument holds an
	// action-type discriminator (e.g. "action" on Anthropic's own
	// computer-use tool shape); the visual judge only runs when that
	// argument's value is one of VisualJudgeTriggerValues (e.g.
	// left_click, type) - not on screenshot/scroll/arrow-key calls, which
	// can't meaningfully be "manufactured by deceptive content" the way a
	// click or a typed value can. Leaving VisualJudgeActionArg empty means
	// no filter - every call to a VisualProvenanceJudge tool triggers the
	// check, the honest (costlier) default for a tool with no action-type
	// convention to filter on at all.
	VisualJudgeActionArg     string   `yaml:"visual_judge_action_arg,omitempty"`
	VisualJudgeTriggerValues []string `yaml:"visual_judge_trigger_values,omitempty"`

	// DBRole/Query/QueryArgs make this tool database-backed instead of
	// HTTP-backed - the real Vault dynamic-secrets path (a genuine
	// database/creds/<DBRole> mint, executing a real CREATE ROLE against
	// the actual database) rather than a biscuit token verified by an
	// HTTP upstream. DBRole names a Vault database secrets engine role;
	// Query is a parameterized SQL statement ($1, $2, ...); QueryArgs
	// names which validated args_schema fields fill those placeholders,
	// in order. Mutually exclusive with Method/Path - see
	// validateToolDefinition. Restricted to Class B for now: a raw SQL
	// mutation's compensation semantics (what's the "pre-image" of an
	// UPDATE with an arbitrary WHERE clause?) aren't designed yet.
	DBRole    string   `yaml:"db_role,omitempty"`
	Query     string   `yaml:"query,omitempty"`
	QueryArgs []string `yaml:"query_args,omitempty"`

	// AWSRole/S3Bucket/S3KeyArg make this tool AWS-backed instead of
	// HTTP- or DB-backed - the real Vault AWS dynamic-secrets path (a
	// genuine sts:AssumeRole against the actual AWS account). Unlike
	// DBRole, a fresh credential is minted on EVERY call, not cached per
	// session - a real AssumeRole is cheap and AWS-TTL-enforced, unlike a
	// database CREATE ROLE, so there's no cost reason to reuse one across
	// calls, and every reason not to (shorter-lived exposure per call).
	// AWSRole names a Vault AWS secrets engine role; S3Bucket is the
	// bucket to read from; S3KeyArg names which validated args_schema
	// field supplies the object key. Scoped to a single S3 GetObject for
	// now, matching DBRole's own scope discipline (Class B, read-only).
	AWSRole  string `yaml:"aws_role,omitempty"`
	S3Bucket string `yaml:"aws_s3_bucket,omitempty"`
	S3KeyArg string `yaml:"aws_s3_key_arg,omitempty"`

	// MCPTool makes this tool MCP-backed: the proxy forwards the call
	// onward to an upstream MCP server (internal/mcpclient) as a real
	// tools/call, instead of an HTTP route, a SQL query, or an S3 read.
	// This is the shape that lets the firewall sit in front of an MCP
	// server someone already runs, which is the whole adoption story - an
	// MCP tool advertises no upstream HTTP route, so before this existed a
	// scanned catalog could not be loaded without a human hand-writing
	// method/path for every entry.
	//
	// Unlike DBRole and AWSRole, this is NOT restricted to Class B. Those
	// two are read-only scopes this build deliberately hasn't extended to
	// mutations yet; an upstream MCP server's catalog is the general case
	// and routinely contains genuinely irreversible tools - refusing to
	// load them would just push exactly the calls that most need gating
	// back outside the firewall. Class A works too, via PreImage.MCPTool.
	//
	// The name may differ from Tool.Name: the agent-facing name is
	// whatever this catalog calls it, MCPTool is what the upstream server
	// calls it. Empty means "same as Name," which is the normal case for
	// a catalog produced by scanning that server.
	MCPTool string `yaml:"mcp_tool,omitempty"`
}

func (t Tool) IsDBBacked() bool  { return t.DBRole != "" }
func (t Tool) IsAWSBacked() bool { return t.AWSRole != "" }
func (t Tool) IsMCPBacked() bool { return t.MCPTool != "" }

// UpstreamMCPTool is the name to call on the upstream MCP server - the
// explicit mcp_tool if the catalog renamed it, otherwise this tool's own
// name.
func (t Tool) UpstreamMCPTool() string {
	if t.MCPTool == mcpSameName {
		return t.Name
	}
	return t.MCPTool
}

// mcpSameName is the sentinel a catalog uses to say "MCP-backed, and the
// upstream calls it exactly what we call it" - needed because an empty
// mcp_tool has to keep meaning "not MCP-backed at all," and a scanned
// catalog would otherwise have to repeat every tool's own name back to
// itself on every entry.
const mcpSameName = "="

type fileFormat struct {
	Tools []Tool `yaml:"tools"`
}

type Registry struct {
	tools map[string]Tool
}

func LoadFromYAML(path string) (*Registry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("registry: read %s: %w", path, err)
	}
	var ff fileFormat
	if err := yaml.Unmarshal(raw, &ff); err != nil {
		return nil, fmt.Errorf("registry: parse %s: %w", path, err)
	}

	r := &Registry{tools: make(map[string]Tool, len(ff.Tools))}
	for _, t := range ff.Tools {
		if err := validateToolDefinition(t); err != nil {
			return nil, fmt.Errorf("registry: tool %q: %w", t.Name, err)
		}
		r.tools[t.Name] = t
	}
	return r, nil
}

// FromTools builds a registry from tools assembled in memory rather than
// read from a file - what zero-config mode needs after scanning a live MCP
// server. Every tool goes through the exact same validateToolDefinition as
// a YAML catalog would: a discovered tool is held to the identical contract
// as a hand-written one, so auto-discovery can never introduce a tool shape
// a file could not.
func FromTools(tools []Tool) (*Registry, error) {
	r := &Registry{tools: make(map[string]Tool, len(tools))}
	for _, t := range tools {
		if err := validateToolDefinition(t); err != nil {
			return nil, fmt.Errorf("registry: tool %q: %w", t.Name, err)
		}
		r.tools[t.Name] = t
	}
	return r, nil
}

func validateToolDefinition(t Tool) error {
	if t.Name == "" {
		return fmt.Errorf("missing name")
	}
	switch t.ReversibilityClass {
	case ClassA, ClassB, ClassC:
	default:
		return fmt.Errorf("missing or invalid reversibility_class (must be A, B, or C)")
	}
	if t.ArgsSchema == nil {
		return fmt.Errorf("missing args_schema - every tool must declare an allowlist schema, even if empty ({})")
	}
	if t.ReversibilityClass == ClassA {
		// Automated compensation always restores FROM a captured pre-image,
		// so both pieces are mandatory: pre_image is where the prior values come from,
		// compensate_fields says which argument names get restored from
		// it. compensate_with stays optional - empty means the tool calls
		// itself again with the restored value(s), which is what every
		// tool in this catalog does.
		if t.PreImage == nil {
			return fmt.Errorf("class A tools must declare pre_image - compensation restores from it")
		}
		if len(t.CompensateFields) == 0 {
			return fmt.Errorf("class A tools must declare compensate_fields - the argument name(s) restored from pre_image on compensation")
		}
	}
	// Class A and C both need a reviewer_role: C for its normal tier-3 path,
	// A because a tainted call on it forces the same step-up flow even
	// though its baseline reversibility class never otherwise routes
	// through approval - see internal/handler's step-up logic. Requiring
	// this at load time catches the misconfiguration before a tainted call
	// arrives at runtime and finds nobody able to satisfy the (empty)
	// reviewer role.
	if (t.ReversibilityClass == ClassA || t.ReversibilityClass == ClassC) && t.ReviewerRole == "" {
		return fmt.Errorf("class %s tools must declare reviewer_role - class C needs it for its normal approval tier, class A needs it because a tainted call forces the same step-up flow", t.ReversibilityClass)
	}
	// VisualProvenanceJudge is triggered independent of ReversibilityClass
	// (internal/handler.assessVisualProvenance) - deliberately, since the
	// A/C-only taint gate would otherwise never reach the realistic case
	// (a "computer use" tool registered Class B because per-call danger
	// varies too much to fix one class). That means a Class B tool CAN
	// reach step-up now, and step-up unconditionally needs tool.ReviewerRole
	// (internal/handler.stepUp) - so this needs the same requirement the
	// A/C check above already enforces, or a flagged call would create a
	// pending approval routed to an empty reviewer role that nobody could
	// ever satisfy, stuck forever.
	if t.VisualProvenanceJudge && t.ReviewerRole == "" {
		return fmt.Errorf("visual_provenance_judge tools must declare reviewer_role - a flagged call forces the same step-up flow regardless of reversibility_class")
	}
	kinds := 0
	for _, on := range []bool{t.IsDBBacked(), t.IsAWSBacked(), t.IsMCPBacked()} {
		if on {
			kinds++
		}
	}
	if kinds > 1 {
		return fmt.Errorf("tool declares more than one of db_role/aws_role/mcp_tool - a tool is HTTP-backed, DB-backed, AWS-backed, or MCP-backed, exactly one")
	}
	if t.IsMCPBacked() {
		if t.Method != "" || t.Path != "" {
			return fmt.Errorf("mcp-backed tools (mcp_tool set) must not also set method/path - the upstream is an MCP server, not an HTTP route")
		}
		// Class A over MCP compensates by calling another MCP tool to read
		// the prior state, so the pre-image has to be declared in the MCP
		// shape. Catching the mismatch here means a catalog can never load
		// in a state where compensation would silently do nothing at the
		// moment it's actually needed.
		if t.ReversibilityClass == ClassA && t.PreImage != nil && t.PreImage.MCPTool == "" {
			return fmt.Errorf("class A mcp-backed tools must declare pre_image.mcp_tool - compensation reads prior state through the same MCP server")
		}
		return nil
	} else if t.PreImage != nil && t.PreImage.MCPTool != "" {
		return fmt.Errorf("pre_image.mcp_tool is only meaningful on an mcp-backed tool (mcp_tool set)")
	} else if t.PreImage != nil && (t.PreImage.Method == "" || t.PreImage.Path == "") {
		return fmt.Errorf("pre_image must declare method and path for an HTTP-backed tool")
	}
	if t.IsDBBacked() {
		if t.Method != "" || t.Path != "" {
			return fmt.Errorf("db-backed tools (db_role set) must not also set method/path - a tool is HTTP-backed or DB-backed, not both")
		}
		if t.Query == "" {
			return fmt.Errorf("db-backed tools must declare query")
		}
		if t.ReversibilityClass != ClassB {
			return fmt.Errorf("db-backed tools must be reversibility_class B for now - a raw SQL mutation's compensation semantics aren't designed yet, see the plan's AWS/DB dynamic secrets section")
		}
		for _, arg := range t.QueryArgs {
			if _, ok := t.ArgsSchema[arg]; !ok {
				return fmt.Errorf("query_args references %q, which is not in args_schema", arg)
			}
		}
		return nil
	}
	if t.IsAWSBacked() {
		if t.Method != "" || t.Path != "" {
			return fmt.Errorf("aws-backed tools (aws_role set) must not also set method/path - a tool is HTTP-backed or AWS-backed, not both")
		}
		if t.S3Bucket == "" || t.S3KeyArg == "" {
			return fmt.Errorf("aws-backed tools must declare aws_s3_bucket and aws_s3_key_arg")
		}
		if t.ReversibilityClass != ClassB {
			return fmt.Errorf("aws-backed tools must be reversibility_class B for now, see the plan's AWS/DB dynamic secrets section")
		}
		if _, ok := t.ArgsSchema[t.S3KeyArg]; !ok {
			return fmt.Errorf("aws_s3_key_arg references %q, which is not in args_schema", t.S3KeyArg)
		}
		return nil
	}
	if t.Method == "" || t.Path == "" {
		return fmt.Errorf("missing method/path (upstream route)")
	}
	return nil
}

func (r *Registry) Get(name string) (Tool, bool) {
	t, ok := r.tools[name]
	return t, ok
}

func (r *Registry) All() map[string]Tool {
	return r.tools
}

// RequireReviewed is the strict-catalog gate: it returns an error naming
// every tool in r that has no reviewed_by/reviewed_at, or whose
// reviewed_at doesn't parse as a real date. cmd/rinwall calls this right
// after loading a catalog, only when require_reviewed_tools is set in
// config.yaml - never in zero-config mode, which has no config file to
// set it in and whose entire premise (scan and start with no human in the
// loop) is structurally incompatible with this gate anyway.
//
// This exists because classification accuracy was never the risk this
// closes - blastradius's own hand-validation found 82-100% precision by
// class, genuinely good for a heuristic. The risk is procedural: nothing
// stops `blastradius --mcp <url> --emit-registry > tools.yaml` from being
// piped straight into a running production proxy with zero human
// judgment applied to the result. Same philosophy as the loopback-bind
// refusal in zero-config mode - make the unsafe path structurally
// impossible rather than warn about it and hope someone reads the
// warning.
func RequireReviewed(r *Registry) error {
	var missing []string
	for name, t := range r.tools {
		// A blastradius-emitted catalog leaves these as "TODO-..." - reject
		// that placeholder text itself, not just emptiness, so leaving it
		// unedited can't masquerade as a real review.
		if t.ReviewedBy == "" || t.ReviewedAt == "" ||
			strings.HasPrefix(t.ReviewedBy, "TODO") || strings.HasPrefix(t.ReviewedAt, "TODO") {
			missing = append(missing, name)
			continue
		}
		if _, err := time.Parse(time.RFC3339, t.ReviewedAt); err != nil {
			if _, err := time.Parse("2006-01-02", t.ReviewedAt); err != nil {
				missing = append(missing, fmt.Sprintf("%s (reviewed_at %q is not a valid date - use RFC3339 or YYYY-MM-DD)", name, t.ReviewedAt))
			}
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf("require_reviewed_tools is set, but %d tool(s) have no valid reviewed_by/reviewed_at: %s - review each one (blastradius's classifier reasoning is a good starting point, not a substitute) and annotate it before this catalog can load in this mode", len(missing), strings.Join(missing, ", "))
}
