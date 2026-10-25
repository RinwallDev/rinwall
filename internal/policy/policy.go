// Package policy embeds OPA directly in the proxy process - no network hop
// to a separate policy service, no per-call serialization round trip. This
// is the Fast Capability Plane's first latency bet: the policy bundle is
// compiled once at startup, and every subsequent evaluation runs in-memory.
package policy

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/rego"
)

type Decision struct {
	Allow  bool
	Reason string
}

type Engine struct {
	prepared rego.PreparedEvalQuery
}

func New(ctx context.Context, policyPath string) (*Engine, error) {
	r := rego.New(
		rego.Query(`result := {"allow": data.rinwall.allow, "reason": data.rinwall.deny_reason}`),
		rego.Load([]string{policyPath}, nil),
	)
	prepared, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy: compile %s: %w", policyPath, err)
	}
	return &Engine{prepared: prepared}, nil
}

func (e *Engine) Evaluate(ctx context.Context, input map[string]any) (Decision, error) {
	rs, err := e.prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return Decision{}, fmt.Errorf("policy: eval: %w", err)
	}
	if len(rs) == 0 {
		return Decision{}, fmt.Errorf("policy: eval produced no result")
	}
	// The query is an assignment ("result := {...}") - its truth value lands
	// in Expressions, but the assigned object itself lands in Bindings.
	bound, ok := rs[0].Bindings["result"]
	if !ok {
		return Decision{}, fmt.Errorf("policy: eval result missing %q binding", "result")
	}
	result, ok := bound.(map[string]any)
	if !ok {
		return Decision{}, fmt.Errorf("policy: unexpected result shape")
	}
	allow, _ := result["allow"].(bool)
	reason, _ := result["reason"].(string)
	return Decision{Allow: allow, Reason: reason}, nil
}
