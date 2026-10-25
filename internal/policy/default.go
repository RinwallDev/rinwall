package policy

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/rego"
)

// defaultBundle is what runs when zero-config mode starts with no Rego
// bundle of its own (cmd/rinwall's --mcp flag).
//
// It permits every role to ATTEMPT every tool, and that needs saying
// plainly rather than hiding behind "sane defaults": this default gives up
// the role dimension entirely. Nobody can write a correct per-role rule for
// a catalog they have never seen, and the alternative - default deny -
// produces a proxy where every call fails, which teaches an evaluator
// nothing except that it doesn't work.
//
// What survives, and why zero-config is still worth running:
//
//   - Class C never executes without a human. Policy allowing an attempt is
//     not the same as the call going through; internal/handler's Class C
//     tiering still routes it to approval, and with no reviewer configured
//     it simply stays blocked. That is the correct fail-closed answer, and
//     it's the demo.
//   - Class A still captures a pre-image and still auto-compensates when
//     something later in the run fails.
//   - A tool the classifier could not read becomes Class C, so an
//     unrecognized verb needs approval instead of sailing through.
//   - Every call is still validated against its schema, rate limited, loop
//     broken, capability scoped, and audit logged.
//
// So the honest summary: this default drops "which humans may do what" and
// keeps "what can this action do, and can it be undone." Writing a real
// bundle adds the first back. Deliberately expressed as a rule with a body
// rather than `default allow = true`, so it shows up in an OPA trace as a
// decision that fired, not as an absence.
const defaultBundle = `package rinwall

default allow = false
default deny_reason = "no matching policy rule"

# Zero-config default: any authenticated role may ATTEMPT any tool. The
# reversibility class, not the role, is what gates whether it executes.
allow {
	input.tool != ""
}

deny_reason = reason {
	not allow
	reason := sprintf("no tool named in the request (tool=%q)", [input.tool])
}
`

// NewDefault compiles the built-in permissive bundle - see defaultBundle
// for exactly what it does and does not enforce. Callers are expected to
// tell the operator they are running on it.
func NewDefault(ctx context.Context) (*Engine, error) {
	r := rego.New(
		rego.Query(`result := {"allow": data.rinwall.allow, "reason": data.rinwall.deny_reason}`),
		rego.Module("rinwall_default.rego", defaultBundle),
	)
	prepared, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy: compile built-in default bundle: %w", err)
	}
	return &Engine{prepared: prepared}, nil
}
