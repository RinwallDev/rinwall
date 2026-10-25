// Package saga records each run's execution trace so it can be walked
// back. It is simpler than a "dynamic DAG" once one fact is taken
// seriously: an agent's tool-calling loop is sequential from this
// proxy's vantage point - one call, one result, one next decision. There is
// no concurrent branching to reconcile here. So the "graph" a run's steps
// need is just an ordered list, appended to as calls actually execute, with
// no workflow pre-declared anywhere. That's the literal meaning of "built
// from the execution trace, not a static declaration" - branching or
// retrying earlier in an agent's reasoning never has to be modeled,
// because only what actually executed ever lands in the trace.
//
// Only Class A steps are ever compensated - that's what Class A means.
// Class B/C steps still get recorded for a human's visibility into the
// full run, they're just never walked back.
package saga

import (
	"encoding/json"
	"time"
)

type Step struct {
	RunID              string
	Seq                int
	Tool               string
	ReversibilityClass string
	Resource           string
	Args               map[string]any
	PreImage           json.RawMessage
	DelegatedUser      string
	DelegatedRole      string
	AgentID            string
	ExecutedAt         time.Time

	Compensated        bool
	CompensationFailed bool
	CompensationNote   string
}
