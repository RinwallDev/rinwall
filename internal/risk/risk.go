// Package risk computes a continuous score used ONLY to add friction, never
// to grant access on its own - the earlier design critique was explicit
// that an ML/heuristic risk score is a soft, adversarially-attackable
// signal, and must never be a standalone ALLOW condition for a mutating
// call. Concretely in this codebase, the score has exactly one effect: it
// decides how many distinct human approvers a step-up requires (one vs.
// four-eyes). It never bypasses, weakens, or substitutes for the taint
// check itself - that check is a hard rule in internal/handler, not scored.
//
// This is a deterministic heuristic, not a real ML classifier - integrating
// one would mean pretending to call a model that isn't actually wired up.
// The interface exists specifically so a real classifier can be dropped in
// later without touching any caller.
package risk

import (
	"github.com/RinwallDev/rinwall/internal/proxytypes"
	"github.com/RinwallDev/rinwall/internal/registry"
)

// FourEyesThreshold: a request scoring at or above this requires two
// distinct, non-requester approvers instead of one. See
// internal/approval's RequiredApprovals.
const FourEyesThreshold = 0.7

type Scorer interface {
	Score(tool string, class registry.ReversibilityClass, provenance map[string]proxytypes.Provenance) float64
}

// HeuristicScorer: 0 with no tainted arguments (nothing for a score to add
// friction to - the taint check itself is what gates these calls, not
// this). Otherwise a base cost per tainted argument, with irreversible
// (Class C) calls weighted higher than compensable (Class A) ones -
// deliberately simple and auditable at a glance, not tunable machinery.
type HeuristicScorer struct{}

func (HeuristicScorer) Score(tool string, class registry.ReversibilityClass, provenance map[string]proxytypes.Provenance) float64 {
	tainted := TaintedArgs(provenance)
	if len(tainted) == 0 {
		return 0
	}
	score := 0.4 + 0.15*float64(len(tainted))
	if class == registry.ClassC {
		score += 0.2
	}
	if score > 1.0 {
		score = 1.0
	}
	return score
}

// TaintedArgs returns the sorted-by-insertion names of every argument
// explicitly marked tainted - the hard trigger for mandatory step-up,
// independent of whatever the risk score comes out to.
func TaintedArgs(provenance map[string]proxytypes.Provenance) []string {
	var out []string
	for name, p := range provenance {
		if p == proxytypes.ProvenanceTainted {
			out = append(out, name)
		}
	}
	return out
}

// RequiredApprovals maps a score to how many distinct approvers a step-up
// needs - the score's only real effect anywhere in this system.
func RequiredApprovals(score float64) int {
	if score >= FourEyesThreshold {
		return 2
	}
	return 1
}
