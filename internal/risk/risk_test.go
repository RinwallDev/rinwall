package risk

import (
	"testing"

	"github.com/RinwallDev/rinwall/internal/proxytypes"
	"github.com/RinwallDev/rinwall/internal/registry"
)

func TestHeuristicScorer_NoTaint_ZeroScore(t *testing.T) {
	s := HeuristicScorer{}
	score := s.Score("close_account", registry.ClassC, nil)
	if score != 0 {
		t.Fatalf("expected 0 score with no tainted args, got %v", score)
	}
	if RequiredApprovals(score) != 1 {
		t.Fatalf("expected 1 required approval at score 0, got %d", RequiredApprovals(score))
	}
}

func TestHeuristicScorer_ClassCWeightedHigherThanClassA(t *testing.T) {
	s := HeuristicScorer{}
	prov := map[string]proxytypes.Provenance{"x": proxytypes.ProvenanceTainted}
	scoreA := s.Score("some_tool", registry.ClassA, prov)
	scoreC := s.Score("some_tool", registry.ClassC, prov)
	if scoreC <= scoreA {
		t.Fatalf("expected Class C to score higher than Class A for the same taint, got A=%v C=%v", scoreA, scoreC)
	}
}

func TestHeuristicScorer_MoreTaintedArgsScoresHigher(t *testing.T) {
	s := HeuristicScorer{}
	one := s.Score("t", registry.ClassA, map[string]proxytypes.Provenance{"a": proxytypes.ProvenanceTainted})
	two := s.Score("t", registry.ClassA, map[string]proxytypes.Provenance{
		"a": proxytypes.ProvenanceTainted, "b": proxytypes.ProvenanceTainted,
	})
	if two <= one {
		t.Fatalf("expected more tainted args to score higher, got one=%v two=%v", one, two)
	}
}

func TestHeuristicScorer_TrustedOnlyNeverCountsAsTaint(t *testing.T) {
	s := HeuristicScorer{}
	prov := map[string]proxytypes.Provenance{"a": proxytypes.ProvenanceTrusted}
	if score := s.Score("t", registry.ClassC, prov); score != 0 {
		t.Fatalf("expected an explicitly-trusted-only provenance map to score 0, got %v", score)
	}
}

func TestRequiredApprovals_CrossesThresholdAtFourEyes(t *testing.T) {
	if RequiredApprovals(FourEyesThreshold-0.01) != 1 {
		t.Fatal("expected just below the threshold to require only 1 approver")
	}
	if RequiredApprovals(FourEyesThreshold) != 2 {
		t.Fatal("expected exactly at the threshold to require four-eyes")
	}
}

func TestTaintedArgs_OnlyReturnsTaintedNames(t *testing.T) {
	got := TaintedArgs(map[string]proxytypes.Provenance{
		"a": proxytypes.ProvenanceTainted,
		"b": proxytypes.ProvenanceTrusted,
		"c": proxytypes.ProvenanceTainted,
	})
	if len(got) != 2 {
		t.Fatalf("expected 2 tainted args, got %v", got)
	}
}
