package provenance

import "context"

// FakeJudge is deterministic and makes no network call - used by tests so
// go test never depends on a live model API or incurs real cost, the same
// pattern as capability.FakeSeedMinter standing in for Vault.
type FakeJudge struct {
	// Confidences maps argument name -> the confidence to return for it.
	// An argument not present here defaults to DefaultConfidence.
	Confidences       map[string]float64
	DefaultConfidence float64
	Err               error
}

func (f *FakeJudge) Assess(ctx context.Context, contextWindow []Message, tool string, args map[string]any) (map[string]ArgAssessment, Usage, error) {
	if f.Err != nil {
		return nil, Usage{}, f.Err
	}
	out := make(map[string]ArgAssessment, len(args))
	for name := range args {
		conf, ok := f.Confidences[name]
		if !ok {
			conf = f.DefaultConfidence
		}
		out[name] = ArgAssessment{Confidence: conf, Rationale: "fake judge"}
	}
	return out, Usage{}, nil
}
