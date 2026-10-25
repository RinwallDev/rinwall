package visualprovenance

import "context"

// FakeJudge is deterministic and makes no network call - go test never
// depends on a live model API or incurs real cost, the same pattern as
// internal/provenance.FakeJudge and internal/capability.FakeSeedMinter.
type FakeJudge struct {
	Confidence float64
	Rationale  string
	Err        error
}

func (f *FakeJudge) Assess(ctx context.Context, screenshot []byte, statedIntent, action string) (Assessment, Usage, error) {
	if f.Err != nil {
		return Assessment{}, Usage{}, f.Err
	}
	rationale := f.Rationale
	if rationale == "" {
		rationale = "fake judge"
	}
	return Assessment{Confidence: f.Confidence, Rationale: rationale}, Usage{}, nil
}
