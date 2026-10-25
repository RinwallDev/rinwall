package visualprovenance

import (
	"context"
	"errors"
	"testing"
)

func TestFakeJudge_ReturnsConfiguredAssessment(t *testing.T) {
	f := &FakeJudge{Confidence: 0.15, Rationale: "mismatched target"}
	a, usage, err := f.Assess(context.Background(), []byte("fake-png-bytes"), "clicking Cancel", "left_click at (275,220)")
	if err != nil {
		t.Fatal(err)
	}
	if a.Confidence != 0.15 || a.Rationale != "mismatched target" {
		t.Fatalf("unexpected assessment: %+v", a)
	}
	if usage != (Usage{}) {
		t.Fatalf("a fake judge makes no real API call, so usage must be zero, got %+v", usage)
	}
}

func TestFakeJudge_PropagatesConfiguredError(t *testing.T) {
	want := errors.New("boom")
	f := &FakeJudge{Err: want}
	if _, _, err := f.Assess(context.Background(), nil, "", ""); err != want {
		t.Fatalf("expected the configured error to propagate, got %v", err)
	}
}

func TestFakeJudge_DefaultRationale(t *testing.T) {
	f := &FakeJudge{Confidence: 0.9}
	a, _, err := f.Assess(context.Background(), []byte("x"), "intent", "action")
	if err != nil {
		t.Fatal(err)
	}
	if a.Rationale == "" {
		t.Fatal("expected a non-empty default rationale")
	}
}

func TestClamp01(t *testing.T) {
	cases := map[float64]float64{-0.5: 0, 0: 0, 0.5: 0.5, 1: 1, 1.5: 1}
	for in, want := range cases {
		if got := clamp01(in); got != want {
			t.Fatalf("clamp01(%v) = %v, want %v", in, got, want)
		}
	}
}
