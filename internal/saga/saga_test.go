package saga

import (
	"encoding/json"
	"testing"
	"time"
)

func TestRecordStep_AssignsIncreasingSeq(t *testing.T) {
	s := NewStore()
	s.RecordStep(&Step{RunID: "run-1", Tool: "a", ReversibilityClass: "A", ExecutedAt: time.Now()})
	s.RecordStep(&Step{RunID: "run-1", Tool: "b", ReversibilityClass: "A", ExecutedAt: time.Now()})
	s.RecordStep(&Step{RunID: "run-1", Tool: "c", ReversibilityClass: "B", ExecutedAt: time.Now()})

	steps := s.StepsFor("run-1")
	if len(steps) != 3 {
		t.Fatalf("expected 3 steps, got %d", len(steps))
	}
	for i, step := range steps {
		if step.Seq != i {
			t.Fatalf("expected step %d to have seq %d, got %d", i, i, step.Seq)
		}
	}
	if steps[0].Tool != "a" || steps[1].Tool != "b" || steps[2].Tool != "c" {
		t.Fatalf("expected execution order preserved, got %s, %s, %s", steps[0].Tool, steps[1].Tool, steps[2].Tool)
	}
}

func TestStepsFor_UnknownRunReturnsEmpty(t *testing.T) {
	s := NewStore()
	if steps := s.StepsFor("no-such-run"); len(steps) != 0 {
		t.Fatalf("expected no steps for an unknown run, got %d", len(steps))
	}
}

func TestHasCompensableSteps(t *testing.T) {
	s := NewStore()
	if s.HasCompensableSteps("run-1") {
		t.Fatal("expected no compensable steps before anything is recorded")
	}

	s.RecordStep(&Step{RunID: "run-1", Tool: "read_thing", ReversibilityClass: "B", ExecutedAt: time.Now()})
	if s.HasCompensableSteps("run-1") {
		t.Fatal("expected a Class B step to never count as compensable")
	}

	s.RecordStep(&Step{RunID: "run-1", Tool: "mutate_thing", ReversibilityClass: "A", ExecutedAt: time.Now()})
	if !s.HasCompensableSteps("run-1") {
		t.Fatal("expected a Class A step to count as compensable")
	}
}

func TestMarkCompensated_ExcludesFromHasCompensableSteps(t *testing.T) {
	s := NewStore()
	s.RecordStep(&Step{RunID: "run-1", Tool: "mutate_thing", ReversibilityClass: "A", ExecutedAt: time.Now()})
	if !s.HasCompensableSteps("run-1") {
		t.Fatal("expected the fresh step to be compensable")
	}

	s.MarkCompensated("run-1", 0)
	if s.HasCompensableSteps("run-1") {
		t.Fatal("expected a compensated step to no longer count as compensable")
	}

	steps := s.StepsFor("run-1")
	if !steps[0].Compensated {
		t.Fatal("expected the step's Compensated flag to be set")
	}
}

func TestMarkCompensationFailed_ExcludesFromHasCompensableSteps(t *testing.T) {
	s := NewStore()
	s.RecordStep(&Step{RunID: "run-1", Tool: "mutate_thing", ReversibilityClass: "A", ExecutedAt: time.Now()})
	s.MarkCompensationFailed("run-1", 0, "policy denied the compensating call")

	if s.HasCompensableSteps("run-1") {
		t.Fatal("expected a failed-compensation step to not be retried automatically")
	}
	steps := s.StepsFor("run-1")
	if !steps[0].CompensationFailed || steps[0].CompensationNote == "" {
		t.Fatal("expected CompensationFailed set with a note")
	}
}

func TestPersistence_SurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/saga.db"

	s1, err := NewPersistentStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	preImage, _ := json.Marshal(map[string]any{"tier": "silver"})
	s1.RecordStep(&Step{RunID: "run-1", Tool: "update_customer_tier", ReversibilityClass: "A",
		Resource: "42", Args: map[string]any{"tier": "gold"}, PreImage: preImage, ExecutedAt: time.Now()})
	s1.MarkCompensated("run-1", 0)
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := NewPersistentStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s2.Close() })
	steps := s2.StepsFor("run-1")
	if len(steps) != 1 {
		t.Fatalf("expected 1 step to survive reopen, got %d", len(steps))
	}
	if !steps[0].Compensated {
		t.Fatal("expected Compensated status to survive reopen")
	}
	if steps[0].Resource != "42" || string(steps[0].PreImage) != string(preImage) {
		t.Fatalf("expected resource and pre_image to survive reopen intact, got resource=%q preImage=%s", steps[0].Resource, steps[0].PreImage)
	}
}
