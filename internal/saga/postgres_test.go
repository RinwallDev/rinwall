package saga

import (
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// testPostgresDSN mirrors internal/approval/postgres_test.go's convention -
// same env var, same local Postgres container, different database tables.
func testPostgresDSN(t *testing.T) string {
	t.Helper()
	if os.Getenv("JIT_INTEGRATION_POSTGRES") != "1" {
		t.Skip("set JIT_INTEGRATION_POSTGRES=1 to run against a real local Postgres (see the plan's Tier 1 storage-backend section for setup)")
	}
	if v := os.Getenv("JIT_TEST_STATE_PG_DSN"); v != "" {
		return v
	}
	return "postgres://postgres:state-test-pw@127.0.0.1:5434/jitfirewall_state?sslmode=disable"
}

func newTestPostgresStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewPostgresStore(testPostgresDSN(t))
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	if _, err := s.pg.Exec(`TRUNCATE saga_steps`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	t.Cleanup(func() { s.pg.Close() })
	return s
}

func TestPostgres_RecordStep_AssignsIncreasingSeq(t *testing.T) {
	s := newTestPostgresStore(t)
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

func TestPostgres_HasCompensableSteps_And_MarkCompensated(t *testing.T) {
	s := newTestPostgresStore(t)
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
	s.MarkCompensated("run-1", 1)
	if s.HasCompensableSteps("run-1") {
		t.Fatal("expected the compensated step to no longer count")
	}
	steps := s.StepsFor("run-1")
	if !steps[1].Compensated {
		t.Fatal("expected the persisted step to reflect compensated=true")
	}
}

func TestPostgres_MarkCompensationFailed_RecordsNote(t *testing.T) {
	s := newTestPostgresStore(t)
	s.RecordStep(&Step{RunID: "run-1", Tool: "mutate_thing", ReversibilityClass: "A", ExecutedAt: time.Now()})
	s.MarkCompensationFailed("run-1", 0, "upstream refused the reversal")
	steps := s.StepsFor("run-1")
	if !steps[0].CompensationFailed || steps[0].CompensationNote != "upstream refused the reversal" {
		t.Fatalf("expected compensation failure + note persisted, got %+v", steps[0])
	}
	if s.HasCompensableSteps("run-1") {
		t.Fatal("expected a failed-compensation step to also stop counting as compensable (nothing more to do automatically)")
	}
}

// TestPostgres_ConcurrentRecordStep_NoDuplicateSeq is the actual proof:
// two "instances" (two separate *sql.DB handles against the same Postgres
// database) recording steps for the SAME run at the same instant. The
// in-process mutex that makes the in-memory Store's len(s.runs[runID])
// sequencing correct for one process provides no protection here -
// without recordStepPG's row lock, both could compute the same Seq and
// either collide on the primary key or silently overwrite one another.
func TestPostgres_ConcurrentRecordStep_NoDuplicateSeq(t *testing.T) {
	dsn := testPostgresDSN(t)
	s1, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s1.pg.Close()
	if _, err := s1.pg.Exec(`TRUNCATE saga_steps`); err != nil {
		t.Fatal(err)
	}
	s2, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.pg.Close()

	const perInstance = 10
	var wg sync.WaitGroup
	wg.Add(2)
	record := func(s *Store, toolPrefix string) {
		defer wg.Done()
		for i := 0; i < perInstance; i++ {
			s.RecordStep(&Step{RunID: "run-concurrent", Tool: toolPrefix, ReversibilityClass: "A", ExecutedAt: time.Now()})
		}
	}
	go record(s1, "from-instance-1")
	go record(s2, "from-instance-2")
	wg.Wait()

	steps := s1.StepsFor("run-concurrent")
	if len(steps) != perInstance*2 {
		t.Fatalf("expected %d total steps, got %d", perInstance*2, len(steps))
	}
	seen := make(map[int]bool)
	for _, step := range steps {
		if seen[step.Seq] {
			t.Fatalf("duplicate seq %d found - two instances assigned the same sequence number", step.Seq)
		}
		seen[step.Seq] = true
	}
	for i := 0; i < perInstance*2; i++ {
		if !seen[i] {
			t.Fatalf("expected a contiguous 0..%d sequence, missing %d", perInstance*2-1, i)
		}
	}
}
