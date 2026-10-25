package approval

import (
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// testPostgresDSN returns the DSN for the local Postgres this package's
// integration tests run against, and skips the calling test unless
// JIT_INTEGRATION_POSTGRES=1 - same convention already established by
// internal/capability/dbsecrets_test.go, so one running Postgres container
// (see the plan's Tier 1 section for the docker run command) serves every
// integration test in this repo.
func testPostgresDSN(t *testing.T) string {
	t.Helper()
	if os.Getenv("JIT_INTEGRATION_POSTGRES") != "1" {
		t.Skip("set JIT_INTEGRATION_POSTGRES=1 to run against a real local Postgres (see the plan's Tier 1 storage-backend section for setup)")
	}
	return envOrDefault("JIT_TEST_STATE_PG_DSN", "postgres://postgres:state-test-pw@127.0.0.1:5434/jitfirewall_state?sslmode=disable")
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// newTestPostgresStore opens a fresh Postgres-backed Store and truncates
// all three tables first, so each test starts from a clean slate against
// the same long-lived database rather than needing a throwaway database
// per test.
func newTestPostgresStore(t *testing.T) *Store {
	t.Helper()
	dsn := testPostgresDSN(t)
	s, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	if _, err := s.pg.Exec(`TRUNCATE envelopes, approvals, holds RESTART IDENTITY`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	t.Cleanup(func() { s.pg.Close() })
	return s
}

// --- functional parity with the in-memory/SQLite path -----------------

func TestPostgres_Envelope_TierOneMatchAndBudget(t *testing.T) {
	s := newTestPostgresStore(t)
	env, err := s.CreateEnvelope("send_refund_email", map[string]Constraint{
		"amount_cents": {Op: "lte", Value: "5000"},
	}, 2, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.CheckPreAuth("send_refund_email", map[string]any{"amount_cents": 1500.0}); !ok {
		t.Fatal("expected a call within the envelope's constraint to match")
	}
	if _, ok := s.CheckPreAuth("send_refund_email", map[string]any{"amount_cents": 9000.0}); ok {
		t.Fatal("expected a call exceeding the constraint to NOT match")
	}
	if _, ok := s.CheckPreAuth("send_refund_email", map[string]any{"amount_cents": 1500.0}); !ok {
		t.Fatal("expected second use within budget to match")
	}
	if _, ok := s.CheckPreAuth("send_refund_email", map[string]any{"amount_cents": 1500.0}); ok {
		t.Fatal("expected envelope to be exhausted after max_uses is spent")
	}
	envs := s.ListEnvelopes()
	if len(envs) != 1 || envs[0].ID != env.ID || envs[0].UsesRemaining != 0 {
		t.Fatalf("expected the persisted envelope to show 0 uses remaining, got %+v", envs)
	}
}

func TestPostgres_Approve_FullInvariantSet(t *testing.T) {
	s := newTestPostgresStore(t)
	p, err := s.CreateApproval("close_account", map[string]any{"user_id": "42"}, "42", "alex@example.com", "admin-lead", time.Minute, 1, 0, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(p.ID, "wrong-hash", "morgan@example.com", "admin-lead"); err == nil {
		t.Fatal("expected hash mismatch to be rejected")
	}
	if _, err := s.Approve(p.ID, p.Hash, "morgan@example.com", "support"); err == nil {
		t.Fatal("expected wrong reviewer role to be rejected")
	}
	if _, err := s.Approve(p.ID, p.Hash, "alex@example.com", "admin-lead"); err == nil {
		t.Fatal("expected the requester to be rejected approving their own request")
	}
	got, err := s.Approve(p.ID, p.Hash, "morgan@example.com", "admin-lead")
	if err != nil {
		t.Fatalf("expected a valid approval to succeed, got: %v", err)
	}
	if got.Status != StatusApproved {
		t.Fatalf("expected status Approved, got %s", got.Status)
	}
	if _, err := s.Approve(p.ID, p.Hash, "morgan@example.com", "admin-lead"); err == nil {
		t.Fatal("expected approving an already-approved request to be rejected")
	}
}

func TestPostgres_FourEyes_RequiresTwoDistinctApprovers(t *testing.T) {
	s := newTestPostgresStore(t)
	p, err := s.CreateApproval("send_refund_email", map[string]any{"user_id": "42"}, "42", "alex@example.com", "support-lead", time.Minute, 2, 0.75, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Approve(p.ID, p.Hash, "sam@example.com", "support-lead")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusPending {
		t.Fatalf("expected still pending after 1 of 2, got %s", got.Status)
	}
	if _, err := s.Approve(p.ID, p.Hash, "sam@example.com", "support-lead"); err == nil {
		t.Fatal("expected the same approver twice to be rejected")
	}
	got, err = s.Approve(p.ID, p.Hash, "robin@example.com", "support-lead")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusApproved || len(got.Approvers) != 2 {
		t.Fatalf("expected approved with 2 distinct approvers, got %+v", got)
	}
}

func TestPostgres_Hold_CreateCancelAndPollFire(t *testing.T) {
	s := newTestPostgresStore(t)

	cancelMe, err := s.EnqueueHold("send_refund_email", map[string]any{"user_id": "1"}, 3600, "alex@example.com", "support", "a1", "run-1", "support-lead", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CancelHold(cancelMe.ID, "admin-lead"); err == nil {
		t.Fatal("expected cancel with the wrong reviewer_role to be rejected")
	}
	if _, err := s.CancelHold(cancelMe.ID, "support-lead"); err != nil {
		t.Fatalf("expected cancel to succeed, got: %v", err)
	}

	// holdSeconds=0 -> immediately due.
	dueNow, err := s.EnqueueHold("send_refund_email", map[string]any{"user_id": "2"}, 0, "alex@example.com", "support", "a1", "run-2", "support-lead", nil)
	if err != nil {
		t.Fatal(err)
	}

	var fired []*Hold
	var mu sync.Mutex
	s.PollAndFireDueHolds(10, func(h *Hold) {
		mu.Lock()
		fired = append(fired, h)
		mu.Unlock()
	})

	if len(fired) != 1 || fired[0].ID != dueNow.ID {
		t.Fatalf("expected exactly the due, uncancelled hold to fire, got %+v", fired)
	}
	if _, err := s.CancelHold(dueNow.ID, "support-lead"); err == nil {
		t.Fatal("expected cancelling an already-fired hold to fail")
	}

	// A second poll pass must not re-fire it.
	fired = nil
	s.PollAndFireDueHolds(10, func(h *Hold) { fired = append(fired, h) })
	if len(fired) != 0 {
		t.Fatalf("expected a second poll pass to find nothing new, got %+v", fired)
	}
}

// --- the actual proof: concurrent multi-"instance" correctness ---------

// TestPostgres_ConcurrentApprove_NoLostUpdate simulates two proxy
// instances (two separate *sql.DB connections against the same Postgres
// database, exactly like two real processes) racing to record different
// approvers on the same four-eyes request at the same instant. The
// in-process sync.Mutex that makes the in-memory Store correct for one
// process provides zero protection here - this test is the actual proof
// that approvePG's row lock (SELECT ... FOR UPDATE) does the job instead.
func TestPostgres_ConcurrentApprove_NoLostUpdate(t *testing.T) {
	dsn := testPostgresDSN(t)
	s1, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s1.pg.Close()
	if _, err := s1.pg.Exec(`TRUNCATE envelopes, approvals, holds RESTART IDENTITY`); err != nil {
		t.Fatal(err)
	}
	s2, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.pg.Close()

	p, err := s1.CreateApproval("send_refund_email", map[string]any{"user_id": "42"}, "42", "alex@example.com", "support-lead", time.Minute, 2, 0.75, nil, "")
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	results := make([]error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); _, results[0] = s1.Approve(p.ID, p.Hash, "sam@example.com", "support-lead") }()
	go func() { defer wg.Done(); _, results[1] = s2.Approve(p.ID, p.Hash, "robin@example.com", "support-lead") }()
	wg.Wait()

	if results[0] != nil || results[1] != nil {
		t.Fatalf("expected both distinct approvers to succeed, got %v / %v", results[0], results[1])
	}
	final, ok := s1.Get(p.ID)
	if !ok {
		t.Fatal("expected the approval to still exist")
	}
	if final.Status != StatusApproved {
		t.Fatalf("expected status Approved once both approvers landed, got %s", final.Status)
	}
	if len(final.Approvers) != 2 {
		t.Fatalf("expected exactly 2 recorded approvers (no lost update), got %d: %v", len(final.Approvers), final.Approvers)
	}
}

// TestPostgres_ConcurrentCheckPreAuth_NeverOverConsumes fires many
// concurrent CheckPreAuth calls (simulating many instances/agents) at a
// tightly-budgeted envelope and asserts the number of successful
// consumptions exactly equals the budget - proving the row lock in
// checkPreAuthPG, not luck, is what prevents over-granting the same
// "last use" to more than one caller.
func TestPostgres_ConcurrentCheckPreAuth_NeverOverConsumes(t *testing.T) {
	s := newTestPostgresStore(t)
	const budget = 5
	const attempts = 30
	if _, err := s.CreateEnvelope("send_refund_email", nil, budget, time.Hour); err != nil {
		t.Fatal(err)
	}

	var successes int64
	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			if _, ok := s.CheckPreAuth("send_refund_email", map[string]any{}); ok {
				atomic.AddInt64(&successes, 1)
			}
		}()
	}
	wg.Wait()

	if successes != budget {
		t.Fatalf("expected exactly %d successful consumptions out of %d attempts, got %d", budget, attempts, successes)
	}
}

// TestPostgres_ConcurrentPollAndFireDueHolds_FiresExactlyOnce simulates
// two instances polling at once (SELECT ... FOR UPDATE SKIP LOCKED) and
// asserts a single due hold fires exactly once, not zero or two times.
func TestPostgres_ConcurrentPollAndFireDueHolds_FiresExactlyOnce(t *testing.T) {
	dsn := testPostgresDSN(t)
	s1, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s1.pg.Close()
	if _, err := s1.pg.Exec(`TRUNCATE envelopes, approvals, holds RESTART IDENTITY`); err != nil {
		t.Fatal(err)
	}
	s2, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.pg.Close()

	if _, err := s1.EnqueueHold("send_refund_email", map[string]any{"user_id": "1"}, 0, "alex@example.com", "support", "a1", "run-1", "support-lead", nil); err != nil {
		t.Fatal(err)
	}

	var fireCount int64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		s1.PollAndFireDueHolds(10, func(h *Hold) { atomic.AddInt64(&fireCount, 1) })
	}()
	go func() {
		defer wg.Done()
		s2.PollAndFireDueHolds(10, func(h *Hold) { atomic.AddInt64(&fireCount, 1) })
	}()
	wg.Wait()

	if fireCount != 1 {
		t.Fatalf("expected the due hold to fire exactly once across two concurrently polling instances, got %d", fireCount)
	}
}
