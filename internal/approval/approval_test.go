package approval

import (
	"sync"
	"testing"
	"time"
)

func TestRequestHash_ChangedPayloadProducesDifferentHash(t *testing.T) {
	h1, err := RequestHash("close_account", map[string]any{"user_id": "42"}, "42", "alex@example.com")
	if err != nil {
		t.Fatal(err)
	}
	h2, err := RequestHash("close_account", map[string]any{"user_id": "43"}, "43", "alex@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h2 {
		t.Fatal("expected different args to produce different hashes")
	}
	h1Again, _ := RequestHash("close_account", map[string]any{"user_id": "42"}, "42", "alex@example.com")
	if h1 != h1Again {
		t.Fatal("expected identical inputs to produce a deterministic hash")
	}
}

func TestEnvelope_TierOneMatchAndBudget(t *testing.T) {
	s := NewStore()
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
	if env.UsesRemaining != 0 {
		t.Fatalf("expected 0 uses remaining, got %d", env.UsesRemaining)
	}
}

func TestEnvelope_Expired(t *testing.T) {
	s := NewStore()
	if _, err := s.CreateEnvelope("send_refund_email", nil, 5, -time.Hour); err != nil { // already expired
		t.Fatal(err)
	}
	if _, ok := s.CheckPreAuth("send_refund_email", map[string]any{}); ok {
		t.Fatal("expected an expired envelope to never match")
	}
}

func TestApprove_HashMismatchRejected(t *testing.T) {
	s := NewStore()
	p, err := s.CreateApproval("close_account", map[string]any{"user_id": "42"}, "42", "alex@example.com", "admin-lead", time.Minute, 1, 0, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(p.ID, "wrong-hash", "morgan@example.com", "admin-lead"); err == nil {
		t.Fatal("expected hash mismatch to be rejected")
	}
}

func TestApprove_WrongReviewerRoleRejected(t *testing.T) {
	s := NewStore()
	p, err := s.CreateApproval("close_account", map[string]any{"user_id": "42"}, "42", "alex@example.com", "admin-lead", time.Minute, 1, 0, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(p.ID, p.Hash, "morgan@example.com", "support"); err == nil {
		t.Fatal("expected approver with wrong role to be rejected")
	}
}

func TestApprove_SelfApprovalRejected(t *testing.T) {
	s := NewStore()
	p, err := s.CreateApproval("close_account", map[string]any{"user_id": "42"}, "42", "alex@example.com", "admin-lead", time.Minute, 1, 0, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	// alex requested it - alex, even with the right role, cannot approve their own request.
	if _, err := s.Approve(p.ID, p.Hash, "alex@example.com", "admin-lead"); err == nil {
		t.Fatal("expected the original requester to be rejected as their own approver")
	}
}

func TestApprove_CorrectApproverSucceeds(t *testing.T) {
	s := NewStore()
	p, err := s.CreateApproval("close_account", map[string]any{"user_id": "42"}, "42", "alex@example.com", "admin-lead", time.Minute, 1, 0, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	approved, err := s.Approve(p.ID, p.Hash, "morgan@example.com", "admin-lead")
	if err != nil {
		t.Fatalf("expected a correctly-routed, non-self approval to succeed, got: %v", err)
	}
	if approved.Status != StatusApproved {
		t.Fatalf("expected status approved, got %s", approved.Status)
	}
	// Can't approve twice.
	if _, err := s.Approve(p.ID, p.Hash, "morgan@example.com", "admin-lead"); err == nil {
		t.Fatal("expected re-approving an already-approved request to fail")
	}
}

func TestApprove_FourEyesRequiresTwoDistinctApprovers(t *testing.T) {
	s := NewStore()
	p, err := s.CreateApproval("close_account", map[string]any{"user_id": "42"}, "42", "alex@example.com", "admin-lead", time.Minute, 2, 0.85, []string{"user_id"}, "")
	if err != nil {
		t.Fatal(err)
	}

	first, err := s.Approve(p.ID, p.Hash, "morgan@example.com", "admin-lead")
	if err != nil {
		t.Fatalf("expected the first of two required approvals to be recorded, got: %v", err)
	}
	if first.Status == StatusApproved {
		t.Fatal("expected status to still be pending after only 1 of 2 required approvals")
	}
	if len(first.Approvers) != 1 {
		t.Fatalf("expected 1 recorded approver, got %d", len(first.Approvers))
	}

	// The same approver again must be rejected - one person can't satisfy
	// four-eyes by clicking twice.
	if _, err := s.Approve(p.ID, p.Hash, "morgan@example.com", "admin-lead"); err == nil {
		t.Fatal("expected the same approver approving twice to be rejected")
	}

	second, err := s.Approve(p.ID, p.Hash, "priya@example.com", "admin-lead")
	if err != nil {
		t.Fatalf("expected the second, distinct approver to succeed, got: %v", err)
	}
	if second.Status != StatusApproved {
		t.Fatalf("expected status approved after 2 of 2 required approvals, got %s", second.Status)
	}
}

func TestDeny_SelfDenialRejected(t *testing.T) {
	s := NewStore()
	p, err := s.CreateApproval("close_account", map[string]any{"user_id": "42"}, "42", "alex@example.com", "admin-lead", time.Minute, 1, 0, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Deny(p.ID, "alex@example.com", "admin-lead"); err == nil {
		t.Fatal("expected the original requester to be rejected as their own denier")
	}
}

func TestHold_CancelBeforeFire(t *testing.T) {
	s := NewStore()
	fired := make(chan struct{}, 1)
	hold, err := s.EnqueueHold("send_refund_email", map[string]any{"user_id": "42"}, 3600, "alex@example.com", "support", "a1", "run-1", "support-lead", func() {
		fired <- struct{}{}
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CancelHold(hold.ID, "support-lead"); err != nil {
		t.Fatalf("expected cancel before fire to succeed, got: %v", err)
	}
	select {
	case <-fired:
		t.Fatal("cancelled hold should never fire")
	case <-time.After(50 * time.Millisecond):
		// expected: nothing fired
	}
}

func TestHold_FiresAndThenCannotBeCancelled(t *testing.T) {
	s := NewStore()
	var wg sync.WaitGroup
	wg.Add(1)
	hold, err := s.EnqueueHold("send_refund_email", map[string]any{"user_id": "42"}, 0, "alex@example.com", "support", "a1", "run-1", "support-lead", func() {
		wg.Done()
	})
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait() // fires ~immediately with holdSeconds=0
	time.Sleep(10 * time.Millisecond)
	if _, err := s.CancelHold(hold.ID, "support-lead"); err == nil {
		t.Fatal("expected cancelling an already-fired hold to fail")
	}
}

func TestHold_CancelRequiresMatchingReviewerRole(t *testing.T) {
	s := NewStore()
	hold, err := s.EnqueueHold("send_refund_email", map[string]any{"user_id": "42"}, 3600, "alex@example.com", "support", "a1", "run-1", "support-lead", func() {})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CancelHold(hold.ID, "admin-lead"); err == nil {
		t.Fatal("expected cancel with the wrong role to be rejected")
	}
	if _, err := s.CancelHold(hold.ID, "support-lead"); err != nil {
		t.Fatalf("expected cancel with the matching reviewer_role to succeed, got: %v", err)
	}
}

func TestHold_RequesterCanCancelOwnHold(t *testing.T) {
	// Unlike self-approval, cancelling is never blocked for the original
	// requester - it only ever prevents an action, never pushes one
	// through, so there's no conflict of interest to guard against.
	s := NewStore()
	hold, err := s.EnqueueHold("send_refund_email", map[string]any{"user_id": "42"}, 3600, "alex@example.com", "support-lead", "a1", "run-1", "support-lead", func() {})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CancelHold(hold.ID, "support-lead"); err != nil {
		t.Fatalf("expected the original requester (also holding the reviewer role) to be able to cancel their own hold, got: %v", err)
	}
}
