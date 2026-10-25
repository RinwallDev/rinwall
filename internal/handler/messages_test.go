package handler

import (
	"context"
	"strings"
	"testing"

	"github.com/RinwallDev/rinwall/internal/proxytypes"
)

// The text of a held call is what an agent relays to the person it acts
// for. These tests pin what that person must be told: that nothing has
// happened, where to act, and that calling again is wrong (approving runs
// the call, so a retry would create a second request).

func mustContain(t *testing.T, msg string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(msg, w) {
			t.Errorf("message missing %q:\n%s", w, msg)
		}
	}
}

func mustNotContain(t *testing.T, msg string, unwanted ...string) {
	t.Helper()
	for _, u := range unwanted {
		if strings.Contains(msg, u) {
			t.Errorf("message should not contain %q:\n%s", u, msg)
		}
	}
}

func TestMessage_IrreversibleApproval_WithoutConsoleURLNamesTheRole(t *testing.T) {
	h, _ := newTestHandler(t)
	res, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "rest", AgentID: "a1", DelegatedUser: "alex@example.com", DelegatedRole: "support",
		Tool: "close_account", Args: map[string]any{"user_id": "42"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "pending_approval" {
		t.Fatalf("expected pending_approval, got %+v", res)
	}
	mustContain(t, res.Reason,
		"Waiting for approval", res.RequestID, "can't be undone", `"admin-lead"`,
		"Nothing has happened yet", "don't call it again")
	// Written for a person, not an API client.
	mustNotContain(t, res.Reason, "POST /", "hash", "reviewer_role=")
}

func TestMessage_IrreversibleApproval_WithConsoleURLPointsThere(t *testing.T) {
	h, _ := newTestHandler(t)
	h.ReviewURL = "http://127.0.0.1:8080/admin"
	res, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "rest", AgentID: "a1", DelegatedUser: "alex@example.com", DelegatedRole: "support",
		Tool: "close_account", Args: map[string]any{"user_id": "42"},
	})
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, res.Reason, "approve or deny it at http://127.0.0.1:8080/admin", "don't call it again")
	mustNotContain(t, res.Reason, `"admin-lead"`)
}

func TestMessage_TaintStepUp_SaysWhichValueAndHowManyApprovals(t *testing.T) {
	h, _ := newTestHandler(t)
	one, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "rest", AgentID: "a2", DelegatedUser: "jordan@example.com", DelegatedRole: "SalesManager",
		Tool: "update_customer_tier", Args: map[string]any{"user_id": "42", "tier": "gold"},
		ArgProvenance: map[string]proxytypes.Provenance{"tier": proxytypes.ProvenanceTainted},
	})
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, one.Reason, `The value for "tier"`, "content the agent read", "a person's approval")

	// Over the four-eyes threshold, the message says two people are needed.
	two, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "rest", AgentID: "a1", DelegatedUser: "alex@example.com", DelegatedRole: "support",
		Tool: "close_account", Args: map[string]any{"user_id": "42"},
		ArgProvenance: map[string]proxytypes.Provenance{"user_id": proxytypes.ProvenanceTainted},
	})
	if err != nil {
		t.Fatal(err)
	}
	if two.RequiredApprovals != 2 {
		t.Fatalf("expected a four-eyes request, got %d approvals", two.RequiredApprovals)
	}
	mustContain(t, two.Reason, "approval from 2 different people")
}

func TestMessage_Hold_SaysItRunsOnItsOwnAndWhereToStopIt(t *testing.T) {
	h, _ := newTestHandler(t)
	h.ReviewURL = "http://127.0.0.1:8080/admin"
	res, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "rest", AgentID: "a1", DelegatedUser: "alex@example.com", DelegatedRole: "support",
		Tool: "send_refund_email", Args: map[string]any{"user_id": "42", "amount_cents": 9000.0},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "pending_hold" {
		t.Fatalf("expected pending_hold, got %+v", res)
	}
	// Cancel so the hold doesn't fire after the test has moved on.
	defer h.Approvals.CancelHold(res.HoldID, "support-lead")
	mustContain(t, res.Reason, "Scheduled", res.HoldID, "can't be undone",
		"cancel it at http://127.0.0.1:8080/admin", "Don't call it again")
	mustNotContain(t, res.Reason, "POST /")
}

func TestArgList_HandlesNoneOneAndMany(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{nil, "Part of this call"},
		{[]string{"tier"}, `The value for "tier"`},
		{[]string{"tier", "status"}, `The values for "tier", "status"`},
	} {
		if got := argList(tc.in); got != tc.want {
			t.Errorf("argList(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
