package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RinwallDev/rinwall/internal/approval"
	"github.com/RinwallDev/rinwall/internal/audit"
	"github.com/RinwallDev/rinwall/internal/capability"
	"github.com/RinwallDev/rinwall/internal/policy"
	"github.com/RinwallDev/rinwall/internal/provenance"
	"github.com/RinwallDev/rinwall/internal/proxytypes"
	"github.com/RinwallDev/rinwall/internal/registry"
	"github.com/RinwallDev/rinwall/internal/saga"
	"github.com/RinwallDev/rinwall/internal/visualprovenance"
)

const testPolicyPath = "../../policies/tool_policy.rego"

// testToolsYAML mirrors the real examples/tools.yaml but with a 1-second
// hold window (instead of 20s) so the tier-2 test doesn't sit around.
const testToolsYAML = `
tools:
  - name: get_user
    reversibility_class: B
    method: GET
    path: /users/{user_id}
    resource_arg: user_id
    args_schema:
      user_id: {type: string, required: true}

  - name: log_event
    reversibility_class: B
    method: POST
    path: /events
    args_schema:
      message: {type: string, required: true}

  - name: computer
    reversibility_class: B
    method: POST
    path: /events
    reviewer_role: admin-lead
    visual_provenance_judge: true
    visual_judge_action_arg: action
    visual_judge_trigger_values: ["left_click", "type"]
    args_schema:
      action: {type: string, required: true}
      coordinate: {type: string}
      text: {type: string}

  - name: update_customer_tier
    reversibility_class: A
    method: PATCH
    path: /users/{user_id}/tier
    resource_arg: user_id
    compensate_fields: ["tier"]
    reviewer_role: SalesManager
    pre_image:
      method: GET
      path: /users/{user_id}
    args_schema:
      user_id: {type: string, required: true}
      tier: {type: string, required: true, enum: ["silver", "gold"]}

  - name: update_customer_status
    reversibility_class: A
    method: PATCH
    path: /users/{user_id}/status
    resource_arg: user_id
    compensate_fields: ["status"]
    reviewer_role: admin-lead
    provenance_judge: true
    pre_image:
      method: GET
      path: /users/{user_id}
    args_schema:
      user_id: {type: string, required: true}
      status: {type: string, required: true, enum: ["active", "suspended"]}

  - name: send_refund_email
    reversibility_class: C
    method: POST
    path: /refund-emails
    resource_arg: user_id
    deferrable: true
    hold_seconds: 1
    reviewer_role: support-lead
    args_schema:
      user_id: {type: string, required: true}
      amount_cents: {type: number, required: true}

  - name: close_account
    reversibility_class: C
    method: POST
    path: /users/{user_id}/close
    resource_arg: user_id
    reviewer_role: admin-lead
    args_schema:
      user_id: {type: string, required: true}
`

// newTestHandler spins up a permissive fake upstream (no token verification -
// that's exercised by cmd/mockupstream, not here) and wires a real handler
// against it, loading the actual shipped policy bundle so this test breaks
// if policy.rego and the handler ever drift apart.
func newTestHandler(t *testing.T) (*Handler, *fakeUpstream) {
	t.Helper()

	capIssuer, err := capability.NewBiscuitRootIssuer(context.Background(), &capability.FakeKeyRingStore{}, capability.FakeSeedMinter{})
	if err != nil {
		t.Fatal(err)
	}
	pubKeyHex, err := capIssuer.CurrentPublicKeyHex()
	if err != nil {
		t.Fatal(err)
	}

	upstream := newFakeUpstream(t, pubKeyHex)
	server := httptest.NewServer(upstream)
	t.Cleanup(server.Close)

	dir := t.TempDir()
	toolsPath := filepath.Join(dir, "tools.yaml")
	if err := os.WriteFile(toolsPath, []byte(testToolsYAML), 0644); err != nil {
		t.Fatal(err)
	}
	reg, err := registry.LoadFromYAML(toolsPath)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}

	pol, err := policy.New(context.Background(), testPolicyPath)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}

	aud, err := audit.Open(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { aud.Close() })

	h := New(reg, pol, capIssuer, approval.NewStore(), aud, saga.NewStore(), server.URL)
	return h, upstream
}

// fakeUpstream is a minimal stand-in for cmd/mockupstream - verifies real
// biscuit tokens on every mutating route, just like the real thing, plus a
// channel so async paths (tier-2 hold firing) can be awaited deterministically
// instead of slept for.
type fakeUpstream struct {
	mu           sync.Mutex
	tiers        map[string]string
	statuses     map[string]string
	refundCalls  chan map[string]any
	publicKeyHex string
	// failPreImageFor makes GET /users/{id} return 503 for that id, to
	// exercise the pre-image-capture-failed path.
	failPreImageFor string
}

func newFakeUpstream(t *testing.T, publicKeyHex string) *fakeUpstream {
	return &fakeUpstream{
		tiers:        map[string]string{"42": "silver"},
		statuses:     map[string]string{"42": "active"},
		refundCalls:  make(chan map[string]any, 10),
		publicKeyHex: publicKeyHex,
	}
}

func (f *fakeUpstream) verify(r *http.Request, tool, resource string) error {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return capability.Verify(token, []string{f.publicKeyHex}, tool, resource)
}

func (f *fakeUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/users/") && !strings.Contains(strings.TrimPrefix(r.URL.Path, "/users/"), "/"):
		id := strings.TrimPrefix(r.URL.Path, "/users/")
		f.mu.Lock()
		tier, status, fail := f.tiers[id], f.statuses[id], f.failPreImageFor == id
		f.mu.Unlock()
		if fail {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"id": id, "tier": tier, "status": status})
	case r.Method == "PATCH" && strings.HasSuffix(r.URL.Path, "/tier") && strings.HasPrefix(r.URL.Path, "/users/"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/users/"), "/tier")
		if err := f.verify(r, "update_customer_tier", id); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"detail": err.Error()})
			return
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		prev := f.tiers[id]
		f.tiers[id] = fmt.Sprintf("%v", body["tier"])
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"status": "updated", "previous_tier": prev})
	case r.Method == "PATCH" && strings.HasSuffix(r.URL.Path, "/status") && strings.HasPrefix(r.URL.Path, "/users/"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/users/"), "/status")
		if err := f.verify(r, "update_customer_status", id); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"detail": err.Error()})
			return
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		prev := f.statuses[id]
		f.statuses[id] = fmt.Sprintf("%v", body["status"])
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"status": "updated", "previous_status": prev})
	case r.Method == "POST" && r.URL.Path == "/events":
		json.NewEncoder(w).Encode(map[string]any{"status": "logged"})
	case r.Method == "POST" && r.URL.Path == "/refund-emails":
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if err := f.verify(r, "send_refund_email", fmt.Sprintf("%v", body["user_id"])); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"detail": err.Error()})
			return
		}
		f.refundCalls <- body
		json.NewEncoder(w).Encode(map[string]any{"status": "sent"})
	case r.Method == "POST" && r.URL.Path == "/users/42/close":
		if err := f.verify(r, "close_account", "42"); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"detail": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "closed"})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeUpstream) TierOf(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tiers[id]
}

func (f *fakeUpstream) StatusOf(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.statuses[id]
}

func TestHandle_ClassB_LogEvent(t *testing.T) {
	h, _ := newTestHandler(t)
	res, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "rest", AgentID: "a1", DelegatedUser: "alex@example.com", DelegatedRole: "support",
		Tool: "log_event", Args: map[string]any{"message": "hi"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "executed" {
		t.Fatalf("expected executed, got %+v", res)
	}
}

func TestHandle_ClassA_TierUpdate_CapturesPreImage(t *testing.T) {
	h, _ := newTestHandler(t)
	res, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "rest", AgentID: "a1", DelegatedUser: "jordan@example.com", DelegatedRole: "SalesManager",
		Tool: "update_customer_tier", Args: map[string]any{"user_id": "42", "tier": "gold"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "executed" {
		t.Fatalf("expected executed, got %+v", res)
	}
	pre, ok := h.LastPreImage("update_customer_tier", "42")
	if !ok {
		t.Fatal("expected a pre-image snapshot to have been captured before the mutation")
	}
	var snapshot map[string]any
	json.Unmarshal(pre, &snapshot)
	if snapshot["tier"] != "silver" {
		t.Fatalf("expected pre-image to capture the OLD tier (silver), got %v", snapshot["tier"])
	}
}

func TestHandle_ConfusedDeputy_Denied(t *testing.T) {
	h, _ := newTestHandler(t)
	res, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "rest", AgentID: "a1", DelegatedUser: "alex@example.com", DelegatedRole: "support",
		Tool: "update_customer_tier", Args: map[string]any{"user_id": "42", "tier": "gold"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "denied" {
		t.Fatalf("expected a support-role tier change to be denied, got %+v", res)
	}
}

func TestHandle_ClassC_Tier1_Envelope(t *testing.T) {
	h, _ := newTestHandler(t)
	if _, err := h.Approvals.CreateEnvelope("send_refund_email", map[string]approval.Constraint{
		"amount_cents": {Op: "lte", Value: "5000"},
	}, 1, time.Hour); err != nil {
		t.Fatal(err)
	}

	res, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "rest", AgentID: "a1", DelegatedUser: "alex@example.com", DelegatedRole: "support",
		Tool: "send_refund_email", Args: map[string]any{"user_id": "42", "amount_cents": 1500.0},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "executed" {
		t.Fatalf("expected tier-1 envelope match to execute immediately, got %+v", res)
	}
}

func TestHandle_ClassC_Tier2_HoldFiresAfterWindow(t *testing.T) {
	h, upstream := newTestHandler(t)
	res, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "rest", AgentID: "a1", DelegatedUser: "alex@example.com", DelegatedRole: "support",
		Tool: "send_refund_email", Args: map[string]any{"user_id": "42", "amount_cents": 9000.0},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "pending_hold" {
		t.Fatalf("expected pending_hold (no matching envelope), got %+v", res)
	}
	select {
	case call := <-upstream.refundCalls:
		if call["user_id"] != "42" {
			t.Fatalf("expected the held call to fire for user 42, got %v", call)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("expected the tier-2 hold to fire on its own after its window elapsed")
	}
}

func TestHandle_ClassC_Tier2_CancelledHoldNeverFires(t *testing.T) {
	h, upstream := newTestHandler(t)
	res, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "rest", AgentID: "a1", DelegatedUser: "alex@example.com", DelegatedRole: "support",
		Tool: "send_refund_email", Args: map[string]any{"user_id": "42", "amount_cents": 9000.0},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Approvals.CancelHold(res.HoldID, "support-lead"); err != nil {
		t.Fatalf("expected cancel to succeed: %v", err)
	}
	select {
	case call := <-upstream.refundCalls:
		t.Fatalf("expected a cancelled hold to never fire, but it executed: %v", call)
	case <-time.After(1500 * time.Millisecond):
		// expected: nothing fired
	}
}

func TestHandle_ClassC_Tier3_ApprovalFlow(t *testing.T) {
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

	// Wrong hash rejected.
	if _, err := h.Approvals.Approve(res.RequestID, "wrong-hash", "morgan@example.com", "admin-lead"); err == nil {
		t.Fatal("expected hash-mismatched approval to be rejected")
	}
	// Self-approval rejected even with the right role.
	if _, err := h.Approvals.Approve(res.RequestID, res.RequestHash, "alex@example.com", "admin-lead"); err == nil {
		t.Fatal("expected the original requester to be rejected as their own approver")
	}

	pending, _ := h.Approvals.Get(res.RequestID)
	approved, err := h.Approvals.Approve(res.RequestID, res.RequestHash, "morgan@example.com", "admin-lead")
	if err != nil {
		t.Fatalf("expected correctly-routed approval to succeed: %v", err)
	}
	final, err := h.CompleteApproval(context.Background(), approved, proxytypes.CallRequest{
		Transport: "rest", DelegatedUser: "morgan@example.com", DelegatedRole: "admin-lead", Tool: pending.Tool,
	})
	if err != nil {
		t.Fatal(err)
	}
	if final.Status != "executed" {
		t.Fatalf("expected the approved call to finally execute, got %+v", final)
	}
}

func TestHandle_CircuitBreaker_LoopDetection(t *testing.T) {
	h, _ := newTestHandler(t)
	req := proxytypes.CallRequest{
		Transport: "rest", AgentID: "a1", DelegatedUser: "alex@example.com", DelegatedRole: "support",
		Tool: "log_event", Args: map[string]any{"message": "same call repeated"},
	}
	var lastDenied bool
	for i := 0; i < loopThreshold+2; i++ {
		res, err := h.Handle(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if res.Status == "denied" {
			lastDenied = true
		}
	}
	if !lastDenied {
		t.Fatal("expected the identical call, repeated past the loop threshold, to eventually be denied")
	}
}

// --- Phase 2: Intent Integrity Plane ---------------------------------------

func TestHandle_TaintedClassA_ForcesStepUp_EvenWithPermittedRole(t *testing.T) {
	h, _ := newTestHandler(t)
	// jordan/SalesManager is fully permitted by policy to set tier=gold -
	// see TestHandle_ClassA_TierUpdate_CapturesPreImage, which executes
	// immediately with this exact role. The only difference here is that
	// "tier" is marked tainted - that alone must force step-up.
	res, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "rest", AgentID: "a2", DelegatedUser: "jordan@example.com", DelegatedRole: "SalesManager",
		Tool: "update_customer_tier", Args: map[string]any{"user_id": "42", "tier": "gold"},
		ArgProvenance: map[string]proxytypes.Provenance{"tier": proxytypes.ProvenanceTainted},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "pending_approval" {
		t.Fatalf("expected a tainted argument to force step-up despite a fully-permitted role, got %+v", res)
	}
	if len(res.TaintedArgs) != 1 || res.TaintedArgs[0] != "tier" {
		t.Fatalf("expected tainted_args=[tier], got %v", res.TaintedArgs)
	}
}

func TestHandle_TaintedClassC_SkipsMatchingEnvelope(t *testing.T) {
	h, _ := newTestHandler(t)
	if _, err := h.Approvals.CreateEnvelope("send_refund_email", map[string]approval.Constraint{
		"amount_cents": {Op: "lte", Value: "5000"},
	}, 5, time.Hour); err != nil {
		t.Fatal(err)
	}

	// Without taint, this exact call matches the envelope and executes
	// instantly - see TestHandle_ClassC_Tier1_Envelope. With "amount_cents"
	// tainted, it must be routed to tier-3 approval instead, even though
	// a live envelope that would otherwise cover it exists.
	res, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "rest", AgentID: "a1", DelegatedUser: "alex@example.com", DelegatedRole: "support",
		Tool: "send_refund_email", Args: map[string]any{"user_id": "42", "amount_cents": 1500.0},
		ArgProvenance: map[string]proxytypes.Provenance{"amount_cents": proxytypes.ProvenanceTainted},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "pending_approval" {
		t.Fatalf("expected taint to skip the matching envelope and force tier-3 approval, got %+v", res)
	}

	// The envelope must still show its full, unspent budget - it was never
	// consulted for this call.
	envelopes := h.Approvals.ListEnvelopes()
	if len(envelopes) != 1 || envelopes[0].UsesRemaining != 5 {
		t.Fatalf("expected the envelope's budget to be untouched by the tainted call, got %+v", envelopes)
	}
}

func TestHandle_HighRiskTaint_RequiresFourEyes(t *testing.T) {
	h, _ := newTestHandler(t)
	res, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "rest", AgentID: "a1", DelegatedUser: "alex@example.com", DelegatedRole: "support",
		Tool: "close_account", Args: map[string]any{"user_id": "42"},
		ArgProvenance: map[string]proxytypes.Provenance{"user_id": proxytypes.ProvenanceTainted},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "pending_approval" {
		t.Fatalf("expected pending_approval, got %+v", res)
	}
	// Class C + 1 tainted arg: 0.4 + 0.15 + 0.2 = 0.75, over the 0.7
	// four-eyes threshold.
	if res.RequiredApprovals != 2 {
		t.Fatalf("expected this risk score to require four-eyes (2 approvers), got %d (score %.2f)", res.RequiredApprovals, res.RiskScore)
	}

	// One approval is not enough to execute yet.
	first, err := h.Approvals.Approve(res.RequestID, res.RequestHash, "morgan@example.com", "admin-lead")
	if err != nil {
		t.Fatal(err)
	}
	if first.Status == approval.StatusApproved {
		t.Fatal("expected 1 of 2 required approvals to NOT yet mark the request approved")
	}

	// A second, distinct approver completes it.
	second, err := h.Approvals.Approve(res.RequestID, res.RequestHash, "priya@example.com", "admin-lead")
	if err != nil {
		t.Fatal(err)
	}
	if second.Status != approval.StatusApproved {
		t.Fatalf("expected 2 of 2 required approvals to mark the request approved, got %s", second.Status)
	}
}

func TestHandle_TaintNotSpecified_BehavesLikePhase1(t *testing.T) {
	h, _ := newTestHandler(t)
	// No ArgProvenance at all - an orchestrator that hasn't integrated
	// taint plumbing yet. Must behave exactly like Phase 0/1: direct
	// execution for a permitted role, no forced step-up.
	res, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "rest", AgentID: "a2", DelegatedUser: "jordan@example.com", DelegatedRole: "SalesManager",
		Tool: "update_customer_tier", Args: map[string]any{"user_id": "42", "tier": "gold"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "executed" {
		t.Fatalf("expected unspecified provenance to preserve Phase 0/1 behavior (direct execution), got %+v", res)
	}
}

// --- Phase 3: Dynamic Saga Engine -------------------------------------------

func TestHandle_SagaCompensation_ReverseOrderOnDenial(t *testing.T) {
	h, upstream := newTestHandler(t)
	ctx := context.Background()
	const runID = "run-multi-1"

	step := func(tool string, args map[string]any, role string) proxytypes.CallRequest {
		return proxytypes.CallRequest{Transport: "rest", AgentID: "a1", DelegatedUser: "morgan@example.com",
			DelegatedRole: role, Tool: tool, Args: args, RunID: runID}
	}

	// Step 1: tier silver -> gold.
	res1, err := h.Handle(ctx, step("update_customer_tier", map[string]any{"user_id": "42", "tier": "gold"}, "admin"))
	if err != nil || res1.Status != "executed" {
		t.Fatalf("expected step 1 to execute, got %+v err=%v", res1, err)
	}
	if upstream.TierOf("42") != "gold" {
		t.Fatalf("expected tier=gold after step 1, got %s", upstream.TierOf("42"))
	}

	// Step 2: status active -> suspended, same run.
	res2, err := h.Handle(ctx, step("update_customer_status", map[string]any{"user_id": "42", "status": "suspended"}, "admin"))
	if err != nil || res2.Status != "executed" {
		t.Fatalf("expected step 2 to execute, got %+v err=%v", res2, err)
	}
	if upstream.StatusOf("42") != "suspended" {
		t.Fatalf("expected status=suspended after step 2, got %s", upstream.StatusOf("42"))
	}

	// Step 3: same run, but role "support" is not authorized for
	// update_customer_tier - a confused-deputy denial, this time INSIDE an
	// active run with two prior executed Class A steps.
	res3, err := h.Handle(ctx, step("update_customer_tier", map[string]any{"user_id": "42", "tier": "gold"}, "support"))
	if err != nil {
		t.Fatal(err)
	}
	if res3.Status != "denied" {
		t.Fatalf("expected step 3 to be denied, got %+v", res3)
	}

	// Both prior steps must now be unwound, in REVERSE order: status back
	// to active, tier back to silver.
	if upstream.StatusOf("42") != "active" {
		t.Fatalf("expected status compensated back to active, got %s", upstream.StatusOf("42"))
	}
	if upstream.TierOf("42") != "silver" {
		t.Fatalf("expected tier compensated back to silver, got %s", upstream.TierOf("42"))
	}

	steps := h.Sagas.StepsFor(runID)
	if len(steps) != 2 {
		t.Fatalf("expected 2 recorded steps (the denied call itself is never recorded), got %d", len(steps))
	}
	if !steps[0].Compensated || !steps[1].Compensated {
		t.Fatalf("expected both steps marked compensated, got %+v", steps)
	}
}

func TestHandle_SagaCompensation_DeniedApprovalTriggersIt(t *testing.T) {
	h, upstream := newTestHandler(t)
	ctx := context.Background()
	const runID = "run-multi-2"

	// Step 1: a normal, executed Class A step.
	res1, err := h.Handle(ctx, proxytypes.CallRequest{Transport: "rest", AgentID: "a1", DelegatedUser: "morgan@example.com",
		DelegatedRole: "admin", Tool: "update_customer_tier", Args: map[string]any{"user_id": "42", "tier": "gold"}, RunID: runID})
	if err != nil || res1.Status != "executed" {
		t.Fatalf("expected step 1 to execute, got %+v err=%v", res1, err)
	}

	// Step 2: a tainted Class A call in the SAME run - forced to step-up,
	// pending approval, not yet a failure.
	res2, err := h.Handle(ctx, proxytypes.CallRequest{Transport: "rest", AgentID: "a1", DelegatedUser: "morgan@example.com",
		DelegatedRole: "admin", Tool: "update_customer_status", Args: map[string]any{"user_id": "42", "status": "suspended"},
		ArgProvenance: map[string]proxytypes.Provenance{"status": proxytypes.ProvenanceTainted}, RunID: runID})
	if err != nil || res2.Status != "pending_approval" {
		t.Fatalf("expected step 2 to require step-up, got %+v err=%v", res2, err)
	}
	if upstream.TierOf("42") != "gold" {
		t.Fatal("expected step 1 to still be in effect while step 2 is only pending")
	}

	// A reviewer denies it - the run never completes step 2, and that's
	// the same "this workflow broke" signal a synchronous deny is.
	if err := h.Approvals.Deny(res2.RequestID, "priya@example.com", "admin-lead"); err != nil {
		t.Fatal(err)
	}
	pending, _ := h.Approvals.Get(res2.RequestID)
	h.CompensateRun(ctx, pending.RunID, "test: approval denied")

	if upstream.TierOf("42") != "silver" {
		t.Fatalf("expected step 1 compensated back to silver after the pending approval was denied, got %s", upstream.TierOf("42"))
	}
}

func TestCompensateRun_StopsOnFirstFailure(t *testing.T) {
	h, upstream := newTestHandler(t)
	ctx := context.Background()
	const runID = "run-fail-1"

	res, err := h.Handle(ctx, proxytypes.CallRequest{Transport: "rest", AgentID: "a1", DelegatedUser: "morgan@example.com",
		DelegatedRole: "admin", Tool: "update_customer_tier", Args: map[string]any{"user_id": "42", "tier": "gold"}, RunID: runID})
	if err != nil || res.Status != "executed" {
		t.Fatalf("expected the real step to execute, got %+v err=%v", res, err)
	}

	// Directly inject a second, LATER step with a corrupted pre-image -
	// simulating some other Class A action whose captured snapshot can't
	// be parsed. This deterministically exercises the failure path without
	// needing a contrived policy mismatch.
	h.Sagas.RecordStep(&saga.Step{
		RunID: runID, Tool: "update_customer_status", ReversibilityClass: "A", Resource: "42",
		Args: map[string]any{"user_id": "42", "status": "suspended"}, PreImage: json.RawMessage(`not valid json`),
		DelegatedUser: "morgan@example.com", DelegatedRole: "admin", AgentID: "a1", ExecutedAt: time.Now(),
	})

	h.CompensateRun(ctx, runID, "test: forced failure")

	steps := h.Sagas.StepsFor(runID)
	if !steps[1].CompensationFailed || steps[1].CompensationNote == "" {
		t.Fatalf("expected the broken later step to be marked CompensationFailed with a note, got %+v", steps[1])
	}
	if steps[0].Compensated {
		t.Fatal("expected the walk to STOP at the failure, never reaching the earlier (real, valid) step")
	}
	if upstream.TierOf("42") != "gold" {
		t.Fatalf("expected tier to remain unchanged (compensation never reached it), got %s", upstream.TierOf("42"))
	}
}

// TestCompensateRun_FailureOnOneResourceDoesNotBlockAnother is the actual
// bug fix: two independent resources in the same run - a compensation
// failure on ONE must not stop the OTHER's chain from compensating, since
// they share nothing. Before the resource-scoped redesign, a single flat
// reverse walk meant a failure anywhere in the run halted the whole thing,
// even for a completely unrelated resource.
func TestCompensateRun_FailureOnOneResourceDoesNotBlockAnother(t *testing.T) {
	h, upstream := newTestHandler(t)
	ctx := context.Background()
	const runID = "run-multi-resource-1"

	// Resource "42": a real, valid, compensable tier change.
	res1, err := h.Handle(ctx, proxytypes.CallRequest{Transport: "rest", AgentID: "a1", DelegatedUser: "morgan@example.com",
		DelegatedRole: "admin", Tool: "update_customer_tier", Args: map[string]any{"user_id": "42", "tier": "gold"}, RunID: runID})
	if err != nil || res1.Status != "executed" {
		t.Fatalf("expected step on resource 42 to execute, got %+v err=%v", res1, err)
	}

	// Resource "7": a real, valid, compensable status change - a
	// completely different resource, unrelated to "42".
	res2, err := h.Handle(ctx, proxytypes.CallRequest{Transport: "rest", AgentID: "a1", DelegatedUser: "morgan@example.com",
		DelegatedRole: "admin", Tool: "update_customer_status", Args: map[string]any{"user_id": "7", "status": "suspended"}, RunID: runID})
	if err != nil || res2.Status != "executed" {
		t.Fatalf("expected step on resource 7 to execute, got %+v err=%v", res2, err)
	}

	// Break resource "7"'s chain specifically: inject a later step on "7"
	// with a corrupted pre-image, so ITS compensation fails - resource
	// "42" is never touched by this at all.
	h.Sagas.RecordStep(&saga.Step{
		RunID: runID, Tool: "update_customer_status", ReversibilityClass: "A", Resource: "7",
		Args: map[string]any{"user_id": "7", "status": "active"}, PreImage: json.RawMessage(`not valid json`),
		DelegatedUser: "morgan@example.com", DelegatedRole: "admin", AgentID: "a1", ExecutedAt: time.Now(),
	})

	h.CompensateRun(ctx, runID, "test: resource 7 fails, resource 42 must still compensate")

	// Resource "42" must have compensated successfully, entirely
	// independent of resource "7"'s broken chain.
	if upstream.TierOf("42") != "silver" {
		t.Fatalf("expected resource 42 compensated back to silver despite resource 7's chain failing, got %s", upstream.TierOf("42"))
	}
	// Resource "7"'s real step must NOT be compensated - its chain's walk
	// stopped at the injected failure, same "stop within this chain"
	// semantics as TestCompensateRun_StopsOnFirstFailure, just now scoped
	// to one resource instead of the whole run.
	if upstream.StatusOf("7") != "suspended" {
		t.Fatalf("expected resource 7 to remain unchanged (its chain stopped at the failure), got %s", upstream.StatusOf("7"))
	}

	var resource42Compensated, resource7Failed bool
	for _, s := range h.Sagas.StepsFor(runID) {
		if s.Resource == "42" && s.Compensated {
			resource42Compensated = true
		}
		if s.Resource == "7" && s.CompensationFailed {
			resource7Failed = true
		}
	}
	if !resource42Compensated {
		t.Fatal("expected resource 42's step marked Compensated")
	}
	if !resource7Failed {
		t.Fatal("expected resource 7's injected broken step marked CompensationFailed")
	}
}

func TestHandle_NoRunID_NeverTracksOrCompensates(t *testing.T) {
	h, upstream := newTestHandler(t)
	ctx := context.Background()

	res1, err := h.Handle(ctx, proxytypes.CallRequest{Transport: "rest", AgentID: "a1", DelegatedUser: "morgan@example.com",
		DelegatedRole: "admin", Tool: "update_customer_tier", Args: map[string]any{"user_id": "42", "tier": "gold"}})
	if err != nil || res1.Status != "executed" {
		t.Fatalf("expected step 1 to execute, got %+v err=%v", res1, err)
	}

	res2, err := h.Handle(ctx, proxytypes.CallRequest{Transport: "rest", AgentID: "a1", DelegatedUser: "morgan@example.com",
		DelegatedRole: "support", Tool: "update_customer_tier", Args: map[string]any{"user_id": "42", "tier": "gold"}})
	if err != nil || res2.Status != "denied" {
		t.Fatalf("expected step 2 to be denied, got %+v err=%v", res2, err)
	}

	// No RunID was ever set - the denial must NOT have unwound step 1.
	if upstream.TierOf("42") != "gold" {
		t.Fatalf("expected tier to remain gold - untracked calls must never trigger compensation, got %s", upstream.TierOf("42"))
	}
}

// --- Model-based provenance judge add-on -----------------------------------

func ctxCall(tool string, args map[string]any) proxytypes.CallRequest {
	return proxytypes.CallRequest{
		Transport: "rest", AgentID: "a1", DelegatedUser: "morgan@example.com", DelegatedRole: "admin",
		Tool: tool, Args: args,
		ContextWindow: []proxytypes.ContextMessage{
			{Role: "user", Content: "please handle customer 42's account"},
		},
	}
}

func TestHandle_ProvenanceJudge_LowConfidenceForcesStepUp(t *testing.T) {
	h, _ := newTestHandler(t)
	h.ProvenanceJudge = &provenance.FakeJudge{DefaultConfidence: 0.1} // below threshold

	// admin is fully permitted for update_customer_status, and NO explicit
	// arg_provenance is set at all - the judge alone must be enough to
	// force step-up.
	res, err := h.Handle(context.Background(), ctxCall("update_customer_status", map[string]any{"user_id": "42", "status": "suspended"}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "pending_approval" {
		t.Fatalf("expected the judge's low confidence to force step-up despite a permitted role and no explicit taint, got %+v", res)
	}
}

func TestHandle_ProvenanceJudge_HighConfidenceExecutesDirectly(t *testing.T) {
	h, _ := newTestHandler(t)
	h.ProvenanceJudge = &provenance.FakeJudge{DefaultConfidence: 0.95} // above threshold

	res, err := h.Handle(context.Background(), ctxCall("update_customer_status", map[string]any{"user_id": "42", "status": "suspended"}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "executed" {
		t.Fatalf("expected high judge confidence to execute directly, got %+v", res)
	}
}

func TestHandle_ProvenanceJudge_RequiresPerToolOptIn(t *testing.T) {
	h, _ := newTestHandler(t)
	h.ProvenanceJudge = &provenance.FakeJudge{DefaultConfidence: 0.0} // would force step-up if consulted

	// update_customer_tier does NOT have provenance_judge: true in the test
	// catalog - the judge must never be consulted for it, regardless of a
	// deployment-wide judge being configured.
	res, err := h.Handle(context.Background(), ctxCall("update_customer_tier", map[string]any{"user_id": "42", "tier": "gold"}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "executed" {
		t.Fatalf("expected a tool without provenance_judge opt-in to ignore the configured judge entirely, got %+v", res)
	}
}

func TestHandle_ProvenanceJudge_NilJudgeFallsBackSilently(t *testing.T) {
	h, _ := newTestHandler(t)
	// h.ProvenanceJudge left nil - no deployment-wide judge configured at
	// all, even though the tool opted in and a context window was supplied.
	res, err := h.Handle(context.Background(), ctxCall("update_customer_status", map[string]any{"user_id": "42", "status": "suspended"}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "executed" {
		t.Fatalf("expected no judge configured to behave exactly like the add-on doesn't exist, got %+v", res)
	}
}

func TestHandle_ProvenanceJudge_ErrorFallsBackGracefully(t *testing.T) {
	h, _ := newTestHandler(t)
	h.ProvenanceJudge = &provenance.FakeJudge{Err: fmt.Errorf("simulated API outage")}

	res, err := h.Handle(context.Background(), ctxCall("update_customer_status", map[string]any{"user_id": "42", "status": "suspended"}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "executed" {
		t.Fatalf("expected a judge error to fall back to the explicit-only path (no taint reported), not fail the call, got %+v", res)
	}
}

func TestHandle_ProvenanceJudge_ORCombinesWithExplicitProvenance(t *testing.T) {
	h, _ := newTestHandler(t)
	// Judge says HIGH confidence (would not taint on its own) but the
	// caller explicitly marked the argument tainted - the explicit signal
	// must still win; the judge only ever ADDS taint, never removes it.
	h.ProvenanceJudge = &provenance.FakeJudge{DefaultConfidence: 0.99}

	req := ctxCall("update_customer_status", map[string]any{"user_id": "42", "status": "suspended"})
	req.ArgProvenance = map[string]proxytypes.Provenance{"status": proxytypes.ProvenanceTainted}

	res, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "pending_approval" {
		t.Fatalf("expected the explicit taint to force step-up even though the judge scored high confidence, got %+v", res)
	}
}

// --- Model-based VISUAL provenance judge add-on ----------------------------

func computerCall(action string, screenshot bool, statedIntent string) proxytypes.CallRequest {
	req := proxytypes.CallRequest{
		Transport: "rest", AgentID: "a1", DelegatedUser: "morgan@example.com", DelegatedRole: "admin",
		Tool: "computer", Args: map[string]any{"action": action, "coordinate": "482,310"},
	}
	if screenshot {
		req.Screenshot = []byte("fake-png-bytes")
	}
	req.StatedIntent = statedIntent
	return req
}

// The headline reason this exists at all: a Class B tool has to actually
// reach the judge, since the pre-existing text-taint gate only ever runs
// for Class A/C - "computer" in the test catalog is Class B specifically to
// prove this path doesn't depend on that gate.
func TestHandle_VisualProvenanceJudge_LowConfidenceForcesStepUpOnClassB(t *testing.T) {
	h, _ := newTestHandler(t)
	h.VisualProvenanceJudge = &visualprovenance.FakeJudge{Confidence: 0.1} // below threshold

	res, err := h.Handle(context.Background(), computerCall("left_click", true, "clicking Submit"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "pending_approval" {
		t.Fatalf("expected low visual-judge confidence to force step-up on a CLASS B tool, got %+v", res)
	}
}

func TestHandle_VisualProvenanceJudge_HighConfidenceExecutesDirectly(t *testing.T) {
	h, _ := newTestHandler(t)
	h.VisualProvenanceJudge = &visualprovenance.FakeJudge{Confidence: 0.95}

	res, err := h.Handle(context.Background(), computerCall("left_click", true, "clicking Submit"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "executed" {
		t.Fatalf("expected high visual-judge confidence to execute directly, got %+v", res)
	}
}

// The cost filter: "screenshot" isn't in visual_judge_trigger_values for
// the test tool, so the judge must never even be called for it - proven by
// configuring a judge that would force step-up if consulted and confirming
// it wasn't.
func TestHandle_VisualProvenanceJudge_CostFilterSkipsInertActions(t *testing.T) {
	h, _ := newTestHandler(t)
	h.VisualProvenanceJudge = &visualprovenance.FakeJudge{Confidence: 0.0} // would force step-up if consulted

	res, err := h.Handle(context.Background(), computerCall("screenshot", true, "just looking around"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "executed" {
		t.Fatalf("expected an inert action (not in visual_judge_trigger_values) to skip the judge entirely, got %+v", res)
	}
}

func TestHandle_VisualProvenanceJudge_RequiresPerToolOptIn(t *testing.T) {
	h, _ := newTestHandler(t)
	h.VisualProvenanceJudge = &visualprovenance.FakeJudge{Confidence: 0.0}

	// update_customer_tier does NOT have visual_provenance_judge: true -
	// even with a screenshot and stated intent supplied, the judge must
	// never be consulted.
	req := proxytypes.CallRequest{Transport: "rest", AgentID: "a1", DelegatedUser: "jordan@example.com",
		DelegatedRole: "SalesManager", Tool: "update_customer_tier", Args: map[string]any{"user_id": "42", "tier": "gold"},
		Screenshot: []byte("fake-png"), StatedIntent: "changing the tier"}
	res, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "executed" {
		t.Fatalf("expected a tool without visual_provenance_judge opt-in to ignore the configured judge, got %+v", res)
	}
}

func TestHandle_VisualProvenanceJudge_RequiresScreenshotAndStatedIntent(t *testing.T) {
	h, _ := newTestHandler(t)
	h.VisualProvenanceJudge = &visualprovenance.FakeJudge{Confidence: 0.0} // would force step-up if consulted

	// Screenshot present, but no stated intent - the judge must not run.
	res, err := h.Handle(context.Background(), computerCall("left_click", true, ""))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "executed" {
		t.Fatalf("expected a missing stated_intent to skip the judge even with a screenshot present, got %+v", res)
	}

	// Stated intent present, but no screenshot - same expectation.
	res, err = h.Handle(context.Background(), computerCall("left_click", false, "clicking Submit"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "executed" {
		t.Fatalf("expected a missing screenshot to skip the judge even with stated_intent present, got %+v", res)
	}
}

func TestHandle_VisualProvenanceJudge_NilJudgeFallsBackSilently(t *testing.T) {
	h, _ := newTestHandler(t)
	// h.VisualProvenanceJudge left nil.
	res, err := h.Handle(context.Background(), computerCall("left_click", true, "clicking Submit"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "executed" {
		t.Fatalf("expected no judge configured to behave exactly like the add-on doesn't exist, got %+v", res)
	}
}

func TestHandle_VisualProvenanceJudge_ErrorFallsBackGracefully(t *testing.T) {
	h, _ := newTestHandler(t)
	h.VisualProvenanceJudge = &visualprovenance.FakeJudge{Err: fmt.Errorf("simulated API outage")}

	res, err := h.Handle(context.Background(), computerCall("left_click", true, "clicking Submit"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "executed" {
		t.Fatalf("expected a visual judge error to fall back gracefully, not fail the call, got %+v", res)
	}
}

// agent_id is a caller-supplied label. Keying the circuit breakers on it
// let an agent dodge the rate limit (and force a fresh Vault root mint) by
// varying the label per call - the session key is now the verified user.
func TestHandle_RateLimit_NotBypassedByRotatingAgentID(t *testing.T) {
	h, _ := newTestHandler(t)
	denied := false
	for i := 0; i < int(rateLimitTokens)+5; i++ {
		res, err := h.Handle(context.Background(), proxytypes.CallRequest{
			Transport: "rest", AgentID: fmt.Sprintf("agent-%d", i), DelegatedUser: "alex@example.com", DelegatedRole: "support",
			Tool: "log_event", Args: map[string]any{"message": fmt.Sprintf("unique message %d", i)},
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.Status == "denied" && strings.Contains(res.Reason, "rate limit") {
			denied = true
			break
		}
	}
	if !denied {
		t.Fatal("rotating agent_id must not escape the per-user rate limit")
	}
}

// Class A means "we can put this back." With no snapshot there is nothing
// to put back, so the mutation is refused rather than executed as a
// silently irreversible action - and nothing is recorded as a saga step.
func TestHandle_ClassA_RefusedWhenPreImageCaptureFails(t *testing.T) {
	h, upstream := newTestHandler(t)
	upstream.mu.Lock()
	upstream.failPreImageFor = "42"
	upstream.mu.Unlock()

	res, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "rest", AgentID: "a1", DelegatedUser: "jordan@example.com", DelegatedRole: "SalesManager",
		Tool: "update_customer_tier", Args: map[string]any{"user_id": "42", "tier": "gold"}, RunID: "run-noimg",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "error" || !strings.Contains(res.Reason, "pre-image") {
		t.Fatalf("expected the mutation to be refused for lack of a pre-image, got %+v", res)
	}
	if got := upstream.TierOf("42"); got != "silver" {
		t.Fatalf("mutation must not have reached the upstream, tier is now %q", got)
	}
	if steps := h.Sagas.StepsFor("run-noimg"); len(steps) != 0 {
		t.Fatalf("a refused call must not be recorded as an executed saga step, got %d", len(steps))
	}
}
