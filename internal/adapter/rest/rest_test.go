package rest

import (
	"context"
	"encoding/json"
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
	"github.com/RinwallDev/rinwall/internal/authn"
	"github.com/RinwallDev/rinwall/internal/capability"
	"github.com/RinwallDev/rinwall/internal/handler"
	"github.com/RinwallDev/rinwall/internal/policy"
	"github.com/RinwallDev/rinwall/internal/registry"
	"github.com/RinwallDev/rinwall/internal/saga"
)

const testToolsYAML = `
tools:
  - name: get_user
    reversibility_class: B
    method: GET
    path: /users/{user_id}
    resource_arg: user_id
    args_schema:
      user_id: {type: string, required: true}

  - name: close_account
    reversibility_class: C
    method: POST
    path: /users/{user_id}/close
    resource_arg: user_id
    reviewer_role: admin-lead
    args_schema:
      user_id: {type: string, required: true}
`

const jwtSecret = "test-jwt-secret"

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
	}))
	t.Cleanup(upstream.Close)

	dir := t.TempDir()
	toolsPath := filepath.Join(dir, "tools.yaml")
	os.WriteFile(toolsPath, []byte(testToolsYAML), 0644)
	reg, err := registry.LoadFromYAML(toolsPath)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.New(context.Background(), "../../../policies/tool_policy.rego")
	if err != nil {
		t.Fatal(err)
	}
	aud, err := audit.Open(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { aud.Close() })

	capIssuer, err := capability.NewBiscuitRootIssuer(context.Background(), &capability.FakeKeyRingStore{}, capability.FakeSeedMinter{})
	if err != nil {
		t.Fatal(err)
	}
	h := handler.New(reg, pol, capIssuer, approval.NewStore(), aud, saga.NewStore(), upstream.URL)
	verifier := authn.NewVerifier(jwtSecret)

	mux := http.NewServeMux()
	Register(mux, h, h.Approvals, verifier)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func mint(t *testing.T, user, role string) string {
	t.Helper()
	tok, err := authn.Mint(jwtSecret, user, role, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestEnvelopes_NoAuthRejected(t *testing.T) {
	server := newTestServer(t)
	resp, _ := http.Post(server.URL+"/envelopes", "application/json", strings.NewReader(`{"tool":"close_account","max_uses":1}`))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 with no token, got %d", resp.StatusCode)
	}
}

func TestEnvelopes_WrongRoleRejected(t *testing.T) {
	server := newTestServer(t)
	req, _ := http.NewRequest("POST", server.URL+"/envelopes", strings.NewReader(`{"tool":"close_account","max_uses":1}`))
	req.Header.Set("Authorization", "Bearer "+mint(t, "alex@example.com", "support"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for a role that doesn't match close_account's reviewer_role, got %d", resp.StatusCode)
	}
}

func TestEnvelopes_NonClassCToolRejected(t *testing.T) {
	server := newTestServer(t)
	req, _ := http.NewRequest("POST", server.URL+"/envelopes", strings.NewReader(`{"tool":"get_user","max_uses":1}`))
	req.Header.Set("Authorization", "Bearer "+mint(t, "morgan@example.com", "admin-lead"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for a non-Class-C tool, got %d", resp.StatusCode)
	}
}

func TestEnvelopes_CorrectReviewerRoleSucceeds(t *testing.T) {
	server := newTestServer(t)
	req, _ := http.NewRequest("POST", server.URL+"/envelopes", strings.NewReader(`{"tool":"close_account","max_uses":1,"ttl_seconds":3600}`))
	req.Header.Set("Authorization", "Bearer "+mint(t, "morgan@example.com", "admin-lead"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for the tool's actual reviewer_role, got %d", resp.StatusCode)
	}
}

func TestHoldCancel_NoAuthRejected(t *testing.T) {
	server := newTestServer(t)
	resp, _ := http.Post(server.URL+"/holds/hold-does-not-matter/cancel", "application/json", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 with no token, got %d", resp.StatusCode)
	}
}

// hold/compensate_run behavior needs a stateful upstream (real pre-image
// content, real tier state) to prove real compensation happened - the
// shared newTestServer's generic {"status":"ok"} stub isn't enough, so
// this builds its own small server rather than reusing it.
const compensateRunTestToolsYAML = `
tools:
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
      tier: {type: string, required: true}

  - name: send_refund_email
    reversibility_class: C
    method: POST
    path: /refund-emails
    resource_arg: user_id
    deferrable: true
    hold_seconds: 3600
    reviewer_role: support-lead
    args_schema:
      user_id: {type: string, required: true}
      amount_cents: {type: number, required: true}
`

func newCompensateRunTestServer(t *testing.T) (server *httptest.Server, tierOf func() string) {
	t.Helper()

	var mu sync.Mutex
	tier := "silver"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && r.URL.Path == "/users/42":
			mu.Lock()
			cur := tier
			mu.Unlock()
			json.NewEncoder(w).Encode(map[string]any{"id": "42", "tier": cur})
		case r.Method == "PATCH" && r.URL.Path == "/users/42/tier":
			var body struct {
				Tier string `json:"tier"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			tier = body.Tier
			mu.Unlock()
			json.NewEncoder(w).Encode(map[string]any{"status": "updated"})
		default:
			json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
		}
	}))
	t.Cleanup(upstream.Close)
	tierOf = func() string {
		mu.Lock()
		defer mu.Unlock()
		return tier
	}

	dir := t.TempDir()
	toolsPath := filepath.Join(dir, "tools.yaml")
	os.WriteFile(toolsPath, []byte(compensateRunTestToolsYAML), 0644)
	reg, err := registry.LoadFromYAML(toolsPath)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.New(context.Background(), "../../../policies/tool_policy.rego")
	if err != nil {
		t.Fatal(err)
	}
	aud, err := audit.Open(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { aud.Close() })

	capIssuer, err := capability.NewBiscuitRootIssuer(context.Background(), &capability.FakeKeyRingStore{}, capability.FakeSeedMinter{})
	if err != nil {
		t.Fatal(err)
	}
	h := handler.New(reg, pol, capIssuer, approval.NewStore(), aud, saga.NewStore(), upstream.URL)
	verifier := authn.NewVerifier(jwtSecret)

	mux := http.NewServeMux()
	Register(mux, h, h.Approvals, verifier)
	restServer := httptest.NewServer(mux)
	t.Cleanup(restServer.Close)
	return restServer, tierOf
}

func TestHoldCancel_CompensateRunOptIn_RollsBackEarlierStep(t *testing.T) {
	server, tierOf := newCompensateRunTestServer(t)
	const runID = "run-cancel-compensate-1"

	// Step 1: a real Class A tier change, admin role (allowed
	// unconditionally by the real policy bundle).
	tierReq, _ := http.NewRequest("POST", server.URL+"/tool-call",
		strings.NewReader(`{"tool":"update_customer_tier","args":{"user_id":"42","tier":"gold"},"run_id":"`+runID+`"}`))
	tierReq.Header.Set("Authorization", "Bearer "+mint(t, "morgan@example.com", "admin"))
	tierResp, err := http.DefaultClient.Do(tierReq)
	if err != nil {
		t.Fatal(err)
	}
	var tierResult map[string]any
	json.NewDecoder(tierResp.Body).Decode(&tierResult)
	if tierResult["status"] != "executed" {
		t.Fatalf("expected the tier change to execute, got %v", tierResult)
	}

	// Step 2: a deferrable Class C hold, same run, admin role (also allowed).
	holdReq, _ := http.NewRequest("POST", server.URL+"/tool-call",
		strings.NewReader(`{"tool":"send_refund_email","args":{"user_id":"42","amount_cents":1000},"run_id":"`+runID+`"}`))
	holdReq.Header.Set("Authorization", "Bearer "+mint(t, "morgan@example.com", "admin"))
	holdResp, err := http.DefaultClient.Do(holdReq)
	if err != nil {
		t.Fatal(err)
	}
	var holdResult map[string]any
	json.NewDecoder(holdResp.Body).Decode(&holdResult)
	holdID, _ := holdResult["hold_id"].(string)
	if holdResult["status"] != "pending_hold" || holdID == "" {
		t.Fatalf("expected a pending hold, got %v", holdResult)
	}

	// Cancel the hold with compensate_run:true, as the tool's actual
	// reviewer_role (support-lead) - not the role that requested either step.
	cancelReq, _ := http.NewRequest("POST", server.URL+"/holds/"+holdID+"/cancel",
		strings.NewReader(`{"compensate_run":true}`))
	cancelReq.Header.Set("Authorization", "Bearer "+mint(t, "jordan@example.com", "support-lead"))
	cancelResp, err := http.DefaultClient.Do(cancelReq)
	if err != nil {
		t.Fatal(err)
	}
	if cancelResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 cancelling with the matching reviewer_role, got %d", cancelResp.StatusCode)
	}

	// The earlier tier change must now be compensated - back to silver -
	// because compensate_run was explicitly requested at cancel time.
	if got := tierOf(); got != "silver" {
		t.Fatalf("expected the tier change compensated back to silver after compensate_run cancel, got %q", got)
	}
}

func TestHoldCancel_WithoutCompensateRun_LeavesEarlierStepStanding(t *testing.T) {
	server, tierOf := newCompensateRunTestServer(t)
	const runID = "run-cancel-no-compensate-1"

	tierReq, _ := http.NewRequest("POST", server.URL+"/tool-call",
		strings.NewReader(`{"tool":"update_customer_tier","args":{"user_id":"42","tier":"gold"},"run_id":"`+runID+`"}`))
	tierReq.Header.Set("Authorization", "Bearer "+mint(t, "morgan@example.com", "admin"))
	if _, err := http.DefaultClient.Do(tierReq); err != nil {
		t.Fatal(err)
	}

	holdReq, _ := http.NewRequest("POST", server.URL+"/tool-call",
		strings.NewReader(`{"tool":"send_refund_email","args":{"user_id":"42","amount_cents":1000},"run_id":"`+runID+`"}`))
	holdReq.Header.Set("Authorization", "Bearer "+mint(t, "morgan@example.com", "admin"))
	holdResp, err := http.DefaultClient.Do(holdReq)
	if err != nil {
		t.Fatal(err)
	}
	var holdResult map[string]any
	json.NewDecoder(holdResp.Body).Decode(&holdResult)
	holdID, _ := holdResult["hold_id"].(string)

	// Cancel WITHOUT compensate_run - default behavior, must leave the
	// earlier tier change standing.
	cancelReq, _ := http.NewRequest("POST", server.URL+"/holds/"+holdID+"/cancel", strings.NewReader(`{}`))
	cancelReq.Header.Set("Authorization", "Bearer "+mint(t, "jordan@example.com", "support-lead"))
	cancelResp, err := http.DefaultClient.Do(cancelReq)
	if err != nil {
		t.Fatal(err)
	}
	if cancelResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", cancelResp.StatusCode)
	}

	// Default behavior (no compensate_run) must leave the earlier tier
	// change standing - the whole point of making this opt-in.
	if got := tierOf(); got != "gold" {
		t.Fatalf("expected the tier change left standing at gold without compensate_run, got %q", got)
	}
}

func TestToolCall_NoAuthRejected(t *testing.T) {
	server := newTestServer(t)
	resp, _ := http.Post(server.URL+"/tool-call", "application/json", strings.NewReader(`{"tool":"get_user","args":{"user_id":"1"}}`))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 with no token, got %d", resp.StatusCode)
	}
}
