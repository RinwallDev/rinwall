package compliance

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RinwallDev/rinwall/internal/audit"
	"github.com/RinwallDev/rinwall/internal/registry"
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

  - name: close_account
    reversibility_class: C
    method: POST
    path: /users/{user_id}/close
    resource_arg: user_id
    reviewer_role: admin-lead
    args_schema:
      user_id: {type: string, required: true}
`

func testRegistry(t *testing.T) *registry.Registry {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "tools.yaml")
	if err := os.WriteFile(path, []byte(testToolsYAML), 0644); err != nil {
		t.Fatal(err)
	}
	reg, err := registry.LoadFromYAML(path)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func TestGenerate_TalliesRealisticEntries(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	l, err := audit.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	// Mirrors the exact shape internal/handler actually writes for each of
	// these decisions - not synthetic data invented for the test.
	l.Write(map[string]any{"decision": "EXECUTED", "tool": "get_user", "delegated_role": "support", "reason": "class_b_direct"})
	l.Write(map[string]any{"decision": "EXECUTED", "tool": "get_user", "delegated_role": "support", "reason": "class_b_direct"})
	l.Write(map[string]any{"decision": "ALLOW", "tool": "update_customer_tier", "delegated_role": "SalesManager", "reason": "tier1: matched pre-authorized envelope env-1"})
	l.Write(map[string]any{"decision": "PENDING", "tool": "close_account", "delegated_role": "support", "reason": "tier3: routed to reviewer_role=admin-lead, bound to hash abc"})
	l.Write(map[string]any{"decision": "PENDING", "tool": "update_customer_tier", "delegated_role": "SalesManager",
		"reason": "step-up: tainted args [tier] (risk_score=0.75, requires 2 approver(s)), routed to reviewer_role=SalesManager, bound to hash def"})
	l.Write(map[string]any{"decision": "COMPENSATED", "tool": "update_customer_tier", "resource": "42", "reason": "saga run-1: restored"})
	l.Write(map[string]any{"decision": "COMPENSATION_FAILED", "tool": "close_account", "resource": "7", "reason": "saga run-2: could not compensate"})
	l.Write(map[string]any{"decision": "PROVENANCE_JUDGED", "tool": "update_customer_tier", "arg": "tier", "reason": "confidence=0.85: matches human request"})
	l.Write(map[string]any{"decision": "PROVENANCE_JUDGE_ERROR", "tool": "update_customer_tier", "reason": "judge call failed, falling back"})
	l.Write(map[string]any{"decision": "biscuit_key_rotated", "delegated_user": "security@example.com", "new_key_id": "abcd1234"})
	l.Write(map[string]any{"decision": "DENY", "tool": "close_account", "delegated_role": "support", "reason": "policy: role mismatch"})
	l.Close()

	report, err := Generate(logPath, testRegistry(t), nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if report.TotalEvents != 11 {
		t.Fatalf("expected 11 total events, got %d", report.TotalEvents)
	}
	if !report.AuditChain.OK {
		t.Fatalf("expected a clean, freshly-written log to have an intact chain, got: %+v", report.AuditChain)
	}
	if report.ByDecision["EXECUTED"] != 2 {
		t.Fatalf("expected 2 EXECUTED, got %d", report.ByDecision["EXECUTED"])
	}
	if report.ByReversibilityClass["B"] != 2 {
		t.Fatalf("expected 2 class-B completed calls (get_user x2), got %d", report.ByReversibilityClass["B"])
	}
	if report.ByReversibilityClass["A"] != 1 {
		t.Fatalf("expected 1 class-A completed call (the tier1 envelope ALLOW), got %d", report.ByReversibilityClass["A"])
	}
	if report.ByApprovalTier["tier1_envelope"] != 1 {
		t.Fatalf("expected 1 tier1_envelope, got %d", report.ByApprovalTier["tier1_envelope"])
	}
	if report.ByApprovalTier["tier3_approval"] != 1 {
		t.Fatalf("expected 1 tier3_approval, got %d", report.ByApprovalTier["tier3_approval"])
	}
	if report.ByApprovalTier["step_up_taint"] != 1 {
		t.Fatalf("expected 1 step_up_taint, got %d", report.ByApprovalTier["step_up_taint"])
	}
	if report.FourEyesRequired != 1 {
		t.Fatalf("expected 1 four-eyes-required (the 'requires 2 approver(s)' entry), got %d", report.FourEyesRequired)
	}
	if report.SagaCompensationsSucceeded != 1 || report.SagaCompensationsFailed != 1 {
		t.Fatalf("expected 1 succeeded + 1 failed saga compensation, got %d/%d", report.SagaCompensationsSucceeded, report.SagaCompensationsFailed)
	}
	if report.ProvenanceJudgeInvocations != 1 || report.ProvenanceJudgeErrors != 1 {
		t.Fatalf("expected 1 judge invocation + 1 judge error, got %d/%d", report.ProvenanceJudgeInvocations, report.ProvenanceJudgeErrors)
	}
	if report.KeyRotations != 1 {
		t.Fatalf("expected 1 key rotation, got %d", report.KeyRotations)
	}
}

func TestGenerate_FiltersByPeriod(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	l, err := audit.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	l.Write(map[string]any{"decision": "EXECUTED", "tool": "get_user", "delegated_role": "support", "reason": "class_b_direct"})
	l.Close()

	// The one entry's real timestamp is "now" - a period entirely in the
	// past must exclude it.
	past := time.Now().Add(-48 * time.Hour)
	earlier := time.Now().Add(-72 * time.Hour)
	report, err := Generate(logPath, testRegistry(t), &earlier, &past)
	if err != nil {
		t.Fatal(err)
	}
	if report.TotalEvents != 0 {
		t.Fatalf("expected 0 events in a period that excludes the only entry, got %d", report.TotalEvents)
	}

	// An open-ended period (nil bounds) must include it.
	fullReport, err := Generate(logPath, testRegistry(t), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fullReport.TotalEvents != 1 {
		t.Fatalf("expected 1 event with no period bounds, got %d", fullReport.TotalEvents)
	}
}

func TestGenerate_ReflectsBrokenChain(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	l, err := audit.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	l.Write(map[string]any{"decision": "EXECUTED", "tool": "get_user", "delegated_role": "support", "reason": "class_b_direct"})
	l.Write(map[string]any{"decision": "DENY", "tool": "close_account", "delegated_role": "support", "reason": "policy: role mismatch"})
	l.Close()

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := string(raw)
	tampered = tampered[:len(tampered)-2] + "X\n" // corrupt the last entry's trailing content
	if err := os.WriteFile(logPath, []byte(tampered), 0644); err != nil {
		t.Fatal(err)
	}

	report, err := Generate(logPath, testRegistry(t), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.AuditChain.OK {
		t.Fatal("expected the report to reflect a broken chain, not silently report OK")
	}
}
