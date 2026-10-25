package policy

import (
	"context"
	"testing"
)

const testPolicyPath = "../../policies/tool_policy.rego"

func TestPolicy_AllowDenyTable(t *testing.T) {
	engine, err := New(context.Background(), testPolicyPath)
	if err != nil {
		t.Fatalf("failed to load real policy bundle at %s: %v", testPolicyPath, err)
	}

	cases := []struct {
		name  string
		input map[string]any
		want  bool
	}{
		{"get_user any role", map[string]any{"tool": "get_user", "delegated_role": "support", "args": map[string]any{}}, true},
		{"log_event any role", map[string]any{"tool": "log_event", "delegated_role": "support", "args": map[string]any{}}, true},
		{"tier update, SalesManager, silver", map[string]any{"tool": "update_customer_tier", "delegated_role": "SalesManager", "args": map[string]any{"tier": "silver"}}, true},
		{"tier update, SalesManager, gold", map[string]any{"tool": "update_customer_tier", "delegated_role": "SalesManager", "args": map[string]any{"tier": "gold"}}, true},
		{"tier update, admin", map[string]any{"tool": "update_customer_tier", "delegated_role": "admin", "args": map[string]any{"tier": "gold"}}, true},
		{"tier update, support - confused deputy", map[string]any{"tool": "update_customer_tier", "delegated_role": "support", "args": map[string]any{"tier": "gold"}}, false},
		{"refund email, support", map[string]any{"tool": "send_refund_email", "delegated_role": "support", "args": map[string]any{}}, true},
		{"refund email, admin", map[string]any{"tool": "send_refund_email", "delegated_role": "admin", "args": map[string]any{}}, true},
		{"refund email, unrelated role", map[string]any{"tool": "send_refund_email", "delegated_role": "intern", "args": map[string]any{}}, false},
		{"close account, support", map[string]any{"tool": "close_account", "delegated_role": "support", "args": map[string]any{}}, true},
		{"close account, admin", map[string]any{"tool": "close_account", "delegated_role": "admin", "args": map[string]any{}}, true},
		{"unknown tool", map[string]any{"tool": "delete_everything", "delegated_role": "admin", "args": map[string]any{}}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decision, err := engine.Evaluate(context.Background(), tc.input)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if decision.Allow != tc.want {
				t.Errorf("Allow = %v, want %v (reason: %q)", decision.Allow, tc.want, decision.Reason)
			}
			if !decision.Allow && decision.Reason == "" {
				t.Error("expected a non-empty reason on denial")
			}
		})
	}
}
