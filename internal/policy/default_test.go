package policy

import (
	"context"
	"testing"
)

// The built-in default is permissive by design, and that has to be
// verified rather than assumed: if it silently denied, zero-config mode
// would look broken; if it silently allowed a request naming no tool, it
// would be sloppier than it claims to be.
func TestDefaultBundle_AllowsAnyRoleAnyTool(t *testing.T) {
	e, err := NewDefault(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ tool, role string }{
		{"get_user", "support"},
		{"close_account", "intern"},
		{"delete_everything", ""},
	} {
		d, err := e.Evaluate(context.Background(), map[string]any{
			"tool": tc.tool, "delegated_role": tc.role,
			"reversibility_class": "C", "args": map[string]any{},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !d.Allow {
			t.Fatalf("the default bundle should allow %s/%s to be attempted: %s", tc.role, tc.tool, d.Reason)
		}
	}
}

// "Allowed to attempt" is not "executes" - that distinction is the whole
// reason a permissive default is defensible. Class C gating lives in
// internal/handler, not here, so this only has to confirm the bundle isn't
// pretending to make a class-based decision it doesn't make.
func TestDefaultBundle_DeniesARequestNamingNoTool(t *testing.T) {
	e, err := NewDefault(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	d, err := e.Evaluate(context.Background(), map[string]any{
		"tool": "", "delegated_role": "admin", "args": map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Allow {
		t.Fatal("a request naming no tool must not be allowed")
	}
	if d.Reason == "" {
		t.Fatal("a denial must carry a reason")
	}
}
