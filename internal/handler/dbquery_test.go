package handler

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/RinwallDev/rinwall/internal/approval"
	"github.com/RinwallDev/rinwall/internal/audit"
	"github.com/RinwallDev/rinwall/internal/capability"
	"github.com/RinwallDev/rinwall/internal/policy"
	"github.com/RinwallDev/rinwall/internal/proxytypes"
	"github.com/RinwallDev/rinwall/internal/registry"
	"github.com/RinwallDev/rinwall/internal/saga"
)

const dbTestToolsYAML = `
tools:
  - name: list_customer_orders
    reversibility_class: B
    db_role: readonly-orders
    query: "SELECT customer_email, amount_cents, status FROM customer_orders ORDER BY id"
    args_schema: {}
`

// TestHandle_DBBackedTool_RealPostgresIntegration drives a full request
// through the real pipeline (Handle -> handleInner -> execute ->
// executeDBQuery) against the real Vault + Postgres set up for the
// AWS/DB dynamic secrets work - not a fake DB, not a fake Vault. Proves
// the whole path a real agent call would take: policy evaluation,
// session-scoped credential minting, a real SQL query, and the result
// shape a caller actually receives. Skipped unless
// JIT_INTEGRATION_POSTGRES=1 - see the plan's AWS/DB dynamic secrets
// section for the exact setup this expects.
func TestHandle_DBBackedTool_RealPostgresIntegration(t *testing.T) {
	if os.Getenv("JIT_INTEGRATION_POSTGRES") != "1" {
		t.Skip("set JIT_INTEGRATION_POSTGRES=1 to run against a real Vault + Postgres (see the plan's AWS/DB dynamic secrets section for setup)")
	}

	dir := t.TempDir()
	toolsPath := filepath.Join(dir, "tools.yaml")
	if err := os.WriteFile(toolsPath, []byte(dbTestToolsYAML), 0644); err != nil {
		t.Fatal(err)
	}
	reg, err := registry.LoadFromYAML(toolsPath)
	if err != nil {
		t.Fatal(err)
	}

	pol, err := policy.New(context.Background(), testPolicyPath)
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

	vaultAddr := testEnvOrDefault("JIT_TEST_VAULT_ADDR", "http://127.0.0.1:8200")
	vaultToken := testEnvOrDefault("JIT_TEST_VAULT_TOKEN", "dev-root-token")
	dsnTemplate := testEnvOrDefault("JIT_TEST_PG_DSN", "postgres://%s:%s@127.0.0.1:5433/jitdemo?sslmode=disable")

	vaultClient, err := capability.NewVaultClient(vaultAddr, vaultToken)
	if err != nil {
		t.Fatal(err)
	}

	h := New(reg, pol, capIssuer, approval.NewStore(), aud, saga.NewStore(), "http://unused.invalid")
	h.DBSecrets = capability.NewVaultDBCredentialMinter(vaultClient)
	h.DBDSNTemplate = dsnTemplate

	result, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "test", AgentID: "a1", DelegatedUser: "alex@example.com", DelegatedRole: "support",
		Tool: "list_customer_orders", Args: map[string]any{},
	})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if result.Status != "executed" {
		t.Fatalf("expected status executed, got %q (reason: %s)", result.Status, result.Reason)
	}
	rows, ok := result.UpstreamBody.([]map[string]any)
	if !ok {
		t.Fatalf("expected UpstreamBody to be []map[string]any, got %T: %v", result.UpstreamBody, result.UpstreamBody)
	}
	if len(rows) == 0 {
		t.Fatal("expected at least one row from the real customer_orders table")
	}
	if _, ok := rows[0]["customer_email"]; !ok {
		t.Fatalf("expected a customer_email column in the real query result, got: %v", rows[0])
	}

	// A second call in the same session must reuse the cached connection,
	// not mint a fresh Vault credential (the same "paid once per session"
	// property the biscuit root capability has) - not directly observable
	// from CallResult, but a second call succeeding at all within the
	// same short-TTL role's lease window is consistent with reuse rather
	// than a fresh CREATE ROLE each time hitting a different lease.
	result2, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "test", AgentID: "a1", DelegatedUser: "alex@example.com", DelegatedRole: "support",
		Tool: "list_customer_orders", Args: map[string]any{},
	})
	if err != nil {
		t.Fatalf("second Handle: %v", err)
	}
	if result2.Status != "executed" {
		t.Fatalf("expected second call to also execute, got %q: %s", result2.Status, result2.Reason)
	}
}

func testEnvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
