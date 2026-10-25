package capability

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestFakeDBCredentialMinter_MintReturnsConfiguredCredential(t *testing.T) {
	f := &FakeDBCredentialMinter{NextUsername: "v-token-abc", NextPassword: "secret123"}
	cred, err := f.MintDBCredential(context.Background(), "readonly-orders")
	if err != nil {
		t.Fatal(err)
	}
	if cred.Username != "v-token-abc" || cred.Password != "secret123" {
		t.Fatalf("unexpected credential: %+v", cred)
	}
	if cred.LeaseID == "" {
		t.Fatal("expected a non-empty lease id")
	}
}

func TestFakeDBCredentialMinter_MintErrorPropagates(t *testing.T) {
	wantErr := context.DeadlineExceeded
	f := &FakeDBCredentialMinter{MintErr: wantErr}
	_, err := f.MintDBCredential(context.Background(), "readonly-orders")
	if err != wantErr {
		t.Fatalf("expected the configured error to propagate, got %v", err)
	}
}

func TestFakeDBCredentialMinter_RevokeRecordsLeaseID(t *testing.T) {
	f := &FakeDBCredentialMinter{}
	if err := f.RevokeDBCredential(context.Background(), "lease-123"); err != nil {
		t.Fatal(err)
	}
	if len(f.Revoked) != 1 || f.Revoked[0] != "lease-123" {
		t.Fatalf("expected lease-123 recorded as revoked, got %v", f.Revoked)
	}
}

// TestVaultDBCredentialMinter_RealPostgresIntegration is the real thing,
// not a simulation: mints an actual Vault-issued Postgres role (a genuine
// CREATE ROLE executed against a real database), connects over the
// network with it, confirms the granted table is readable and a
// non-granted table is genuinely denied by Postgres itself, revokes the
// lease, and confirms the credential no longer authenticates - proving
// Vault really ran DROP ROLE, not just forgot about the lease on its own
// side. Skipped unless JIT_INTEGRATION_POSTGRES=1, since it needs the
// real local Vault dev server (database secrets engine mounted, role
// "readonly-orders" configured against a Postgres on 127.0.0.1:5433 - see
// the plan's AWS/DB dynamic secrets section for the exact setup) rather
// than anything this test can spin up itself.
func TestVaultDBCredentialMinter_RealPostgresIntegration(t *testing.T) {
	if os.Getenv("JIT_INTEGRATION_POSTGRES") != "1" {
		t.Skip("set JIT_INTEGRATION_POSTGRES=1 to run against a real Vault + Postgres (see the plan's AWS/DB dynamic secrets section for setup)")
	}

	vaultAddr := envOrDefault("JIT_TEST_VAULT_ADDR", "http://127.0.0.1:8200")
	vaultToken := envOrDefault("JIT_TEST_VAULT_TOKEN", "dev-root-token")
	pgDSN := envOrDefault("JIT_TEST_PG_DSN", "postgres://%s:%s@127.0.0.1:5433/jitdemo?sslmode=disable")

	client, err := NewVaultClient(vaultAddr, vaultToken)
	if err != nil {
		t.Fatal(err)
	}
	minter := NewVaultDBCredentialMinter(client)

	ctx := context.Background()
	cred, err := minter.MintDBCredential(ctx, "readonly-orders")
	if err != nil {
		t.Fatalf("mint: %v - is the database secrets engine configured? see the plan's setup notes", err)
	}
	if cred.Username == "" || cred.Password == "" {
		t.Fatalf("expected a real username/password, got %+v", cred)
	}

	dsn := fmt.Sprintf(pgDSN, cred.Username, cred.Password)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// The granted table must be readable.
	var count int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM customer_orders").Scan(&count); err != nil {
		t.Fatalf("expected the minted credential to read the granted table, got: %v", err)
	}
	if count == 0 {
		t.Fatal("expected customer_orders to have rows (test fixture)")
	}

	// A table NOT granted must be genuinely denied by Postgres itself -
	// this is what proves least-privilege, not just "some credential works."
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM internal_secrets").Scan(&count); err == nil {
		t.Fatal("expected a permission error reading a non-granted table, got none")
	}
	db.Close()

	if err := minter.RevokeDBCredential(ctx, cred.LeaseID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// A fresh connection attempt with the same credential must now fail -
	// proving Vault actually ran DROP ROLE against the real database, not
	// just discarded the lease on its own side.
	db2, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	if err := db2.PingContext(ctx); err == nil {
		t.Fatal("expected the revoked credential to no longer authenticate, but it did")
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
