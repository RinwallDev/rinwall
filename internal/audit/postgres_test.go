package audit

import (
	"database/sql"
	"os"
	"sync"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func testPostgresDSN(t *testing.T) string {
	t.Helper()
	if os.Getenv("JIT_INTEGRATION_POSTGRES") != "1" {
		t.Skip("set JIT_INTEGRATION_POSTGRES=1 to run against a real local Postgres (see the plan's Tier 1 storage-backend section for setup)")
	}
	if v := os.Getenv("JIT_TEST_STATE_PG_DSN"); v != "" {
		return v
	}
	return "postgres://postgres:state-test-pw@127.0.0.1:5434/jitfirewall_state?sslmode=disable"
}

func resetAuditTables(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`DROP TABLE IF EXISTS audit_log, audit_chain_head`); err != nil {
		t.Fatal(err)
	}
}

func TestPostgres_CleanLogVerifiesOK(t *testing.T) {
	dsn := testPostgresDSN(t)
	resetAuditTables(t, dsn)

	l, err := OpenPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	l.Write(map[string]any{"decision": "ALLOW", "tool": "get_user", "delegated_role": "support", "reason": "ok"})
	l.Write(map[string]any{"decision": "DENY", "tool": "close_account", "delegated_role": "support", "reason": "policy"})
	l.Write(map[string]any{"decision": "ALLOW", "tool": "update_customer_tier", "delegated_role": "SalesManager", "reason": "ok", "risk_score": 0.55})
	l.Close()

	result, err := VerifyChainPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK {
		t.Fatalf("expected a clean, untouched chain to verify OK, got: %+v", result)
	}
	if result.EntriesChecked != 3 {
		t.Fatalf("expected 3 entries checked, got %d", result.EntriesChecked)
	}
}

func TestPostgres_DetectsEditedEntry(t *testing.T) {
	dsn := testPostgresDSN(t)
	resetAuditTables(t, dsn)

	l, err := OpenPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	l.Write(map[string]any{"decision": "ALLOW", "tool": "get_user", "delegated_role": "support", "reason": "ok"})
	l.Write(map[string]any{"decision": "DENY", "tool": "close_account", "delegated_role": "support", "reason": "policy: role mismatch"})
	l.Write(map[string]any{"decision": "ALLOW", "tool": "update_customer_tier", "delegated_role": "SalesManager", "reason": "ok"})
	l.Close()

	// Tamper directly in the database - the exact "quietly rewrite a DENY
	// to look like it was never denied" attack this feature exists to
	// catch, done at the storage layer this time instead of a flat file.
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	res, err := db.Exec(`UPDATE audit_log SET event = replace(event, '"decision":"DENY"', '"decision":"ALLOW"') WHERE event LIKE '%"decision":"DENY"%'`)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		t.Fatalf("test setup: expected to tamper with exactly 1 row, affected %d", n)
	}

	result, err := VerifyChainPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if result.OK {
		t.Fatal("expected tampering to be detected, got OK")
	}
	if result.BrokenAtSeq != 2 {
		t.Fatalf("expected the break pinpointed at seq 2, got %d (reason: %s)", result.BrokenAtSeq, result.Reason)
	}
}

// TestPostgres_ConcurrentWriters_ChainStaysGapless is the actual proof:
// two "instances" (two separate *Logger handles, each with its own
// *sql.DB, against the same Postgres database) writing concurrently. The
// file-backed Logger's in-process mutex and cached lastHash/seq provide no
// protection across processes - this is what proves writePG's chain-head
// row lock serializes them correctly instead, producing one gapless,
// verifiable chain rather than two instances silently clobbering each
// other's notion of "the last hash."
func TestPostgres_ConcurrentWriters_ChainStaysGapless(t *testing.T) {
	dsn := testPostgresDSN(t)
	resetAuditTables(t, dsn)

	l1, err := OpenPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer l1.Close()
	l2, err := OpenPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()

	const perLogger = 25
	var wg sync.WaitGroup
	wg.Add(2)
	write := func(l *Logger, tool string) {
		defer wg.Done()
		for i := 0; i < perLogger; i++ {
			l.Write(map[string]any{"decision": "ALLOW", "tool": tool, "delegated_role": "support", "reason": "ok"})
		}
	}
	go write(l1, "from-instance-1")
	go write(l2, "from-instance-2")
	wg.Wait()

	result, err := VerifyChainPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK {
		t.Fatalf("expected the chain to stay gapless and verify OK across two concurrent writers, got: %+v", result)
	}
	if result.EntriesChecked != perLogger*2 {
		t.Fatalf("expected %d entries checked, got %d", perLogger*2, result.EntriesChecked)
	}
}

func TestPostgres_ReadRecent_NewestFirstAndRespectsLimit(t *testing.T) {
	dsn := testPostgresDSN(t)
	resetAuditTables(t, dsn)

	l, err := OpenPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.Write(map[string]any{"decision": "ALLOW", "tool": "get_user", "reason": "first"})
	l.Write(map[string]any{"decision": "DENY", "tool": "close_account", "reason": "second"})
	l.Write(map[string]any{"decision": "EXECUTED", "tool": "log_event", "reason": "third"})

	entries, err := ReadRecentPostgres(dsn, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries (limit respected), got %d", len(entries))
	}
	if entries[0]["reason"] != "third" || entries[1]["reason"] != "second" {
		t.Fatalf("expected newest-first order, got %v then %v", entries[0]["reason"], entries[1]["reason"])
	}
}
