// Postgres-backed audit log for multi-instance/HA deployments. The
// file-backed Logger serializes the hash chain with an in-process mutex
// plus locally cached lastHash/seq fields - correct for one process, but
// meaningless once a second process can also be appending to the same
// chain: two instances logging at nearly the same instant would both read
// a stale "last hash" and both compute the same next seq/prev_chain_hash,
// splitting the chain into two disconnected branches.
//
// Postgres mode fixes this the same way internal/approval and
// internal/saga's Postgres backends do: a tiny singleton "chain head" row,
// locked with SELECT ... FOR UPDATE inside the same transaction as the
// new row's insert, so reading the current head and advancing it is one
// atomic, serialized operation across every instance - not two operations
// racing between instances that only synchronize within themselves.
package audit

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// event is stored as plain TEXT, deliberately not JSONB: jsonb is a parsed
// binary representation that does not guarantee reproducing the original
// bytes verbatim on read-back (whitespace and, per Postgres's own
// documentation, object key order are not preserved). This chain's whole
// guarantee depends on recomputing a hash over byte-identical input to
// what was hashed at write time - the same reason chainEntry/
// normalizeRawMessage in audit.go go out of their way to canonicalize
// before hashing. TEXT stores exactly what chainEntry produced, with zero
// reformatting, the same guarantee the file-backed log's raw bytes give
// for free.
const pgSchema = `
CREATE TABLE IF NOT EXISTS audit_log (
	seq BIGINT PRIMARY KEY,
	chain_hash TEXT NOT NULL,
	prev_chain_hash TEXT NOT NULL,
	event TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_chain_head (
	id INTEGER PRIMARY KEY,
	seq BIGINT NOT NULL,
	chain_hash TEXT NOT NULL
);
`

// OpenPostgres opens (creating the schema if needed) a Postgres-backed
// Logger safe for concurrent use by multiple proxy processes appending to
// the same chain. Reuses the same "pgx" database/sql driver as the
// approval/saga Postgres backends.
func OpenPostgres(dsn string) (*Logger, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("audit: open postgres: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("audit: ping postgres: %w", err)
	}
	if _, err := db.Exec(pgSchema); err != nil {
		return nil, fmt.Errorf("audit: create postgres schema: %w", err)
	}
	// Seed the singleton head row exactly once - "ON CONFLICT DO NOTHING"
	// makes this safe to run from every instance at startup regardless of
	// which one gets there first.
	if _, err := db.Exec(`INSERT INTO audit_chain_head (id, seq, chain_hash) VALUES (1, 0, $1) ON CONFLICT (id) DO NOTHING`, genesisHash); err != nil {
		return nil, fmt.Errorf("audit: seed chain head: %w", err)
	}
	return &Logger{pg: db}, nil
}

// writePG re-reads the chain head from Postgres and appends inside one
// transaction - see the package doc comment above for why the file-backed
// path's cached lastHash/seq fields can't be trusted here. Errors are
// logged to stderr, matching Write's existing best-effort-but-visible
// contract for the file-backed path (a write failure is printed, not
// silently swallowed, but doesn't panic the caller either).
func (l *Logger) writePG(event map[string]any) {
	tx, err := l.pg.Begin()
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit: postgres: begin write: %v\n", err)
		return
	}
	defer tx.Rollback()

	var seq int64
	var prevHash string
	if err := tx.QueryRow(`SELECT seq, chain_hash FROM audit_chain_head WHERE id = 1 FOR UPDATE`).Scan(&seq, &prevHash); err != nil {
		fmt.Fprintf(os.Stderr, "audit: postgres: read chain head: %v\n", err)
		return
	}
	seq++

	chainHash, line, err := chainEntry(event, seq, prevHash)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return
	}

	if _, err := tx.Exec(`INSERT INTO audit_log (seq, chain_hash, prev_chain_hash, event) VALUES ($1,$2,$3,$4)`, seq, chainHash, prevHash, line); err != nil {
		fmt.Fprintf(os.Stderr, "audit: postgres: insert entry seq=%d: %v\n", seq, err)
		return
	}
	if _, err := tx.Exec(`UPDATE audit_chain_head SET seq = $1, chain_hash = $2 WHERE id = 1`, seq, chainHash); err != nil {
		fmt.Fprintf(os.Stderr, "audit: postgres: advance chain head: %v\n", err)
		return
	}
	if err := tx.Commit(); err != nil {
		fmt.Fprintf(os.Stderr, "audit: postgres: commit write seq=%d: %v\n", seq, err)
		return
	}

	fmt.Fprintf(os.Stderr, "[audit] %-6v tool=%-22v role=%-14v reason=%v\n",
		event["decision"], event["tool"], event["delegated_role"], event["reason"])
}

// VerifyChainPostgres is VerifyChainFile's exact counterpart for the
// Postgres-backed log: walks every stored entry in seq order and confirms
// the chain is unbroken, using the identical recomputation algorithm
// (verifyChainLines in audit.go) - one implementation of "what makes a
// chain valid" shared by both storage backends.
func VerifyChainPostgres(dsn string) (VerifyResult, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("audit: open postgres: %w", err)
	}
	defer db.Close()

	rows, err := db.Query(`SELECT event FROM audit_log ORDER BY seq ASC`)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("audit: postgres: query entries: %w", err)
	}
	defer rows.Close()

	var lines [][]byte
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return VerifyResult{}, fmt.Errorf("audit: postgres: scan entry: %w", err)
		}
		lines = append(lines, bytes.TrimSpace(raw))
	}
	if err := rows.Err(); err != nil {
		return VerifyResult{}, fmt.Errorf("audit: postgres: iterate entries: %w", err)
	}

	return verifyChainLines(lines)
}

// ReadRecentPostgres is ReadRecent's exact counterpart for a Postgres-
// backed audit log - the most recent (up to limit) entries, newest first,
// for the admin console's live activity feed. Deliberately lenient like
// ReadRecent: a malformed row is skipped, not a hard failure.
func ReadRecentPostgres(dsn string, limit int) ([]map[string]any, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("audit: open postgres: %w", err)
	}
	defer db.Close()

	rows, err := db.Query(`SELECT event FROM audit_log ORDER BY seq DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("audit: postgres: query recent entries: %w", err)
	}
	defer rows.Close()

	entries := make([]map[string]any, 0, limit)
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("audit: postgres: scan entry: %w", err)
		}
		var entry map[string]any
		if err := json.Unmarshal(raw, &entry); err != nil {
			continue
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: postgres: iterate recent entries: %w", err)
	}
	return entries, nil
}
