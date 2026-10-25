// Postgres-backed persistence for multi-instance/HA deployments - same
// reasoning as internal/approval/postgres.go: the in-memory map + mutex is
// correct for one process, but a saga step's Seq assignment
// (len(s.runs[runID]) today) would collide across two instances appending
// to the same run concurrently. Postgres mode locks a run's existing rows
// before assigning the next Seq, serializing that assignment across
// instances the same way the in-process mutex does within one.
// MarkCompensated/MarkCompensationFailed need no such locking - they're
// idempotent single-row UPDATEs, and two instances marking the same step
// compensated concurrently land on the identical end state.
package saga

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const pgSchema = `
CREATE TABLE IF NOT EXISTS saga_steps (
	run_id TEXT NOT NULL,
	seq INTEGER NOT NULL,
	tool TEXT NOT NULL,
	reversibility_class TEXT NOT NULL,
	resource TEXT NOT NULL,
	args TEXT NOT NULL,
	pre_image TEXT NOT NULL,
	delegated_user TEXT NOT NULL,
	delegated_role TEXT NOT NULL,
	agent_id TEXT NOT NULL,
	executed_at BIGINT NOT NULL,
	compensated BOOLEAN NOT NULL DEFAULT FALSE,
	compensation_failed BOOLEAN NOT NULL DEFAULT FALSE,
	compensation_note TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (run_id, seq)
);
`

// NewPostgresStore opens (creating the schema if needed) a Postgres-backed
// Store safe for concurrent use by multiple proxy processes against the
// same database. Reuses the same "pgx" database/sql driver as
// internal/approval's Postgres backend and cmd/rinwall's DB dynamic-secrets
// path - one driver, blank-imported wherever it's used directly.
func NewPostgresStore(dsn string) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("saga: open postgres: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("saga: ping postgres: %w", err)
	}
	if _, err := db.Exec(pgSchema); err != nil {
		return nil, fmt.Errorf("saga: create postgres schema: %w", err)
	}
	return &Store{runs: make(map[string][]*Step), pg: db}, nil
}

// recordStepPG takes a transaction-scoped Postgres advisory lock keyed by
// a hash of run_id before computing the next Seq, so two instances
// recording a step for the same run at the same instant don't both
// compute the same Seq - the advisory lock is what serializes it, not the
// in-process mutex the SQLite/in-memory path relies on. A plain "SELECT
// count(*) ... FOR UPDATE" doesn't work here - Postgres rejects FOR UPDATE
// combined with an aggregate, and even a row lock on existing rows
// wouldn't block a concurrent FIRST insert for a brand-new run, since
// there'd be no row yet to lock. An advisory lock has no such
// row-existence requirement and is released automatically at
// commit/rollback, matching this function's transaction scope exactly.
// A Postgres error here is surfaced by logging only, matching RecordStep's
// existing no-error-return contract (the in-memory path's persistStep is
// already best-effort/log-only for the same reason: a storage hiccup here
// shouldn't block an already-decided execution).
func (s *Store) recordStepPG(step *Step) {
	tx, err := s.pg.Begin()
	if err != nil {
		log.Printf("[saga] postgres: begin recordStep tx: %v", err)
		return
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, step.RunID); err != nil {
		log.Printf("[saga] postgres: acquire run lock for %s: %v", step.RunID, err)
		return
	}

	var count int
	if err := tx.QueryRow(`SELECT count(*) FROM saga_steps WHERE run_id = $1`, step.RunID).Scan(&count); err != nil {
		log.Printf("[saga] postgres: count existing steps for run %s: %v", step.RunID, err)
		return
	}
	step.Seq = count

	argsJSON, err := json.Marshal(step.Args)
	if err != nil {
		log.Printf("[saga] postgres: marshal step args: %v", err)
		return
	}
	_, err = tx.Exec(
		`INSERT INTO saga_steps (run_id, seq, tool, reversibility_class, resource, args, pre_image, delegated_user, delegated_role, agent_id, executed_at, compensated, compensation_failed, compensation_note)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,FALSE,FALSE,'')`,
		step.RunID, step.Seq, step.Tool, step.ReversibilityClass, step.Resource, string(argsJSON), string(step.PreImage),
		step.DelegatedUser, step.DelegatedRole, step.AgentID, step.ExecutedAt.Unix(),
	)
	if err != nil {
		log.Printf("[saga] postgres: insert step %s#%d: %v", step.RunID, step.Seq, err)
		return
	}
	if err := tx.Commit(); err != nil {
		log.Printf("[saga] postgres: commit recordStep %s#%d: %v", step.RunID, step.Seq, err)
	}
}

func (s *Store) stepsForPG(runID string) []*Step {
	rows, err := s.pg.Query(
		`SELECT run_id, seq, tool, reversibility_class, resource, args, pre_image, delegated_user, delegated_role, agent_id, executed_at, compensated, compensation_failed, compensation_note
		 FROM saga_steps WHERE run_id = $1 ORDER BY seq ASC`, runID)
	if err != nil {
		log.Printf("[saga] postgres: stepsFor %s: %v", runID, err)
		return nil
	}
	defer rows.Close()
	var out []*Step
	for rows.Next() {
		var step Step
		var argsJSON, preImageJSON string
		var executedAtUnix int64
		if err := rows.Scan(&step.RunID, &step.Seq, &step.Tool, &step.ReversibilityClass, &step.Resource,
			&argsJSON, &preImageJSON, &step.DelegatedUser, &step.DelegatedRole, &step.AgentID,
			&executedAtUnix, &step.Compensated, &step.CompensationFailed, &step.CompensationNote); err != nil {
			log.Printf("[saga] postgres: scan step: %v", err)
			continue
		}
		_ = json.Unmarshal([]byte(argsJSON), &step.Args)
		step.PreImage = json.RawMessage(preImageJSON)
		step.ExecutedAt = time.Unix(executedAtUnix, 0)
		out = append(out, &step)
	}
	return out
}

func (s *Store) hasCompensableStepsPG(runID string) bool {
	var count int
	err := s.pg.QueryRow(
		`SELECT count(*) FROM saga_steps WHERE run_id = $1 AND reversibility_class = 'A' AND NOT compensated AND NOT compensation_failed`,
		runID,
	).Scan(&count)
	if err != nil {
		log.Printf("[saga] postgres: hasCompensableSteps %s: %v", runID, err)
		return false
	}
	return count > 0
}

func (s *Store) markCompensationStatusPG(runID string, seq int, compensated, failed bool, note string) {
	_, err := s.pg.Exec(
		`UPDATE saga_steps SET compensated = $1, compensation_failed = $2, compensation_note = $3 WHERE run_id = $4 AND seq = $5`,
		compensated, failed, note, runID, seq,
	)
	if err != nil {
		log.Printf("[saga] postgres: mark compensation status %s#%d: %v", runID, seq, err)
	}
}
