// Persistence for the saga Store - same reasoning as internal/approval's:
// a proxy restart mid-run must not silently lose the ability to compensate
// steps that already executed. Best-effort writes; a storage hiccup is
// logged, never blocks or fails the in-memory operation.
package saga

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
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
	executed_at INTEGER NOT NULL,
	compensated INTEGER NOT NULL DEFAULT 0,
	compensation_failed INTEGER NOT NULL DEFAULT 0,
	compensation_note TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (run_id, seq)
);
`

func NewPersistentStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("saga: open sqlite %s: %w", dbPath, err)
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("saga: create schema: %w", err)
	}

	s := &Store{runs: make(map[string][]*Step), db: db}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	rows, err := s.db.Query(`SELECT run_id, seq, tool, reversibility_class, resource, args, pre_image, delegated_user, delegated_role, agent_id, executed_at, compensated, compensation_failed, compensation_note FROM saga_steps ORDER BY run_id, seq`)
	if err != nil {
		return fmt.Errorf("saga: load steps: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var step Step
		var argsJSON, preImageJSON string
		var executedAtUnix int64
		var compensated, compensationFailed int
		if err := rows.Scan(&step.RunID, &step.Seq, &step.Tool, &step.ReversibilityClass, &step.Resource,
			&argsJSON, &preImageJSON, &step.DelegatedUser, &step.DelegatedRole, &step.AgentID,
			&executedAtUnix, &compensated, &compensationFailed, &step.CompensationNote); err != nil {
			return fmt.Errorf("saga: scan step: %w", err)
		}
		_ = json.Unmarshal([]byte(argsJSON), &step.Args)
		step.PreImage = json.RawMessage(preImageJSON)
		step.ExecutedAt = time.Unix(executedAtUnix, 0)
		step.Compensated = compensated != 0
		step.CompensationFailed = compensationFailed != 0
		s.runs[step.RunID] = append(s.runs[step.RunID], &step)
	}
	return rows.Err()
}

func (s *Store) persistStep(step *Step) {
	if s.db == nil {
		return
	}
	argsJSON, _ := json.Marshal(step.Args)
	_, err := s.db.Exec(`INSERT OR REPLACE INTO saga_steps (run_id, seq, tool, reversibility_class, resource, args, pre_image, delegated_user, delegated_role, agent_id, executed_at, compensated, compensation_failed, compensation_note) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		step.RunID, step.Seq, step.Tool, step.ReversibilityClass, step.Resource, string(argsJSON), string(step.PreImage),
		step.DelegatedUser, step.DelegatedRole, step.AgentID, step.ExecutedAt.Unix(), 0, 0, "")
	if err != nil {
		log.Printf("[saga] warning: persist step %s#%d failed: %v", step.RunID, step.Seq, err)
	}
}

func (s *Store) persistCompensationStatus(runID string, seq int, compensated, failed bool, note string) {
	if s.db == nil {
		return
	}
	c, f := 0, 0
	if compensated {
		c = 1
	}
	if failed {
		f = 1
	}
	_, err := s.db.Exec(`UPDATE saga_steps SET compensated = ?, compensation_failed = ?, compensation_note = ? WHERE run_id = ? AND seq = ?`,
		c, f, note, runID, seq)
	if err != nil {
		log.Printf("[saga] warning: persist compensation status %s#%d failed: %v", runID, seq, err)
	}
}
