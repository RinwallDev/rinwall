package saga

import (
	"database/sql"
	"sync"
)

// Store holds each tracked run's ordered step trace. Same shape as
// internal/approval.Store: in-memory by default (tests), optionally
// SQLite-backed (NewPersistentStore) so a proxy restart mid-run doesn't
// lose the ability to compensate it, or Postgres-backed (NewPostgresStore,
// postgres.go) for multi-instance/HA deployments - see that file's doc
// comment for why Postgres mode is a genuinely different concurrency
// model, not just a different file format.
type Store struct {
	mu   sync.Mutex
	runs map[string][]*Step // runID -> ordered steps, append-only except for the Compensated* fields
	db   *sql.DB            // SQLite, single-instance
	pg   *sql.DB            // Postgres, multi-instance/HA - when set, db/runs are unused; every method branches to its *PG counterpart
}

func NewStore() *Store {
	return &Store{runs: make(map[string][]*Step)}
}

// Close releases the underlying DB handle, if any (NewStore's in-memory
// Store has none, and Close is a no-op for it).
func (s *Store) Close() error {
	if s.pg != nil {
		return s.pg.Close()
	}
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// RecordStep appends a step to its run's trace - always append-only; the
// sequence number is assigned here so callers never have to coordinate it.
func (s *Store) RecordStep(step *Step) {
	if s.pg != nil {
		s.recordStepPG(step)
		return
	}
	s.mu.Lock()
	step.Seq = len(s.runs[step.RunID])
	s.runs[step.RunID] = append(s.runs[step.RunID], step)
	s.mu.Unlock()
	s.persistStep(step)
}

// StepsFor returns a run's trace in EXECUTION order (oldest first). Callers
// that want to compensate walk this slice backwards themselves - Store has
// no opinion on compensation ordering, only on what happened and when.
func (s *Store) StepsFor(runID string) []*Step {
	if s.pg != nil {
		return s.stepsForPG(runID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	steps := s.runs[runID]
	out := make([]*Step, len(steps))
	copy(out, steps)
	return out
}

// HasCompensableSteps reports whether runID has any executed, not-yet-
// compensated Class A step - the gate before bothering to trigger a
// compensation walk at all.
func (s *Store) HasCompensableSteps(runID string) bool {
	if s.pg != nil {
		return s.hasCompensableStepsPG(runID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, step := range s.runs[runID] {
		if step.ReversibilityClass == "A" && !step.Compensated && !step.CompensationFailed {
			return true
		}
	}
	return false
}

func (s *Store) MarkCompensated(runID string, seq int) {
	if s.pg != nil {
		s.markCompensationStatusPG(runID, seq, true, false, "")
		return
	}
	s.mu.Lock()
	for _, step := range s.runs[runID] {
		if step.Seq == seq {
			step.Compensated = true
			break
		}
	}
	s.mu.Unlock()
	s.persistCompensationStatus(runID, seq, true, false, "")
}

func (s *Store) MarkCompensationFailed(runID string, seq int, note string) {
	if s.pg != nil {
		s.markCompensationStatusPG(runID, seq, false, true, note)
		return
	}
	s.mu.Lock()
	for _, step := range s.runs[runID] {
		if step.Seq == seq {
			step.CompensationFailed = true
			step.CompensationNote = note
			break
		}
	}
	s.mu.Unlock()
	s.persistCompensationStatus(runID, seq, false, true, note)
}
