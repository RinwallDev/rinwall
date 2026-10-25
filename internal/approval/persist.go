// Persistence for the approval Store: envelopes, pending approvals, and
// holds are the state that must survive a proxy restart mid-pilot (a
// crash today silently drops every one of them). The audit log stays a
// plain JSONL file on purpose - append-only is already the right shape for
// an audit trail; this file is about state that needs to be re-actionable
// after a restart, not about durability of the history.
//
// Persistence writes are best-effort: a DB hiccup is logged but never
// blocks or fails the in-memory operation, since audit.log already has the
// decision recorded and a storage blip shouldn't take down enforcement.
package approval

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS envelopes (
	id TEXT PRIMARY KEY,
	tool TEXT NOT NULL,
	arg_constraints TEXT NOT NULL,
	max_uses INTEGER NOT NULL,
	uses_remaining INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
	id TEXT PRIMARY KEY,
	tool TEXT NOT NULL,
	args TEXT NOT NULL,
	resource TEXT NOT NULL,
	requested_by TEXT NOT NULL,
	reviewer_role TEXT NOT NULL,
	hash TEXT NOT NULL,
	status TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	required_approvals INTEGER NOT NULL DEFAULT 1,
	approvers TEXT NOT NULL DEFAULT '[]',
	risk_score REAL NOT NULL DEFAULT 0,
	tainted_args TEXT NOT NULL DEFAULT '[]',
	run_id TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS holds (
	id TEXT PRIMARY KEY,
	tool TEXT NOT NULL,
	args TEXT NOT NULL,
	requested_by TEXT NOT NULL,
	delegated_role TEXT NOT NULL,
	agent_id TEXT NOT NULL,
	fire_at INTEGER NOT NULL,
	cancelled INTEGER NOT NULL,
	fired INTEGER NOT NULL,
	run_id TEXT NOT NULL DEFAULT '',
	reviewer_role TEXT NOT NULL DEFAULT ''
);
`

// migrateAddColumn adds a column to an already-existing table from an
// earlier version of schema - CREATE TABLE IF NOT EXISTS above only
// applies to a brand-new database; a database from before run_id/
// reviewer_role existed on holds needs this to actually gain the columns.
// Safe to call every startup: SQLite has no ADD COLUMN IF NOT EXISTS this
// driver can rely on being present, so a "duplicate column name" error is
// the expected, ignored outcome once the migration has already run once.
func migrateAddColumn(db *sql.DB, table, column, definition string) error {
	_, err := db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, definition))
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		return fmt.Errorf("approval: migrate %s.%s: %w", table, column, err)
	}
	return nil
}

// NewPersistentStore opens (creating if needed) a SQLite-backed store and
// reloads any live state from a previous run. Holds are loaded but NOT
// automatically re-armed here - resuming a hold requires an onFire callback
// that only the handler package can supply (it needs the registry and the
// upstream client), so the caller (cmd/rinwall) must call ScheduleResumedHold
// for each id in ResumableHoldIDs() once the handler exists.
func NewPersistentStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("approval: open sqlite %s: %w", dbPath, err)
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("approval: create schema: %w", err)
	}
	if err := migrateAddColumn(db, "holds", "run_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return nil, err
	}
	if err := migrateAddColumn(db, "holds", "reviewer_role", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return nil, err
	}

	s := &Store{
		envelopes: make(map[string]*Envelope),
		approvals: make(map[string]*PendingApproval),
		holds:     make(map[string]*Hold),
		db:        db,
	}
	maxSeen := 0
	if err := s.loadEnvelopes(&maxSeen); err != nil {
		return nil, err
	}
	if err := s.loadApprovals(&maxSeen); err != nil {
		return nil, err
	}
	if err := s.loadHolds(&maxSeen); err != nil {
		return nil, err
	}
	s.nextID = maxSeen
	return s, nil
}

func idSeq(id string) int {
	var n int
	if _, err := fmt.Sscanf(id, "%*[a-z]-%d", &n); err != nil {
		return 0
	}
	return n
}

func (s *Store) loadEnvelopes(maxSeen *int) error {
	rows, err := s.db.Query(`SELECT id, tool, arg_constraints, max_uses, uses_remaining, expires_at FROM envelopes`)
	if err != nil {
		return fmt.Errorf("approval: load envelopes: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var e Envelope
		var constraintsJSON string
		var expiresAtUnix int64
		if err := rows.Scan(&e.ID, &e.Tool, &constraintsJSON, &e.MaxUses, &e.UsesRemaining, &expiresAtUnix); err != nil {
			return fmt.Errorf("approval: scan envelope: %w", err)
		}
		_ = json.Unmarshal([]byte(constraintsJSON), &e.ArgConstraints)
		e.ExpiresAt = time.Unix(expiresAtUnix, 0)
		s.envelopes[e.ID] = &e
		if n := idSeq(e.ID); n > *maxSeen {
			*maxSeen = n
		}
	}
	return rows.Err()
}

func (s *Store) loadApprovals(maxSeen *int) error {
	rows, err := s.db.Query(`SELECT id, tool, args, resource, requested_by, reviewer_role, hash, status, created_at, expires_at, required_approvals, approvers, risk_score, tainted_args, run_id FROM approvals`)
	if err != nil {
		return fmt.Errorf("approval: load approvals: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var p PendingApproval
		var argsJSON, approversJSON, taintedArgsJSON string
		var createdAtUnix, expiresAtUnix int64
		var status string
		if err := rows.Scan(&p.ID, &p.Tool, &argsJSON, &p.Resource, &p.RequestedBy, &p.ReviewerRole, &p.Hash, &status, &createdAtUnix, &expiresAtUnix, &p.RequiredApprovals, &approversJSON, &p.RiskScore, &taintedArgsJSON, &p.RunID); err != nil {
			return fmt.Errorf("approval: scan approval: %w", err)
		}
		_ = json.Unmarshal([]byte(argsJSON), &p.Args)
		_ = json.Unmarshal([]byte(approversJSON), &p.Approvers)
		_ = json.Unmarshal([]byte(taintedArgsJSON), &p.TaintedArgs)
		p.Status = ApprovalStatus(status)
		p.CreatedAt = time.Unix(createdAtUnix, 0)
		p.ExpiresAt = time.Unix(expiresAtUnix, 0)
		s.approvals[p.ID] = &p
		if n := idSeq(p.ID); n > *maxSeen {
			*maxSeen = n
		}
	}
	return rows.Err()
}

func (s *Store) loadHolds(maxSeen *int) error {
	rows, err := s.db.Query(`SELECT id, tool, args, requested_by, delegated_role, agent_id, fire_at, cancelled, fired, run_id, reviewer_role FROM holds`)
	if err != nil {
		return fmt.Errorf("approval: load holds: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var h Hold
		var argsJSON string
		var fireAtUnix int64
		var cancelled, fired int
		if err := rows.Scan(&h.ID, &h.Tool, &argsJSON, &h.RequestedBy, &h.DelegatedRole, &h.AgentID, &fireAtUnix, &cancelled, &fired, &h.RunID, &h.ReviewerRole); err != nil {
			return fmt.Errorf("approval: scan hold: %w", err)
		}
		_ = json.Unmarshal([]byte(argsJSON), &h.Args)
		h.FireAt = time.Unix(fireAtUnix, 0)
		h.Cancelled = cancelled != 0
		h.Fired = fired != 0
		s.holds[h.ID] = &h
		if n := idSeq(h.ID); n > *maxSeen {
			*maxSeen = n
		}
	}
	return rows.Err()
}

// ResumableHoldIDs returns holds from a previous run that never fired and
// were never cancelled - these need a fresh timer via ScheduleResumedHold.
func (s *Store) ResumableHoldIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ids []string
	for id, h := range s.holds {
		if !h.Cancelled && !h.Fired {
			ids = append(ids, id)
		}
	}
	return ids
}

// ScheduleResumedHold re-arms a hold loaded from a previous run. If its
// window already elapsed while the process was down, it fires immediately.
func (s *Store) ScheduleResumedHold(id string, onFire func()) {
	s.mu.Lock()
	h, ok := s.holds[id]
	if !ok || h.Cancelled || h.Fired {
		s.mu.Unlock()
		return
	}
	remaining := time.Until(h.FireAt)
	if remaining < 0 {
		remaining = 0
	}
	h.timer = time.AfterFunc(remaining, func() {
		s.mu.Lock()
		if h.Cancelled {
			s.mu.Unlock()
			return
		}
		h.Fired = true
		s.mu.Unlock()
		s.persistHoldFired(h.ID)
		onFire()
	})
	s.mu.Unlock()
}

// --- write-through helpers, called from approval.go after each mutation ---

func (s *Store) persistEnvelope(e *Envelope) {
	if s.db == nil {
		return
	}
	constraintsJSON, _ := json.Marshal(e.ArgConstraints)
	_, err := s.db.Exec(`INSERT OR REPLACE INTO envelopes (id, tool, arg_constraints, max_uses, uses_remaining, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		e.ID, e.Tool, string(constraintsJSON), e.MaxUses, e.UsesRemaining, e.ExpiresAt.Unix())
	if err != nil {
		log.Printf("[approval] warning: persist envelope %s failed: %v", e.ID, err)
	}
}

func (s *Store) persistApproval(p *PendingApproval) {
	if s.db == nil {
		return
	}
	argsJSON, _ := json.Marshal(p.Args)
	approversJSON, _ := json.Marshal(p.Approvers)
	taintedArgsJSON, _ := json.Marshal(p.TaintedArgs)
	_, err := s.db.Exec(`INSERT OR REPLACE INTO approvals (id, tool, args, resource, requested_by, reviewer_role, hash, status, created_at, expires_at, required_approvals, approvers, risk_score, tainted_args, run_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Tool, string(argsJSON), p.Resource, p.RequestedBy, p.ReviewerRole, p.Hash, string(p.Status), p.CreatedAt.Unix(), p.ExpiresAt.Unix(), p.RequiredApprovals, string(approversJSON), p.RiskScore, string(taintedArgsJSON), p.RunID)
	if err != nil {
		log.Printf("[approval] warning: persist approval %s failed: %v", p.ID, err)
	}
}

func (s *Store) persistApprovalApprovers(id string, approvers []string) {
	if s.db == nil {
		return
	}
	approversJSON, _ := json.Marshal(approvers)
	if _, err := s.db.Exec(`UPDATE approvals SET approvers = ? WHERE id = ?`, string(approversJSON), id); err != nil {
		log.Printf("[approval] warning: persist approval-approvers %s failed: %v", id, err)
	}
}

func (s *Store) persistHold(h *Hold) {
	if s.db == nil {
		return
	}
	argsJSON, _ := json.Marshal(h.Args)
	cancelled, fired := 0, 0
	if h.Cancelled {
		cancelled = 1
	}
	if h.Fired {
		fired = 1
	}
	_, err := s.db.Exec(`INSERT OR REPLACE INTO holds (id, tool, args, requested_by, delegated_role, agent_id, fire_at, cancelled, fired, run_id, reviewer_role) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		h.ID, h.Tool, string(argsJSON), h.RequestedBy, h.DelegatedRole, h.AgentID, h.FireAt.Unix(), cancelled, fired, h.RunID, h.ReviewerRole)
	if err != nil {
		log.Printf("[approval] warning: persist hold %s failed: %v", h.ID, err)
	}
}

func (s *Store) persistHoldCancelled(id string) {
	if s.db == nil {
		return
	}
	if _, err := s.db.Exec(`UPDATE holds SET cancelled = 1 WHERE id = ?`, id); err != nil {
		log.Printf("[approval] warning: persist hold-cancelled %s failed: %v", id, err)
	}
}

func (s *Store) persistHoldFired(id string) {
	if s.db == nil {
		return
	}
	if _, err := s.db.Exec(`UPDATE holds SET fired = 1 WHERE id = ?`, id); err != nil {
		log.Printf("[approval] warning: persist hold-fired %s failed: %v", id, err)
	}
}

func (s *Store) persistApprovalStatus(id string, status ApprovalStatus) {
	if s.db == nil {
		return
	}
	if _, err := s.db.Exec(`UPDATE approvals SET status = ? WHERE id = ?`, string(status), id); err != nil {
		log.Printf("[approval] warning: persist approval-status %s failed: %v", id, err)
	}
}

func (s *Store) persistEnvelopeUses(id string, usesRemaining int) {
	if s.db == nil {
		return
	}
	if _, err := s.db.Exec(`UPDATE envelopes SET uses_remaining = ? WHERE id = ?`, usesRemaining, id); err != nil {
		log.Printf("[approval] warning: persist envelope-uses %s failed: %v", id, err)
	}
}
