// Postgres-backed persistence for multi-instance/HA deployments.
//
// This is a genuinely different concurrency model from persist.go's
// SQLite-backed NewPersistentStore, not just a different file format.
// NewPersistentStore treats the in-memory map as the sole authority and
// SQLite as a write-behind log purely for restart recovery - correct for
// one process, since Store's own sync.Mutex serializes every access. Once
// a second process can read/write the same state, that mutex protects
// nothing: two reviewers hitting two different instances at nearly the
// same moment could both read "not yet approved" and both flip status to
// Approved, double-counting a four-eyes approval. So in Postgres mode,
// Postgres itself is the authority - every mutating method here runs
// inside a transaction with row-level locking (SELECT ... FOR UPDATE),
// which serializes concurrent access across ALL instances the same way
// the in-process mutex serializes access within one. The in-memory maps
// on Store are allocated but unused in this mode.
package approval

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const pgSchema = `
CREATE TABLE IF NOT EXISTS envelopes (
	id BIGSERIAL PRIMARY KEY,
	tool TEXT NOT NULL,
	arg_constraints TEXT NOT NULL,
	max_uses INTEGER NOT NULL,
	uses_remaining INTEGER NOT NULL,
	expires_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
	id BIGSERIAL PRIMARY KEY,
	tool TEXT NOT NULL,
	args TEXT NOT NULL,
	resource TEXT NOT NULL,
	requested_by TEXT NOT NULL,
	reviewer_role TEXT NOT NULL,
	hash TEXT NOT NULL,
	status TEXT NOT NULL,
	created_at BIGINT NOT NULL,
	expires_at BIGINT NOT NULL,
	required_approvals INTEGER NOT NULL DEFAULT 1,
	approvers TEXT NOT NULL DEFAULT '[]',
	risk_score DOUBLE PRECISION NOT NULL DEFAULT 0,
	tainted_args TEXT NOT NULL DEFAULT '[]',
	run_id TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS holds (
	id BIGSERIAL PRIMARY KEY,
	tool TEXT NOT NULL,
	args TEXT NOT NULL,
	requested_by TEXT NOT NULL,
	delegated_role TEXT NOT NULL,
	agent_id TEXT NOT NULL,
	fire_at BIGINT NOT NULL,
	cancelled BOOLEAN NOT NULL DEFAULT FALSE,
	fired BOOLEAN NOT NULL DEFAULT FALSE,
	run_id TEXT NOT NULL DEFAULT '',
	reviewer_role TEXT NOT NULL DEFAULT ''
);
`

// NewPostgresStore opens (creating the schema if needed) a Postgres-backed
// Store safe for concurrent use by multiple proxy processes against the
// same database. Reuses the "pgx" database/sql driver already registered
// by cmd/rinwall (github.com/jackc/pgx/v5/stdlib) - blank-imported here too
// so this file has no hidden dependency on being wired up after main.go's
// own import runs.
func NewPostgresStore(dsn string) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("approval: open postgres: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("approval: ping postgres: %w", err)
	}
	if _, err := db.Exec(pgSchema); err != nil {
		return nil, fmt.Errorf("approval: create postgres schema: %w", err)
	}
	return &Store{
		envelopes: make(map[string]*Envelope),
		approvals: make(map[string]*PendingApproval),
		holds:     make(map[string]*Hold),
		pg:        db,
	}, nil
}

func pgFormatID(prefix string, n int64) string { return fmt.Sprintf("%s-%d", prefix, n) }

func pgParseID(prefix, id string) (int64, error) {
	var n int64
	if _, err := fmt.Sscanf(id, prefix+"-%d", &n); err != nil {
		return 0, fmt.Errorf("approval: malformed id %q for prefix %q", id, prefix)
	}
	return n, nil
}

// --- envelopes ---------------------------------------------------------

func (s *Store) createEnvelopePG(tool string, constraints map[string]Constraint, maxUses int, ttl time.Duration) (*Envelope, error) {
	constraintsJSON, err := json.Marshal(constraints)
	if err != nil {
		return nil, fmt.Errorf("approval: marshal constraints: %w", err)
	}
	expiresAt := time.Now().Add(ttl)
	var id int64
	err = s.pg.QueryRow(
		`INSERT INTO envelopes (tool, arg_constraints, max_uses, uses_remaining, expires_at) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
		tool, string(constraintsJSON), maxUses, maxUses, expiresAt.Unix(),
	).Scan(&id)
	if err != nil {
		return nil, fmt.Errorf("approval: postgres create envelope: %w", err)
	}
	return &Envelope{
		ID: pgFormatID("env", id), Tool: tool, ArgConstraints: constraints,
		MaxUses: maxUses, UsesRemaining: maxUses, ExpiresAt: expiresAt,
	}, nil
}

// checkPreAuthPG locks every live candidate envelope for this tool, runs
// the exact same Envelope.matches() constraint-DSL logic already used in
// the in-memory path against each locked row, then atomically decrements
// the winning envelope's uses_remaining - all inside one transaction, so
// no other instance can consume the same "last use" concurrently. A
// Postgres error here fails closed to "no match" (log, return false)
// rather than blocking the call outright: skipping a pre-authorized
// envelope on a transient DB hiccup only means a human sees one extra
// approval request, never that a check gets bypassed.
func (s *Store) checkPreAuthPG(tool string, args map[string]any) (*Envelope, bool) {
	tx, err := s.pg.Begin()
	if err != nil {
		log.Printf("[approval] postgres: begin checkPreAuth tx: %v", err)
		return nil, false
	}
	defer tx.Rollback()

	rows, err := tx.Query(
		`SELECT id, arg_constraints, max_uses, uses_remaining, expires_at FROM envelopes
		 WHERE tool = $1 AND uses_remaining > 0 AND expires_at > $2 FOR UPDATE`,
		tool, time.Now().Unix(),
	)
	if err != nil {
		log.Printf("[approval] postgres: query envelopes: %v", err)
		return nil, false
	}
	type candidate struct {
		id            int64
		e             *Envelope
		usesRemaining int
	}
	var candidates []candidate
	for rows.Next() {
		var id int64
		var constraintsJSON string
		var maxUses, usesRemaining int
		var expiresAtUnix int64
		if err := rows.Scan(&id, &constraintsJSON, &maxUses, &usesRemaining, &expiresAtUnix); err != nil {
			rows.Close()
			log.Printf("[approval] postgres: scan envelope: %v", err)
			return nil, false
		}
		e := &Envelope{ID: pgFormatID("env", id), Tool: tool, MaxUses: maxUses, UsesRemaining: usesRemaining, ExpiresAt: time.Unix(expiresAtUnix, 0)}
		_ = json.Unmarshal([]byte(constraintsJSON), &e.ArgConstraints)
		candidates = append(candidates, candidate{id: id, e: e, usesRemaining: usesRemaining})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		log.Printf("[approval] postgres: iterate envelopes: %v", err)
		return nil, false
	}

	for _, c := range candidates {
		if !c.e.matches(args) {
			continue
		}
		if _, err := tx.Exec(`UPDATE envelopes SET uses_remaining = uses_remaining - 1 WHERE id = $1`, c.id); err != nil {
			log.Printf("[approval] postgres: consume envelope %d: %v", c.id, err)
			return nil, false
		}
		if err := tx.Commit(); err != nil {
			log.Printf("[approval] postgres: commit checkPreAuth: %v", err)
			return nil, false
		}
		c.e.UsesRemaining--
		return c.e, true
	}
	return nil, false
}

// --- holds ---------------------------------------------------------------

// enqueueHoldPG persists a hold's due time and request context; it does
// NOT arm a local timer or hold onto the caller's onFire closure the way
// the in-memory path does, since there is no guarantee the instance that
// created it is still running when the window elapses. Firing is instead
// the poll loop's job (see PollAndFireDueHolds below), which reconstructs
// what to do purely from the hold's own stored fields - the same
// restart-safe pattern SQLite mode already uses for ScheduleResumedHold,
// just as the ONLY firing mechanism in Postgres mode rather than a
// fallback for the resume-after-restart case specifically.
func (s *Store) enqueueHoldPG(tool string, args map[string]any, holdSeconds int, requestedBy, delegatedRole, agentID, runID, reviewerRole string) (*Hold, error) {
	argsJSON, err := json.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("approval: marshal hold args: %w", err)
	}
	fireAt := time.Now().Add(time.Duration(holdSeconds) * time.Second)
	var id int64
	err = s.pg.QueryRow(
		`INSERT INTO holds (tool, args, requested_by, delegated_role, agent_id, fire_at, cancelled, fired, run_id, reviewer_role)
		 VALUES ($1,$2,$3,$4,$5,$6,FALSE,FALSE,$7,$8) RETURNING id`,
		tool, string(argsJSON), requestedBy, delegatedRole, agentID, fireAt.Unix(), runID, reviewerRole,
	).Scan(&id)
	if err != nil {
		return nil, fmt.Errorf("approval: postgres create hold: %w", err)
	}
	return &Hold{
		ID: pgFormatID("hold", id), Tool: tool, Args: args, RequestedBy: requestedBy,
		DelegatedRole: delegatedRole, AgentID: agentID, RunID: runID, ReviewerRole: reviewerRole, FireAt: fireAt,
	}, nil
}

func (s *Store) cancelHoldPG(id, cancellerRole string) (*Hold, error) {
	n, err := pgParseID("hold", id)
	if err != nil {
		return nil, err
	}
	tx, err := s.pg.Begin()
	if err != nil {
		return nil, fmt.Errorf("approval: postgres: begin cancel hold: %w", err)
	}
	defer tx.Rollback()

	var tool, argsJSON, requestedBy, delegatedRole, agentID, runID, reviewerRole string
	var fireAtUnix int64
	var cancelled, fired bool
	err = tx.QueryRow(
		`SELECT tool, args, requested_by, delegated_role, agent_id, fire_at, cancelled, fired, run_id, reviewer_role
		 FROM holds WHERE id = $1 FOR UPDATE`, n,
	).Scan(&tool, &argsJSON, &requestedBy, &delegatedRole, &agentID, &fireAtUnix, &cancelled, &fired, &runID, &reviewerRole)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("no such hold %q", id)
	}
	if err != nil {
		return nil, fmt.Errorf("approval: postgres: load hold %q: %w", id, err)
	}
	if cancellerRole != reviewerRole {
		return nil, fmt.Errorf("hold %q requires reviewer_role=%q, canceller has role %q", id, reviewerRole, cancellerRole)
	}
	if fired {
		return nil, fmt.Errorf("hold %q already fired - too late to cancel", id)
	}
	if _, err := tx.Exec(`UPDATE holds SET cancelled = TRUE WHERE id = $1`, n); err != nil {
		return nil, fmt.Errorf("approval: postgres: cancel hold %q: %w", id, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("approval: postgres: commit cancel hold %q: %w", id, err)
	}

	h := &Hold{ID: id, Tool: tool, RequestedBy: requestedBy, DelegatedRole: delegatedRole, AgentID: agentID,
		FireAt: time.Unix(fireAtUnix, 0), Cancelled: true, Fired: fired, RunID: runID, ReviewerRole: reviewerRole}
	_ = json.Unmarshal([]byte(argsJSON), &h.Args)
	return h, nil
}

func (s *Store) getHoldPG(id string) (*Hold, bool) {
	n, err := pgParseID("hold", id)
	if err != nil {
		return nil, false
	}
	var tool, argsJSON, requestedBy, delegatedRole, agentID, runID, reviewerRole string
	var fireAtUnix int64
	var cancelled, fired bool
	err = s.pg.QueryRow(
		`SELECT tool, args, requested_by, delegated_role, agent_id, fire_at, cancelled, fired, run_id, reviewer_role
		 FROM holds WHERE id = $1`, n,
	).Scan(&tool, &argsJSON, &requestedBy, &delegatedRole, &agentID, &fireAtUnix, &cancelled, &fired, &runID, &reviewerRole)
	if err != nil {
		if err != sql.ErrNoRows {
			log.Printf("[approval] postgres: get hold %q: %v", id, err)
		}
		return nil, false
	}
	h := &Hold{ID: id, Tool: tool, RequestedBy: requestedBy, DelegatedRole: delegatedRole, AgentID: agentID,
		FireAt: time.Unix(fireAtUnix, 0), Cancelled: cancelled, Fired: fired, RunID: runID, ReviewerRole: reviewerRole}
	_ = json.Unmarshal([]byte(argsJSON), &h.Args)
	return h, true
}

func (s *Store) listHoldsPG() []*Hold {
	rows, err := s.pg.Query(`SELECT id, tool, args, requested_by, delegated_role, agent_id, fire_at, cancelled, fired, run_id, reviewer_role FROM holds`)
	if err != nil {
		log.Printf("[approval] postgres: list holds: %v", err)
		return nil
	}
	defer rows.Close()
	var out []*Hold
	for rows.Next() {
		var id int64
		var tool, argsJSON, requestedBy, delegatedRole, agentID, runID, reviewerRole string
		var fireAtUnix int64
		var cancelled, fired bool
		if err := rows.Scan(&id, &tool, &argsJSON, &requestedBy, &delegatedRole, &agentID, &fireAtUnix, &cancelled, &fired, &runID, &reviewerRole); err != nil {
			log.Printf("[approval] postgres: scan hold: %v", err)
			continue
		}
		h := &Hold{ID: pgFormatID("hold", id), Tool: tool, RequestedBy: requestedBy, DelegatedRole: delegatedRole, AgentID: agentID,
			FireAt: time.Unix(fireAtUnix, 0), Cancelled: cancelled, Fired: fired, RunID: runID, ReviewerRole: reviewerRole}
		_ = json.Unmarshal([]byte(argsJSON), &h.Args)
		out = append(out, h)
	}
	return out
}

// PollAndFireDueHolds claims and fires holds whose window has elapsed,
// safe to call concurrently from multiple proxy instances polling the
// same Postgres database: "FOR UPDATE SKIP LOCKED" lets each instance's
// poll pass skip rows another instance already has locked, so a due hold
// is claimed by exactly one instance rather than fired twice. onFire is
// called once per claimed hold, AFTER the row is durably marked fired -
// the same "mark fired, then run the side effect" order Logger's SQLite
// path already uses for its timer callback. Call this on a ticker (see
// cmd/rinwall/main.go) only when Postgres mode is active; SQLite/in-memory
// mode keeps using time.AfterFunc/ScheduleResumedHold instead, since a
// single process needs no distributed claiming.
func (s *Store) PollAndFireDueHolds(limit int, onFire func(*Hold)) {
	rows, err := s.pg.Query(
		`SELECT id, tool, args, requested_by, delegated_role, agent_id, run_id
		 FROM holds WHERE NOT cancelled AND NOT fired AND fire_at <= $1
		 ORDER BY fire_at ASC LIMIT $2 FOR UPDATE SKIP LOCKED`,
		time.Now().Unix(), limit,
	)
	if err != nil {
		log.Printf("[approval] postgres: poll due holds: %v", err)
		return
	}
	type due struct {
		id                                                         int64
		tool, argsJSON, requestedBy, delegatedRole, agentID, runID string
	}
	var claimed []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.id, &d.tool, &d.argsJSON, &d.requestedBy, &d.delegatedRole, &d.agentID, &d.runID); err != nil {
			log.Printf("[approval] postgres: scan due hold: %v", err)
			continue
		}
		claimed = append(claimed, d)
	}
	rows.Close()

	for _, d := range claimed {
		if _, err := s.pg.Exec(`UPDATE holds SET fired = TRUE WHERE id = $1`, d.id); err != nil {
			log.Printf("[approval] postgres: mark hold %d fired: %v", d.id, err)
			continue
		}
		h := &Hold{ID: pgFormatID("hold", d.id), Tool: d.tool, RequestedBy: d.requestedBy,
			DelegatedRole: d.delegatedRole, AgentID: d.agentID, RunID: d.runID, Fired: true}
		_ = json.Unmarshal([]byte(d.argsJSON), &h.Args)
		onFire(h)
	}
}

// --- approvals -------------------------------------------------------------

func (s *Store) createApprovalPG(tool string, args map[string]any, resource, requestedBy, reviewerRole string, ttl time.Duration, requiredApprovals int, riskScore float64, taintedArgs []string, runID string) (*PendingApproval, error) {
	if requiredApprovals < 1 {
		requiredApprovals = 1
	}
	hash, err := RequestHash(tool, args, resource, requestedBy)
	if err != nil {
		return nil, err
	}
	argsJSON, err := json.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("approval: marshal args: %w", err)
	}
	taintedArgsJSON, _ := json.Marshal(taintedArgs)
	createdAt := time.Now()
	expiresAt := createdAt.Add(ttl)

	var id int64
	err = s.pg.QueryRow(
		`INSERT INTO approvals (tool, args, resource, requested_by, reviewer_role, hash, status, created_at, expires_at, required_approvals, approvers, risk_score, tainted_args, run_id)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'[]',$11,$12,$13) RETURNING id`,
		tool, string(argsJSON), resource, requestedBy, reviewerRole, hash, string(StatusPending),
		createdAt.Unix(), expiresAt.Unix(), requiredApprovals, riskScore, string(taintedArgsJSON), runID,
	).Scan(&id)
	if err != nil {
		return nil, fmt.Errorf("approval: postgres create approval: %w", err)
	}
	return &PendingApproval{
		ID: pgFormatID("appr", id), Tool: tool, Args: args, Resource: resource, RequestedBy: requestedBy,
		ReviewerRole: reviewerRole, Hash: hash, Status: StatusPending, CreatedAt: createdAt, ExpiresAt: expiresAt,
		RequiredApprovals: requiredApprovals, RiskScore: riskScore, TaintedArgs: taintedArgs, RunID: runID,
	}, nil
}

func scanApprovalRow(row interface{ Scan(...any) error }) (*PendingApproval, error) {
	var p PendingApproval
	var id int64
	var argsJSON, status, approversJSON, taintedArgsJSON string
	var createdAtUnix, expiresAtUnix int64
	if err := row.Scan(&id, &p.Tool, &argsJSON, &p.Resource, &p.RequestedBy, &p.ReviewerRole, &p.Hash, &status,
		&createdAtUnix, &expiresAtUnix, &p.RequiredApprovals, &approversJSON, &p.RiskScore, &taintedArgsJSON, &p.RunID); err != nil {
		return nil, err
	}
	p.ID = pgFormatID("appr", id)
	p.Status = ApprovalStatus(status)
	p.CreatedAt = time.Unix(createdAtUnix, 0)
	p.ExpiresAt = time.Unix(expiresAtUnix, 0)
	_ = json.Unmarshal([]byte(argsJSON), &p.Args)
	_ = json.Unmarshal([]byte(approversJSON), &p.Approvers)
	_ = json.Unmarshal([]byte(taintedArgsJSON), &p.TaintedArgs)
	return &p, nil
}

const approvalSelectCols = `id, tool, args, resource, requested_by, reviewer_role, hash, status, created_at, expires_at, required_approvals, approvers, risk_score, tainted_args, run_id`

func (s *Store) getApprovalPG(id string) (*PendingApproval, bool) {
	n, err := pgParseID("appr", id)
	if err != nil {
		return nil, false
	}
	row := s.pg.QueryRow(`SELECT `+approvalSelectCols+` FROM approvals WHERE id = $1`, n)
	p, err := scanApprovalRow(row)
	if err != nil {
		if err != sql.ErrNoRows {
			log.Printf("[approval] postgres: get approval %q: %v", id, err)
		}
		return nil, false
	}
	return p, true
}

func (s *Store) listPendingApprovalsPG() []*PendingApproval {
	rows, err := s.pg.Query(`SELECT ` + approvalSelectCols + ` FROM approvals`)
	if err != nil {
		log.Printf("[approval] postgres: list approvals: %v", err)
		return nil
	}
	defer rows.Close()
	var out []*PendingApproval
	for rows.Next() {
		p, err := scanApprovalRow(rows)
		if err != nil {
			log.Printf("[approval] postgres: scan approval: %v", err)
			continue
		}
		out = append(out, p)
	}
	return out
}

// approvePG locks the target row, applies the exact same invariant checks
// as the in-memory path (hash binding, reviewer role, self-approval
// rejection, duplicate-approver rejection), and only flips status to
// Approved once the locked row's approver count reaches
// required_approvals - all inside one transaction, so two approvers
// hitting two different instances at once genuinely serialize through
// Postgres's row lock instead of racing.
func (s *Store) approvePG(id, hash, approverUser, approverRole string) (*PendingApproval, error) {
	n, err := pgParseID("appr", id)
	if err != nil {
		return nil, err
	}
	tx, err := s.pg.Begin()
	if err != nil {
		return nil, fmt.Errorf("approval: postgres: begin approve: %w", err)
	}
	defer tx.Rollback()

	row := tx.QueryRow(`SELECT `+approvalSelectCols+` FROM approvals WHERE id = $1 FOR UPDATE`, n)
	p, err := scanApprovalRow(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("no such approval %q", id)
	}
	if err != nil {
		return nil, fmt.Errorf("approval: postgres: load approval %q: %w", id, err)
	}
	if p.Status != StatusPending {
		return nil, fmt.Errorf("approval %q is already %s", id, p.Status)
	}
	if time.Now().After(p.ExpiresAt) {
		if _, err := tx.Exec(`UPDATE approvals SET status = $1 WHERE id = $2`, string(StatusExpired), n); err != nil {
			return nil, fmt.Errorf("approval: postgres: expire approval %q: %w", id, err)
		}
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("approval: postgres: commit expire %q: %w", id, err)
		}
		return nil, fmt.Errorf("approval %q expired", id)
	}
	if hash != p.Hash {
		return nil, fmt.Errorf("approval %q: hash mismatch - the call has changed since this approval was requested, rejected", id)
	}
	if approverRole != p.ReviewerRole {
		return nil, fmt.Errorf("approval %q requires reviewer_role=%q, approver has role %q", id, p.ReviewerRole, approverRole)
	}
	if approverUser == p.RequestedBy {
		return nil, fmt.Errorf("approval %q: the requester cannot approve their own request", id)
	}
	for _, already := range p.Approvers {
		if already == approverUser {
			return nil, fmt.Errorf("approval %q: %s has already approved this request - a second, different approver is required", id, approverUser)
		}
	}

	p.Approvers = append(p.Approvers, approverUser)
	approversJSON, _ := json.Marshal(p.Approvers)
	if len(p.Approvers) >= p.RequiredApprovals {
		p.Status = StatusApproved
		_, err = tx.Exec(`UPDATE approvals SET approvers = $1, status = $2 WHERE id = $3`, string(approversJSON), string(StatusApproved), n)
	} else {
		_, err = tx.Exec(`UPDATE approvals SET approvers = $1 WHERE id = $2`, string(approversJSON), n)
	}
	if err != nil {
		return nil, fmt.Errorf("approval: postgres: record approver for %q: %w", id, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("approval: postgres: commit approve %q: %w", id, err)
	}
	return p, nil
}

func (s *Store) denyPG(id, approverUser, approverRole string) error {
	n, err := pgParseID("appr", id)
	if err != nil {
		return err
	}
	tx, err := s.pg.Begin()
	if err != nil {
		return fmt.Errorf("approval: postgres: begin deny: %w", err)
	}
	defer tx.Rollback()

	row := tx.QueryRow(`SELECT `+approvalSelectCols+` FROM approvals WHERE id = $1 FOR UPDATE`, n)
	p, err := scanApprovalRow(row)
	if err == sql.ErrNoRows {
		return fmt.Errorf("no such approval %q", id)
	}
	if err != nil {
		return fmt.Errorf("approval: postgres: load approval %q: %w", id, err)
	}
	if approverRole != p.ReviewerRole {
		return fmt.Errorf("approval %q requires reviewer_role=%q, approver has role %q", id, p.ReviewerRole, approverRole)
	}
	if approverUser == p.RequestedBy {
		return fmt.Errorf("approval %q: the requester cannot deny their own request", id)
	}
	if _, err := tx.Exec(`UPDATE approvals SET status = $1 WHERE id = $2`, string(StatusDenied), n); err != nil {
		return fmt.Errorf("approval: postgres: deny %q: %w", id, err)
	}
	return tx.Commit()
}

// --- envelope listing --------------------------------------------------

func (s *Store) listEnvelopesPG() []*Envelope {
	rows, err := s.pg.Query(`SELECT id, tool, arg_constraints, max_uses, uses_remaining, expires_at FROM envelopes`)
	if err != nil {
		log.Printf("[approval] postgres: list envelopes: %v", err)
		return nil
	}
	defer rows.Close()
	var out []*Envelope
	for rows.Next() {
		var id int64
		var e Envelope
		var constraintsJSON string
		var expiresAtUnix int64
		if err := rows.Scan(&id, &e.Tool, &constraintsJSON, &e.MaxUses, &e.UsesRemaining, &expiresAtUnix); err != nil {
			log.Printf("[approval] postgres: scan envelope: %v", err)
			continue
		}
		e.ID = pgFormatID("env", id)
		e.ExpiresAt = time.Unix(expiresAtUnix, 0)
		_ = json.Unmarshal([]byte(constraintsJSON), &e.ArgConstraints)
		out = append(out, &e)
	}
	return out
}
