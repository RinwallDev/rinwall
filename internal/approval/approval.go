// Package approval implements the three-tier mechanism for Class C
// (irreversible) tools, replacing naive "approve or deny every call" HITL -
// which trains reviewers to rubber-stamp - with a tiered design where only
// the irreducible remainder ever reaches a live person. ARCHITECTURE.md
// has the reasoning; this file is the runtime implementation.
package approval

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// --- Tier 1: pre-authorized envelope --------------------------------------

// Constraint is a small, explicit matcher DSL - deliberately not a general
// expression language, so envelopes stay auditable at a glance.
type Constraint struct {
	Op    string // "eq" | "lte" | "gte" | "in"
	Value string
}

type Envelope struct {
	ID             string
	Tool           string
	ArgConstraints map[string]Constraint
	MaxUses        int
	UsesRemaining  int
	ExpiresAt      time.Time
}

func (e *Envelope) matches(args map[string]any) bool {
	if e.UsesRemaining <= 0 || time.Now().After(e.ExpiresAt) {
		return false
	}
	for field, c := range e.ArgConstraints {
		val, ok := args[field]
		if !ok || !c.satisfiedBy(val) {
			return false
		}
	}
	return true
}

func (c Constraint) satisfiedBy(val any) bool {
	switch c.Op {
	case "eq":
		return fmt.Sprintf("%v", val) == c.Value
	case "in":
		for _, want := range splitCSV(c.Value) {
			if fmt.Sprintf("%v", val) == want {
				return true
			}
		}
		return false
	case "lte", "gte":
		f, ok := toFloat(val)
		if !ok {
			return false
		}
		threshold, ok := toFloat(c.Value)
		if !ok {
			return false
		}
		if c.Op == "lte" {
			return f <= threshold
		}
		return f >= threshold
	default:
		return false
	}
}

// --- Tier 2: hold-and-cancel window ----------------------------------------

type Hold struct {
	ID            string
	Tool          string
	Args          map[string]any
	RequestedBy   string
	DelegatedRole string
	AgentID       string
	FireAt        time.Time
	Cancelled     bool
	Fired         bool
	// RunID lets cancellation optionally trigger compensation of earlier
	// steps in the same run - see CancelHold and the REST adapter's
	// /holds/{id}/cancel. Empty for an untracked call, same convention as
	// PendingApproval.RunID.
	RunID string
	// ReviewerRole gates who may cancel this hold - the same reviewer_role
	// the tool itself requires, checked in CancelHold the same way Deny
	// checks it for approvals.
	ReviewerRole string
	timer        *time.Timer
}

// --- Tier 3: bound, routed approval -----------------------------------------

type ApprovalStatus string

const (
	StatusPending  ApprovalStatus = "pending"
	StatusApproved ApprovalStatus = "approved"
	StatusDenied   ApprovalStatus = "denied"
	StatusExpired  ApprovalStatus = "expired"
)

type PendingApproval struct {
	ID           string
	Tool         string
	Args         map[string]any
	Resource     string
	RequestedBy  string
	ReviewerRole string
	Hash         string
	Status       ApprovalStatus
	CreatedAt    time.Time
	ExpiresAt    time.Time
	RunID        string // Phase 3: if set, a denial here can trigger internal/saga compensation for prior steps in this run

	// Four-eyes support (internal/risk decides RequiredApprovals; this
	// package only enforces "N distinct, non-requester approvers", it has
	// no opinion on risk scoring itself). Approvers accumulates as each
	// qualifying approval lands; Status only flips to StatusApproved once
	// len(Approvers) reaches RequiredApprovals.
	RequiredApprovals int
	Approvers         []string
	RiskScore         float64
	TaintedArgs       []string
}

// RequestHash cryptographically binds an approval to the EXACT call - tool,
// args, resource, and requester. If any of it changes between the ask and
// the click, the hash no longer matches and the stale approval is rejected.
func RequestHash(tool string, args map[string]any, resource, requestedBy string) (string, error) {
	canonicalArgs, err := json.Marshal(args) // Go marshals map keys sorted - deterministic
	if err != nil {
		return "", fmt.Errorf("approval: hash: %w", err)
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s", tool, canonicalArgs, resource, requestedBy)))
	return hex.EncodeToString(sum[:]), nil
}

// --- Store -------------------------------------------------------------------

type Store struct {
	mu        sync.Mutex
	envelopes map[string]*Envelope
	approvals map[string]*PendingApproval
	holds     map[string]*Hold
	nextID    int
	db        *sql.DB // nil for NewStore() (tests, no persistence); set by NewPersistentStore (SQLite, single-instance)
	pg        *sql.DB // set by NewPostgresStore (multi-instance/HA) - see postgres.go's package doc for why this is a different concurrency model, not just a different file format. When set, db/the in-memory maps below are unused; every method branches to its *PG counterpart instead.
}

func NewStore() *Store {
	return &Store{
		envelopes: make(map[string]*Envelope),
		approvals: make(map[string]*PendingApproval),
		holds:     make(map[string]*Hold),
	}
}

func (s *Store) newID(prefix string) string {
	s.nextID++
	return fmt.Sprintf("%s-%d", prefix, s.nextID)
}

func (s *Store) CreateEnvelope(tool string, constraints map[string]Constraint, maxUses int, ttl time.Duration) (*Envelope, error) {
	if s.pg != nil {
		return s.createEnvelopePG(tool, constraints, maxUses, ttl)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := &Envelope{
		ID:             s.newID("env"),
		Tool:           tool,
		ArgConstraints: constraints,
		MaxUses:        maxUses,
		UsesRemaining:  maxUses,
		ExpiresAt:      time.Now().Add(ttl),
	}
	s.envelopes[e.ID] = e
	s.persistEnvelope(e)
	return e, nil
}

// CheckPreAuth looks for a live envelope covering this exact call and, if
// found, atomically consumes one use. Tier 1 - most Class C traffic should
// resolve here, instantly, with no human paged. In Postgres mode, a
// transient DB error fails closed to "no match" rather than blocking the
// call - skipping a pre-authorized envelope on a hiccup only costs one
// extra human approval, never a bypassed check.
func (s *Store) CheckPreAuth(tool string, args map[string]any) (*Envelope, bool) {
	if s.pg != nil {
		return s.checkPreAuthPG(tool, args)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.envelopes {
		if e.Tool == tool && e.matches(args) {
			e.UsesRemaining--
			s.persistEnvelopeUses(e.ID, e.UsesRemaining)
			return e, true
		}
	}
	return nil, false
}

// EnqueueHold queues a Class C action with a natural dispatch delay instead
// of firing it immediately. onFire runs automatically when the window
// elapses unless CancelHold is called first - Tier 2. requestedBy/
// delegatedRole/agentID are stored purely for audit/resume attribution -
// they play no role in the fire decision. runID/reviewerRole are stored so
// CancelHold can enforce who may cancel and, if asked, trigger
// compensation of the run's earlier steps.
func (s *Store) EnqueueHold(tool string, args map[string]any, holdSeconds int, requestedBy, delegatedRole, agentID, runID, reviewerRole string, onFire func()) (*Hold, error) {
	if s.pg != nil {
		// onFire is deliberately unused in Postgres mode: there's no
		// guarantee the creating instance is still running when the
		// window elapses, so firing is the poll loop's job instead - see
		// PollAndFireDueHolds's doc comment in postgres.go.
		return s.enqueueHoldPG(tool, args, holdSeconds, requestedBy, delegatedRole, agentID, runID, reviewerRole)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	h := &Hold{
		ID:            s.newID("hold"),
		Tool:          tool,
		Args:          args,
		RequestedBy:   requestedBy,
		DelegatedRole: delegatedRole,
		AgentID:       agentID,
		RunID:         runID,
		ReviewerRole:  reviewerRole,
		FireAt:        time.Now().Add(time.Duration(holdSeconds) * time.Second),
	}
	h.timer = time.AfterFunc(time.Duration(holdSeconds)*time.Second, func() {
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
	s.holds[h.ID] = h
	s.persistHold(h)
	return h, nil
}

// CancelHold requires the canceller's role to match the hold's
// reviewer_role, the same check Deny applies to approvals - cancelling a
// queued Class C action is at least as sensitive as approving one.
// Deliberately does NOT block the original requester from cancelling their
// own hold, unlike self-approval: cancelling only ever prevents an action
// from happening, it never lets anyone push one through, so the
// conflict-of-interest self-approval guards against doesn't apply here.
// Returns the cancelled Hold so a caller can decide whether to also
// compensate the run it belongs to - see the REST adapter's
// /holds/{id}/cancel and its compensate_run option.
func (s *Store) CancelHold(id, cancellerRole string) (*Hold, error) {
	if s.pg != nil {
		return s.cancelHoldPG(id, cancellerRole)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.holds[id]
	if !ok {
		return nil, fmt.Errorf("no such hold %q", id)
	}
	if cancellerRole != h.ReviewerRole {
		return nil, fmt.Errorf("hold %q requires reviewer_role=%q, canceller has role %q", id, h.ReviewerRole, cancellerRole)
	}
	if h.Fired {
		return nil, fmt.Errorf("hold %q already fired - too late to cancel", id)
	}
	h.Cancelled = true
	h.timer.Stop()
	s.persistHoldCancelled(id)
	return h, nil
}

// CreateApproval opens a Tier 3 (or taint step-up) request, bound to the
// exact call by hash and routed to whichever reviewer role owns this class
// of decision. requiredApprovals/riskScore/taintedArgs come from
// internal/risk's scoring - this package just enforces whatever count it's
// told, it has no opinion on how that count was decided.
func (s *Store) CreateApproval(tool string, args map[string]any, resource, requestedBy, reviewerRole string, ttl time.Duration, requiredApprovals int, riskScore float64, taintedArgs []string, runID string) (*PendingApproval, error) {
	if s.pg != nil {
		return s.createApprovalPG(tool, args, resource, requestedBy, reviewerRole, ttl, requiredApprovals, riskScore, taintedArgs, runID)
	}
	if requiredApprovals < 1 {
		requiredApprovals = 1
	}
	hash, err := RequestHash(tool, args, resource, requestedBy)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p := &PendingApproval{
		ID:                s.newID("appr"),
		Tool:              tool,
		Args:              args,
		Resource:          resource,
		RequestedBy:       requestedBy,
		ReviewerRole:      reviewerRole,
		Hash:              hash,
		Status:            StatusPending,
		CreatedAt:         time.Now(),
		ExpiresAt:         time.Now().Add(ttl),
		RequiredApprovals: requiredApprovals,
		RiskScore:         riskScore,
		TaintedArgs:       taintedArgs,
		RunID:             runID,
	}
	s.approvals[p.ID] = p
	s.persistApproval(p)
	return p, nil
}

func (s *Store) Get(id string) (*PendingApproval, bool) {
	if s.pg != nil {
		return s.getApprovalPG(id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.approvals[id]
	return p, ok
}

// ListPendingApprovals, ListHolds, and ListEnvelopes back the reviewer UI
// (internal/adapter/rest's GET /approvals, /holds, /envelopes) - point
// lookups (Get, GetHold) aren't enough for a human to see what's actually
// waiting on them.
func (s *Store) ListPendingApprovals() []*PendingApproval {
	if s.pg != nil {
		return s.listPendingApprovalsPG()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*PendingApproval, 0, len(s.approvals))
	for _, p := range s.approvals {
		out = append(out, p)
	}
	return out
}

func (s *Store) ListHolds() []*Hold {
	if s.pg != nil {
		return s.listHoldsPG()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Hold, 0, len(s.holds))
	for _, h := range s.holds {
		out = append(out, h)
	}
	return out
}

func (s *Store) ListEnvelopes() []*Envelope {
	if s.pg != nil {
		return s.listEnvelopesPG()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Envelope, 0, len(s.envelopes))
	for _, e := range s.envelopes {
		out = append(out, e)
	}
	return out
}

// GetHold exposes a hold's tool/args/requester so a caller resuming it
// after a restart (cmd/rinwall) can build the right replay closure - the
// timer/onFire wiring itself stays inside the store via ScheduleResumedHold.
// Not used in Postgres mode, where PollAndFireDueHolds replaces both the
// fresh-fire and restart-resume paths with one mechanism - see postgres.go.
func (s *Store) GetHold(id string) (*Hold, bool) {
	if s.pg != nil {
		return s.getHoldPG(id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.holds[id]
	return h, ok
}

// Approve records one qualifying approval, only if: the supplied hash still
// matches (a payload that changed between the ask and the click is rejected
// automatically, not silently re-approved against new values), the
// approver's verified role matches the tool's configured ReviewerRole, the
// approver is not the original requester - closing the self-approval hole
// outright rather than relying on role mismatch alone - and the approver
// hasn't already approved this same request (the trivial way to defeat
// four-eyes is one person clicking twice). Status only flips to
// StatusApproved once len(Approvers) reaches RequiredApprovals - the
// caller must check p.Status before treating this as a green light to
// execute; a return with Status still Pending means more approvers needed.
func (s *Store) Approve(id, hash, approverUser, approverRole string) (*PendingApproval, error) {
	if s.pg != nil {
		return s.approvePG(id, hash, approverUser, approverRole)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.approvals[id]
	if !ok {
		return nil, fmt.Errorf("no such approval %q", id)
	}
	if p.Status != StatusPending {
		return nil, fmt.Errorf("approval %q is already %s", id, p.Status)
	}
	if time.Now().After(p.ExpiresAt) {
		p.Status = StatusExpired
		s.persistApprovalStatus(id, StatusExpired)
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
	if len(p.Approvers) >= p.RequiredApprovals {
		p.Status = StatusApproved
		s.persistApprovalStatus(id, StatusApproved)
	} else {
		s.persistApprovalApprovers(id, p.Approvers)
	}
	return p, nil
}

func (s *Store) Deny(id, approverUser, approverRole string) error {
	if s.pg != nil {
		return s.denyPG(id, approverUser, approverRole)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.approvals[id]
	if !ok {
		return fmt.Errorf("no such approval %q", id)
	}
	if approverRole != p.ReviewerRole {
		return fmt.Errorf("approval %q requires reviewer_role=%q, approver has role %q", id, p.ReviewerRole, approverRole)
	}
	if approverUser == p.RequestedBy {
		return fmt.Errorf("approval %q: the requester cannot deny their own request", id)
	}
	p.Status = StatusDenied
	s.persistApprovalStatus(id, StatusDenied)
	return nil
}

func splitCSV(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return out
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case string:
		var f float64
		_, err := fmt.Sscanf(n, "%f", &f)
		return f, err == nil
	default:
		return 0, false
	}
}
