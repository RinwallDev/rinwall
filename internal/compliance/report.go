// Package compliance turns the raw material this proxy already collects -
// the tamper-evident audit log (internal/audit) and the reversibility
// registry (internal/registry) - into the thing a SOC2 auditor or a
// customer's compliance team actually wants: a structured summary over a
// time period, not a JSONL file they have to grep themselves.
//
// Deliberately scoped to what a single, principled pass over the audit
// log can answer honestly. The audit log is the append-only source of
// truth; the approval/saga stores are mutable current-state views that
// can diverge from historical truth as records expire or get pruned, so
// this reads the log, not those stores, to avoid a report whose numbers
// could disagree with themselves depending on when it's run. It does mean
// a few figures (four-eyes count, approval tier) are recovered by parsing
// the human-readable "reason" string handler.go already writes - a real
// simplification, not hidden: see parseTier/parseRequiredApprovers below.
// A cleaner structured field on future audit entries would remove the
// need for this; not worth a wider handler.go change just for reporting.
package compliance

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/RinwallDev/rinwall/internal/audit"
	"github.com/RinwallDev/rinwall/internal/registry"
)

type Report struct {
	GeneratedAt time.Time  `json:"generated_at"`
	PeriodFrom  *time.Time `json:"period_from,omitempty"`
	PeriodTo    *time.Time `json:"period_to,omitempty"`

	// AuditChain is the tamper-evidence check embedded directly in the
	// report - a report generated from a log whose chain doesn't verify
	// says so plainly, rather than presenting numbers from a log that
	// might have been altered.
	AuditChain audit.VerifyResult `json:"audit_chain"`

	TotalEvents          int            `json:"total_events"`
	ByDecision           map[string]int `json:"by_decision"`
	ByReversibilityClass map[string]int `json:"by_reversibility_class"` // completed (EXECUTED/ALLOW) calls only, classified via the live registry
	ByApprovalTier       map[string]int `json:"by_approval_tier"`       // tier1_envelope / tier2_hold / tier3_approval / step_up_taint

	FourEyesRequired int `json:"four_eyes_required"`

	SagaCompensationsSucceeded int `json:"saga_compensations_succeeded"`
	SagaCompensationsFailed    int `json:"saga_compensations_failed"`

	ProvenanceJudgeInvocations int `json:"provenance_judge_invocations"`
	ProvenanceJudgeErrors      int `json:"provenance_judge_errors"`

	KeyRotations int `json:"key_rotations"`
}

var requiredApproversRe = regexp.MustCompile(`requires (\d+) approver`)

// Generate walks auditLogPath once, classifying each entry against reg
// (for reversibility class) and the period bounds (either may be nil for
// "no lower/upper bound").
func Generate(auditLogPath string, reg *registry.Registry, from, to *time.Time) (Report, error) {
	chainResult, err := audit.VerifyChainFile(auditLogPath)
	if err != nil {
		return Report{}, fmt.Errorf("compliance: verify audit chain: %w", err)
	}

	raw, err := os.ReadFile(auditLogPath)
	if err != nil {
		return Report{}, fmt.Errorf("compliance: read %s: %w", auditLogPath, err)
	}
	lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))

	return tally(lines, chainResult, reg, from, to), nil
}

// GenerateFromPostgres is Generate's exact counterpart for a Postgres-
// backed audit log (see internal/audit's OpenPostgres) - same tally logic
// over rows read from the database instead of lines read from a file, for
// the same reason internal/audit's VerifyChainPostgres shares its
// recomputation algorithm with VerifyChainFile rather than duplicating it.
func GenerateFromPostgres(dsn string, reg *registry.Registry, from, to *time.Time) (Report, error) {
	chainResult, err := audit.VerifyChainPostgres(dsn)
	if err != nil {
		return Report{}, fmt.Errorf("compliance: verify audit chain: %w", err)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return Report{}, fmt.Errorf("compliance: open postgres: %w", err)
	}
	defer db.Close()

	rows, err := db.Query(`SELECT event FROM audit_log ORDER BY seq ASC`)
	if err != nil {
		return Report{}, fmt.Errorf("compliance: postgres: query entries: %w", err)
	}
	defer rows.Close()

	var lines [][]byte
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return Report{}, fmt.Errorf("compliance: postgres: scan entry: %w", err)
		}
		lines = append(lines, raw)
	}
	if err := rows.Err(); err != nil {
		return Report{}, fmt.Errorf("compliance: postgres: iterate entries: %w", err)
	}

	return tally(lines, chainResult, reg, from, to), nil
}

// tally is the one implementation of "turn a list of raw JSONL entry
// lines into a Report," shared by the file-backed and Postgres-backed
// paths above.
func tally(lines [][]byte, chainResult audit.VerifyResult, reg *registry.Registry, from, to *time.Time) Report {
	report := Report{
		GeneratedAt:          time.Now().UTC(),
		PeriodFrom:           from,
		PeriodTo:             to,
		AuditChain:           chainResult,
		ByDecision:           map[string]int{},
		ByReversibilityClass: map[string]int{},
		ByApprovalTier:       map[string]int{},
	}

	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal(line, &entry); err != nil {
			continue // a line that fails to parse is a chain-integrity concern, already surfaced via AuditChain above, not a reason to abort the whole report
		}

		if ts, ok := entry["ts"].(string); ok {
			t, err := time.Parse(time.RFC3339Nano, ts)
			if err == nil {
				if from != nil && t.Before(*from) {
					continue
				}
				if to != nil && t.After(*to) {
					continue
				}
			}
		}

		decision, _ := entry["decision"].(string)
		reason, _ := entry["reason"].(string)
		tool, _ := entry["tool"].(string)

		report.TotalEvents++
		if decision != "" {
			report.ByDecision[decision]++
		}

		switch decision {
		case "EXECUTED", "ALLOW":
			if t, ok := reg.Get(tool); ok {
				report.ByReversibilityClass[string(t.ReversibilityClass)]++
			} else {
				report.ByReversibilityClass["unknown"]++
			}
		case "COMPENSATED":
			report.SagaCompensationsSucceeded++
		case "COMPENSATION_FAILED":
			report.SagaCompensationsFailed++
		case "PROVENANCE_JUDGED":
			report.ProvenanceJudgeInvocations++
		case "PROVENANCE_JUDGE_ERROR":
			report.ProvenanceJudgeErrors++
		case "biscuit_key_rotated":
			report.KeyRotations++
		}

		if tier := parseTier(reason); tier != "" {
			report.ByApprovalTier[tier]++
		}
		if n := parseRequiredApprovers(reason); n >= 2 {
			report.FourEyesRequired++
		}
	}

	return report
}

func parseTier(reason string) string {
	switch {
	case strings.HasPrefix(reason, "step-up:"):
		return "step_up_taint"
	case strings.HasPrefix(reason, "tier1:"):
		return "tier1_envelope"
	case strings.HasPrefix(reason, "tier2:"):
		return "tier2_hold"
	case strings.HasPrefix(reason, "tier3:"):
		return "tier3_approval"
	default:
		return ""
	}
}

func parseRequiredApprovers(reason string) int {
	m := requiredApproversRe.FindStringSubmatch(reason)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}
