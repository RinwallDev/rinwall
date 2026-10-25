// Package usage turns the audit log's real, per-call judge token usage
// into a cost report - both judges this project has: the text provenance
// judge (internal/provenance, PROVENANCE_JUDGE_USAGE entries) and the
// screenshot-reasoning one (internal/visualprovenance,
// VISUAL_PROVENANCE_JUDGE_USAGE entries).
//
// This is the first concrete slice of the metered-judge paid layer: real
// usage accounting from real API responses, not yet real billing. The
// point is to have a genuine, working answer to "here's how this would
// actually be billed" before any billing integration exists - the same
// "prove the mechanism standalone before wiring it into anything" pattern
// this project has used everywhere else (biscuit-go, the Anthropic SDK,
// Vault dynamic secrets all got a throwaway validation step before being
// built on top of).
//
// One pricing rate covers both judges, deliberately not two: Anthropic
// bills image content as regular input tokens (confirmed against the real
// API response when internal/visualprovenance was validated - a screenshot
// simply produces a larger input_tokens count, not a different billing
// field), so the per-token rate below is the whole story for either judge.
// What differs is the token VOLUME per call, which the real numbers below
// already capture without needing a second rate.
//
// Like internal/compliance, this is a single pass over the audit log - the
// append-only source of truth - not a running counter kept in memory, so a
// report generated at any point reflects real historical usage rather than
// only what happened to occur since the process last restarted.
package usage

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// haikuPricingPerMillionUSD is Anthropic's published Claude Haiku 4.5 rate
// as of September 2026 (input $1.00/output $5.00 per million tokens,
// confirmed against Anthropic's own pricing page and cross-checked against
// independent third-party trackers). This is exactly the kind of number
// that goes stale - it is a real, cited external fact, not a constant
// invented for this report, and it needs updating if Anthropic's pricing
// changes or if either judge is ever pointed at a different model.
const (
	haikuInputPerMillionUSD  = 1.00
	haikuOutputPerMillionUSD = 5.00
)

type ToolUsage struct {
	Invocations   int     `json:"invocations"`
	InputTokens   int64   `json:"input_tokens"`
	OutputTokens  int64   `json:"output_tokens"`
	EstimatedCost float64 `json:"estimated_cost_usd"`
}

type DayUsage struct {
	Invocations   int     `json:"invocations"`
	InputTokens   int64   `json:"input_tokens"`
	OutputTokens  int64   `json:"output_tokens"`
	EstimatedCost float64 `json:"estimated_cost_usd"`
}

// JudgeUsage is real invocation counts and real token totals from real API
// responses, for one judge - text or visual - with an estimated dollar
// cost computed from the named, cited rate above, never presented as more
// precise than "estimated."
type JudgeUsage struct {
	TotalInvocations int     `json:"total_invocations"`
	TotalErrors      int     `json:"total_errors"`
	InputTokens      int64   `json:"input_tokens"`
	OutputTokens     int64   `json:"output_tokens"`
	EstimatedCostUSD float64 `json:"estimated_cost_usd"`

	ByTool map[string]*ToolUsage `json:"by_tool"`
	ByDay  map[string]*DayUsage  `json:"by_day"`
}

// SortedDays returns ByDay's keys in chronological order, for a report
// that reads front-to-back rather than in random map order.
func (j JudgeUsage) SortedDays() []string {
	days := make([]string, 0, len(j.ByDay))
	for d := range j.ByDay {
		days = append(days, d)
	}
	sort.Strings(days)
	return days
}

type Report struct {
	PricingNote string     `json:"pricing_note"`
	Text        JudgeUsage `json:"text_judge"`
	Visual      JudgeUsage `json:"visual_judge"`
}

func newJudgeUsage() JudgeUsage {
	return JudgeUsage{ByTool: map[string]*ToolUsage{}, ByDay: map[string]*DayUsage{}}
}

func estimateCost(inputTokens, outputTokens int64) float64 {
	return float64(inputTokens)/1_000_000*haikuInputPerMillionUSD +
		float64(outputTokens)/1_000_000*haikuOutputPerMillionUSD
}

// Generate reads the audit log once and tallies both judges' usage/error
// entries (see internal/handler's assessProvenance and
// assessVisualProvenance for exactly what gets written). Malformed lines
// are skipped, not fatal - the audit log is append-only and long-running;
// one bad line (a truncated write mid-crash, say) shouldn't take the whole
// report down.
func Generate(auditLogPath string) (Report, error) {
	f, err := os.Open(auditLogPath)
	if err != nil {
		return Report{}, fmt.Errorf("usage: open %s: %w", auditLogPath, err)
	}
	defer f.Close()

	report := Report{
		Text:   newJudgeUsage(),
		Visual: newJudgeUsage(),
		PricingNote: fmt.Sprintf(
			"estimated at Claude Haiku 4.5 published rates ($%.2f/M input, $%.2f/M output tokens) - one rate covers both judges, since Anthropic bills image content as regular input tokens, not a separate rate - real invocation counts and token totals, estimated dollar cost",
			haikuInputPerMillionUSD, haikuOutputPerMillionUSD),
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var entry struct {
			Decision     string `json:"decision"`
			Tool         string `json:"tool"`
			Timestamp    string `json:"ts"`
			InputTokens  int64  `json:"input_tokens"`
			OutputTokens int64  `json:"output_tokens"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}

		switch entry.Decision {
		case "PROVENANCE_JUDGE_ERROR":
			report.Text.TotalErrors++
		case "VISUAL_PROVENANCE_JUDGE_ERROR":
			report.Visual.TotalErrors++
		case "PROVENANCE_JUDGE_USAGE":
			tally(&report.Text, entry.Tool, entry.Timestamp, entry.InputTokens, entry.OutputTokens)
		case "VISUAL_PROVENANCE_JUDGE_USAGE":
			tally(&report.Visual, entry.Tool, entry.Timestamp, entry.InputTokens, entry.OutputTokens)
		}
	}
	if err := scanner.Err(); err != nil {
		return Report{}, fmt.Errorf("usage: reading %s: %w", auditLogPath, err)
	}

	finalize(&report.Text)
	finalize(&report.Visual)
	return report, nil
}

func tally(j *JudgeUsage, tool, timestamp string, inputTokens, outputTokens int64) {
	j.TotalInvocations++
	j.InputTokens += inputTokens
	j.OutputTokens += outputTokens

	if j.ByTool[tool] == nil {
		j.ByTool[tool] = &ToolUsage{}
	}
	t := j.ByTool[tool]
	t.Invocations++
	t.InputTokens += inputTokens
	t.OutputTokens += outputTokens

	day := "unknown"
	if len(timestamp) >= 10 {
		day = timestamp[:10] // RFC3339Nano's date prefix, e.g. "2026-09-10"
	}
	if j.ByDay[day] == nil {
		j.ByDay[day] = &DayUsage{}
	}
	d := j.ByDay[day]
	d.Invocations++
	d.InputTokens += inputTokens
	d.OutputTokens += outputTokens
}

func finalize(j *JudgeUsage) {
	j.EstimatedCostUSD = estimateCost(j.InputTokens, j.OutputTokens)
	for _, t := range j.ByTool {
		t.EstimatedCost = estimateCost(t.InputTokens, t.OutputTokens)
	}
	for _, d := range j.ByDay {
		d.EstimatedCost = estimateCost(d.InputTokens, d.OutputTokens)
	}
}
