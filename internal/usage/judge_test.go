package usage

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func writeLog(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	var body string
	for _, l := range lines {
		body += l + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func usageLine(decision, tool, day string, in, out int64) string {
	return fmt.Sprintf(`{"decision":%q,"tool":%q,"ts":%q,"input_tokens":%d,"output_tokens":%d}`,
		decision, tool, day+"T12:00:00.000000000Z", in, out)
}

func TestGenerate_TalliesTextJudgeByToolAndDay(t *testing.T) {
	path := writeLog(t,
		usageLine("PROVENANCE_JUDGE_USAGE", "update_customer_tier", "2026-09-10", 500, 100),
		usageLine("PROVENANCE_JUDGE_USAGE", "update_customer_tier", "2026-09-10", 300, 80),
		usageLine("PROVENANCE_JUDGE_USAGE", "update_customer_status", "2026-09-11", 1000, 200),
		`{"decision":"EXECUTED","tool":"get_user"}`, // unrelated entry, must be ignored
	)

	report, err := Generate(path)
	if err != nil {
		t.Fatal(err)
	}
	if report.Text.TotalInvocations != 3 {
		t.Fatalf("expected 3 invocations, got %d", report.Text.TotalInvocations)
	}
	if report.Text.InputTokens != 1800 || report.Text.OutputTokens != 380 {
		t.Fatalf("expected real token totals 1800/380, got %d/%d", report.Text.InputTokens, report.Text.OutputTokens)
	}
	if report.Visual.TotalInvocations != 0 {
		t.Fatalf("text-only entries must not leak into the visual judge's tally, got %d", report.Visual.TotalInvocations)
	}

	tier := report.Text.ByTool["update_customer_tier"]
	if tier == nil || tier.Invocations != 2 || tier.InputTokens != 800 {
		t.Fatalf("unexpected per-tool tally for update_customer_tier: %+v", tier)
	}

	day := report.Text.ByDay["2026-09-10"]
	if day == nil || day.Invocations != 2 {
		t.Fatalf("unexpected per-day tally for 2026-09-10: %+v", day)
	}
	days := report.Text.SortedDays()
	if len(days) != 2 || days[0] != "2026-09-10" || days[1] != "2026-09-11" {
		t.Fatalf("expected sorted days, got %v", days)
	}
}

// The two judges have to stay separately attributable - "how much did text
// taint judging cost vs. the visual one" is a real, distinct operational
// question, not just a shared total.
func TestGenerate_TextAndVisualJudgesTallySeparately(t *testing.T) {
	path := writeLog(t,
		usageLine("PROVENANCE_JUDGE_USAGE", "update_customer_tier", "2026-09-10", 200, 50),
		usageLine("VISUAL_PROVENANCE_JUDGE_USAGE", "computer", "2026-09-10", 1571, 115),
	)
	report, err := Generate(path)
	if err != nil {
		t.Fatal(err)
	}
	if report.Text.TotalInvocations != 1 || report.Visual.TotalInvocations != 1 {
		t.Fatalf("expected 1 invocation each, got text=%d visual=%d", report.Text.TotalInvocations, report.Visual.TotalInvocations)
	}
	if report.Visual.InputTokens != 1571 {
		t.Fatalf("expected the visual judge's real (larger, image-inclusive) token count, got %d", report.Visual.InputTokens)
	}
	// Same rate for both - a screenshot just produces more real tokens,
	// which the cost formula already reflects without a second rate.
	wantVisualCost := estimateCost(1571, 115)
	if report.Visual.EstimatedCostUSD != wantVisualCost {
		t.Fatalf("expected the visual judge billed at the same per-token rate, got %.6f want %.6f", report.Visual.EstimatedCostUSD, wantVisualCost)
	}
}

// Cost has to be computed from the real accumulated tokens, at the named
// rate - not hardcoded per call, which would silently drift from the real
// total as soon as calls vary in size.
func TestGenerate_EstimatedCostMatchesRealRate(t *testing.T) {
	path := writeLog(t, usageLine("PROVENANCE_JUDGE_USAGE", "t", "2026-09-10", 1_000_000, 1_000_000))
	report, err := Generate(path)
	if err != nil {
		t.Fatal(err)
	}
	want := haikuInputPerMillionUSD + haikuOutputPerMillionUSD // exactly 1M of each
	if report.Text.EstimatedCostUSD != want {
		t.Fatalf("expected $%.2f for 1M in + 1M out tokens, got $%.4f", want, report.Text.EstimatedCostUSD)
	}
}

// A call that errored (no usable usage) still needs to be visible - "the
// judge ran N times and failed M of them" is a real operational fact - but
// must never be counted as billable usage it didn't actually incur.
func TestGenerate_ErrorsCountedSeparatelyFromUsage(t *testing.T) {
	path := writeLog(t,
		usageLine("PROVENANCE_JUDGE_USAGE", "t", "2026-09-10", 100, 20),
		`{"decision":"PROVENANCE_JUDGE_ERROR","tool":"t","reason":"judge call failed"}`,
	)
	report, err := Generate(path)
	if err != nil {
		t.Fatal(err)
	}
	if report.Text.TotalInvocations != 1 {
		t.Fatalf("expected 1 real invocation, got %d", report.Text.TotalInvocations)
	}
	if report.Text.TotalErrors != 1 {
		t.Fatalf("expected 1 error, got %d", report.Text.TotalErrors)
	}
}

func TestGenerate_VisualJudgeErrorsCountedSeparately(t *testing.T) {
	path := writeLog(t, `{"decision":"VISUAL_PROVENANCE_JUDGE_ERROR","tool":"computer","reason":"api error"}`)
	report, err := Generate(path)
	if err != nil {
		t.Fatal(err)
	}
	if report.Visual.TotalErrors != 1 || report.Visual.TotalInvocations != 0 {
		t.Fatalf("expected 1 visual error and 0 invocations, got errors=%d invocations=%d", report.Visual.TotalErrors, report.Visual.TotalInvocations)
	}
}

func TestGenerate_EmptyLogIsZeroNotError(t *testing.T) {
	path := writeLog(t)
	report, err := Generate(path)
	if err != nil {
		t.Fatal(err)
	}
	if report.Text.TotalInvocations != 0 || report.Text.EstimatedCostUSD != 0 {
		t.Fatalf("expected an all-zero text report for an empty log, got %+v", report.Text)
	}
	if report.Visual.TotalInvocations != 0 || report.Visual.EstimatedCostUSD != 0 {
		t.Fatalf("expected an all-zero visual report for an empty log, got %+v", report.Visual)
	}
}

// A malformed line (a truncated write, say) must not take the whole report
// down - the audit log is long-running and append-only.
func TestGenerate_SkipsMalformedLinesWithoutFailing(t *testing.T) {
	path := writeLog(t,
		usageLine("PROVENANCE_JUDGE_USAGE", "t", "2026-09-10", 100, 20),
		`{not valid json`,
		usageLine("PROVENANCE_JUDGE_USAGE", "t", "2026-09-10", 50, 10),
	)
	report, err := Generate(path)
	if err != nil {
		t.Fatal(err)
	}
	if report.Text.TotalInvocations != 2 {
		t.Fatalf("expected the 2 valid lines counted despite the malformed one, got %d", report.Text.TotalInvocations)
	}
}
