// Package provenance is the model-based add-on to the Intent Integrity
// Plane: instead of requiring an orchestrator to compute and self-report
// whether a tool-call argument came from the human, the proxy sees a
// bounded slice of the actual recent conversation itself and asks a real
// model to judge it directly. This turns a hard reasoning task we'd have
// to trust a third party to get right into a data-forwarding task (send us
// the recent conversation) plus a judgment call we make ourselves.
//
// This is deliberately a CONFIDENCE score, not a binary verdict - humans
// paraphrase ("upgrade her" -> tier="gold"), and naive matching would be
// full of false positives/negatives. Because it can never be perfectly
// precise, low confidence here only ever joins internal/risk's existing
// taint-forces-step-up machinery as an additional signal - it never grants
// access on its own, same constraint every soft signal in this system is
// held to.
package provenance

import "context"

type Message struct {
	Role    string // "user" | "assistant" | "tool"
	Content string
}

type ArgAssessment struct {
	Confidence float64 // 0.0 (clearly not from the human) .. 1.0 (clearly is)
	Rationale  string
}

// Usage is per-CALL, not per-argument - one real API request judges every
// argument in a call at once (see anthropic.go's single Messages.New call
// per Assess), so it's returned once per Assess rather than folded into
// each ArgAssessment, where summing it per-argument would double-count.
// Zero value for a judge that makes no real API call (FakeJudge) - that's
// the honest answer, not a placeholder: no real call means no real cost.
type Usage struct {
	InputTokens  int64
	OutputTokens int64
}

type Judge interface {
	Assess(ctx context.Context, contextWindow []Message, tool string, args map[string]any) (map[string]ArgAssessment, Usage, error)
}

// Bounding constants for "reasonable recent context" - enforced
// server-side regardless of what a caller sends, both to
// keep judge cost/latency bounded and because the relevant context for a
// single tool-call decision is realistically nearby in the conversation,
// not the entire session history.
const (
	maxContextMessages = 8
	maxContextChars    = 4000 * 4 // ~4000 tokens at a ~4-chars/token rough estimate
)

// boundContextWindow keeps only the most recent messages, then trims from
// the front if the remainder is still over the character budget - recency
// wins on both axes.
func boundContextWindow(msgs []Message) []Message {
	if len(msgs) > maxContextMessages {
		msgs = msgs[len(msgs)-maxContextMessages:]
	}
	total := 0
	for _, m := range msgs {
		total += len(m.Content)
	}
	start := 0
	for total > maxContextChars && start < len(msgs)-1 {
		total -= len(msgs[start].Content)
		start++
	}
	return msgs[start:]
}
