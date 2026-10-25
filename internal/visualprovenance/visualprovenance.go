// Package visualprovenance is the screenshot-reasoning analog of
// internal/provenance - and deliberately a SEPARATE package, not an
// extension of it, because the trigger condition, the cost profile, and
// the reasoning task are all different enough that conflating them would
// muddy both.
//
// The gap this closes: a pure screenshot-reasoning agent (computer-use
// style) is typically ONE generic tool ("computer", an `action` field:
// left_click/type/key/screenshot) rather than semantically-named ones. Two
// consequences follow, both real, both checked against this project's own
// code before this package was written:
//
//  1. internal/classify correctly fails such a tool closed to
//     "unclassifiable" - a coordinate pair carries no semantic signal for
//     a name-based heuristic to read. But this system classifies a tool
//     ONCE, at registration, not per call - so whatever class a human
//     picks for "computer" applies to every click it ever makes. Class C
//     makes every scroll need a human (unusable); Class B means nothing
//     is ever gated, including the one click that matters. Neither is
//     right, because the actual danger of a given call depends entirely
//     on what's on screen at that instant, not on the tool's name.
//  2. internal/handler's existing taint/step-up path only ever runs for
//     Class A/C tools (`tool.ReversibilityClass == ClassA ||
//     tool.ReversibilityClass == ClassC` - see handler.go). A
//     Class-B-registered "computer" tool would never reach it even if a
//     visual judge existed - confirmed by reading the actual gate before
//     writing anything here, not assumed.
//
// So this package's Judge is wired at a NEW call site in the handler,
// independent of ReversibilityClass entirely (see
// Handler.assessVisualProvenance) - the fix isn't "extend the existing
// judge," it's "give this tool shape a trigger path the class model
// doesn't gate at all."
//
// What's actually judged is also a different question than the text
// judge's. internal/provenance asks "does this argument's VALUE trace to
// the human's own words." A coordinate can't be judged that way - there's
// nothing in "click at (482, 310)" to compare against anything. What CAN
// be judged: does the screen content AT that target plausibly match what
// the agent says it's doing, or does it look like the action was
// manufactured by deceptive or injected on-screen content (a fake system
// dialog, a mislabeled button, hidden instructions) - structurally the
// same confused-deputy question the text judge asks, just multimodal, and
// requiring the agent's own stated reasoning as the thing to check the
// screenshot against. Validated against the real API before any of this
// interface existed: a legitimate order-submission screenshot scored
// confidence 0.95; a fake "System Notice" payment-approval dialog
// embedded in an email scored 0.05 with the model unprompted noticing the
// suspicious sender domain; a screenshot where the stated intent
// ("clicking Cancel") didn't match the actual button at the target
// coordinate ("Delete Account") scored 0.15 and named the mismatch
// directly.
package visualprovenance

import "context"

// Assessment is a confidence score, not a binary verdict, for the same
// reason internal/provenance's isn't: judging this can never be perfectly
// precise, so - consistent with every other soft signal in this system -
// a low score only ever ADDS friction (forces the same step-up path taint
// already uses), never grants access on its own.
type Assessment struct {
	Confidence float64 // 0.0 (looks manufactured by deceptive/injected content) .. 1.0 (legitimate)
	Rationale  string
}

// Usage is per-call, not per-argument - identical reasoning to
// internal/provenance.Usage. Zero value for a judge that makes no real API
// call (FakeJudge) - real numbers or no numbers, never an estimate
// standing in for one.
type Usage struct {
	InputTokens  int64
	OutputTokens int64
}

// Judge assesses one proposed action against one screenshot and the
// agent's own stated reasoning for taking it. action is a short
// human-readable description of what's about to happen (e.g. "left_click
// at coordinate (482, 310)") - not the raw tool arguments, since those
// (a bare coordinate) carry no meaning on their own; the point is to give
// the model enough to compare against what it sees in the image.
type Judge interface {
	Assess(ctx context.Context, screenshot []byte, statedIntent, action string) (Assessment, Usage, error)
}
