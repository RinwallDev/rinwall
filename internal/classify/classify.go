// Package classify infers a tool's reversibility class from its name,
// description, and schema - the single biggest onboarding barrier this
// system had. Hand-classifying an entire tool catalog into A/B/C before
// you can run anything is real work nobody wants to do on day one, and it
// was the difference between "docker run and see something" and "read the
// docs for an hour first."
//
// Two honest limits, stated up front because they shape the whole design:
//
//  1. This is a HEURISTIC, not an authority. It reads names, descriptions,
//     and schemas - it cannot know that `archive_record` in your system
//     actually hard-deletes. Every result carries the signals that fired
//     and a confidence, and anything it calls Class C (or can't read
//     confidently) is flagged for human review rather than silently
//     trusted.
//
//  2. It fails CLOSED. An unrecognized verb doesn't become "probably safe
//     Class B" - it becomes "unknown, review this," because the expensive
//     mistake here is under-classifying something irreversible, not
//     over-classifying something harmless. A false Class C costs someone
//     an approval click; a false Class B costs them a sent email they
//     can't recall.
package classify

import (
	"strings"
	"unicode"

	"github.com/RinwallDev/rinwall/internal/registry"
)

// Signal is one heuristic that fired, kept in the result so a human
// reviewing a classification can see WHY rather than having to trust it.
type Signal struct {
	Rule   string `json:"rule"`
	Detail string `json:"detail"`
}

type Result struct {
	Tool       string                      `json:"tool"`
	Class      registry.ReversibilityClass `json:"class,omitempty"`
	Confidence float64                     `json:"confidence"`
	Rationale  string                      `json:"rationale"`
	Signals    []Signal                    `json:"signals,omitempty"`

	// NeedsReview is set whenever a human must look before this
	// classification is trusted in production: anything irreversible,
	// anything ambiguous, and anything unrecognized.
	NeedsReview bool `json:"needs_review"`

	// Unclassified means no rule matched with enough confidence to name a
	// class at all. Deliberately distinct from "Class C" - "I don't know"
	// and "I know this is dangerous" are different messages to a human.
	Unclassified bool `json:"unclassified,omitempty"`
}

// Input is what the classifier can actually see about a tool. MCP gives
// name/description/schema and no HTTP verb; a REST-style catalog gives a
// method too. Both paths feed the same engine, the method is just an
// extra signal when it happens to be there.
type Input struct {
	Name        string
	Description string
	Method      string   // optional: GET/POST/PATCH/DELETE, when known
	ArgNames    []string // optional: property names from the tool's schema
}

// Verb tables. Ordered by how much damage a wrong call does, and checked
// in that order - irreversible first, because when a name carries both a
// read verb and a destructive one ("get_and_delete_backups"), the
// destructive reading is the one that matters.
var (
	irreversibleVerbs = map[string]string{
		"delete": "deletes data", "destroy": "destroys data", "purge": "purges data",
		"drop": "drops data", "erase": "erases data", "wipe": "wipes data",
		"terminate": "terminates a resource", "shutdown": "shuts down a resource",
		"send": "sends an outbound message", "email": "sends email", "notify": "sends a notification",
		"sms": "sends an SMS", "call": "places a call", "dispatch": "dispatches an external action",
		"publish": "publishes externally", "post": "posts externally", "tweet": "posts externally",
		"broadcast": "broadcasts externally", "announce": "announces externally",
		"charge": "moves money", "pay": "moves money", "transfer": "moves money",
		"wire": "moves money", "withdraw": "moves money", "refund": "moves money",
		"purchase": "moves money", "buy": "moves money", "sell": "moves money",
		"submit": "submits to an external system", "file": "files with an external system",
		"deploy": "deploys", "release": "releases", "revoke": "revokes access",
		"escalate": "escalates externally", "execute": "executes an arbitrary action",
	}

	// Words in irreversibleVerbs that are at least as often nouns: a
	// "post" is a thing you read, an "email" a thing you look up, a
	// "refund" a thing you check eligibility for. When such a word appears
	// AFTER a recognized read or compensable verb (get_post, list_release_events,
	// check_refund_eligibility, add_knowledge_file) it is the object of that
	// verb, not a second action. The anywhere-rule below skips exactly these
	// in exactly that position; every other irreversible verb still matches
	// anywhere, so get_and_delete_backups and fetch_and_send_report keep the
	// destructive reading. A name with no recognized verb in front
	// (how_to_pay, claim_escrow_refund) still fails closed to Class C.
	alsoANoun = map[string]bool{
		"email": true, "sms": true, "call": true, "post": true, "charge": true,
		"pay": true, "transfer": true, "wire": true, "withdraw": true, "refund": true,
		"purchase": true, "buy": true, "sell": true, "file": true, "release": true,
		"deploy": true,
	}

	readOnlyVerbs = map[string]string{
		"get": "reads", "list": "reads", "read": "reads", "fetch": "reads",
		"search": "reads", "find": "reads", "query": "reads", "lookup": "reads",
		"describe": "reads", "show": "reads", "view": "reads", "count": "reads",
		"check": "reads", "inspect": "reads", "status": "reads", "download": "reads",
		"log": "append-only, retry-safe", "record": "append-only, retry-safe",
		"track": "append-only, retry-safe", "emit": "append-only, retry-safe",

		// The compute/transform family. Added after scanning 420 real
		// public MCP servers, where 41% of 4,735 tools came back
		// unclassifiable - the tables above had been built against
		// CRUD-shaped APIs and missed an entire category that turns out to
		// be one of the most common shapes an MCP tool takes. These take
		// input and return a derived answer; the operation is the reading.
		//
		// Every entry here had to pass one test: is it side-effect-free by
		// its own nature, not merely usually? That is why `generate`,
		// `run`, `invoke`, `build` and `request` are deliberately absent
		// despite being just as common in the corpus - each can plausibly
		// write something or execute something, and "usually safe" is not
		// the standard for a table whose entries mean "let this through
		// without a gate."
		"calculate": "computes a derived value", "compute": "computes a derived value",
		"compare": "computes a derived value", "convert": "computes a derived value",
		"format": "computes a derived value", "parse": "computes a derived value",
		"extract": "computes a derived value", "summarize": "computes a derived value",
		"translate": "computes a derived value", "render": "computes a derived value",
		"analyze": "computes a derived value", "analyse": "computes a derived value",
		"assess": "computes a derived value", "evaluate": "computes a derived value",
		"score": "computes a derived value", "estimate": "computes a derived value",
		"predict": "computes a derived value", "detect": "computes a derived value",
		"classify": "computes a derived value", "explain": "computes a derived value",
		"recommend": "computes a derived value", "suggest": "computes a derived value",
		"validate": "checks without changing anything", "verify": "checks without changing anything",
		"resolve": "reads", "browse": "reads", "stats": "reads", "info": "reads",
	}

	compensableVerbs = map[string]string{
		"update": "mutates state with a natural inverse", "set": "mutates state with a natural inverse",
		"change": "mutates state with a natural inverse", "modify": "mutates state with a natural inverse",
		"edit": "mutates state with a natural inverse", "patch": "mutates state with a natural inverse",
		"rename": "mutates state with a natural inverse", "move": "mutates state with a natural inverse",
		"assign": "mutates state with a natural inverse", "unassign": "mutates state with a natural inverse",
		"tag": "mutates state with a natural inverse", "label": "mutates state with a natural inverse",
		"enable": "mutates state with a natural inverse", "disable": "mutates state with a natural inverse",
		"activate": "mutates state with a natural inverse", "deactivate": "mutates state with a natural inverse",
		"upgrade": "mutates state with a natural inverse", "downgrade": "mutates state with a natural inverse",
		"add": "creates a record that can be removed", "create": "creates a record that can be removed",
		"insert": "creates a record that can be removed", "attach": "creates a link that can be detached",
		"grant": "grants access that can be revoked", "invite": "creates an invite that can be withdrawn",
		"archive": "reversible in most systems, but verify", "close": "reversible in most systems, but verify",
		"cancel": "reversible in most systems, but verify", "remove": "removal - verify whether soft or hard",
	}

	// Nouns that escalate whatever the verb suggested. `update_label` and
	// `update_payment_method` are not the same risk, and the verb alone
	// can't tell them apart.
	escalatingNouns = map[string]string{
		"payment": "touches payments", "invoice": "touches billing", "charge": "touches payments",
		"card": "touches payment instruments", "bank": "touches banking", "payout": "touches payouts",
		"subscription": "touches billing", "billing": "touches billing", "price": "touches pricing",
		"email": "touches outbound messaging", "message": "touches outbound messaging",
		"notification": "touches outbound messaging", "webhook": "triggers external systems",
		"production": "touches production", "prod": "touches production",
		"permission": "touches access control", "role": "touches access control",
		"credential": "touches credentials", "secret": "touches secrets", "key": "touches keys",
		"account": "touches account lifecycle",
	}
	// "user" deliberately does NOT appear above, though it did once. It is
	// the most common noun in any CRUD catalog, so escalating on it pushed
	// rename_user, set_user_name and update_user_tier - all genuinely
	// compensable - to Class C, which means nearly every mutation in a
	// typical catalog needs an approval click. That is the exact failure
	// the Class C tiering exists to avoid: reviewers trained to
	// rubber-stamp stop reading, and the gate stops meaning anything.
	//
	// Nothing dangerous escapes by removing it, because the specific nouns
	// still catch the specific risks: update_user_email escalates on
	// "email", update_user_role on "role", update_user_permissions on
	// "permission", and delete_user is Class C from the verb regardless.
	// update_user_role is thereby reported as "touches access control,"
	// not "touches user records." Over-flagging is nearly free in a
	// report and expensive as live enforcement (internal/discover).

	// Description phrases that override everything - if the author wrote
	// "cannot be undone", believe them over any verb heuristic.
	irreversiblePhrases = []string{
		"cannot be undone", "can not be undone", "cannot be reversed", "irreversible",
		"permanently", "permanent deletion", "this is destructive", "destructive operation",
		"no undo", "not recoverable", "unrecoverable", "immediately sends", "will send an email",
	}
)

// Classify runs the heuristics over one tool.
func Classify(in Input) Result {
	res := Result{Tool: in.Name}
	tokens := tokenize(in.Name)
	desc := strings.ToLower(in.Description)

	// 1. Explicit author warnings in the description beat every other
	// signal - nobody writes "cannot be undone" by accident.
	for _, phrase := range irreversiblePhrases {
		if strings.Contains(desc, phrase) {
			res.Signals = append(res.Signals, Signal{"description-phrase", "description says " + quote(phrase)})
			return finish(res, registry.ClassC, 0.95,
				"the tool's own description describes an irreversible action", true)
		}
	}

	// 2. Irreversible verbs, checked before anything else - see the table
	// comment for why order matters here. The one exception is a word that
	// doubles as a noun sitting after a recognized read or compensable
	// verb (see alsoANoun) - there it is the object, not the action.
	head := leadingVerb(tokens)
	_, headReads := readOnlyVerbs[head]
	_, headCompensates := compensableVerbs[head]
	for _, tok := range tokens {
		why, ok := irreversibleVerbs[tok]
		if !ok {
			continue
		}
		if (headReads || headCompensates) && alsoANoun[tok] {
			res.Signals = append(res.Signals, Signal{"noun-position", quote(tok) + " after the verb " + quote(head) + " is the object, not an action"})
			continue
		}
		res.Signals = append(res.Signals, Signal{"verb", quote(tok) + " " + why})
		conf := 0.85
		if noun, why2, found := matchNoun(tokens); found {
			res.Signals = append(res.Signals, Signal{"noun", quote(noun) + " " + why2})
			conf = 0.92
		}
		return finish(res, registry.ClassC, conf, "verb "+quote(tok)+" "+why, true)
	}

	// 3. DELETE as an HTTP method is as strong a signal as a destructive
	// verb, and often the only one a thinly-named tool gives us.
	if strings.EqualFold(in.Method, "DELETE") {
		res.Signals = append(res.Signals, Signal{"http-method", "DELETE"})
		return finish(res, registry.ClassC, 0.9, "HTTP DELETE", true)
	}

	// Everything past here matches POSITIONALLY - the leading token. Tool
	// names put the verb first by near-universal convention (get_user,
	// update_tier, send_email), and matching a verb table against any
	// token anywhere reads `update_customer_status` as a read because
	// "status" is in the read table. Destructive verbs above are the
	// deliberate exception: those match anywhere, because a name that
	// mentions deleting ANYTHING deserves the cautious reading.

	// 4. Leading read verb. High confidence, and the one case where a
	// confident answer genuinely needs no human review.
	if why, ok := readOnlyVerbs[head]; ok {
		res.Signals = append(res.Signals, Signal{"leading-verb", quote(head) + " " + why})
		// An escalating noun on a read verb is worth surfacing but
		// doesn't change the class - reading a payment is still a read.
		if noun, why2, found := matchNoun(tokens); found {
			res.Signals = append(res.Signals, Signal{"noun", quote(noun) + " " + why2 + " (sensitive to read, but still a read)"})
		}
		return finish(res, registry.ClassB, 0.9, "leading verb "+quote(head)+" "+why, false)
	}
	if strings.EqualFold(in.Method, "GET") || strings.EqualFold(in.Method, "HEAD") {
		res.Signals = append(res.Signals, Signal{"http-method", strings.ToUpper(in.Method)})
		return finish(res, registry.ClassB, 0.85, "HTTP "+strings.ToUpper(in.Method), false)
	}

	// 5. Leading mutating verb with a natural inverse. An escalating noun
	// pushes these to Class C - "update the payment method" is not a thing
	// to undo by writing the old value back and hoping.
	if why, ok := compensableVerbs[head]; ok {
		res.Signals = append(res.Signals, Signal{"leading-verb", quote(head) + " " + why})
		if noun, why2, found := matchNoun(tokens); found {
			res.Signals = append(res.Signals, Signal{"noun", quote(noun) + " " + why2})
			return finish(res, registry.ClassC, 0.7,
				"verb "+quote(head)+" would be compensable, but it "+why2, true)
		}
		// "remove"/"archive"/"close"/"cancel" are genuinely ambiguous -
		// soft-delete in one system, hard-delete in the next.
		if head == "remove" || head == "archive" || head == "close" || head == "cancel" {
			return finish(res, registry.ClassA, 0.55, "verb "+quote(head)+": "+why, true)
		}
		return finish(res, registry.ClassA, 0.8, "verb "+quote(head)+" "+why, false)
	}
	if m := strings.ToUpper(in.Method); m == "PATCH" || m == "PUT" || m == "POST" {
		res.Signals = append(res.Signals, Signal{"http-method", m})
		return finish(res, registry.ClassA, 0.6, "HTTP "+m+" mutates state", true)
	}

	// 6. The verb isn't leading (customer_tier_update, order.status.get).
	// Fall back to scanning the rest, mutation first: if a name carries
	// both readings, the mutating one is the safer assumption. Lower
	// confidence, always flagged - positional certainty is gone.
	var rest []string
	if len(tokens) > 1 {
		rest = tokens[1:]
	}
	for _, tok := range rest {
		if why, ok := compensableVerbs[tok]; ok {
			res.Signals = append(res.Signals, Signal{"trailing-verb", quote(tok) + " " + why})
			return finish(res, registry.ClassA, 0.5,
				"verb "+quote(tok)+" appears outside the leading position - "+why, true)
		}
	}
	for _, tok := range rest {
		if why, ok := readOnlyVerbs[tok]; ok {
			res.Signals = append(res.Signals, Signal{"trailing-verb", quote(tok) + " " + why})
			return finish(res, registry.ClassB, 0.5,
				"verb "+quote(tok)+" appears outside the leading position - "+why, true)
		}
	}

	// 7. Nothing matched. Fail closed: unknown, needs review - never a
	// silent "probably fine."
	res.Unclassified = true
	res.NeedsReview = true
	res.Confidence = 0
	res.Rationale = "no recognized verb, method, or description signal - classify this one by hand"
	return res
}

func finish(res Result, class registry.ReversibilityClass, conf float64, rationale string, review bool) Result {
	res.Class = class
	res.Confidence = conf
	res.Rationale = rationale
	res.NeedsReview = review
	return res
}

// leadingVerb picks the token to treat as the verb. Normally that is the
// first one - tool names put the verb first by near-universal convention.
//
// The exception is a namespace prefix. Scanning 420 real public MCP servers
// turned up a naming style the original rule couldn't read at all:
// `dataset_compare`, `checker_start`, `weather_get` - a namespace, then the
// verb. Strict leading-token matching saw "dataset" and gave up, which put
// a large share of a real corpus into "unclassifiable."
//
// So: if the first token is not a verb and the second one is, the second
// wins. The window stops at two deliberately. Widening it further would
// re-introduce exactly the bug positional matching was added to fix -
// `update_customer_status` reading as a safe read because "status" appears
// somewhere - and the further right a match is found, the more likely it is
// a noun that merely shares a word with a verb.
func leadingVerb(tokens []string) string {
	if len(tokens) == 0 {
		return ""
	}
	if isKnownVerb(tokens[0]) || len(tokens) == 1 {
		return tokens[0]
	}
	if isKnownVerb(tokens[1]) {
		return tokens[1]
	}
	return tokens[0]
}

func isKnownVerb(tok string) bool {
	if _, ok := readOnlyVerbs[tok]; ok {
		return true
	}
	if _, ok := compensableVerbs[tok]; ok {
		return true
	}
	_, ok := irreversibleVerbs[tok]
	return ok
}

func matchNoun(tokens []string) (noun, why string, found bool) {
	for _, tok := range tokens {
		if why, ok := escalatingNouns[tok]; ok {
			return tok, why, true
		}
		// Plurals are extremely common in tool names (update_permissions,
		// rotate_keys, list_invoices) and the table is written in the
		// singular. Missing them means an escalating noun silently fails to
		// escalate, which is a fail-OPEN gap - the one direction this
		// package must never fail in.
		if singular, ok := depluralize(tok); ok {
			if why, ok := escalatingNouns[singular]; ok {
				return singular, why, true
			}
		}
	}
	return "", "", false
}

// depluralize strips a trailing "s" for table lookup only. Deliberately
// crude: it is not trying to be a stemmer, just to catch the regular plural
// that names actually use. It skips words ending in "ss" ("address" must
// not become "addres") and anything too short to survive the trim.
func depluralize(word string) (string, bool) {
	if len(word) < 4 || !strings.HasSuffix(word, "s") || strings.HasSuffix(word, "ss") {
		return "", false
	}
	return strings.TrimSuffix(word, "s"), true
}

// tokenize splits a tool name into lowercase words across the three
// conventions tools actually use - snake_case, kebab-case, and camelCase -
// so matching is on whole words. Substring matching would read "undelete"
// as "delete" and "together" as "get", which is exactly the kind of
// silent misclassification this package can't afford.
func tokenize(name string) []string {
	var words []string
	var cur strings.Builder

	flush := func() {
		if cur.Len() > 0 {
			words = append(words, strings.ToLower(cur.String()))
			cur.Reset()
		}
	}
	runes := []rune(name)
	for i, r := range runes {
		switch {
		case r == '_' || r == '-' || r == '.' || r == '/' || r == ' ':
			flush()
		case unicode.IsUpper(r):
			// Two camelCase boundaries to handle, and acronyms are why:
			// a lower-to-upper transition starts a new word (sendAlert ->
			// send, alert), and so does the LAST capital of a run when a
			// lowercase follows it, which is where an acronym ends and the
			// next word begins (sendSMSAlert -> send, sms, alert - not
			// send, smsalert).
			startsAfterLower := i > 0 && !unicode.IsUpper(runes[i-1])
			endsAcronym := i > 0 && unicode.IsUpper(runes[i-1]) &&
				i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if startsAfterLower || endsAcronym {
				flush()
			}
			cur.WriteRune(r)
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return words
}

func quote(s string) string { return "\"" + s + "\"" }

// --- blast radius ----------------------------------------------------------

// Report is the aggregate view over a whole catalog - the thing that
// actually answers "how much damage can this agent do." The individual
// classifications matter less than these three numbers: how much of this
// catalog is irreversible, how much of it nobody has reviewed, and how
// much of it claims to be undoable without any way to actually undo it.
type Report struct {
	Source         string         `json:"source"`
	TotalTools     int            `json:"total_tools"`
	ByClass        map[string]int `json:"by_class"`
	Irreversible   []string       `json:"irreversible_tools,omitempty"`
	NeedsReview    []string       `json:"needs_review_tools,omitempty"`
	Unclassified   []string       `json:"unclassified_tools,omitempty"`
	UndoableInName []string       `json:"compensable_but_no_pre_image,omitempty"`
	Results        []Result       `json:"results"`
}

// Summarize turns per-tool results into the aggregate. compensableGaps
// names tools classified compensable (Class A) that have no way to
// capture a pre-image - they read as "undoable" in a catalog while being
// undoable by nobody, which is the most dangerous kind of wrong.
func Summarize(source string, results []Result, compensableGaps []string) Report {
	rep := Report{
		Source:         source,
		TotalTools:     len(results),
		ByClass:        map[string]int{},
		Results:        results,
		UndoableInName: compensableGaps,
	}
	for _, r := range results {
		switch {
		case r.Unclassified:
			rep.ByClass["unknown"]++
			rep.Unclassified = append(rep.Unclassified, r.Tool)
		default:
			rep.ByClass[string(r.Class)]++
		}
		if r.Class == registry.ClassC && !r.Unclassified {
			rep.Irreversible = append(rep.Irreversible, r.Tool)
		}
		if r.NeedsReview {
			rep.NeedsReview = append(rep.NeedsReview, r.Tool)
		}
	}
	return rep
}
