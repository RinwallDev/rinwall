package classify

import (
	"testing"

	"github.com/RinwallDev/rinwall/internal/registry"
)

func TestClassify_Table(t *testing.T) {
	cases := []struct {
		name      string
		in        Input
		wantClass registry.ReversibilityClass
		wantUnk   bool
		review    bool
	}{
		// Clear reads.
		{"get", Input{Name: "get_user"}, registry.ClassB, false, false},
		{"list", Input{Name: "list_customer_orders"}, registry.ClassB, false, false},
		{"search camel", Input{Name: "searchInvoices"}, registry.ClassB, false, false},
		{"http GET", Input{Name: "customer_lookup_v2", Method: "GET"}, registry.ClassB, false, false},
		{"append-only log", Input{Name: "log_event"}, registry.ClassB, false, false},

		// Clear irreversibles.
		{"delete", Input{Name: "delete_account"}, registry.ClassC, false, true},
		{"send", Input{Name: "send_refund_email"}, registry.ClassC, false, true},
		{"charge", Input{Name: "charge_card"}, registry.ClassC, false, true},
		{"publish", Input{Name: "publish_release"}, registry.ClassC, false, true},
		{"http DELETE", Input{Name: "customer_record", Method: "DELETE"}, registry.ClassC, false, true},

		// Compensable mutations.
		{"update", Input{Name: "update_customer_tier"}, registry.ClassA, false, false},
		{"rename", Input{Name: "rename_project"}, registry.ClassA, false, false},
		{"assign camel", Input{Name: "assignTicketOwner"}, registry.ClassA, false, false},

		// Escalating noun pushes an otherwise-compensable verb to C.
		{"update payment", Input{Name: "update_payment_method"}, registry.ClassC, false, true},
		{"set price", Input{Name: "set_price"}, registry.ClassC, false, true},

		// Ambiguous soft/hard verbs stay Class A but demand review.
		{"archive", Input{Name: "archive_thread"}, registry.ClassA, false, true},
		{"remove", Input{Name: "remove_label"}, registry.ClassA, false, true},

		// Unrecognized - must fail closed, never a silent Class B.
		{"opaque", Input{Name: "frobnicate_widget"}, "", true, true},
		{"empty", Input{Name: ""}, "", true, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.in)
			if tc.wantUnk {
				if !got.Unclassified {
					t.Fatalf("expected unclassified, got class %q (%s)", got.Class, got.Rationale)
				}
				if !got.NeedsReview {
					t.Fatal("an unclassified tool must always be flagged for review")
				}
				return
			}
			if got.Unclassified {
				t.Fatalf("expected class %q, got unclassified", tc.wantClass)
			}
			if got.Class != tc.wantClass {
				t.Fatalf("expected class %q, got %q (%s)", tc.wantClass, got.Class, got.Rationale)
			}
			if got.NeedsReview != tc.review {
				t.Fatalf("expected NeedsReview=%v, got %v (%s)", tc.review, got.NeedsReview, got.Rationale)
			}
			if len(got.Signals) == 0 {
				t.Fatal("every classification must carry the signals that produced it")
			}
		})
	}
}

// Regression: a live scan classified `update_customer_status` as
// read-only, because "status" sits in the read-verb table and verbs were
// being matched anywhere in the name rather than positionally. A mutation
// silently reading as a safe read is exactly the failure mode this
// package is supposed to make impossible.
func TestClassify_NounInVerbTableDoesNotHijackLeadingVerb(t *testing.T) {
	for _, name := range []string{
		"update_customer_status", // "status" is a read verb, but trails
		"set_check_interval",     // "check" is a read verb, but trails
		"create_log_entry",       // "log" is a read verb, but trails
	} {
		got := Classify(Input{Name: name})
		if got.Class == registry.ClassB {
			t.Fatalf("%s: a leading mutation verb must win over a trailing read noun, got class B (%s)",
				name, got.Rationale)
		}
	}
}

func TestClassify_TrailingVerbFallback(t *testing.T) {
	// Verb-last naming still resolves, at lower confidence and always
	// flagged, rather than falling through to "unclassifiable."
	got := Classify(Input{Name: "customer_tier_update"})
	if got.Class != registry.ClassA || got.Unclassified {
		t.Fatalf("expected trailing-verb fallback to reach class A, got %q unclassified=%v", got.Class, got.Unclassified)
	}
	if !got.NeedsReview {
		t.Fatal("a non-positional verb match must be flagged for review")
	}
	if got.Confidence >= 0.8 {
		t.Fatalf("expected reduced confidence for a trailing-verb match, got %.2f", got.Confidence)
	}
}

func TestClassify_DescriptionOverridesVerb(t *testing.T) {
	// "update" would normally be Class A - the author's own warning has to
	// win, because they know their system and the heuristic doesn't.
	got := Classify(Input{
		Name:        "update_retention_policy",
		Description: "Updates the retention window. Purged data cannot be undone.",
	})
	if got.Class != registry.ClassC {
		t.Fatalf("expected the description warning to force Class C, got %q", got.Class)
	}
	if !got.NeedsReview {
		t.Fatal("expected review flag")
	}
}

func TestClassify_DestructiveVerbBeatsReadVerb(t *testing.T) {
	// A name carrying both readings must resolve to the dangerous one.
	got := Classify(Input{Name: "get_and_delete_backups"})
	if got.Class != registry.ClassC {
		t.Fatalf("expected the destructive reading to win, got %q (%s)", got.Class, got.Rationale)
	}
}

func TestTokenize_WordBoundaries(t *testing.T) {
	// The failure this guards against: substring matching reading
	// "undelete" as "delete" and "together" as "get".
	if got := Classify(Input{Name: "undelete_record"}); got.Class == registry.ClassC {
		t.Fatal("\"undelete\" must not match the \"delete\" verb")
	}
	if got := Classify(Input{Name: "together_report"}); got.Class == registry.ClassB {
		t.Fatal("\"together\" must not match the \"get\" verb")
	}

	words := tokenize("sendSMSAlert_to-user.now")
	want := []string{"send", "sms", "alert", "to", "user", "now"}
	if len(words) != len(want) {
		t.Fatalf("expected %v, got %v", want, words)
	}
	for i := range want {
		if words[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, words)
		}
	}
}

func TestSummarize_CountsAndBuckets(t *testing.T) {
	results := []Result{
		Classify(Input{Name: "get_user"}),
		Classify(Input{Name: "update_customer_tier"}),
		Classify(Input{Name: "delete_account"}),
		Classify(Input{Name: "send_refund_email"}),
		Classify(Input{Name: "frobnicate_widget"}),
	}
	rep := Summarize("test", results, []string{"update_customer_tier"})

	if rep.TotalTools != 5 {
		t.Fatalf("expected 5 tools, got %d", rep.TotalTools)
	}
	if rep.ByClass["C"] != 2 {
		t.Fatalf("expected 2 irreversible, got %d", rep.ByClass["C"])
	}
	if rep.ByClass["unknown"] != 1 {
		t.Fatalf("expected 1 unknown, got %d", rep.ByClass["unknown"])
	}
	if len(rep.Irreversible) != 2 {
		t.Fatalf("expected 2 named irreversible tools, got %v", rep.Irreversible)
	}
	if len(rep.UndoableInName) != 1 {
		t.Fatalf("expected the compensable-but-no-pre-image gap carried through, got %v", rep.UndoableInName)
	}
}

// "user" used to sit in escalatingNouns, which pushed every ordinary CRUD
// mutation on a user record to Class C - and Class C means an approval
// click. Over-gating like that is not a safe default: it is exactly what
// trains reviewers to rubber-stamp, at which point the gate stops meaning
// anything. Found when the classifier's output started driving live
// enforcement (internal/discover) rather than only a report.
func TestClassify_OrdinaryUserMutationsAreCompensableNotGated(t *testing.T) {
	for _, name := range []string{"update_user_tier", "rename_user", "set_user_name"} {
		got := Classify(Input{Name: name})
		if got.Class != registry.ClassA {
			t.Fatalf("%s: an ordinary user-record mutation should be compensable, got %s (%s)",
				name, got.Class, got.Rationale)
		}
	}
}

// The other half of that change: nothing dangerous may escape as a result.
// Each of these is still Class C, and each for its own specific reason
// rather than a blanket noun.
func TestClassify_SensitiveUserMutationsStillGated(t *testing.T) {
	for _, name := range []string{
		"update_user_email",       // outbound messaging
		"update_user_role",        // access control
		"update_user_permissions", // access control, via the plural
		"delete_user",             // destructive verb, noun irrelevant
		"close_account",           // account lifecycle
	} {
		if got := Classify(Input{Name: name}); got.Class != registry.ClassC {
			t.Fatalf("%s must stay class C, got %s (%s)", name, got.Class, got.Rationale)
		}
	}
}

// Regression for a fail-OPEN gap: escalatingNouns is written in the
// singular, but tool names are routinely plural, so an escalating noun
// silently failed to escalate. Masked until "user" was removed.
func TestClassify_PluralEscalatingNounsStillEscalate(t *testing.T) {
	for _, name := range []string{"update_permissions", "update_keys", "update_prices"} {
		if got := Classify(Input{Name: name}); got.Class != registry.ClassC {
			t.Fatalf("%s: a plural escalating noun must still escalate, got %s (%s)",
				name, got.Class, got.Rationale)
		}
	}
	// The depluralizer is crude on purpose - it is a table-lookup helper,
	// not a stemmer, so producing a non-word like "statu" is harmless
	// because nothing matches it. What it must NOT do is maul a word that
	// merely ends in a double s, since "addres" could collide with a real
	// entry someday.
	if _, ok := depluralize("address"); ok {
		t.Fatal(`"address" must not be depluralized to "addres"`)
	}
	if _, ok := depluralize("id"); ok {
		t.Fatal("a word too short to survive the trim must be left alone")
	}
	// And a bogus stem must never escalate anything on its own.
	if got := Classify(Input{Name: "update_status"}); got.Class != registry.ClassA {
		t.Fatalf(`"status" must not escalate via a bogus "statu" stem, got %s (%s)`, got.Class, got.Rationale)
	}
}

// Scanning 420 real public MCP servers found 41% of 4,735 tools coming back
// unclassifiable. Two causes, both fixed, both pinned here.
//
// Cause one: an entire missing verb family. The tables had been built
// against CRUD-shaped APIs and had nothing for compute/transform tools,
// which turn out to be one of the most common shapes a real MCP tool takes.
func TestClassify_ComputeVerbsAreReadOnly(t *testing.T) {
	for _, name := range []string{
		"calculate_shipping", "compare_prices", "convert_currency",
		"summarize_document", "analyze_sentiment", "validate_address",
		"render_chart", "estimate_delivery", "translate_text",
	} {
		got := Classify(Input{Name: name})
		if got.Unclassified {
			t.Fatalf("%s: a compute/transform tool should classify, not fall through", name)
		}
		if got.Class != registry.ClassB {
			t.Fatalf("%s: expected class B, got %s (%s)", name, got.Class, got.Rationale)
		}
	}
}

// The other half of that change, and the more important half: verbs that
// are only USUALLY safe stay out of the read table. "Usually safe" is not
// the standard for an entry meaning "let this through with no gate," so
// these must still fail closed to review rather than be waved through.
func TestClassify_AmbiguousComputeVerbsStillFailClosed(t *testing.T) {
	for _, name := range []string{"generate_report", "run_job", "invoke_handler", "build_index"} {
		got := Classify(Input{Name: name})
		if got.Class == registry.ClassB && !got.NeedsReview {
			t.Fatalf("%s: a verb that can write or execute must not be waved through as read-only (%s)",
				name, got.Rationale)
		}
	}
}

// Cause two: a namespace prefix put the verb in second position, which
// strict leading-token matching could not read at all.
func TestClassify_NamespacePrefixedVerbIsFound(t *testing.T) {
	cases := map[string]registry.ReversibilityClass{
		"dataset_compare": registry.ClassB,
		"weather_get":     registry.ClassB,
		"account_delete":  registry.ClassC,
		"payment_update":  registry.ClassC, // verb compensable, noun escalates
		"project_rename":  registry.ClassA,
	}
	for name, want := range cases {
		got := Classify(Input{Name: name})
		if got.Class != want {
			t.Fatalf("%s: expected %s, got %s (%s)", name, want, got.Class, got.Rationale)
		}
	}
}

// The window stops at two tokens on purpose. Widening it would re-introduce
// the exact bug positional matching was added to fix: a trailing noun that
// happens to share a word with a verb hijacking the reading.
func TestClassify_VerbWindowDoesNotReachThirdToken(t *testing.T) {
	// "status" is a read verb, but it sits third - a mutation must not be
	// read as a safe read just because a read word appears later.
	if got := Classify(Input{Name: "update_customer_status"}); got.Class == registry.ClassB {
		t.Fatalf("a third-position read word must not hijack the verb (%s)", got.Rationale)
	}
	// Same shape, one position further out.
	if got := Classify(Input{Name: "set_account_check_interval"}); got.Class == registry.ClassB {
		t.Fatalf("a deep read word must not hijack the verb (%s)", got.Rationale)
	}
}

func TestClassify_NounAfterVerbIsTheObjectNotAnAction(t *testing.T) {
	// Found by hand-validating the October 2026 public scan: 9 of 20
	// sampled Class C calls were over-classified, six of them because a
	// word that is also a noun ("post", "email", "refund", "release",
	// "pay", "file") matched the irreversible table anywhere in the name
	// even though the leading verb plainly read or edited something.
	// get_post reads a post; it does not post.
	reads := []string{
		"get_post", "read_post", "get_sender_email", "list_release_events",
		"check_prime_refund_eligibility", "get_entity_file", "calculate_vacation_pay",
		"megaventory_list_purchase_orders", "list_on_call", "check_deploy_prerequisites",
	}
	for _, name := range reads {
		if got := Classify(Input{Name: name}); got.Class != registry.ClassB {
			t.Errorf("%s: want B (the trailing word is the object of a read), got %q (%s)", name, got.Class, got.Rationale)
		}
	}
	compensable := []string{"add_knowledge_file", "create_social_post_draft", "update_release_notes"}
	for _, name := range compensable {
		if got := Classify(Input{Name: name}); got.Class != registry.ClassA {
			t.Errorf("%s: want A, got %q (%s)", name, got.Class, got.Rationale)
		}
	}

	// The exception is narrow. Genuinely destructive or outbound verbs
	// still match anywhere, the same words in the verb position are still
	// actions, an escalating noun still escalates a compensable verb, and
	// a name with no recognized verb in front still fails closed.
	stillC := []string{
		"get_and_delete_backups", "fetch_and_send_report", "update_and_send_invoice",
		"send_email", "email_customer", "post_reply", "pay_invoice", "release_funds",
		"update_sender_email", "update_payment_method",
		"how_to_pay", "claim_escrow_refund", "gripforge_server_deploy",
	}
	for _, name := range stillC {
		if got := Classify(Input{Name: name}); got.Class != registry.ClassC {
			t.Errorf("%s: want C, got %q (%s)", name, got.Class, got.Rationale)
		}
	}
}
