package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyChainFile_CleanLogVerifiesOK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Write(map[string]any{"decision": "ALLOW", "tool": "get_user", "delegated_role": "support", "reason": "ok"})
	l.Write(map[string]any{"decision": "DENY", "tool": "close_account", "delegated_role": "support", "reason": "policy"})
	l.Write(map[string]any{"decision": "ALLOW", "tool": "update_customer_tier", "delegated_role": "SalesManager", "reason": "ok", "risk_score": 0.55})
	l.Close()

	result, err := VerifyChainFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK {
		t.Fatalf("expected a clean, untouched log to verify OK, got: %+v", result)
	}
	if result.EntriesChecked != 3 {
		t.Fatalf("expected 3 entries checked, got %d", result.EntriesChecked)
	}
}

func TestVerifyChainFile_DetectsEditedEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Write(map[string]any{"decision": "ALLOW", "tool": "get_user", "delegated_role": "support", "reason": "ok"})
	l.Write(map[string]any{"decision": "DENY", "tool": "close_account", "delegated_role": "support", "reason": "policy: role mismatch"})
	l.Write(map[string]any{"decision": "ALLOW", "tool": "update_customer_tier", "delegated_role": "SalesManager", "reason": "ok"})
	l.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Tamper with the middle entry: change what actually happened (a DENY
	// quietly rewritten to look like it was never denied) without
	// re-signing anything - exactly the attack this feature exists to catch.
	tampered := strings.Replace(string(raw), `"decision":"DENY"`, `"decision":"ALLOW"`, 1)
	if tampered == string(raw) {
		t.Fatal("test setup: expected to find and replace the DENY entry")
	}
	if err := os.WriteFile(path, []byte(tampered), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := VerifyChainFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if result.OK {
		t.Fatal("expected a tampered entry to be detected, got OK")
	}
	if result.BrokenAtLine != 2 {
		t.Fatalf("expected tampering detected at line 2 (the edited entry), got line %d: %s", result.BrokenAtLine, result.Reason)
	}
}

func TestVerifyChainFile_DetectsDeletedEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Write(map[string]any{"decision": "ALLOW", "tool": "get_user", "delegated_role": "support", "reason": "ok"})
	l.Write(map[string]any{"decision": "DENY", "tool": "close_account", "delegated_role": "support", "reason": "policy"})
	l.Write(map[string]any{"decision": "ALLOW", "tool": "update_customer_tier", "delegated_role": "SalesManager", "reason": "ok"})
	l.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("test setup: expected 3 lines, got %d", len(lines))
	}
	// Remove the middle entry entirely - a deletion, not an edit. The
	// third entry's prev_chain_hash still names the (now-missing) second
	// entry's hash, so this must be caught at the third entry.
	withoutMiddle := lines[0] + "\n" + lines[2] + "\n"
	if err := os.WriteFile(path, []byte(withoutMiddle), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := VerifyChainFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if result.OK {
		t.Fatal("expected a deleted entry to break the chain, got OK")
	}
	if result.BrokenAtLine != 2 {
		t.Fatalf("expected the break detected at line 2 (now the third original entry), got line %d: %s", result.BrokenAtLine, result.Reason)
	}
}

func TestOpen_ResumesChainAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	l1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l1.Write(map[string]any{"decision": "ALLOW", "tool": "get_user", "delegated_role": "support", "reason": "ok"})
	l1.Close()

	// A second Logger over the same file, simulating a proxy restart -
	// must continue the SAME chain, not start a disconnected one.
	l2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l2.Write(map[string]any{"decision": "DENY", "tool": "close_account", "delegated_role": "support", "reason": "policy"})
	l2.Close()

	result, err := VerifyChainFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK {
		t.Fatalf("expected the chain to remain valid across a restart, got: %+v", result)
	}
	if result.EntriesChecked != 2 {
		t.Fatalf("expected both pre- and post-restart entries chained together, got %d checked", result.EntriesChecked)
	}
}

func TestOpen_LegacyLogWithoutChainHashStartsFreshChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	// A pre-Phase-4 entry: no chain_hash/seq/prev_chain_hash fields at all -
	// exactly what every audit.log written before this feature looks like.
	legacy := `{"decision":"ALLOW","tool":"get_user","delegated_role":"support","reason":"ok","ts":"2026-01-01T00:00:00Z"}` + "\n"
	if err := os.WriteFile(path, []byte(legacy), 0644); err != nil {
		t.Fatal(err)
	}

	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Write(map[string]any{"decision": "DENY", "tool": "close_account", "delegated_role": "support", "reason": "policy"})
	l.Close()

	result, err := VerifyChainFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK {
		t.Fatalf("expected legacy entry + one fresh chained entry to verify OK, got: %+v", result)
	}
	if result.LegacyEntries != 1 {
		t.Fatalf("expected 1 legacy entry skipped, got %d", result.LegacyEntries)
	}
	if result.EntriesChecked != 1 {
		t.Fatalf("expected 1 chained entry checked, got %d", result.EntriesChecked)
	}
}

func TestVerifyChainFile_LargeNumericFieldDoesNotFalsePositive(t *testing.T) {
	// Regression guard for the exact bug class this feature must avoid: a
	// naive map[string]any round-trip through float64 can reformat a large
	// integer during verification, making an untouched entry look
	// tampered. json.Number decoding (see VerifyChainFile) is what
	// prevents this.
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Write(map[string]any{"decision": "ALLOW", "tool": "send_refund_email", "delegated_role": "support-lead",
		"reason": "ok", "amount_cents": int64(123456789012345)})
	l.Close()

	result, err := VerifyChainFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK {
		t.Fatalf("expected a large integer field to round-trip exactly and verify OK, got: %+v", result)
	}
}

// Regression for a real bug found live: docker-compose.yml's reference
// stack ran a genuine Class A capture end to end and cmd/auditverify
// reported TAMPERING DETECTED on an entry nobody had touched. Root cause -
// a different failure mode of the same underlying principle as the large-
// integer test above, but for nested OBJECTS rather than scalars: a
// caller (handler.go's pre-image capture) embeds an already-serialized
// upstream JSON response verbatim as json.RawMessage, so its bytes pass
// through with whatever key order the ORIGINAL sender used - a Go struct's
// declared field order, not alphabetical. json.Marshal alphabetizes every
// other field in the event map, but a json.RawMessage bypasses that
// entirely at write time. VerifyChainFile has no way to know the original
// wasn't already serialized - it decodes generically into a
// map[string]any and re-marshals, which DOES alphabetize that nested
// object. The two computations diverged on any entry whose raw payload
// wasn't already alphabetical, which is most real upstream JSON (Go
// structs marshal in field-declaration order, not alphabetical).
// normalizeRawMessage (Write's own canonicalization pass) is the fix.
func TestVerifyChainFile_NestedRawJSONWithNonAlphabeticalKeysDoesNotFalsePositive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// Field order deliberately NOT alphabetical - mirrors a real upstream
	// struct's declared field order (id, name, email, tier, status), the
	// exact shape that triggered this live.
	preImage := json.RawMessage(`{"id":"42","name":"Priya Shah","email":"priya@example.com","tier":"silver","status":"active"}`)
	l.Write(map[string]any{"decision": "SNAPSHOT", "tool": "update_customer_tier", "resource": "42",
		"reason": "pre-image captured for possible compensation", "pre_image": preImage})
	l.Close()

	result, err := VerifyChainFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK {
		t.Fatalf("expected a captured pre-image with non-alphabetical keys to verify OK, got: %+v", result)
	}
	if result.EntriesChecked != 1 {
		t.Fatalf("expected 1 entry checked, got %d", result.EntriesChecked)
	}
}

// The normalization itself must not weaken tamper detection - an actual
// edit inside a nested raw-JSON field (not just its key order) still has
// to be caught.
func TestVerifyChainFile_StillDetectsEditInsideNestedRawJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Write(map[string]any{"decision": "SNAPSHOT", "tool": "update_customer_tier", "resource": "42",
		"reason": "pre-image captured", "pre_image": json.RawMessage(`{"id":"42","tier":"silver"}`)})
	l.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Tamper the tier value inside the nested pre_image object specifically
	// - this must still be caught, not swallowed by the normalization that
	// now runs on this field.
	tampered := strings.Replace(string(raw), `"tier\":\"silver\"`, `"tier\":\"gold\"`, 1)
	if tampered == string(raw) {
		tampered = strings.Replace(string(raw), `tier":"silver"`, `tier":"gold"`, 1)
	}
	if tampered == string(raw) {
		t.Fatal("test setup: tamper substitution did not match anything in the written line")
	}
	if err := os.WriteFile(path, []byte(tampered), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := VerifyChainFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if result.OK {
		t.Fatal("expected a real edit inside the nested pre_image to still be detected")
	}
}

func TestReadRecent_NewestFirstAndRespectsLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Write(map[string]any{"decision": "ALLOW", "tool": "get_user", "reason": "first"})
	l.Write(map[string]any{"decision": "DENY", "tool": "close_account", "reason": "second"})
	l.Write(map[string]any{"decision": "EXECUTED", "tool": "log_event", "reason": "third"})
	l.Close()

	entries, err := ReadRecent(path, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries (limit respected), got %d", len(entries))
	}
	if entries[0]["reason"] != "third" || entries[1]["reason"] != "second" {
		t.Fatalf("expected newest-first order, got %v then %v", entries[0]["reason"], entries[1]["reason"])
	}
}

func TestReadRecent_MissingFileReturnsEmptyNotError(t *testing.T) {
	entries, err := ReadRecent(filepath.Join(t.TempDir(), "does-not-exist.log"), 10)
	if err != nil {
		t.Fatalf("expected a missing (fresh deployment, no calls yet) log to return no error, got: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no entries, got %d", len(entries))
	}
}

func TestReadRecent_SkipsMalformedLinesRatherThanFailing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Write(map[string]any{"decision": "ALLOW", "tool": "get_user", "reason": "good"})
	l.Close()

	// Append a genuinely malformed line by hand - a display read must
	// tolerate this, unlike VerifyChainFile which correctly treats it as
	// tampering.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("not valid json at all\n")
	f.Close()

	entries, err := ReadRecent(path, 10)
	if err != nil {
		t.Fatalf("expected a malformed line to be skipped, not fail the whole read: %v", err)
	}
	if len(entries) != 1 || entries[0]["reason"] != "good" {
		t.Fatalf("expected exactly the one well-formed entry, got %v", entries)
	}
}
