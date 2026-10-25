// Package audit is the append-only event log every decision lands in: a
// local JSONL file by default, or a Postgres table in multi-instance mode
// (postgres.go).
//
// Every entry carries a running SHA-256 hash chain (chain_hash,
// prev_chain_hash, seq), the same construction a git commit history uses:
// each entry's hash covers its own content plus the previous entry's hash,
// so altering, deleting, or reordering any past entry breaks the chain
// from that point forward in a way VerifyChainFile can pinpoint exactly.
// "How do we know this log wasn't edited after the fact" is a standard
// auditor question, and a local file editable by anyone with disk access
// doesn't answer it; the chain does.
package audit

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// genesisHash is what the very first chained entry names as its
// prev_chain_hash - there is no real prior entry to point to, so this is a
// fixed, publicly-known constant (not a secret) marking "the start of the
// chain," the same role a genesis block plays.
var genesisHash = strings.Repeat("0", 64)

// normalizeRawMessage decodes a json.RawMessage into a plain value using
// UseNumber (the same decoder mode VerifyChainFile uses) and recurses into
// any nested object/array, so a caller-embedded raw JSON blob ends up in
// the exact canonical shape - plain maps/slices/json.Number, no leftover
// original byte ordering - that a later generic decode-then-remarshal will
// also produce. See Write's own comment for why this has to happen once,
// at write time, rather than trusting the raw bytes to already agree with
// whatever VerifyChainFile does later.
//
// Anything that isn't a json.RawMessage (or doesn't contain one) passes
// through unchanged - only this one type needs normalizing, since every
// other value in an event map already goes through json.Marshal's own
// (already-alphabetized, already-deterministic) encoding on both the write
// and verify sides.
func normalizeRawMessage(v any) any {
	switch val := v.(type) {
	case json.RawMessage:
		var out any
		dec := json.NewDecoder(bytes.NewReader(val))
		dec.UseNumber()
		if err := dec.Decode(&out); err != nil {
			// Malformed embedded JSON - leave it as the raw bytes. Write's
			// own json.Marshal call will fail on it visibly (json.RawMessage
			// still has to be valid JSON to marshal at all), the same
			// failure mode as before this normalization existed.
			return val
		}
		return normalizeRawMessage(out)
	case map[string]any:
		for k, elem := range val {
			val[k] = normalizeRawMessage(elem)
		}
		return val
	case []any:
		for i, elem := range val {
			val[i] = normalizeRawMessage(elem)
		}
		return val
	default:
		return v
	}
}

type Logger struct {
	mu       sync.Mutex
	file     *os.File
	lastHash string
	seq      int64
	pg       *sql.DB // set by OpenPostgres (multi-instance/HA) - see postgres.go. When set, file/lastHash/seq are unused; Write/Close branch to the pg-backed path instead, which re-reads the chain head from Postgres on every write rather than trusting a locally cached lastHash/seq, since another instance may have written since this process last read it.
}

// Open resumes the hash chain from wherever a prior run left off, not just
// the file offset - it reads the existing log's last entry (if any) and
// recovers its chain_hash/seq so a restart continues the same chain rather
// than silently starting a new, disconnected one. A log written before
// this feature existed (no chain_hash on its last entry) is handled
// explicitly, not treated as corruption: its entries stay in the file for
// historical reference, and the chain simply starts fresh from genesis at
// the first entry written after this upgrade - coverage begins at the
// point the feature was deployed, which is the honest boundary for a
// tamper-evidence feature added retroactively to existing data.
func Open(path string) (*Logger, error) {
	lastHash := genesisHash
	var seq int64

	if existing, err := os.ReadFile(path); err == nil && len(existing) > 0 {
		lines := bytes.Split(bytes.TrimRight(existing, "\n"), []byte("\n"))
		if last := lines[len(lines)-1]; len(last) > 0 {
			dec := json.NewDecoder(bytes.NewReader(last))
			dec.UseNumber()
			var tail map[string]any
			if err := dec.Decode(&tail); err == nil {
				if ch, ok := tail["chain_hash"].(string); ok && ch != "" {
					lastHash = ch
					if sq, ok := tail["seq"].(json.Number); ok {
						seq, _ = sq.Int64()
					}
				}
				// else: last entry predates chain_hash - start the chain
				// fresh from genesis, as documented above.
			}
		}
	} else if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("audit: read %s: %w", path, err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	return &Logger{file: f, lastHash: lastHash, seq: seq}, nil
}

// chainEntry computes a chained entry's hash and final serialized line
// given its seq and prev_chain_hash - the one place this logic lives, so
// the file-backed path and the Postgres-backed path (postgres.go) always
// compute identically. Mutates event in place (adds seq/prev_chain_hash/
// chain_hash) the same way the original inline version did.
//
// A caller (handler.go's pre-image capture) embeds already-serialized JSON
// verbatim as json.RawMessage, e.g. a captured upstream response, so its
// bytes pass through untouched. "Untouched" includes whatever KEY ORDER
// the original sender used - typically a Go struct's declared field
// order, not alphabetical. json.Marshal on the rest of this event map DOES
// sort keys alphabetically (documented behavior), but a json.RawMessage
// bypasses that entirely. VerifyChainFile, reading the line back later,
// has no way to know the original wasn't already serialized - it decodes
// generically into a map[string]any and re-marshals, which DOES
// alphabetize that nested object's keys. The two computations would then
// diverge on any entry whose raw payload wasn't already alphabetical,
// reporting TAMPERING DETECTED on an entry nobody touched - a real bug
// this package's own hand-off ("run this against the log we gave you") is
// specifically supposed to survive. Canonicalizing every json.RawMessage
// into the same generic shape VerifyChainFile will later produce, once,
// here, at write time, keeps both sides of the chain computing over
// identical bytes forever after.
func chainEntry(event map[string]any, seq int64, prevHash string) (chainHash string, line []byte, err error) {
	event["seq"] = seq
	event["prev_chain_hash"] = prevHash

	for k, v := range event {
		event[k] = normalizeRawMessage(v)
	}

	// The hash covers seq + prev_chain_hash + every caller-supplied field,
	// computed BEFORE chain_hash itself is added (it can't cover its own
	// value). json.Marshal on a map[string]any sorts keys alphabetically -
	// documented Go behavior - so this is deterministic without a separate
	// canonicalization step.
	preHash, err := json.Marshal(event)
	if err != nil {
		return "", nil, fmt.Errorf("audit: marshal error: %w", err)
	}
	sum := sha256.Sum256(preHash)
	chainHash = hex.EncodeToString(sum[:])
	event["chain_hash"] = chainHash

	line, err = json.Marshal(event)
	if err != nil {
		return "", nil, fmt.Errorf("audit: marshal error: %w", err)
	}
	return chainHash, line, nil
}

func (l *Logger) Write(event map[string]any) {
	event["ts"] = time.Now().UTC().Format(time.RFC3339Nano)

	if l.pg != nil {
		l.writePG(event)
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++
	chainHash, line, err := chainEntry(event, l.seq, l.lastHash)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return
	}

	l.file.Write(line)
	l.file.Write([]byte("\n"))
	l.lastHash = chainHash

	fmt.Fprintf(os.Stderr, "[audit] %-6v tool=%-22v role=%-14v reason=%v\n",
		event["decision"], event["tool"], event["delegated_role"], event["reason"])
}

func (l *Logger) Close() error {
	if l.pg != nil {
		return l.pg.Close()
	}
	return l.file.Close()
}

// VerifyResult is the outcome of walking a JSONL audit log and
// recomputing its hash chain from scratch.
type VerifyResult struct {
	OK             bool   `json:"ok"`
	EntriesChecked int    `json:"entries_checked"`
	LegacyEntries  int    `json:"legacy_entries_skipped"` // pre-chain entries: no chain_hash field, not coverable, not a failure
	BrokenAtLine   int    `json:"broken_at_line,omitempty"`
	BrokenAtSeq    int64  `json:"broken_at_seq,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

// VerifyChainFile walks path in order and confirms every chained entry's
// chain_hash matches a fresh recomputation, and that it correctly names
// the prior chained entry's hash as its own prev_chain_hash - exactly the
// chain Logger.Write builds. Any entry edited, deleted, or reordered after
// the chain begins breaks verification at precisely that point, not just
// "somewhere in the file" - BrokenAtLine/BrokenAtSeq name it.
//
// Numeric fields are decoded via json.Number (not the default float64) so
// recomputation is byte-exact regardless of a caller-supplied field's
// magnitude - a naive map[string]any round-trip through float64 can
// silently reformat large integers, which would make a perfectly valid
// entry look tampered. Getting this exactly right matters more here than
// almost anywhere else in this codebase: a false positive ("tampering"
// that never happened) undermines trust in the whole feature as surely as
// a false negative would.
func VerifyChainFile(path string) (VerifyResult, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("audit: read %s: %w", path, err)
	}
	lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))
	return verifyChainLines(lines)
}

// verifyChainLines is VerifyChainFile's actual algorithm, factored out so
// VerifyChainPostgres (postgres.go) walks the identical chain-recomputation
// logic against rows read from Postgres instead of lines read from a file
// - one implementation of "what makes a chain valid," two sources of the
// lines it walks.
func verifyChainLines(lines [][]byte) (VerifyResult, error) {
	result := VerifyResult{OK: true}
	prevHash := genesisHash
	chainStarted := false

	for i, line := range lines {
		if len(line) == 0 {
			continue
		}
		lineNo := i + 1

		dec := json.NewDecoder(bytes.NewReader(line))
		dec.UseNumber()
		var entry map[string]any
		if err := dec.Decode(&entry); err != nil {
			result.OK = false
			result.BrokenAtLine = lineNo
			result.Reason = fmt.Sprintf("line %d: not valid JSON: %v", lineNo, err)
			return result, nil
		}

		chainHash, hasChain := entry["chain_hash"].(string)
		if !hasChain || chainHash == "" {
			if chainStarted {
				result.OK = false
				result.BrokenAtLine = lineNo
				result.Reason = fmt.Sprintf("line %d: missing chain_hash after the chain had already started", lineNo)
				return result, nil
			}
			result.LegacyEntries++
			continue
		}
		chainStarted = true

		prevClaimed, _ := entry["prev_chain_hash"].(string)
		if prevClaimed != prevHash {
			result.OK = false
			result.BrokenAtLine = lineNo
			result.BrokenAtSeq = seqOf(entry)
			result.Reason = fmt.Sprintf("line %d: prev_chain_hash does not match the prior entry's actual hash - chain broken (edited, deleted, or reordered entry)", lineNo)
			return result, nil
		}

		delete(entry, "chain_hash")
		recomputeInput, err := json.Marshal(entry)
		if err != nil {
			return VerifyResult{}, fmt.Errorf("audit: line %d: re-encode: %w", lineNo, err)
		}
		sum := sha256.Sum256(recomputeInput)
		recomputed := hex.EncodeToString(sum[:])
		if recomputed != chainHash {
			result.OK = false
			result.BrokenAtLine = lineNo
			result.BrokenAtSeq = seqOf(entry)
			result.Reason = fmt.Sprintf("line %d: recomputed hash does not match the recorded chain_hash - this entry's content was altered after being written", lineNo)
			return result, nil
		}

		prevHash = chainHash
		result.EntriesChecked++
	}

	return result, nil
}

func seqOf(entry map[string]any) int64 {
	if sq, ok := entry["seq"].(json.Number); ok {
		v, _ := sq.Int64()
		return v
	}
	return 0
}

// ReadRecent returns the most recent (up to limit) entries from the JSONL
// audit log, newest first - the read path behind the admin console's live
// activity feed (internal/adminui). Deliberately lenient, unlike
// VerifyChainFile: a malformed line is skipped, not a hard failure, since
// this is a display convenience, not the tamper-evidence check - a
// display bug over one bad line would be a worse outcome than showing
// everything else. A log that doesn't exist yet (a fresh deployment with
// no calls made) returns an empty slice, not an error.
func ReadRecent(path string, limit int) ([]map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: read %s: %w", path, err)
	}
	lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))
	entries := make([]map[string]any, 0, limit)
	for i := len(lines) - 1; i >= 0 && len(entries) < limit; i-- {
		if len(lines[i]) == 0 {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal(lines[i], &entry); err != nil {
			continue
		}
		entries = append(entries, entry)
	}
	return entries, nil
}
