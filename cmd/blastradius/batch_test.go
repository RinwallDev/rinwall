package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RinwallDev/rinwall/internal/classify"
)

func TestReadTargets_SkipsCommentsBlanksAndDuplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	body := "# a comment\n\nhttps://a.example/mcp\n  https://b.example/mcp  \nhttps://a.example/mcp\n"
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := readTargets(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://a.example/mcp", "https://b.example/mcp"}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, got)
		}
	}
}

// Why the outcome buckets matter: in aggregate, "we couldn't reach it" and
// "it wanted credentials" are different facts about the ecosystem, and
// folding them into one error count would misstate how much of it the
// numbers actually cover.
func TestClassifyFailure_Buckets(t *testing.T) {
	cases := map[string]scanOutcome{
		"mcpclient: https://x/mcp returned HTTP 401: Unauthorized":      outcomeAuth,
		"mcpclient: https://x/mcp returned HTTP 403: Forbidden":         outcomeAuth,
		"mcpclient: reaching https://x/mcp: dial tcp: no such host":     outcomeUnreach,
		"mcpclient: reaching https://x/mcp: context deadline exceeded":  outcomeUnreach,
		"https://x/mcp reported no tools":                               outcomeNoTools,
		"mcpclient: https://x/mcp returned JSON-RPC error -32601: nope": outcomeProtocol,
	}
	for msg, want := range cases {
		if got, _ := classifyFailure(errors.New(msg)); got != want {
			t.Fatalf("%q: expected %s, got %s", msg, want, got)
		}
	}
}

func report(source string, classes map[string]int, total int) *classify.Report {
	return &classify.Report{Source: source, TotalTools: total, ByClass: classes}
}

func TestSummarizeBatch_AggregatesAndCountsServers(t *testing.T) {
	records := []scanRecord{
		{Source: "a", Outcome: outcomeOK, Report: report("a", map[string]int{"C": 2, "B": 3}, 5)},
		{Source: "b", Outcome: outcomeOK, Report: report("b", map[string]int{"B": 4}, 4)},
		{Source: "c", Outcome: outcomeOK, Report: report("c", map[string]int{"A": 1, "unknown": 1, "B": 8}, 10)},
		{Source: "d", Outcome: outcomeAuth},
		{Source: "e", Outcome: outcomeUnreach},
	}
	s := summarizeBatch(records)

	if s.TargetsScanned != 5 || s.ServersWithCat != 3 {
		t.Fatalf("expected 5 scanned / 3 with catalogs, got %d / %d", s.TargetsScanned, s.ServersWithCat)
	}
	if s.ByOutcome["auth_required"] != 1 || s.ByOutcome["unreachable"] != 1 {
		t.Fatalf("outcome buckets wrong: %v", s.ByOutcome)
	}
	if s.TotalTools != 19 {
		t.Fatalf("expected 19 tools, got %d", s.TotalTools)
	}
	if s.ToolsByClass["C"] != 2 || s.ToolsByClass["B"] != 15 || s.ToolsByClass["A"] != 1 {
		t.Fatalf("class totals wrong: %v", s.ToolsByClass)
	}
	if s.ServersAnyClassC != 1 {
		t.Fatalf("expected 1 server with an irreversible tool, got %d", s.ServersAnyClassC)
	}
	// "b" only: "c" has a Class A and an unknown, so it is not read-only.
	if s.ServersAllClassB != 1 {
		t.Fatalf("expected 1 entirely read-only server, got %d", s.ServersAllClassB)
	}
	if s.ServersAnyUnknown != 1 {
		t.Fatalf("expected 1 server with unclassifiable tools, got %d", s.ServersAnyUnknown)
	}
	// A server that failed must never be counted as read-only - that would
	// report an unreachable server as safe, the worst possible direction to
	// be wrong in.
	if s.ServersAllClassB+s.ServersAnyClassC > s.ServersWithCat {
		t.Fatal("failed targets leaked into the per-server counts")
	}
}

func TestSummarizeBatch_EmptyCorpusDoesNotPanic(t *testing.T) {
	s := summarizeBatch(nil)
	if s.TargetsScanned != 0 || s.ServersWithCat != 0 || s.MedianToolsPerServer != 0 {
		t.Fatalf("unexpected summary for an empty corpus: %+v", s)
	}
}

// The restraint the package comment promises, asserted rather than trusted:
// scanning a server must never call one of its tools.
func TestScanOne_NeverCallsATool(t *testing.T) {
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		methods = append(methods, req.Method)
		if req.ID == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		var result any
		switch req.Method {
		case "initialize":
			result = map[string]any{"protocolVersion": "2025-06-18"}
		case "tools/list":
			result = map[string]any{"tools": []map[string]any{
				{"name": "delete_everything", "description": "Deletes everything permanently."},
				{"name": "get_thing", "description": "Reads a thing."},
			}}
		}
		w.Header().Set("Content-Type", "application/json")
		payload, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	rec := scanOne(t.Context(), srv.URL, "", 5*time.Second, false)
	if rec.Outcome != outcomeOK {
		t.Fatalf("expected ok, got %s: %s", rec.Outcome, rec.Error)
	}
	if rec.Report.ByClass["C"] != 1 || rec.Report.ByClass["B"] != 1 {
		t.Fatalf("unexpected classification: %v", rec.Report.ByClass)
	}
	for _, m := range methods {
		if m == "tools/call" {
			t.Fatal("a scan must never call a tool")
		}
	}
}

func TestScanOne_AuthChallengeIsARecordedResultNotACrash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	rec := scanOne(t.Context(), srv.URL, "", 5*time.Second, false)
	if rec.Outcome != outcomeAuth {
		t.Fatalf("expected auth_required, got %s (%s)", rec.Outcome, rec.Error)
	}
	if rec.Report != nil {
		t.Fatal("a server that refused must not produce a catalog")
	}
}
