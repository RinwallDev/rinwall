package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/RinwallDev/rinwall/internal/classify"
	"github.com/RinwallDev/rinwall/internal/mcpclient"
	"github.com/RinwallDev/rinwall/internal/registry"
)

// Batch scanning: point this at a file of MCP server URLs and get one
// aggregate answer across all of them. Built for the question "how much of
// this fleet can take an action nobody can undo" - which is an org's
// question about the servers it runs, and also the question behind
// measuring the public ecosystem.
//
// What it does to each target is exactly what a single scan does:
// initialize, then tools/list. It never calls a tool, never retries into a
// failure, identifies itself honestly in clientInfo, and treats an auth
// challenge as a result rather than something to work around. Reading a
// server's published tool catalog is the thing MCP discovery is FOR, and a
// server listed in a public registry is published precisely to be
// discovered - but the restraint is deliberate and worth stating, because
// a scanner that called tools would be something else entirely.

// scanOutcome distinguishes the reasons a target produced no catalog,
// because in aggregate those reasons are themselves a finding - "how much
// of the public ecosystem is even reachable" turned out to matter as much
// as what the reachable part contains.
type scanOutcome string

const (
	outcomeOK       scanOutcome = "ok"
	outcomeAuth     scanOutcome = "auth_required"
	outcomeNoTools  scanOutcome = "no_tools"
	outcomeUnreach  scanOutcome = "unreachable"
	outcomeProtocol scanOutcome = "protocol_error"
)

type scanRecord struct {
	Source   string           `json:"source"`
	Outcome  scanOutcome      `json:"outcome"`
	Error    string           `json:"error,omitempty"`
	Duration string           `json:"duration"`
	Report   *classify.Report `json:"report,omitempty"`

	// Catalog is the raw tools/list response, kept only when
	// --save-catalogs is set. It exists so a corpus can be re-analyzed
	// offline: improving the classifier and wanting to know what changed
	// should cost zero further requests to anyone else's servers. Without
	// it, every iteration on the heuristic means scanning the whole fleet
	// again, which is both slow and a burden on operators who did nothing
	// but publish a catalog.
	Catalog []mcpclient.Tool `json:"catalog,omitempty"`
}

func classifyFailure(err error) (scanOutcome, string) {
	msg := err.Error()
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "http 401"), strings.Contains(low, "http 403"),
		strings.Contains(low, "unauthorized"), strings.Contains(low, "forbidden"),
		strings.Contains(low, "invalid_token"), strings.Contains(low, "authentication"):
		return outcomeAuth, msg
	case strings.Contains(low, "reported no tools"):
		return outcomeNoTools, msg
	case strings.Contains(low, "no such host"), strings.Contains(low, "timeout"),
		strings.Contains(low, "deadline exceeded"), strings.Contains(low, "connection refused"),
		strings.Contains(low, "tls"), strings.Contains(low, "eof"), strings.Contains(low, "reaching"):
		return outcomeUnreach, msg
	default:
		return outcomeProtocol, msg
	}
}

func readTargets(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	seen := map[string]bool{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !seen[line] {
			seen[line] = true
			out = append(out, line)
		}
	}
	return out, scanner.Err()
}

func scanOne(ctx context.Context, url, auth string, timeout time.Duration, keepCatalog bool) scanRecord {
	started := time.Now()
	rec := scanRecord{Source: url}

	opts := []mcpclient.Option{mcpclient.WithHTTPClient(&http.Client{Timeout: timeout})}
	if auth != "" {
		opts = append(opts, mcpclient.WithAuthorization(auth))
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tools, err := mcpclient.New(url, opts...).ListTools(ctx)
	rec.Duration = time.Since(started).Round(time.Millisecond).String()
	if err != nil {
		rec.Outcome, rec.Error = classifyFailure(err)
		return rec
	}
	if len(tools) == 0 {
		rec.Outcome, rec.Error = outcomeNoTools, "server returned an empty tool list"
		return rec
	}

	var results []classify.Result
	var gaps []string
	for _, t := range tools {
		r := classify.Classify(classify.Input{
			Name: t.Name, Description: t.Description, ArgNames: argNames(t),
		})
		results = append(results, r)
		if r.Class == registry.ClassA {
			gaps = append(gaps, r.Tool)
		}
	}
	report := classify.Summarize(url, results, gaps)
	rec.Outcome, rec.Report = outcomeOK, &report
	if keepCatalog {
		rec.Catalog = tools
	}
	return rec
}

// reclassify rebuilds every report from stored catalogs, with no network
// access at all - the point of saving them. Lets a classifier change be
// measured against the exact same corpus rather than a fresh scan that may
// have drifted, and without asking 800 servers to answer the same question
// twice.
func reclassify(records []scanRecord) []scanRecord {
	out := make([]scanRecord, 0, len(records))
	for _, rec := range records {
		if rec.Catalog == nil {
			out = append(out, rec)
			continue
		}
		var results []classify.Result
		var gaps []string
		for _, t := range rec.Catalog {
			r := classify.Classify(classify.Input{
				Name: t.Name, Description: t.Description, ArgNames: argNames(t),
			})
			results = append(results, r)
			if r.Class == registry.ClassA {
				gaps = append(gaps, r.Tool)
			}
		}
		report := classify.Summarize(rec.Source, results, gaps)
		rec.Report = &report
		out = append(out, rec)
	}
	return out
}

// runBatch scans every target with bounded concurrency and a small delay
// between starts, so a wide scan stays polite rather than arriving as a
// burst. Progress goes to stderr so stdout stays a clean JSON document.
func runBatch(targetsPath, auth string, concurrency int, timeout, delay time.Duration, keepCatalog bool) ([]scanRecord, error) {
	targets, err := readTargets(targetsPath)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets in %s", targetsPath)
	}
	fmt.Fprintf(os.Stderr, "scanning %d MCP servers (concurrency %d, timeout %s)...\n",
		len(targets), concurrency, timeout)

	var (
		mu      sync.Mutex
		records = make([]scanRecord, 0, len(targets))
		done    int
		sem     = make(chan struct{}, concurrency)
		wg      sync.WaitGroup
	)
	ctx := context.Background()

	for _, url := range targets {
		wg.Add(1)
		sem <- struct{}{}
		time.Sleep(delay)
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()
			rec := scanOne(ctx, u, auth, timeout, keepCatalog)
			mu.Lock()
			records = append(records, rec)
			done++
			if done%25 == 0 || done == len(targets) {
				fmt.Fprintf(os.Stderr, "  %d/%d\n", done, len(targets))
			}
			mu.Unlock()
		}(url)
	}
	wg.Wait()

	sort.Slice(records, func(i, j int) bool { return records[i].Source < records[j].Source })
	return records, nil
}

// summarizeBatch is the aggregate view: the numbers a post would actually
// quote, plus the reachability breakdown that says how much of the
// ecosystem those numbers cover.
type batchSummary struct {
	TargetsScanned       int            `json:"targets_scanned"`
	ByOutcome            map[string]int `json:"by_outcome"`
	ServersWithCat       int            `json:"servers_with_catalog"`
	TotalTools           int            `json:"total_tools"`
	ToolsByClass         map[string]int `json:"tools_by_class"`
	ServersAnyClassC     int            `json:"servers_with_at_least_one_irreversible_tool"`
	ServersAllClassB     int            `json:"servers_entirely_read_only"`
	ServersAnyUnknown    int            `json:"servers_with_unclassifiable_tools"`
	MedianToolsPerServer int            `json:"median_tools_per_server"`
	LargestCatalog       string         `json:"largest_catalog"`
	Records              []scanRecord   `json:"records"`
}

func summarizeBatch(records []scanRecord) batchSummary {
	s := batchSummary{
		TargetsScanned: len(records),
		ByOutcome:      map[string]int{},
		ToolsByClass:   map[string]int{},
	}
	var counts []int
	largest, largestN := "", 0

	for _, rec := range records {
		s.ByOutcome[string(rec.Outcome)]++
		if rec.Report == nil {
			continue
		}
		s.ServersWithCat++
		s.TotalTools += rec.Report.TotalTools
		counts = append(counts, rec.Report.TotalTools)
		if rec.Report.TotalTools > largestN {
			largest, largestN = rec.Source, rec.Report.TotalTools
		}
		for class, n := range rec.Report.ByClass {
			s.ToolsByClass[class] += n
		}
		if rec.Report.ByClass["C"] > 0 {
			s.ServersAnyClassC++
		}
		if rec.Report.ByClass["C"] == 0 && rec.Report.ByClass["A"] == 0 && rec.Report.ByClass["unknown"] == 0 {
			s.ServersAllClassB++
		}
		if rec.Report.ByClass["unknown"] > 0 {
			s.ServersAnyUnknown++
		}
	}

	sort.Ints(counts)
	if len(counts) > 0 {
		s.MedianToolsPerServer = counts[len(counts)/2]
	}
	s.LargestCatalog = fmt.Sprintf("%s (%d tools)", largest, largestN)
	s.Records = records
	return s
}

func printBatchSummary(w *os.File, s batchSummary) {
	fmt.Fprintf(w, "\nBlast radius across %d MCP servers\n", s.TargetsScanned)
	fmt.Fprintf(w, "%s\n\n", strings.Repeat("=", 60))

	fmt.Fprintf(w, "  Reachability:\n")
	for _, k := range []scanOutcome{outcomeOK, outcomeAuth, outcomeUnreach, outcomeNoTools, outcomeProtocol} {
		if n := s.ByOutcome[string(k)]; n > 0 {
			fmt.Fprintf(w, "    %4d  %s\n", n, k)
		}
	}

	if s.ServersWithCat == 0 {
		fmt.Fprintf(w, "\n  No catalogs retrieved.\n\n")
		return
	}

	fmt.Fprintf(w, "\n  %d servers published a catalog: %d tools total (median %d per server)\n",
		s.ServersWithCat, s.TotalTools, s.MedianToolsPerServer)
	fmt.Fprintf(w, "    %5d irreversible        (class C)\n", s.ToolsByClass["C"])
	fmt.Fprintf(w, "    %5d compensable         (class A)\n", s.ToolsByClass["A"])
	fmt.Fprintf(w, "    %5d read-only/retryable (class B)\n", s.ToolsByClass["B"])
	fmt.Fprintf(w, "    %5d unclassifiable      (needs a human)\n", s.ToolsByClass["unknown"])

	pct := func(n, of int) float64 {
		if of == 0 {
			return 0
		}
		return float64(n) * 100 / float64(of)
	}
	fmt.Fprintf(w, "\n  %.1f%% of all tools take an action that cannot be undone.\n", pct(s.ToolsByClass["C"], s.TotalTools))
	fmt.Fprintf(w, "  %.1f%% of servers (%d of %d) expose at least one irreversible tool.\n",
		pct(s.ServersAnyClassC, s.ServersWithCat), s.ServersAnyClassC, s.ServersWithCat)
	fmt.Fprintf(w, "  %.1f%% of servers (%d of %d) are entirely read-only.\n",
		pct(s.ServersAllClassB, s.ServersWithCat), s.ServersAllClassB, s.ServersWithCat)
	fmt.Fprintf(w, "  %.1f%% of servers (%d of %d) expose a tool nothing here could classify.\n",
		pct(s.ServersAnyUnknown, s.ServersWithCat), s.ServersAnyUnknown, s.ServersWithCat)
	fmt.Fprintf(w, "\n  Largest catalog: %s\n", s.LargestCatalog)
	fmt.Fprintf(w, "\n  Heuristic classifications from names, descriptions, and schemas.\n")
	fmt.Fprintf(w, "  Nothing was executed - initialize and tools/list only.\n\n")
}

func encodeJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
