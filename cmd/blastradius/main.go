// Command blastradius answers one question, with no setup and no
// integration: how much damage can this agent's tools actually do?
//
// Point it at a live MCP server or an existing tool catalog and it
// classifies every tool by reversibility (internal/classify), then reports
// the numbers that matter - how many tools take irreversible actions, how
// many claim to be undoable without any way to actually undo them, and how
// many nobody can classify without a human looking.
//
// Deliberately zero-dependency on the rest of the system: no Vault, no
// proxy, no config, no policy bundle. It reads and reports, it never
// executes a tool or touches a credential. That's the point - it has to be
// usable before anyone has decided to adopt anything, including by someone
// evaluating a third-party MCP server they don't run.
//
// --emit-registry turns the scan into a starting tools.yaml, which is the
// other half of the job: hand-classifying a catalog was the single biggest
// barrier to getting this system running at all.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/RinwallDev/rinwall/internal/classify"
	"github.com/RinwallDev/rinwall/internal/mcpclient"
	"github.com/RinwallDev/rinwall/internal/registry"
)

func main() {
	mcpURL := flag.String("mcp", "", "URL of a live MCP server to scan (Streamable HTTP, e.g. http://localhost:3000/mcp)")
	registryPath := flag.String("registry", "", "path to an existing tools.yaml to audit instead")
	authHeader := flag.String("auth", "", "optional Authorization header value for the MCP server (e.g. \"Bearer ...\")")
	asJSON := flag.Bool("json", false, "emit the full report as JSON (for aggregating scans across many servers)")
	emitRegistry := flag.Bool("emit-registry", false, "emit a starter tools.yaml from the scan instead of a report")
	targetsPath := flag.String("targets", "", "path to a file of MCP server URLs (one per line, # comments allowed) to scan as a fleet")
	concurrency := flag.Int("concurrency", 4, "how many targets to scan at once in --targets mode")
	timeout := flag.Duration("timeout", 20*time.Second, "per-server timeout in --targets mode")
	delay := flag.Duration("delay", 150*time.Millisecond, "pause between starting scans in --targets mode, so a wide scan stays polite")
	saveCatalogs := flag.Bool("save-catalogs", false, "in --targets mode, keep each server's raw tool list in the output so the corpus can be re-analyzed offline with --reanalyze")
	reanalyze := flag.String("reanalyze", "", "path to a prior --targets --save-catalogs result; re-runs the classifier over the stored catalogs with no network access at all")
	flag.Parse()

	// Offline re-analysis. The reason this exists: iterating on the
	// classifier and wanting to know what changed should cost nothing to
	// the servers that were scanned - and it also makes a before/after a
	// genuine comparison over one fixed corpus rather than two scans that
	// may have drifted.
	if *reanalyze != "" {
		raw, err := os.ReadFile(*reanalyze)
		if err != nil {
			fmt.Fprintf(os.Stderr, "blastradius: %v\n", err)
			os.Exit(1)
		}
		var prior batchSummary
		if err := json.Unmarshal(raw, &prior); err != nil {
			fmt.Fprintf(os.Stderr, "blastradius: parsing %s: %v\n", *reanalyze, err)
			os.Exit(1)
		}
		withCatalogs := 0
		for _, rec := range prior.Records {
			if rec.Catalog != nil {
				withCatalogs++
			}
		}
		if withCatalogs == 0 {
			fmt.Fprintf(os.Stderr, "blastradius: %s has no stored catalogs - it was scanned without --save-catalogs, so there is nothing to re-analyze offline\n", *reanalyze)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "re-analyzing %d stored catalogs offline (no requests sent)\n", withCatalogs)
		summary := summarizeBatch(reclassify(prior.Records))
		if *asJSON {
			encodeJSON(summary)
		} else {
			printBatchSummary(os.Stdout, summary)
		}
		return
	}

	if *targetsPath != "" {
		if *mcpURL != "" || *registryPath != "" {
			fmt.Fprintln(os.Stderr, "blastradius: --targets scans a fleet; don't combine it with --mcp or --registry")
			os.Exit(2)
		}
		records, err := runBatch(*targetsPath, *authHeader, *concurrency, *timeout, *delay, *saveCatalogs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "blastradius: %v\n", err)
			os.Exit(1)
		}
		summary := summarizeBatch(records)
		if *asJSON {
			encodeJSON(summary)
		} else {
			printBatchSummary(os.Stdout, summary)
		}
		return
	}

	if (*mcpURL == "") == (*registryPath == "") {
		fmt.Fprintln(os.Stderr, "blastradius: pass exactly one of --mcp, --registry, or --targets")
		flag.Usage()
		os.Exit(2)
	}

	var (
		results []classify.Result
		gaps    []string
		source  string
		tools   []mcpclient.Tool
		err     error
	)

	switch {
	case *mcpURL != "":
		source = *mcpURL
		tools, err = fetchMCPTools(*mcpURL, *authHeader)
		if err != nil {
			fmt.Fprintf(os.Stderr, "blastradius: %v\n", err)
			os.Exit(1)
		}
		for _, t := range tools {
			results = append(results, classify.Classify(classify.Input{
				Name: t.Name, Description: t.Description, ArgNames: argNames(t),
			}))
		}
		// An MCP tool gives no pre-image route, so anything the classifier
		// calls compensable is compensable in principle only until someone
		// wires up how to read its prior state.
		for _, r := range results {
			if r.Class == registry.ClassA {
				gaps = append(gaps, r.Tool)
			}
		}

	default:
		source = *registryPath
		results, gaps, err = auditRegistry(*registryPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "blastradius: %v\n", err)
			os.Exit(1)
		}
	}

	report := classify.Summarize(source, results, gaps)

	switch {
	case *emitRegistry:
		if err := emitStarterRegistry(os.Stdout, tools, results); err != nil {
			fmt.Fprintf(os.Stderr, "blastradius: %v\n", err)
			os.Exit(1)
		}
	case *asJSON:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	default:
		printReport(os.Stdout, report)
	}
}

// --- scanning a live MCP server --------------------------------------------

// argNames lists a tool's argument names from its JSON Schema, sorted so
// the classifier and the emitted catalog see a stable order.
func argNames(t mcpclient.Tool) []string {
	props, _ := t.InputSchema["properties"].(map[string]any)
	names := make([]string, 0, len(props))
	for k := range props {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// fetchMCPTools uses the same MCP client the proxy itself forwards through
// (internal/mcpclient) rather than a second, scanner-only implementation -
// so a server this can scan is by construction a server the proxy can sit
// in front of. It calls initialize and tools/list and nothing else: a
// scanner has no business executing anything.
func fetchMCPTools(url, auth string) ([]mcpclient.Tool, error) {
	var opts []mcpclient.Option
	if auth != "" {
		opts = append(opts, mcpclient.WithAuthorization(auth))
	}
	tools, err := mcpclient.New(url, opts...).ListTools(context.Background())
	if err != nil {
		return nil, err
	}
	if len(tools) == 0 {
		return nil, fmt.Errorf("%s reported no tools", url)
	}
	return tools, nil
}

// --- auditing an existing catalog ------------------------------------------

// auditRegistry classifies a catalog that already declares its own
// classes, so the interesting output isn't the classification itself -
// it's the DISAGREEMENTS, where a tool is declared safer than it reads.
func auditRegistry(path string) ([]classify.Result, []string, error) {
	reg, err := registry.LoadFromYAML(path)
	if err != nil {
		return nil, nil, err
	}
	var results []classify.Result
	var gaps []string

	names := make([]string, 0, len(reg.All()))
	for name := range reg.All() {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		tool, _ := reg.Get(name)
		argNames := make([]string, 0, len(tool.ArgsSchema))
		for k := range tool.ArgsSchema {
			argNames = append(argNames, k)
		}
		sort.Strings(argNames)

		r := classify.Classify(classify.Input{
			Name: name, Method: tool.Method, ArgNames: argNames,
		})
		// The catalog's own declaration wins - it was presumably written
		// by someone who knows the system. What's worth reporting is where
		// the heuristic reads the tool as MORE dangerous than declared.
		if !r.Unclassified && r.Class != tool.ReversibilityClass {
			r.Rationale = fmt.Sprintf("catalog declares class %s; %s", tool.ReversibilityClass, r.Rationale)
			r.NeedsReview = riskOrder(r.Class) > riskOrder(tool.ReversibilityClass)
		} else {
			r.NeedsReview = false
		}
		r.Class = tool.ReversibilityClass
		results = append(results, r)

		if tool.ReversibilityClass == registry.ClassA && (tool.PreImage == nil || len(tool.CompensateFields) == 0) {
			gaps = append(gaps, name)
		}
	}
	return results, gaps, nil
}

func riskOrder(c registry.ReversibilityClass) int {
	switch c {
	case registry.ClassB:
		return 0
	case registry.ClassA:
		return 1
	case registry.ClassC:
		return 2
	}
	return 0
}

// --- output ----------------------------------------------------------------

func printReport(w *os.File, rep classify.Report) {
	fmt.Fprintf(w, "\nBlast radius: %s\n", rep.Source)
	fmt.Fprintf(w, "%s\n\n", strings.Repeat("=", 60))
	fmt.Fprintf(w, "  %d tools\n", rep.TotalTools)
	fmt.Fprintf(w, "    %2d irreversible        (class C - no undo, needs a human gate)\n", rep.ByClass["C"])
	fmt.Fprintf(w, "    %2d compensable         (class A - undoable if a pre-image is captured)\n", rep.ByClass["A"])
	fmt.Fprintf(w, "    %2d read-only/retryable (class B)\n", rep.ByClass["B"])
	if rep.ByClass["unknown"] > 0 {
		fmt.Fprintf(w, "    %2d unclassifiable      (needs a human - deliberately not guessed)\n", rep.ByClass["unknown"])
	}

	if len(rep.Irreversible) > 0 {
		fmt.Fprintf(w, "\n  Irreversible actions in this catalog:\n")
		for _, r := range rep.Results {
			if r.Class == registry.ClassC && !r.Unclassified {
				fmt.Fprintf(w, "    - %-32s %s\n", r.Tool, r.Rationale)
			}
		}
	}

	if len(rep.UndoableInName) > 0 {
		fmt.Fprintf(w, "\n  Compensable in name only - no way to capture prior state,\n")
		fmt.Fprintf(w, "  so nothing can actually undo these today:\n")
		for _, name := range rep.UndoableInName {
			fmt.Fprintf(w, "    - %s\n", name)
		}
	}

	if len(rep.Unclassified) > 0 {
		fmt.Fprintf(w, "\n  Could not classify (classify these by hand):\n")
		for _, name := range rep.Unclassified {
			fmt.Fprintf(w, "    - %s\n", name)
		}
	}

	pct := 0
	if rep.TotalTools > 0 {
		pct = rep.ByClass["C"] * 100 / rep.TotalTools
	}
	fmt.Fprintf(w, "\n  %d%% of this agent's tools take actions that cannot be undone.\n", pct)
	fmt.Fprintf(w, "\n  These are heuristic classifications from names, descriptions, and\n")
	fmt.Fprintf(w, "  schemas - review anything marked irreversible before trusting it.\n")
	fmt.Fprintf(w, "  Re-run with --emit-registry to get a starting tools.yaml.\n\n")
}

// emitStarterRegistry writes a tools.yaml skeleton - the point being that
// nobody should have to hand-write one from scratch just to try the proxy.
// Everything the scanner couldn't determine is left as an explicit TODO
// rather than a plausible-looking guess.
func emitStarterRegistry(w *os.File, tools []mcpclient.Tool, results []classify.Result) error {
	byName := make(map[string]classify.Result, len(results))
	for _, r := range results {
		byName[r.Tool] = r
	}
	readOnly := make([]string, 0, len(results))
	for _, r := range results {
		if r.Class == registry.ClassB && !r.Unclassified {
			readOnly = append(readOnly, r.Tool)
		}
	}

	// Field order here is the whole reason this is a struct and not a map:
	// yaml.v3 sorts map keys alphabetically, which buries `name` under
	// `args_schema` in a file a human is about to sit down and edit.
	type preImage struct {
		MCPTool string `yaml:"mcp_tool"`
	}
	type emittedTool struct {
		Name               string         `yaml:"name"`
		Description        string         `yaml:"description,omitempty"`
		ReversibilityClass string         `yaml:"reversibility_class"`
		MCPTool            string         `yaml:"mcp_tool"`
		ResourceArg        string         `yaml:"resource_arg,omitempty"`
		ReviewerRole       string         `yaml:"reviewer_role,omitempty"`
		CompensateFields   []string       `yaml:"compensate_fields,omitempty"`
		PreImage           *preImage      `yaml:"pre_image,omitempty"`
		ArgsSchema         map[string]any `yaml:"args_schema"`
		// ReviewedBy/ReviewedAt are always left as TODOs here, on every
		// tool, even a read-only one with no other TODO - they only ever
		// matter to a deployment that turns on require_reviewed_tools
		// (internal/registry.RequireReviewed), and that mode's entire
		// point is that a human looked at the WHOLE catalog, not just the
		// entries the classifier itself flagged as uncertain.
		ReviewedBy string `yaml:"reviewed_by"`
		ReviewedAt string `yaml:"reviewed_at"`
	}
	type fileFormat struct {
		Tools []emittedTool `yaml:"tools"`
	}
	var out fileFormat

	sorted := append([]mcpclient.Tool(nil), tools...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	needsHuman := 0
	for _, t := range sorted {
		r := byName[t.Name]
		// mcp_tool "=" means "forward to the upstream tool of this same
		// name" - which is exactly right for a catalog produced by scanning
		// that upstream. Nothing here is a TODO anymore: before MCP-to-MCP
		// passthrough existed, every entry needed a hand-written upstream
		// HTTP route, because an MCP tool advertises no verb or path.
		entry := emittedTool{
			Name:               t.Name,
			Description:        t.Description,
			ReversibilityClass: string(r.Class),
			MCPTool:            "=",
			ResourceArg:        inferResourceArg(t),
			ArgsSchema:         schemaToArgs(t.InputSchema),
			ReviewedBy:         "TODO-your-name-after-actually-reviewing-this-tool",
			ReviewedAt:         "TODO-YYYY-MM-DD",
		}
		if r.Unclassified {
			entry.ReversibilityClass = "TODO-classify-by-hand"
			needsHuman++
		}
		switch r.Class {
		case registry.ClassC:
			entry.ReviewerRole = "TODO-set-reviewer-role"
			needsHuman++
		case registry.ClassA:
			// Class A is the one place a human genuinely has to decide, and
			// it can't be guessed: which upstream tool reads this
			// resource's current state, and which arguments get restored
			// from it. Emitting a plausible guess here would produce a
			// catalog that looks compensable and silently isn't, at the
			// exact moment compensation is needed.
			entry.ReviewerRole = "TODO-set-reviewer-role"
			entry.CompensateFields = []string{"TODO-which-args-restore-prior-state"}
			entry.PreImage = &preImage{MCPTool: "TODO-upstream-tool-that-reads-current-state"}
			needsHuman++
		}
		out.Tools = append(out.Tools, entry)
	}

	fmt.Fprintf(w, "# Generated by blastradius from a live MCP server.\n")
	fmt.Fprintf(w, "# Classifications are heuristic - review every one, especially class C.\n")
	fmt.Fprintf(w, "#\n")
	fmt.Fprintf(w, "# mcp_tool: \"=\" forwards each call to the upstream tool of the same name,\n")
	fmt.Fprintf(w, "# so point the proxy at that server (mcp_upstream_url) and this catalog\n")
	fmt.Fprintf(w, "# runs as-is.\n")
	if needsHuman == 0 {
		fmt.Fprintf(w, "#\n# No blocking TODOs: every tool here is read-only, so this loads and runs\n")
		fmt.Fprintf(w, "# unedited.\n")
	} else {
		fmt.Fprintf(w, "#\n")
		fmt.Fprintf(w, "# %d tool(s) below carry a TODO and will not load until a human fills it in.\n", needsHuman)
		fmt.Fprintf(w, "# That is deliberate: a reviewer role and a way to read prior state are\n")
		fmt.Fprintf(w, "# real decisions about your system, and a wrong guess here is worse than\n")
		fmt.Fprintf(w, "# no guess. The %d read-only tool(s) need nothing.\n", len(readOnly))
	}
	fmt.Fprintf(w, "#\n")
	fmt.Fprintf(w, "# Every tool also carries a reviewed_by/reviewed_at TODO. Those never block\n")
	fmt.Fprintf(w, "# ordinary loading - they only matter if you set require_reviewed_tools in\n")
	fmt.Fprintf(w, "# config.yaml, which refuses to start unless a human has annotated EVERY\n")
	fmt.Fprintf(w, "# tool here, not just the ones flagged above. That mode exists for exactly\n")
	fmt.Fprintf(w, "# this file: nothing should stop this output from being piped straight into\n")
	fmt.Fprintf(w, "# a running production proxy except a human actually having looked at it.\n")
	fmt.Fprintln(w)
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	defer enc.Close()
	return enc.Encode(out)
}

func schemaToArgs(schema map[string]any) map[string]any {
	props, _ := schema["properties"].(map[string]any)
	requiredList, _ := schema["required"].([]any)
	required := make(map[string]bool, len(requiredList))
	for _, r := range requiredList {
		if s, ok := r.(string); ok {
			required[s] = true
		}
	}

	args := map[string]any{}
	for name, raw := range props {
		prop, _ := raw.(map[string]any)
		spec := map[string]any{"type": jsonTypeToFieldType(prop["type"])}
		if required[name] {
			spec["required"] = true
		}
		if enum, ok := prop["enum"].([]any); ok && len(enum) > 0 {
			vals := make([]string, 0, len(enum))
			for _, e := range enum {
				vals = append(vals, fmt.Sprintf("%v", e))
			}
			spec["enum"] = vals
		}
		args[name] = spec
	}
	return args
}

func jsonTypeToFieldType(t any) string {
	switch fmt.Sprintf("%v", t) {
	case "number", "integer":
		return "number"
	case "boolean":
		return "bool"
	default:
		return "string"
	}
}

// inferResourceArg guesses which argument names the thing being acted on,
// so a generated catalog has a usable resource_arg instead of none. An id-
// shaped argument is the convention nearly every tool follows.
func inferResourceArg(t mcpclient.Tool) string {
	names := argNames(t)
	for _, n := range names {
		if strings.EqualFold(n, "id") {
			return n
		}
	}
	for _, n := range names {
		if strings.HasSuffix(strings.ToLower(n), "_id") || strings.HasSuffix(strings.ToLower(n), "id") {
			return n
		}
	}
	return ""
}
