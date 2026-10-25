// Package discover turns a live MCP server into a runnable tool catalog
// with no human in the loop, which is what makes a one-command start
// possible at all.
//
// It is the same classification cmd/blastradius does, but with a different
// job at the end. blastradius emits YAML for a human to finish, so it
// writes an explicit TODO wherever a real decision is needed. This has to
// produce something that RUNS right now - so wherever blastradius would
// leave a TODO, this has to make a choice, and every one of those choices
// is made in the safe direction:
//
//   - A tool the classifier cannot read becomes Class C: it needs a human
//     before it executes, rather than being waved through as probably fine.
//   - A Class A tool becomes Class A only if a pre-image reader can be
//     identified unambiguously. Compensation restoring from the WRONG
//     source would be worse than not compensating at all, so anything
//     ambiguous is demoted to Class C - still gated, just not claimed
//     undoable.
//
// Every decision is reported in Notes so the startup banner can say what
// was inferred and why, rather than presenting a catalog as if a human had
// written it.
package discover

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/RinwallDev/rinwall/internal/classify"
	"github.com/RinwallDev/rinwall/internal/mcpclient"
	"github.com/RinwallDev/rinwall/internal/registry"
)

// DefaultReviewerRole is the role a discovered Class C tool routes its
// approval to. Discovery cannot know an org's real roles, and Class A and
// Class C both require a non-empty reviewer_role to load at all, so one
// concrete value is needed. Named rather than left blank so the startup
// banner can tell an operator exactly which role to mint a token for.
const DefaultReviewerRole = "approver"

type Note struct {
	Tool   string
	Class  registry.ReversibilityClass
	Detail string
}

type Result struct {
	Tools []registry.Tool
	Notes []Note
	// Demoted names tools the classifier read as compensable but that
	// could not be given a real way to read prior state, so they were
	// gated as irreversible instead. Worth surfacing separately: each one
	// is a tool an operator can move back to Class A by hand, and doing so
	// is the single highest-value edit to a discovered catalog.
	Demoted []string
	// Unreadable names tools the classifier could not interpret at all.
	Unreadable []string
}

// FromMCPServer scans a live MCP server and builds a catalog from it. It
// calls initialize and tools/list only - discovery never executes a tool.
func FromMCPServer(ctx context.Context, client *mcpclient.Client) (Result, error) {
	tools, err := client.ListTools(ctx)
	if err != nil {
		return Result{}, err
	}
	if len(tools) == 0 {
		return Result{}, fmt.Errorf("discover: the upstream MCP server reported no tools")
	}
	return FromMCPTools(tools), nil
}

func FromMCPTools(tools []mcpclient.Tool) Result {
	sorted := append([]mcpclient.Tool(nil), tools...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	classified := make([]classify.Result, 0, len(sorted))
	for _, t := range sorted {
		classified = append(classified, classify.Classify(classify.Input{
			Name: t.Name, Description: t.Description, ArgNames: argNames(t),
		}))
	}
	readers := preImageReaders(sorted, classified)

	var out Result
	for i, t := range sorted {
		r := classified[i]
		resourceArg := inferResourceArg(t)

		tool := registry.Tool{
			Name:        t.Name,
			Description: t.Description,
			MCPTool:     "=",
			ResourceArg: resourceArg,
			ArgsSchema:  schemaToArgs(t.InputSchema),
		}

		switch {
		case r.Unclassified:
			// Fail closed. An unrecognized verb is the case most likely to
			// be something genuinely destructive nobody named clearly.
			tool.ReversibilityClass = registry.ClassC
			tool.ReviewerRole = DefaultReviewerRole
			out.Unreadable = append(out.Unreadable, t.Name)
			out.Notes = append(out.Notes, Note{t.Name, registry.ClassC,
				"could not be classified, so it is gated as irreversible until a human says otherwise"})

		case r.Class == registry.ClassA:
			reader, ok := readers[t.Name]
			compensable := ok && resourceArg != ""
			if compensable {
				tool.ReversibilityClass = registry.ClassA
				tool.ReviewerRole = DefaultReviewerRole
				tool.CompensateFields = compensateFields(tool.ArgsSchema, resourceArg)
				tool.PreImage = &registry.PreImage{MCPTool: reader}
				compensable = len(tool.CompensateFields) > 0
			}
			if !compensable {
				// Classified undoable, but with no trustworthy way to read
				// prior state - "compensable in name only," which the
				// scanner already reports as the most dangerous kind of
				// wrong. Gate it rather than claim an undo that would not
				// work.
				tool.ReversibilityClass = registry.ClassC
				tool.ReviewerRole = DefaultReviewerRole
				tool.CompensateFields = nil
				tool.PreImage = nil
				out.Demoted = append(out.Demoted, t.Name)
				out.Notes = append(out.Notes, Note{t.Name, registry.ClassC,
					"reads as compensable, but no unambiguous tool reads its prior state - gated instead of falsely claimed undoable"})
			} else {
				out.Notes = append(out.Notes, Note{t.Name, registry.ClassA,
					fmt.Sprintf("compensable: prior state read via %s, restoring %s", reader, strings.Join(tool.CompensateFields, ", "))})
			}

		case r.Class == registry.ClassC:
			tool.ReversibilityClass = registry.ClassC
			tool.ReviewerRole = DefaultReviewerRole
			out.Notes = append(out.Notes, Note{t.Name, registry.ClassC, r.Rationale})

		default:
			tool.ReversibilityClass = registry.ClassB
			out.Notes = append(out.Notes, Note{t.Name, registry.ClassB, r.Rationale})
		}

		out.Tools = append(out.Tools, tool)
	}
	return out
}

// preImageReaders pairs each Class A tool with the tool that can read its
// resource's prior state, using a deliberately strict rule: a Class B tool
// taking EXACTLY the mutating tool's resource argument and nothing else.
// "Takes only an id" is about as close to "reads one record" as a schema
// can say without guessing.
//
// Strictness is the whole point. A loose match here would let compensation
// restore from the wrong record, which is a worse failure than not
// compensating - so more than one candidate means none, and the caller
// gates the tool instead.
func preImageReaders(tools []mcpclient.Tool, classified []classify.Result) map[string]string {
	// resource arg -> the single Class B tool that reads it, or "" if the
	// answer is ambiguous.
	byResource := map[string]string{}
	ambiguous := map[string]bool{}
	for i, t := range tools {
		if classified[i].Class != registry.ClassB || classified[i].Unclassified {
			continue
		}
		names := argNames(t)
		if len(names) != 1 {
			continue
		}
		arg := names[0]
		if _, seen := byResource[arg]; seen {
			ambiguous[arg] = true
			continue
		}
		byResource[arg] = t.Name
	}

	out := map[string]string{}
	for i, t := range tools {
		if classified[i].Class != registry.ClassA || classified[i].Unclassified {
			continue
		}
		resourceArg := inferResourceArg(t)
		if resourceArg == "" || ambiguous[resourceArg] {
			continue
		}
		if reader, ok := byResource[resourceArg]; ok && reader != t.Name {
			out[t.Name] = reader
		}
	}
	return out
}

// compensateFields is every argument except the one naming the resource -
// on a mutating tool those are exactly the values being changed, so they
// are what a restore has to put back. Compensation validates these against
// the captured pre-image and fails loudly if they aren't there, so a wrong
// guess here surfaces as a reported compensation failure rather than a
// silent no-op.
func compensateFields(schema map[string]registry.FieldSpec, resourceArg string) []string {
	fields := make([]string, 0, len(schema))
	for name := range schema {
		if name != resourceArg {
			fields = append(fields, name)
		}
	}
	sort.Strings(fields)
	return fields
}

func argNames(t mcpclient.Tool) []string {
	props, _ := t.InputSchema["properties"].(map[string]any)
	names := make([]string, 0, len(props))
	for k := range props {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

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

func schemaToArgs(schema map[string]any) map[string]registry.FieldSpec {
	props, _ := schema["properties"].(map[string]any)
	requiredList, _ := schema["required"].([]any)
	required := make(map[string]bool, len(requiredList))
	for _, r := range requiredList {
		if s, ok := r.(string); ok {
			required[s] = true
		}
	}

	args := make(map[string]registry.FieldSpec, len(props))
	for name, raw := range props {
		prop, _ := raw.(map[string]any)
		spec := registry.FieldSpec{Type: jsonTypeToFieldType(prop["type"]), Required: required[name]}
		if enum, ok := prop["enum"].([]any); ok && len(enum) > 0 {
			for _, e := range enum {
				spec.Enum = append(spec.Enum, fmt.Sprintf("%v", e))
			}
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
