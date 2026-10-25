package discover

import (
	"testing"

	"github.com/RinwallDev/rinwall/internal/mcpclient"
	"github.com/RinwallDev/rinwall/internal/registry"
)

func tool(name, desc string, args ...string) mcpclient.Tool {
	props := map[string]any{}
	required := []any{}
	for _, a := range args {
		props[a] = map[string]any{"type": "string"}
		required = append(required, a)
	}
	return mcpclient.Tool{
		Name: name, Description: desc,
		InputSchema: map[string]any{"type": "object", "properties": props, "required": required},
	}
}

func byName(r Result) map[string]registry.Tool {
	out := map[string]registry.Tool{}
	for _, t := range r.Tools {
		out[t.Name] = t
	}
	return out
}

// Whatever else discovery does, its output has to satisfy the same contract
// a hand-written catalog does - otherwise zero-config mode fails at startup
// on a catalog nobody can inspect.
func assertLoads(t *testing.T, r Result) *registry.Registry {
	t.Helper()
	reg, err := registry.FromTools(r.Tools)
	if err != nil {
		t.Fatalf("a discovered catalog must always validate, got: %v", err)
	}
	return reg
}

func TestDiscover_ClassesAndPreImageInference(t *testing.T) {
	r := FromMCPTools([]mcpclient.Tool{
		tool("get_user", "Read a user.", "user_id"),
		tool("update_user_tier", "Change a user's tier.", "user_id", "tier"),
		tool("delete_user", "Remove a user permanently.", "user_id"),
		tool("search_users", "Search users.", "query"),
	})
	assertLoads(t, r)
	got := byName(r)

	if got["get_user"].ReversibilityClass != registry.ClassB {
		t.Fatalf("get_user should be class B, got %s", got["get_user"].ReversibilityClass)
	}
	if got["delete_user"].ReversibilityClass != registry.ClassC {
		t.Fatalf("delete_user should be class C, got %s", got["delete_user"].ReversibilityClass)
	}

	upd := got["update_user_tier"]
	if upd.ReversibilityClass != registry.ClassA {
		t.Fatalf("update_user_tier should be class A given an unambiguous reader, got %s", upd.ReversibilityClass)
	}
	if upd.PreImage == nil || upd.PreImage.MCPTool != "get_user" {
		t.Fatalf("expected get_user inferred as the pre-image reader, got %+v", upd.PreImage)
	}
	if upd.ResourceArg != "user_id" {
		t.Fatalf("expected resource_arg user_id, got %q", upd.ResourceArg)
	}
	// The resource argument identifies WHICH record; everything else is
	// what's being changed, and so is what a restore has to put back.
	if len(upd.CompensateFields) != 1 || upd.CompensateFields[0] != "tier" {
		t.Fatalf("expected compensate_fields [tier], got %v", upd.CompensateFields)
	}
}

// The decision that matters most: a tool that reads as undoable but has no
// trustworthy way to read prior state must be GATED, not marked compensable.
// Claiming an undo that would silently restore nothing is worse than
// admitting it can't be undone.
func TestDiscover_CompensableWithNoReaderIsGatedNotClaimed(t *testing.T) {
	r := FromMCPTools([]mcpclient.Tool{
		tool("update_user_tier", "Change a user's tier.", "user_id", "tier"),
	})
	assertLoads(t, r)

	got := byName(r)["update_user_tier"]
	if got.ReversibilityClass != registry.ClassC {
		t.Fatalf("with no reader available this must be gated as class C, got %s", got.ReversibilityClass)
	}
	if got.PreImage != nil || len(got.CompensateFields) > 0 {
		t.Fatalf("a gated tool must not carry compensation metadata: %+v", got)
	}
	if len(r.Demoted) != 1 || r.Demoted[0] != "update_user_tier" {
		t.Fatalf("the demotion must be reported so the banner can surface it, got %v", r.Demoted)
	}
}

// Two candidate readers means no candidate: a loose match here would let
// compensation restore from the wrong record.
func TestDiscover_AmbiguousReaderIsNotGuessed(t *testing.T) {
	r := FromMCPTools([]mcpclient.Tool{
		tool("get_user", "Read a user.", "user_id"),
		tool("fetch_user", "Also reads a user.", "user_id"),
		tool("update_user_tier", "Change a user's tier.", "user_id", "tier"),
	})
	assertLoads(t, r)

	if byName(r)["update_user_tier"].ReversibilityClass != registry.ClassC {
		t.Fatal("two candidate readers must resolve to no reader, and therefore a gated tool")
	}
}

// A reader that takes more than the resource argument isn't "read this
// record" - it's something else, and using it would capture the wrong
// pre-image.
func TestDiscover_ReaderMustTakeOnlyTheResourceArg(t *testing.T) {
	r := FromMCPTools([]mcpclient.Tool{
		tool("get_user_field", "Read one field of a user.", "user_id", "field"),
		tool("update_user_tier", "Change a user's tier.", "user_id", "tier"),
	})
	assertLoads(t, r)

	if byName(r)["update_user_tier"].ReversibilityClass != registry.ClassC {
		t.Fatal("a multi-argument read must not be accepted as a pre-image reader")
	}
}

// Fail closed: an unrecognized verb is the case most likely to be something
// destructive nobody named clearly, so it gets the strictest treatment,
// never the most permissive.
func TestDiscover_UnclassifiableBecomesGated(t *testing.T) {
	r := FromMCPTools([]mcpclient.Tool{tool("frobnicate_widget", "", "widget_id")})
	assertLoads(t, r)

	got := byName(r)["frobnicate_widget"]
	if got.ReversibilityClass != registry.ClassC {
		t.Fatalf("an unclassifiable tool must fail closed to class C, got %s", got.ReversibilityClass)
	}
	if got.ReviewerRole == "" {
		t.Fatal("a gated tool needs a reviewer role or nothing can ever approve it")
	}
	if len(r.Unreadable) != 1 {
		t.Fatalf("the banner needs to name what couldn't be read, got %v", r.Unreadable)
	}
}

// Everything discovery emits is MCP-backed and forwards under its own name -
// that's what makes the catalog runnable against the server it was scanned
// from without any editing.
func TestDiscover_EverythingIsMCPBackedUnderItsOwnName(t *testing.T) {
	r := FromMCPTools([]mcpclient.Tool{
		tool("get_user", "Read a user.", "user_id"),
		tool("delete_user", "Delete a user forever.", "user_id"),
	})
	reg := assertLoads(t, r)

	for name, tool := range reg.All() {
		if !tool.IsMCPBacked() {
			t.Fatalf("%s is not MCP-backed", name)
		}
		if tool.UpstreamMCPTool() != name {
			t.Fatalf("%s should forward under its own name, got %q", name, tool.UpstreamMCPTool())
		}
	}
}

func TestDiscover_SchemaEnumAndRequiredCarryThrough(t *testing.T) {
	r := FromMCPTools([]mcpclient.Tool{{
		Name: "set_mode", Description: "Set the mode.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"mode":  map[string]any{"type": "string", "enum": []any{"on", "off"}},
				"count": map[string]any{"type": "integer"},
				"force": map[string]any{"type": "boolean"},
			},
			"required": []any{"mode"},
		},
	}})
	assertLoads(t, r)

	schema := byName(r)["set_mode"].ArgsSchema
	if !schema["mode"].Required {
		t.Fatal("required carried through incorrectly")
	}
	if len(schema["mode"].Enum) != 2 {
		t.Fatalf("enum carried through incorrectly: %v", schema["mode"].Enum)
	}
	if schema["count"].Type != "number" || schema["force"].Type != "bool" {
		t.Fatalf("JSON Schema types mapped incorrectly: %+v", schema)
	}
}
