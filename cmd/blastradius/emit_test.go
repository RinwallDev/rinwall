package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/RinwallDev/rinwall/internal/classify"
	"github.com/RinwallDev/rinwall/internal/mcpclient"
	"github.com/RinwallDev/rinwall/internal/registry"
)

// TestEmitStarterRegistry_AlwaysCarriesReviewedTODOs is the actual proof
// behind the strict-catalog gate's other half: a freshly-scanned catalog
// must NEVER load under require_reviewed_tools until a human has touched
// it, even a catalog that's entirely read-only and has zero other TODOs.
func TestEmitStarterRegistry_AlwaysCarriesReviewedTODOs(t *testing.T) {
	tools := []mcpclient.Tool{
		{Name: "get_user", InputSchema: map[string]any{"properties": map[string]any{
			"user_id": map[string]any{"type": "string"},
		}}},
	}
	results := []classify.Result{{Tool: "get_user", Class: registry.ClassB}}

	path := filepath.Join(t.TempDir(), "emitted.yaml")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := emitStarterRegistry(f, tools, results); err != nil {
		t.Fatal(err)
	}
	f.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("reviewed_by: TODO")) {
		t.Fatalf("expected every emitted tool to carry a reviewed_by TODO, got:\n%s", raw)
	}

	// A read-only, single-tool catalog like this one loads fine normally -
	// the TODO placeholders never block ordinary loading.
	reg, err := registry.LoadFromYAML(path)
	if err != nil {
		t.Fatalf("expected the emitted catalog to load normally despite the reviewed_by/reviewed_at TODOs, got: %v", err)
	}

	// But it must fail the strict gate, since nobody has actually reviewed
	// it - this is the entire point of always emitting the TODO, even for
	// a tool with no other TODO at all.
	if err := registry.RequireReviewed(reg); err == nil {
		t.Fatal("expected a freshly-emitted catalog to fail require_reviewed_tools until a human edits it")
	}
}
