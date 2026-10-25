package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadYAML(t *testing.T, body string) (*Registry, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tools.yaml")
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return LoadFromYAML(path)
}

// The whole point of MCP-to-MCP passthrough: a catalog scanned from an MCP
// server has no upstream HTTP route to declare, and must load anyway.
func TestLoad_MCPBackedToolNeedsNoHTTPRoute(t *testing.T) {
	reg, err := loadYAML(t, `
tools:
  - name: get_user
    reversibility_class: B
    mcp_tool: "="
    args_schema:
      user_id: {type: string, required: true}
`)
	if err != nil {
		t.Fatalf("an mcp-backed tool should load without method/path: %v", err)
	}
	tool, ok := reg.Get("get_user")
	if !ok {
		t.Fatal("tool did not load")
	}
	if !tool.IsMCPBacked() {
		t.Fatal("expected the tool to read as MCP-backed")
	}
	if got := tool.UpstreamMCPTool(); got != "get_user" {
		t.Fatalf(`mcp_tool "=" should resolve to the tool's own name, got %q`, got)
	}
}

func TestLoad_MCPToolRenamesUpstream(t *testing.T) {
	reg, err := loadYAML(t, `
tools:
  - name: safe_get_user
    reversibility_class: B
    mcp_tool: upstream_get_user
    args_schema: {}
`)
	if err != nil {
		t.Fatal(err)
	}
	tool, _ := reg.Get("safe_get_user")
	if got := tool.UpstreamMCPTool(); got != "upstream_get_user" {
		t.Fatalf("expected the explicit upstream name, got %q", got)
	}
}

// Unlike db_role and aws_role, MCP-backed tools are deliberately NOT
// restricted to Class B - an upstream catalog is the general case and
// routinely contains irreversible tools, and refusing to load those would
// push exactly the calls that most need gating back outside the firewall.
func TestLoad_MCPBackedToolMayBeClassC(t *testing.T) {
	if _, err := loadYAML(t, `
tools:
  - name: close_account
    reversibility_class: C
    mcp_tool: "="
    reviewer_role: admin-lead
    args_schema: {}
`); err != nil {
		t.Fatalf("a class C mcp-backed tool must load: %v", err)
	}
}

// A Class A tool whose pre-image is declared in the HTTP shape would look
// compensable and silently do nothing at the moment compensation is
// actually needed - catch it at load time instead.
func TestLoad_MCPClassARequiresMCPPreImage(t *testing.T) {
	_, err := loadYAML(t, `
tools:
  - name: update_customer_tier
    reversibility_class: A
    mcp_tool: "="
    reviewer_role: admin-lead
    compensate_fields: [tier]
    pre_image:
      method: GET
      path: /users/{user_id}
    args_schema: {}
`)
	if err == nil {
		t.Fatal("expected a class A mcp-backed tool with an HTTP pre_image to be rejected")
	}
	if !strings.Contains(err.Error(), "pre_image.mcp_tool") {
		t.Fatalf("the error should name the field that's wrong, got: %v", err)
	}
}

func TestLoad_MCPClassAWithMCPPreImageLoads(t *testing.T) {
	if _, err := loadYAML(t, `
tools:
  - name: update_customer_tier
    reversibility_class: A
    mcp_tool: "="
    resource_arg: user_id
    reviewer_role: admin-lead
    compensate_fields: [tier]
    pre_image:
      mcp_tool: get_user
    args_schema:
      user_id: {type: string, required: true}
      tier: {type: string, required: true}
`); err != nil {
		t.Fatalf("a class A mcp-backed tool with an MCP pre_image must load: %v", err)
	}
}

// The inverse: an MCP pre-image on an HTTP-backed tool would never be
// reachable, since the HTTP path has no MCP client to call it with.
func TestLoad_MCPPreImageOnHTTPToolRejected(t *testing.T) {
	_, err := loadYAML(t, `
tools:
  - name: update_customer_tier
    reversibility_class: A
    method: PATCH
    path: /users/{user_id}/tier
    reviewer_role: admin-lead
    compensate_fields: [tier]
    pre_image:
      mcp_tool: get_user
    args_schema: {}
`)
	if err == nil {
		t.Fatal("expected an MCP pre_image on an HTTP-backed tool to be rejected")
	}
}

func TestLoad_UpstreamKindsAreMutuallyExclusive(t *testing.T) {
	cases := map[string]string{
		"mcp + http": `
tools:
  - name: t
    reversibility_class: B
    mcp_tool: "="
    method: GET
    path: /x
    args_schema: {}
`,
		"mcp + db": `
tools:
  - name: t
    reversibility_class: B
    mcp_tool: "="
    db_role: readonly
    query: "SELECT 1"
    args_schema: {}
`,
		"mcp + aws": `
tools:
  - name: t
    reversibility_class: B
    mcp_tool: "="
    aws_role: reader
    aws_s3_bucket: b
    aws_s3_key_arg: key
    args_schema:
      key: {type: string}
`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := loadYAML(t, body); err == nil {
				t.Fatal("expected a tool declaring two upstream kinds to be rejected")
			}
		})
	}
}

// Fail-closed regression: an HTTP-backed tool with no route at all is still
// rejected. The MCP branch added an early return, and an early return in
// the wrong place is exactly how a check like this goes missing.
func TestLoad_HTTPToolStillRequiresMethodAndPath(t *testing.T) {
	if _, err := loadYAML(t, `
tools:
  - name: mystery
    reversibility_class: B
    args_schema: {}
`); err == nil {
		t.Fatal("expected a tool with no upstream of any kind to be rejected")
	}
}

// The shipped catalog has to actually load - it's the one every live
// verification and the walkthroughs in GETTING_STARTED.md and docs/REFERENCE.md depend on.
func TestLoad_ShippedExampleCatalog(t *testing.T) {
	reg, err := LoadFromYAML("../../examples/tools.yaml")
	if err != nil {
		t.Fatalf("examples/tools.yaml does not load: %v", err)
	}
	var http, db, aws, mcp int
	for _, tool := range reg.All() {
		switch {
		case tool.IsDBBacked():
			db++
		case tool.IsAWSBacked():
			aws++
		case tool.IsMCPBacked():
			mcp++
		default:
			http++
		}
	}
	if http == 0 || db == 0 || aws == 0 || mcp == 0 {
		t.Fatalf("expected the example catalog to exercise all four upstream kinds, got http=%d db=%d aws=%d mcp=%d", http, db, aws, mcp)
	}
}

// --- RequireReviewed: the strict-catalog gate ---------------------------

func TestRequireReviewed_AllAnnotatedPasses(t *testing.T) {
	reg, err := loadYAML(t, `
tools:
  - name: get_user
    reversibility_class: B
    mcp_tool: "="
    reviewed_by: "alex@example.com"
    reviewed_at: "2026-09-13"
    args_schema:
      user_id: {type: string, required: true}
`)
	if err != nil {
		t.Fatal(err)
	}
	if err := RequireReviewed(reg); err != nil {
		t.Fatalf("expected a fully-annotated catalog to pass, got: %v", err)
	}
}

func TestRequireReviewed_MissingAnnotationFails(t *testing.T) {
	reg, err := loadYAML(t, `
tools:
  - name: get_user
    reversibility_class: B
    mcp_tool: "="
    args_schema:
      user_id: {type: string, required: true}
`)
	if err != nil {
		t.Fatal(err)
	}
	if err := RequireReviewed(reg); err == nil {
		t.Fatal("expected a tool with no reviewed_by/reviewed_at to fail")
	}
}

func TestRequireReviewed_TODOPlaceholderTreatedAsUnreviewed(t *testing.T) {
	// Exactly what blastradius --emit-registry leaves behind - must not be
	// mistaken for a real review just because the fields are non-empty.
	reg, err := loadYAML(t, `
tools:
  - name: get_user
    reversibility_class: B
    mcp_tool: "="
    reviewed_by: "TODO-your-name-after-actually-reviewing-this-tool"
    reviewed_at: "TODO-YYYY-MM-DD"
    args_schema:
      user_id: {type: string, required: true}
`)
	if err != nil {
		t.Fatal(err)
	}
	if err := RequireReviewed(reg); err == nil {
		t.Fatal("expected an unedited TODO placeholder to still fail the check")
	}
}

func TestRequireReviewed_InvalidDateFails(t *testing.T) {
	reg, err := loadYAML(t, `
tools:
  - name: get_user
    reversibility_class: B
    mcp_tool: "="
    reviewed_by: "alex@example.com"
    reviewed_at: "sometime last week"
    args_schema:
      user_id: {type: string, required: true}
`)
	if err != nil {
		t.Fatal(err)
	}
	if err := RequireReviewed(reg); err == nil {
		t.Fatal("expected a reviewed_at that isn't a real date to fail")
	}
}

func TestRequireReviewed_AcceptsRFC3339AndPlainDate(t *testing.T) {
	reg, err := loadYAML(t, `
tools:
  - name: get_user
    reversibility_class: B
    mcp_tool: "="
    reviewed_by: "alex@example.com"
    reviewed_at: "2026-09-13T10:00:00Z"
    args_schema:
      user_id: {type: string, required: true}
  - name: log_event
    reversibility_class: B
    mcp_tool: "="
    reviewed_by: "alex@example.com"
    reviewed_at: "2026-09-13"
    args_schema:
      message: {type: string, required: true}
`)
	if err != nil {
		t.Fatal(err)
	}
	if err := RequireReviewed(reg); err != nil {
		t.Fatalf("expected both RFC3339 and plain YYYY-MM-DD dates to be accepted, got: %v", err)
	}
}

// The example catalog this project ships is meant to be a real
// demonstration of what a reviewed catalog looks like - if this ever
// fails, examples/tools.yaml has a tool missing its annotation.
func TestRequireReviewed_ShippedExampleCatalogPasses(t *testing.T) {
	reg, err := LoadFromYAML("../../examples/tools.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := RequireReviewed(reg); err != nil {
		t.Fatalf("expected the shipped example catalog to pass require_reviewed_tools, got: %v", err)
	}
}

// VisualProvenanceJudge forces step-up regardless of ReversibilityClass
// (see internal/handler.assessVisualProvenance) - so it needs a
// reviewer_role for the same reason Class A/C do: a flagged call with no
// reviewer_role would create a pending approval nobody could ever satisfy.
func TestLoad_VisualProvenanceJudgeRequiresReviewerRole(t *testing.T) {
	_, err := loadYAML(t, `
tools:
  - name: computer
    reversibility_class: B
    method: POST
    path: /events
    visual_provenance_judge: true
    args_schema:
      action: {type: string}
`)
	if err == nil {
		t.Fatal("expected a visual_provenance_judge tool with no reviewer_role to be rejected")
	}
	if !strings.Contains(err.Error(), "visual_provenance_judge") {
		t.Fatalf("the error should name the actual setting that requires it, got: %v", err)
	}
}

func TestLoad_VisualProvenanceJudgeWithReviewerRoleLoads(t *testing.T) {
	if _, err := loadYAML(t, `
tools:
  - name: computer
    reversibility_class: B
    method: POST
    path: /events
    reviewer_role: admin-lead
    visual_provenance_judge: true
    args_schema:
      action: {type: string}
`); err != nil {
		t.Fatalf("a visual_provenance_judge tool with a reviewer_role must load: %v", err)
	}
}
