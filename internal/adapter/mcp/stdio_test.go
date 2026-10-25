package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/RinwallDev/rinwall/internal/authn"
)

// runStdio feeds a script of newline-delimited messages through
// ServeStdio and returns stdout split into lines - exactly what a client
// that launched this process would read.
func runStdio(t *testing.T, script string) []string {
	t.Helper()
	h, verifier := newTestComponents(t)
	var out bytes.Buffer
	identity := authn.Claims{DelegatedUser: "alex@example.com", DelegatedRole: "support"}
	if err := NewServer(h, verifier).ServeStdio(context.Background(), strings.NewReader(script), &out, identity, "stdio"); err != nil {
		t.Fatalf("ServeStdio: %v", err)
	}
	raw := strings.TrimRight(out.String(), "\n")
	if raw == "" {
		return nil
	}
	return strings.Split(raw, "\n")
}

func decodeLine(t *testing.T, line string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("stdout line is not valid JSON - the stream is corrupt from a client's point of view: %q (%v)", line, err)
	}
	return m
}

// The full handshake a real client performs, with the one property that
// matters most for stdio: every byte on stdout is a protocol message.
func TestStdio_HandshakeListAndCall(t *testing.T) {
	lines := runStdio(t, strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_user","arguments":{"user_id":"42"}}}`,
	}, "\n")+"\n")

	// Three requests, one notification: exactly three responses, no
	// acknowledgement line for the notification, nothing else at all.
	if len(lines) != 3 {
		t.Fatalf("expected exactly 3 response lines (notification gets none), got %d:\n%s", len(lines), strings.Join(lines, "\n"))
	}

	init := decodeLine(t, lines[0])
	if pv := init["result"].(map[string]any)["protocolVersion"]; pv != "2025-03-26" {
		t.Fatalf("expected the client's supported version echoed back, got %v", pv)
	}

	list := decodeLine(t, lines[1])
	tools := list["result"].(map[string]any)["tools"].([]any)
	foundGetUser := false
	for _, raw := range tools {
		tool := raw.(map[string]any)
		if tool["name"] == "get_user" && tool["description"] == "Look up a customer record by id" {
			foundGetUser = true
		}
	}
	if !foundGetUser {
		t.Fatalf("expected get_user with its description in the stdio tools/list, got %v", tools)
	}

	call := decodeLine(t, lines[2])
	if call["id"] != float64(3) {
		t.Fatalf("response id must match the request, got %v", call["id"])
	}
	result := call["result"].(map[string]any)
	if result["isError"] != false {
		t.Fatalf("expected the call to execute under the fixed identity, got %v", result)
	}
}

func TestStdio_ParseErrorAndEOF(t *testing.T) {
	lines := runStdio(t, "this is not json\n\n{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"nope\"}\n")
	if len(lines) != 2 {
		t.Fatalf("expected a parse error and a method-not-found, got %d lines: %v", len(lines), lines)
	}
	if e := decodeLine(t, lines[0])["error"].(map[string]any); e["code"] != float64(-32700) {
		t.Fatalf("expected -32700 parse error, got %v", e)
	}
	if e := decodeLine(t, lines[1])["error"].(map[string]any); e["code"] != float64(-32601) {
		t.Fatalf("expected -32601 method not found, got %v", e)
	}
	// Blank lines are ignored and EOF ends the loop cleanly - runStdio
	// would have failed on a returned error.
}
