package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/RinwallDev/rinwall/internal/authn"
)

// ServeStdio speaks MCP's stdio transport: newline-delimited JSON-RPC
// messages read from in, responses written one per line to out. This is
// how Claude Desktop, Claude Code's stdio entries, and most editor
// integrations run a local MCP server - they launch the process and own
// its stdin/stdout - so it is the "add one line to your MCP config" path.
//
// Two things differ from the HTTP transport, both by the nature of stdio:
//
//   - identity is fixed for the life of the process. A launched process
//     serves exactly one local user; there is no per-request credential to
//     verify. cmd/rinwall resolves it once at startup (a JWT from the
//     environment, or zero-config mode's local identity) and passes it in.
//   - out must carry protocol messages and nothing else. A stray print to
//     stdout corrupts the stream from the client's point of view. Every
//     diagnostic in this codebase already goes to stderr, and cmd/rinwall
//     additionally redirects os.Stdout to stderr before calling this, so
//     the only writer to the real stdout is the encoder below.
//
// Returns nil when in reaches EOF - the client closed the pipe, which is
// how a stdio server is told to exit.
func (s *Server) ServeStdio(ctx context.Context, in io.Reader, out io.Writer, identity authn.Claims, agentID string) error {
	r := bufio.NewReaderSize(in, 1<<20)
	enc := json.NewEncoder(out)
	for {
		line, err := r.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			if resp := s.handleStdioLine(ctx, line, identity, agentID); resp != nil {
				if err := enc.Encode(resp); err != nil {
					return err
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// handleStdioLine returns the response for one message, or nil for a
// notification (which gets no response on any transport).
func (s *Server) handleStdioLine(ctx context.Context, line []byte, identity authn.Claims, agentID string) map[string]any {
	var req rpcRequest
	if err := json.Unmarshal(line, &req); err != nil {
		return rpcError(nil, -32700, "parse error")
	}
	if len(req.ID) == 0 {
		return nil
	}
	return s.dispatch(ctx, req, func() (authn.Claims, error) { return identity, nil }, agentID)
}
