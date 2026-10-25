// DB-backed tool execution - the real Vault dynamic-secrets path
// (database/creds/<role>, a genuine CREATE ROLE against the actual
// database) alongside the existing biscuit/HTTP path. A DB-backed tool's
// "capability" is the Vault-minted database credential itself, verified
// by the database server directly - there's no biscuit token to mint or
// attenuate here, because nothing would verify it; the database is
// already the real, independent verifier the way mockupstream is for
// HTTP-backed tools.
package handler

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/RinwallDev/rinwall/internal/proxytypes"
	"github.com/RinwallDev/rinwall/internal/registry"
	"github.com/RinwallDev/rinwall/internal/saga"
)

func (h *Handler) executeDBQuery(ctx context.Context, tool registry.Tool, args map[string]any, resource string, req proxytypes.CallRequest, path string) (proxytypes.CallResult, error) {
	if h.DBSecrets == nil {
		return proxytypes.CallResult{Status: "error",
			Reason: "tool " + tool.Name + " is db-backed but no DBSecrets minter is configured on this proxy"}, nil
	}

	db, err := h.dbCache.getOrMint(ctx, h.Metrics, h.DBSecrets, h.DBDSNTemplate, sessionKeyFor(req), tool.DBRole)
	if err != nil {
		return proxytypes.CallResult{}, fmt.Errorf("handler: get/mint db credential: %w", err)
	}

	queryArgs := make([]any, len(tool.QueryArgs))
	for i, name := range tool.QueryArgs {
		queryArgs[i] = args[name]
	}

	queryDone := h.Metrics.Timer("db_query")
	rows, err := db.QueryContext(ctx, tool.Query, queryArgs...)
	queryDone()
	if err != nil {
		h.Audit.Write(map[string]any{"decision": "ERROR", "tool": tool.Name, "delegated_role": req.DelegatedRole,
			"reason": "db query failed: " + err.Error(), "path": path, "db_role": tool.DBRole})
		return proxytypes.CallResult{Status: "error", Reason: err.Error()}, nil
	}
	defer rows.Close()

	results, err := scanRows(rows)
	if err != nil {
		h.Audit.Write(map[string]any{"decision": "ERROR", "tool": tool.Name, "delegated_role": req.DelegatedRole,
			"reason": "db row scan failed: " + err.Error(), "path": path, "db_role": tool.DBRole})
		return proxytypes.CallResult{Status: "error", Reason: err.Error()}, nil
	}

	// Same response-sanitization boundary as the HTTP path - a db_role
	// scoped to least-privilege columns/rows is the primary control, but
	// sanitize_fields still applies if a query ever returns more than a
	// tool should surface to the agent.
	var parsed any = results
	if len(tool.SanitizeFields) > 0 {
		parsed = stripFields(parsed, tool.SanitizeFields)
	}

	h.Audit.Write(map[string]any{"decision": "EXECUTED", "tool": tool.Name, "delegated_role": req.DelegatedRole,
		"reason": path, "resource": resource, "transport": req.Transport, "agent_id": req.AgentID, "db_role": tool.DBRole})

	if req.RunID != "" {
		h.Sagas.RecordStep(&saga.Step{
			RunID: req.RunID, Tool: tool.Name, ReversibilityClass: string(tool.ReversibilityClass),
			Resource: resource, Args: args, DelegatedUser: req.DelegatedUser, DelegatedRole: req.DelegatedRole,
			AgentID: req.AgentID, ExecutedAt: time.Now(),
		})
	}

	return proxytypes.CallResult{Status: "executed", UpstreamBody: parsed}, nil
}

// scanRows converts a generic *sql.Rows into []map[string]any by column
// name - deliberately generic rather than a fixed struct, since this
// serves whatever SELECT a registry.Tool's Query happens to be.
func scanRows(rows *sql.Rows) ([]map[string]any, error) {
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	var out []map[string]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make(map[string]any, len(cols))
		for i, col := range cols {
			row[col] = vals[i]
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
