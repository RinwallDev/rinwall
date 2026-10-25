// Package capability implements the Fast Capability Plane: a root
// capability minted once per agent session (the expensive, Vault-backed
// half - see vault.go) from which every individual tool call is then
// locally attenuated (biscuit.go) into a narrowly-scoped, short-lived
// token with no further network call. The hot path never pays for a
// mint: the only network call is the per-session root.
package capability

import (
	"context"
	"time"
)

type Token struct {
	Value     string
	ExpiresAt time.Time
}

// RootIssuer mints a session-scoped Root. Callers (internal/handler) cache
// the Root per session key and only call MintRoot again once it expires -
// this is the boundary where the real Vault network cost is paid.
type RootIssuer interface {
	MintRoot(ctx context.Context, sessionKey, delegatedUser, delegatedRole string) (Root, error)
}

// Root is attenuated locally, per call, with no network round trip.
type Root interface {
	Attenuate(tool, resource string, ttl time.Duration) (Token, error)
	Expired() bool
}
