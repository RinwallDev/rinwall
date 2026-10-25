package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/RinwallDev/rinwall/internal/authn"
	"github.com/RinwallDev/rinwall/internal/discover"
	"github.com/RinwallDev/rinwall/internal/mcpclient"
	"github.com/RinwallDev/rinwall/internal/registry"
)

// Zero-config mode: `proxy --mcp http://localhost:3000/mcp` and the
// firewall is running in front of that server, with no Vault, no tool
// catalog, no policy bundle, and no token to mint first.
//
// The bet this makes is that the thing worth showing someone in the first
// sixty seconds does not depend on any of those five: Class C still cannot
// execute without a human approving it, Class A still auto-compensates
// when something later in the run fails, and a tool nobody can classify
// still fails closed to Class C. Everything zero-config gives up is about
// WHO may do what and where the keys live - not about what an action can
// do or whether it can be undone.
//
// What it gives up, stated so the banner can repeat it rather than leaving
// an evaluator to discover it later:
//
//   - No authentication. A request with no credential is accepted as a
//     fixed local identity (a request WITH one is still verified strictly -
//     see authn.NewOpenVerifier). This is why the listener refuses any
//     address that isn't loopback.
//   - No role policy. Every role may attempt every tool; see
//     policy.defaultBundle.
//   - No Vault. Session seeds come from crypto/rand and the signing key
//     lives in memory only - see capability/local.go.
//   - A heuristic catalog. Classifications come from names, descriptions,
//     and schemas, and every uncertain call is resolved toward "gate it."

const (
	zeroConfigReviewerUser = "reviewer@localhost"
	zeroConfigAgentUser    = "local"
	zeroConfigAgentRole    = "local"
)

type zeroConfig struct {
	upstreamURL   string
	reviewerToken string
	discovery     discover.Result
	statePath     string
	auditPath     string
}

// isLoopback reports whether a bind address is safely local. Zero-config
// has no authentication, so a non-loopback listener would mean anyone able
// to reach the port controls the agent's tools - a refusal at startup makes
// that structurally impossible instead of a warning nobody reads.
func isLoopback(host string) bool {
	if host == "" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// setupZeroConfig fills in a Config from nothing but an upstream URL, then
// scans that upstream and classifies what it finds.
func setupZeroConfig(ctx context.Context, upstreamURL, authValue string, cfg *Config) (*zeroConfig, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("zero-config: generating a session JWT secret: %w", err)
	}
	// Per-process and random on purpose: a token minted by one run must not
	// be usable against the next, and there is no shipped default secret
	// anyone could copy into a real deployment.
	cfg.JWTSecret = hex.EncodeToString(secret)

	stateDir := filepath.Join(os.TempDir(), "rinwall")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("zero-config: creating state directory %s: %w", stateDir, err)
	}
	// Deliberately not the working directory: starting a tool to try it out
	// should not leave files in someone's project.
	cfg.DBPath = filepath.Join(stateDir, "state.db")
	cfg.AuditLogPath = filepath.Join(stateDir, "audit.log")
	cfg.MCPUpstreamURL = upstreamURL

	var opts []mcpclient.Option
	if authValue != "" {
		opts = append(opts, mcpclient.WithAuthorization(authValue))
	}
	client := mcpclient.New(upstreamURL, opts...)

	log.Printf("scanning %s ...", upstreamURL)
	result, err := discover.FromMCPServer(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("zero-config: %w", err)
	}

	token, err := authn.Mint(cfg.JWTSecret, zeroConfigReviewerUser, discover.DefaultReviewerRole, 24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("zero-config: minting a reviewer token: %w", err)
	}

	return &zeroConfig{
		upstreamURL: upstreamURL, reviewerToken: token, discovery: result,
		statePath: cfg.DBPath, auditPath: cfg.AuditLogPath,
	}, nil
}

func zeroConfigVerifier(secret string) *authn.Verifier {
	return authn.NewOpenVerifier(secret, authn.Claims{
		DelegatedUser: zeroConfigAgentUser,
		DelegatedRole: zeroConfigAgentRole,
	})
}

// printBanner is the whole onboarding experience: what was found, what is
// gated, what is switched off, and the one token needed to approve
// something. Written to be read once by someone deciding whether this is
// worth more of their afternoon.
func (z *zeroConfig) printBanner(reg *registry.Registry, port string) {
	byClass := map[registry.ReversibilityClass][]string{}
	for name, tool := range reg.All() {
		byClass[tool.ReversibilityClass] = append(byClass[tool.ReversibilityClass], name)
	}
	for _, names := range byClass {
		sort.Strings(names)
	}

	out := &strings.Builder{}
	line := func(format string, args ...any) { fmt.Fprintf(out, format+"\n", args...) }

	line("")
	line("  RinWall is running in front of %s", z.upstreamURL)
	line("  %s", strings.Repeat("-", 68))
	line("")
	line("  Scanned %d tools and classified them by what they can undo:", len(reg.All()))
	line("")
	line("    %2d irreversible        needs a human to approve, every time",
		len(byClass[registry.ClassC]))
	for _, n := range byClass[registry.ClassC] {
		line("         %s", n)
	}
	line("    %2d compensable         executes, and is undone automatically if the run fails",
		len(byClass[registry.ClassA]))
	for _, n := range byClass[registry.ClassA] {
		line("         %s", n)
	}
	line("    %2d read-only/retryable executes freely", len(byClass[registry.ClassB]))
	line("")

	if len(z.discovery.Unreadable) > 0 {
		line("  %d tool(s) could not be classified, so they are gated as irreversible:", len(z.discovery.Unreadable))
		line("    %s", strings.Join(z.discovery.Unreadable, ", "))
		line("  That is the safe reading, not the right one - check them.")
		line("")
	}
	if len(z.discovery.Demoted) > 0 {
		line("  %d tool(s) look undoable but nothing here reads their prior state,", len(z.discovery.Demoted))
		line("  so they are gated rather than falsely promised as reversible:")
		line("    %s", strings.Join(z.discovery.Demoted, ", "))
		line("  Giving each a pre_image is the highest-value edit you can make.")
		line("")
	}

	line("  Point your agent at:   http://127.0.0.1:%s/mcp", port)
	line("  Review pending calls:  http://127.0.0.1:%s/admin", port)
	line("")
	line("  To approve something, paste this reviewer token into that page:")
	line("")
	line("    %s", z.reviewerToken)
	line("")
	line("  Audit log: %s", z.auditPath)
	line("  State:     %s", z.statePath)
	line("")
	line("  This is a getting-started mode. It is NOT hardened:")
	line("    - no authentication (any request with no token is accepted as %q)", zeroConfigAgentUser)
	line("    - no role policy (every role may attempt every tool)")
	line("    - no Vault (the signing key is in memory and dies on restart)")
	line("    - the catalog above is heuristic, not reviewed by anyone")
	line("  Loopback only, for exactly those reasons.")
	line("")
	line("  To pin the catalog down and edit it:")
	line("    go run ./cmd/blastradius --mcp %s --emit-registry > tools.yaml", z.upstreamURL)
	line("")

	fmt.Fprint(os.Stderr, out.String())
}
