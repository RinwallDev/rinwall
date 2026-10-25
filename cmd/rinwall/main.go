// Command proxy is the JIT capability firewall itself: loads the tool
// registry and policy bundle, then serves both the REST and MCP adapters
// against the same transport-agnostic handler.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"
	// pprof-only import: registers /debug/pprof/* on http.DefaultServeMux
	// as a side effect. Never reachable on the main proxy port (its own
	// mux is a separate http.NewServeMux() instance below) - only served
	// at all, and only on 127.0.0.1, when JIT_DEBUG_PPROF is set. A
	// profiling aid for load investigations (see docs/REFERENCE.md's benchmarking
	// section), not a standing feature.
	_ "net/http/pprof"
	"os"
	"strconv"

	// Registers the "pgx" database/sql driver used by DB-backed tools'
	// real Vault dynamic-secrets path (internal/handler/dbquery.go) -
	// pure Go, no cgo, matching this project's SQLite driver choice.
	_ "github.com/jackc/pgx/v5/stdlib"

	vaultapi "github.com/hashicorp/vault/api"
	"gopkg.in/yaml.v3"

	"github.com/RinwallDev/rinwall/internal/adapter/mcp"
	"github.com/RinwallDev/rinwall/internal/adapter/rest"
	"github.com/RinwallDev/rinwall/internal/adminui"
	"github.com/RinwallDev/rinwall/internal/approval"
	"github.com/RinwallDev/rinwall/internal/audit"
	"github.com/RinwallDev/rinwall/internal/authn"
	"github.com/RinwallDev/rinwall/internal/capability"
	"github.com/RinwallDev/rinwall/internal/compliance"
	"github.com/RinwallDev/rinwall/internal/handler"
	"github.com/RinwallDev/rinwall/internal/mcpclient"
	"github.com/RinwallDev/rinwall/internal/policy"
	"github.com/RinwallDev/rinwall/internal/provenance"
	"github.com/RinwallDev/rinwall/internal/registry"
	"github.com/RinwallDev/rinwall/internal/saga"
	"github.com/RinwallDev/rinwall/internal/usage"
	"github.com/RinwallDev/rinwall/internal/visualprovenance"

	anthropic "github.com/anthropics/anthropic-sdk-go"
)

// version is stamped by the release workflow (-ldflags "-X main.version=v0.1.0");
// "dev" means a local build.
var version = "dev"

type Config struct {
	Port            string `yaml:"port"`
	UpstreamURL     string `yaml:"upstream_url"`
	PolicyPath      string `yaml:"policy_path"`
	ToolsPath       string `yaml:"tools_path"`
	JWTSecret       string `yaml:"jwt_secret"`
	AuditLogPath    string `yaml:"audit_log_path"`
	DBPath          string `yaml:"db_path"`
	VaultAddr       string `yaml:"vault_addr"`
	VaultToken      string `yaml:"vault_token"`
	VaultTransitKey string `yaml:"vault_transit_key"`
	// VaultKVMount/VaultKeyringPath locate the biscuit signing keyring in
	// Vault's KV v2 engine (see internal/capability/keyring.go); the
	// signing key itself never lives in this config file. Both have
	// sane defaults and are optional.
	VaultKVMount     string `yaml:"vault_kv_mount,omitempty"`
	VaultKeyringPath string `yaml:"vault_keyring_path,omitempty"`
	// ProvenanceJudgeModel: which model backs the provenance add-on -
	// empty means the package's own default (a fast/cheap model, since
	// this is a narrow classification task). ANTHROPIC_API_KEY itself is
	// read from the environment by the SDK, never stored here.
	ProvenanceJudgeModel string `yaml:"provenance_judge_model,omitempty"`
	// DBDSNTemplate is the real Vault dynamic-secrets path's connection
	// string - a printf-style DSN with two %s placeholders (username,
	// password); everything else (host/port/database/sslmode) is fixed
	// per deployment, only the per-session Vault-minted credential
	// varies. Empty means no DB-backed tool can execute - see
	// internal/handler/dbquery.go and docs/REFERENCE.md's dynamic-secrets
	// section. Not a secret itself (no credentials in the template), so
	// it's fine in this config file, unlike an actual DB password.
	DBDSNTemplate string `yaml:"db_dsn_template,omitempty"`
	// AWSRegion enables the real Vault AWS dynamic-secrets path for
	// aws-backed tools (internal/handler/awsquery.go) - empty means no
	// aws-backed tool can execute. Not a secret; the credentials
	// themselves are minted fresh per call from Vault, never stored here.
	AWSRegion string `yaml:"aws_region,omitempty"`
	// MCPUpstreamURL enables MCP-to-MCP passthrough: the endpoint of the
	// real MCP server this proxy sits in front of, which mcp-backed tools
	// (mcp_tool set in the registry) are forwarded to. Empty means no
	// mcp-backed tool can execute.
	//
	// MCPUpstreamAuthEnv names the ENVIRONMENT VARIABLE holding that
	// server's Authorization header value - never the value itself, which
	// would put a live credential in a config file. This credential is the
	// point of the passthrough: it lives in the proxy, so the agent never
	// holds it and no injected instruction can talk the agent out of it.
	MCPUpstreamURL     string `yaml:"mcp_upstream_url,omitempty"`
	MCPUpstreamAuthEnv string `yaml:"mcp_upstream_auth_env,omitempty"`
	// RequireReviewedTools is the strict-catalog gate (see
	// internal/registry.RequireReviewed): when true, every tool in
	// ToolsPath must carry a real reviewed_by/reviewed_at or this proxy
	// refuses to start, full stop - the structural guard against piping
	// `blastradius --emit-registry` straight into production with zero
	// human judgment applied. Only meaningful outside zero-config mode,
	// which has no config file to set this in and whose entire premise is
	// incompatible with it anyway.
	RequireReviewedTools bool `yaml:"require_reviewed_tools,omitempty"`
	// Real-IdP mode (internal/authn.NewJWKSVerifier): set JWTJWKSURL to
	// verify against a real IdP's published RS256 keys instead of the
	// shared JWTSecret above. JWTIssuer is required whenever JWTJWKSURL is
	// set (enforced by NewJWKSVerifier itself, not just here) - see its
	// doc comment for the cross-app token-replay reasoning. JWTAudience is
	// optional. JWTUserClaim/JWTRoleClaim default to "delegated_user"/
	// "delegated_role" if empty, matching the HS256/cmd/devtoken path -
	// set them only if the IdP's own tokens name these claims differently.
	JWTJWKSURL   string `yaml:"jwt_jwks_url,omitempty"`
	JWTIssuer    string `yaml:"jwt_issuer,omitempty"`
	JWTAudience  string `yaml:"jwt_audience,omitempty"`
	JWTUserClaim string `yaml:"jwt_user_claim,omitempty"`
	JWTRoleClaim string `yaml:"jwt_role_claim,omitempty"`
	// StatePostgresDSN is the entire difference between "single instance,
	// SQLite + local JSONL audit log" (empty, the default - exactly
	// today's behavior) and "N replicas, Postgres-backed, safe for real
	// concurrent multi-instance operation" (set). When set, the approval,
	// saga, and audit state all move to this one Postgres database
	// (different tables, one connection string to operate) instead of
	// DBPath/AuditLogPath, and every store becomes genuinely transactional
	// across instances rather than relying on an in-process mutex - see
	// internal/approval/postgres.go's package doc for why that distinction
	// matters. Not a secret itself if it embeds no credential (same
	// convention as DBDSNTemplate above), but most real deployments will
	// want it sourced from an env var in practice.
	StatePostgresDSN string `yaml:"state_postgres_dsn,omitempty"`
}

func loadConfig(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return Config{}, err
	}
	return c, nil
}

// parseOptionalTime returns (nil, nil) for an empty string - "no bound" -
// rather than erroring, so GET /compliance/report?from=...&to=... can
// leave either side open-ended.
func parseOptionalTime(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func main() {
	mcpFlag := flag.String("mcp", "", "zero-config mode: URL of an MCP server to sit in front of, e.g. http://localhost:3000/mcp. Scans it, classifies its tools, and runs with no Vault, catalog, policy bundle, or token needed. Loopback only - see zeroconfig.go")
	mcpAuthFlag := flag.String("mcp-auth", "", "zero-config mode: Authorization header value for that upstream, if it needs one. Prefer --mcp-auth-env so a credential never lands in shell history")
	mcpAuthEnvFlag := flag.String("mcp-auth-env", "", "zero-config mode: NAME of an environment variable holding the upstream's Authorization header value")
	configFlag := flag.String("config", "", "path to config.yaml (default config/config.yaml; a bare positional path also works)")
	bindFlag := flag.String("bind", "", "address to listen on (default: all interfaces; zero-config mode requires loopback)")
	portFlag := flag.String("port", "", "port to listen on, overriding the config file")
	versionFlag := flag.Bool("version", false, "print the version and exit")
	stdioFlag := flag.Bool("stdio", false, "also serve MCP over stdin/stdout, for clients that launch a local server (Claude Desktop, Claude Code stdio entries). Identity: $JIT_STDIO_JWT, or zero-config mode's local identity. All logs go to stderr")
	flag.Parse()
	if *versionFlag {
		fmt.Println("rinwall", version)
		return
	}

	// MCP's stdio transport owns stdout: anything else written there
	// corrupts the stream. Keep the real handle for the protocol and send
	// every other print in the process to stderr - done before anything
	// can print, as a hard guarantee rather than a convention.
	var protocolOut *os.File
	if *stdioFlag {
		protocolOut = os.Stdout
		os.Stdout = os.Stderr
	}

	configPath := *configFlag
	if configPath == "" && flag.NArg() > 0 {
		configPath = flag.Arg(0)
	}

	var (
		cfg Config
		zc  *zeroConfig
		err error
	)
	if *mcpFlag != "" {
		if configPath != "" {
			log.Fatalf("--mcp is zero-config mode and takes no config file; pass one or the other")
		}
		cfg = Config{Port: "8080"}
		if *portFlag != "" {
			cfg.Port = *portFlag
		}
		// No authentication in this mode, so a listener anyone can reach is
		// a listener anyone can drive the agent's tools through. Refuse at
		// startup rather than warn - see zeroconfig.go's isLoopback.
		if !isLoopback(*bindFlag) {
			log.Fatalf("--bind %s: zero-config mode has no authentication and will only listen on loopback.\n"+
				"To serve a real address, write a config file with a JWT secret and a policy bundle.", *bindFlag)
		}
		auth := *mcpAuthFlag
		if *mcpAuthEnvFlag != "" {
			if v := os.Getenv(*mcpAuthEnvFlag); v != "" {
				auth = v
			} else {
				log.Printf("WARNING: --mcp-auth-env names $%s but it is unset - scanning and forwarding with no credential", *mcpAuthEnvFlag)
			}
		}
		zc, err = setupZeroConfig(context.Background(), *mcpFlag, auth, &cfg)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		if configPath == "" {
			configPath = "config/config.yaml"
		}
		cfg, err = loadConfig(configPath)
		if err != nil {
			log.Fatalf("config: %v", err)
		}
		if *portFlag != "" {
			cfg.Port = *portFlag
		}
	}

	if os.Getenv("JIT_DEBUG_PPROF") != "" {
		go func() {
			log.Println("debug pprof listening on 127.0.0.1:6060 (JIT_DEBUG_PPROF set) - dev-only, never enable in production")
			log.Println(http.ListenAndServe("127.0.0.1:6060", nil))
		}()
	}

	var (
		reg         *registry.Registry
		pol         *policy.Engine
		vaultClient *vaultapi.Client
		capIssuer   *capability.BiscuitRootIssuer
	)

	if zc != nil {
		// Everything here is the Vault-free, catalog-free path. Each piece
		// is a real implementation with a documented cost, not a stub - see
		// internal/discover, policy.NewDefault, and capability/local.go.
		reg, err = registry.FromTools(zc.discovery.Tools)
		if err != nil {
			log.Fatalf("registry: the scanned catalog did not validate: %v", err)
		}
		pol, err = policy.NewDefault(context.Background())
		if err != nil {
			log.Fatalf("policy: %v", err)
		}
		capIssuer, err = capability.NewBiscuitRootIssuer(context.Background(),
			&capability.EphemeralKeyRingStore{}, capability.LocalSeedMinter{})
		if err != nil {
			log.Fatalf("biscuit root issuer: %v", err)
		}
	} else {
		reg, err = registry.LoadFromYAML(cfg.ToolsPath)
		if err != nil {
			log.Fatalf("registry: %v", err)
		}
		log.Printf("loaded %d tools from %s", len(reg.All()), cfg.ToolsPath)
		if cfg.RequireReviewedTools {
			if err := registry.RequireReviewed(reg); err != nil {
				log.Fatalf("registry: %v", err)
			}
			log.Printf("require_reviewed_tools is set - every tool in this catalog carries a real reviewed_by/reviewed_at")
		}

		pol, err = policy.New(context.Background(), cfg.PolicyPath)
		if err != nil {
			log.Fatalf("policy: %v", err)
		}

		vaultClient, err = capability.NewVaultClient(cfg.VaultAddr, cfg.VaultToken)
		if err != nil {
			log.Fatalf("vault client: %v", err)
		}
		seedMinter := capability.NewVaultSeedMinter(vaultClient, cfg.VaultTransitKey)
		kvMount := cfg.VaultKVMount
		if kvMount == "" {
			kvMount = "secret"
		}
		keyringPath := cfg.VaultKeyringPath
		if keyringPath == "" {
			keyringPath = "jit/biscuit-keyring"
		}
		keyringStore := capability.NewVaultKeyRingStore(vaultClient, kvMount, keyringPath)
		capIssuer, err = capability.NewBiscuitRootIssuer(context.Background(), keyringStore, seedMinter)
		if err != nil {
			log.Fatalf("biscuit root issuer: %v", err)
		}
		currentKeyHex, err := capIssuer.CurrentPublicKeyHex()
		if err != nil {
			log.Fatalf("biscuit root issuer: %v", err)
		}
		log.Printf("biscuit signing key ready (keyring persisted in Vault KV at %s/%s) - current public key: %s - verifiers should fetch GET /biscuit-keys, not hardcode this", kvMount, keyringPath, currentKeyHex)
	}

	var appr *approval.Store
	var sagas *saga.Store
	var aud *audit.Logger
	multiInstance := cfg.StatePostgresDSN != ""
	if multiInstance {
		appr, err = approval.NewPostgresStore(cfg.StatePostgresDSN)
		if err != nil {
			log.Fatalf("approval store (postgres): %v", err)
		}
		sagas, err = saga.NewPostgresStore(cfg.StatePostgresDSN)
		if err != nil {
			log.Fatalf("saga store (postgres): %v", err)
		}
		aud, err = audit.OpenPostgres(cfg.StatePostgresDSN)
		if err != nil {
			log.Fatalf("audit (postgres): %v", err)
		}
		log.Printf("state backend: Postgres (%s) - safe for multiple replicas of this proxy against the same database", cfg.StatePostgresDSN)
	} else {
		appr, err = approval.NewPersistentStore(cfg.DBPath)
		if err != nil {
			log.Fatalf("approval store: %v", err)
		}
		// Same SQLite file as the approval store, a separate table - one
		// persistence file for the proxy's own state is simpler to operate
		// than two, and the tables don't interact.
		sagas, err = saga.NewPersistentStore(cfg.DBPath)
		if err != nil {
			log.Fatalf("saga store: %v", err)
		}
		aud, err = audit.Open(cfg.AuditLogPath)
		if err != nil {
			log.Fatalf("audit: %v", err)
		}
		log.Printf("state backend: local SQLite (%s) + local JSONL audit log (%s) - single instance only, see state_postgres_dsn for multi-instance/HA", cfg.DBPath, cfg.AuditLogPath)
	}
	defer aud.Close()

	var verifier *authn.Verifier
	switch {
	case zc != nil:
		verifier = zeroConfigVerifier(cfg.JWTSecret)
	case cfg.JWTJWKSURL != "":
		verifier, err = authn.NewJWKSVerifier(cfg.JWTJWKSURL, cfg.JWTIssuer, cfg.JWTAudience, cfg.JWTUserClaim, cfg.JWTRoleClaim)
		if err != nil {
			log.Fatalf("authn: %v", err)
		}
		log.Printf("identity: real IdP mode - verifying RS256 tokens against JWKS at %s (issuer=%s)", cfg.JWTJWKSURL, cfg.JWTIssuer)
	default:
		verifier = authn.NewVerifier(cfg.JWTSecret)
		log.Printf("identity: HS256 shared-secret mode (dev/self-hosted) - see jwt_jwks_url for real IdP integration")
	}

	h := handler.New(reg, pol, capIssuer, appr, aud, sagas, cfg.UpstreamURL)

	// Real Vault dynamic-secrets path for DB-backed tools (db_role set in
	// the registry) - shares the same Vault client as the biscuit
	// keyring/seed minter above, since it's the same Vault deployment.
	// Opt-in the same way the provenance judge is: wired here only if
	// db_dsn_template is configured, and only takes effect for a tool
	// that actually sets db_role - see internal/handler/dbquery.go.
	if cfg.DBDSNTemplate != "" {
		h.DBSecrets = capability.NewVaultDBCredentialMinter(vaultClient)
		h.DBDSNTemplate = cfg.DBDSNTemplate
		log.Printf("real Vault database dynamic-secrets path enabled for db-backed tools")
	}
	if cfg.AWSRegion != "" {
		h.AWSSecrets = capability.NewVaultAWSCredentialMinter(vaultClient)
		h.AWSRegion = cfg.AWSRegion
		log.Printf("real Vault AWS dynamic-secrets path enabled for aws-backed tools (region=%s)", cfg.AWSRegion)
	}
	if cfg.MCPUpstreamURL != "" {
		opts := []mcpclient.Option{}
		if cfg.MCPUpstreamAuthEnv != "" {
			if v := os.Getenv(cfg.MCPUpstreamAuthEnv); v != "" {
				opts = append(opts, mcpclient.WithAuthorization(v))
				log.Printf("upstream MCP credential loaded from $%s (held by the proxy, never sent to the agent)", cfg.MCPUpstreamAuthEnv)
			} else {
				// Loud, not fatal: a public/local MCP server legitimately
				// needs no credential, and failing startup would break that
				// case. But a config that names an env var and finds it
				// empty is far more likely a deployment mistake than an
				// intent, so it must not pass silently.
				log.Printf("WARNING: mcp_upstream_auth_env names $%s but it is unset - forwarding to the upstream MCP server with no credential", cfg.MCPUpstreamAuthEnv)
			}
		}
		h.MCPUpstream = mcpclient.New(cfg.MCPUpstreamURL, opts...)
		log.Printf("MCP-to-MCP passthrough enabled: mcp-backed tools forward to %s", cfg.MCPUpstreamURL)
	}

	// The model-based provenance add-on is opt-in at two levels: a judge
	// must be configured here AT ALL, and a tool must set
	// provenance_judge: true in its registry entry. Missing
	// ANTHROPIC_API_KEY doesn't fail startup - it just means any tool
	// opted into the add-on falls back to the self-reported-only path,
	// exactly as if the add-on didn't exist, per assessProvenance's own
	// error handling.
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		modelName := cfg.ProvenanceJudgeModel
		if modelName == "" {
			modelName = string(anthropic.ModelClaudeHaiku4_5_20251001)
		}
		h.ProvenanceJudge = provenance.NewAnthropicJudge(anthropic.Model(modelName))
		log.Printf("model-based provenance judge enabled (model=%s)", modelName)

		// Same key, same three-gate opt-in shape (deployment + per-tool +
		// per-call), different call site entirely - see
		// registry.Tool.VisualProvenanceJudge and
		// handler.assessVisualProvenance for why this runs independent of
		// ReversibilityClass rather than folding into the check above.
		h.VisualProvenanceJudge = visualprovenance.NewAnthropicJudge(anthropic.Model(modelName))
		log.Printf("model-based visual provenance judge enabled (model=%s)", modelName)
	} else {
		log.Printf("ANTHROPIC_API_KEY not set - model-based provenance judge add-ons (text and visual) disabled; any tool opted into either falls back to no check at all")
	}

	if multiInstance {
		// Postgres mode has no per-process timer to resume in the first
		// place - PollAndFireDueHolds (SELECT ... FOR UPDATE SKIP LOCKED)
		// is the ONLY firing mechanism here, covering both "fires while
		// this instance is up" and "fires after a restart/on a different
		// instance" with one mechanism, since there's no reliable way to
		// know which instance created a given hold or whether it's still
		// running - see internal/approval/postgres.go's PollAndFireDueHolds
		// doc comment.
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				appr.PollAndFireDueHolds(50, func(hold *approval.Hold) {
					h.ReplayHold(context.Background(), hold.Tool, hold.Args, hold.RequestedBy, hold.DelegatedRole, hold.AgentID)
				})
			}
		}()
	} else {
		resumable := appr.ResumableHoldIDs()
		if len(resumable) > 0 {
			log.Printf("resuming %d hold(s) that survived a restart", len(resumable))
		}
		for _, id := range resumable {
			hold, ok := appr.GetHold(id)
			if !ok {
				continue
			}
			appr.ScheduleResumedHold(id, func() {
				h.ReplayHold(context.Background(), hold.Tool, hold.Args, hold.RequestedBy, hold.DelegatedRole, hold.AgentID)
			})
		}
	}

	mux := http.NewServeMux()
	rest.Register(mux, h, appr, verifier)
	mcpServer := mcp.NewServer(h, verifier)
	mcpServer.Register(mux)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(adminui.HTML)
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(h.Metrics.Snapshot())
	})
	// Public by design, same as any JWKS-style discovery endpoint - public
	// keys aren't secret, and a verifier (cmd/mockupstream, or a real
	// upstream service) needs to be able to fetch this without first
	// authenticating to the very proxy whose tokens it's trying to verify.
	mux.HandleFunc("GET /biscuit-keys", func(w http.ResponseWriter, r *http.Request) {
		keys, err := capIssuer.ServablePublicKeys()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	})
	// Rotation is a deliberate, authenticated operator action - not
	// scheduled, not automatic. Gated on role "admin" the same way
	// close_account/update_customer_status's reviewer roles gate their own
	// sensitive actions, since minting a new signing key is at least as
	// privileged as approving any single tool call.
	mux.HandleFunc("POST /admin/biscuit-keys/rotate", func(w http.ResponseWriter, r *http.Request) {
		claims, err := verifier.FromRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if claims.DelegatedRole != "admin" {
			http.Error(w, "biscuit key rotation requires role admin", http.StatusForbidden)
			return
		}
		newID, err := capIssuer.Rotate(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		aud.Write(map[string]any{
			"decision":       "biscuit_key_rotated",
			"delegated_user": claims.DelegatedUser,
			"delegated_role": claims.DelegatedRole,
			"new_key_id":     newID,
		})
		log.Printf("biscuit signing key rotated by %s - new key id %s", claims.DelegatedUser, newID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "rotated", "new_key_id": newID})
	})
	// The compliance evidence report - a SOC2 auditor or a customer's
	// compliance team's actual deliverable, not a JSONL file they'd
	// otherwise have to grep themselves. Gated on role "admin", same bar
	// as key rotation: this is sensitive operational data (denial rates,
	// approval patterns, saga failures), not something every delegated
	// role should be able to pull.
	mux.HandleFunc("GET /compliance/report", func(w http.ResponseWriter, r *http.Request) {
		claims, err := verifier.FromRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if claims.DelegatedRole != "admin" {
			http.Error(w, "compliance report requires role admin", http.StatusForbidden)
			return
		}
		from, err := parseOptionalTime(r.URL.Query().Get("from"))
		if err != nil {
			http.Error(w, "invalid from: "+err.Error(), http.StatusBadRequest)
			return
		}
		to, err := parseOptionalTime(r.URL.Query().Get("to"))
		if err != nil {
			http.Error(w, "invalid to: "+err.Error(), http.StatusBadRequest)
			return
		}
		var report compliance.Report
		if multiInstance {
			report, err = compliance.GenerateFromPostgres(cfg.StatePostgresDSN, reg, from, to)
		} else {
			report, err = compliance.Generate(cfg.AuditLogPath, reg, from, to)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(report)
	})

	// Judge usage/cost report - the first slice of the metered
	// provenance-judge paid layer: real invocation counts and real token
	// totals from real API responses (see internal/usage and
	// internal/handler's PROVENANCE_JUDGE_USAGE audit entries), not yet
	// real billing. Same admin gate as the compliance report - usage
	// volume is operational/cost data, not something every role should see.
	mux.HandleFunc("GET /admin/judge-usage", func(w http.ResponseWriter, r *http.Request) {
		claims, err := verifier.FromRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if claims.DelegatedRole != "admin" {
			http.Error(w, "judge usage report requires role admin", http.StatusForbidden)
			return
		}
		report, err := usage.Generate(cfg.AuditLogPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(report)
	})

	// The activity feed behind the admin console's live view (internal/
	// adminui) - the most recent audit entries, newest first, each
	// enriched with the tool's CURRENT reversibility_class from the live
	// registry (not stored on the entry itself, so a catalog change is
	// reflected immediately rather than showing whatever class was true
	// when the call happened). Same admin gate as the compliance report
	// and judge usage below: the raw activity stream carries real
	// operational detail (args, reasons, roles), not something every
	// delegated role should see.
	mux.HandleFunc("GET /admin/activity", func(w http.ResponseWriter, r *http.Request) {
		claims, err := verifier.FromRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if claims.DelegatedRole != "admin" {
			http.Error(w, "activity feed requires role admin", http.StatusForbidden)
			return
		}
		limit := 50
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
				limit = n
			}
		}
		var entries []map[string]any
		if multiInstance {
			entries, err = audit.ReadRecentPostgres(cfg.StatePostgresDSN, limit)
		} else {
			entries, err = audit.ReadRecent(cfg.AuditLogPath, limit)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, e := range entries {
			if tool, ok := e["tool"].(string); ok && tool != "" {
				if t, ok := reg.Get(tool); ok {
					e["reversibility_class"] = string(t.ReversibilityClass)
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(entries)
	})

	listenAddr := *bindFlag + ":" + cfg.Port
	if zc != nil {
		// Not merely defaulted - forced. The non-loopback case already
		// exited above; this makes the actual bind match that promise even
		// if --bind was left empty, which would otherwise mean every
		// interface.
		listenAddr = "127.0.0.1:" + cfg.Port
		h.ReviewURL = "http://127.0.0.1:" + cfg.Port + "/admin"
		zc.printBanner(reg, cfg.Port)
	} else {
		log.Printf("rinwall %s listening on %s  (rest: POST /tool-call, mcp: POST /mcp, admin: GET /admin, metrics: GET /metrics, biscuit keys: GET /biscuit-keys, rotate: POST /admin/biscuit-keys/rotate, compliance: GET /compliance/report, judge usage: GET /admin/judge-usage, activity feed: GET /admin/activity)", version, listenAddr)
	}
	if *stdioFlag {
		identity := stdioIdentity(verifier)
		// The HTTP listener stays up alongside stdio: /admin is where a
		// reviewer approves what the stdio session gates, and
		// /biscuit-keys is where an upstream verifier fetches keys.
		go func() { log.Fatal(http.ListenAndServe(listenAddr, mux)) }()
		log.Printf("mcp over stdio: serving as %s (%s); HTTP listener on %s for /admin and /biscuit-keys", identity.DelegatedUser, identity.DelegatedRole, listenAddr)
		if err := mcpServer.ServeStdio(context.Background(), os.Stdin, protocolOut, identity, "stdio"); err != nil {
			log.Fatalf("mcp stdio: %v", err)
		}
		return
	}
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}

// stdioIdentity resolves the one identity a stdio session runs as: a JWT
// from $JIT_STDIO_JWT if set (verified exactly as an Authorization header
// would be), otherwise zero-config mode's local identity, otherwise a
// startup error - a config-file deployment never runs an unauthenticated
// stdio session.
func stdioIdentity(verifier *authn.Verifier) authn.Claims {
	if tok := os.Getenv("JIT_STDIO_JWT"); tok != "" {
		claims, err := verifier.Verify(tok)
		if err != nil {
			log.Fatalf("--stdio: $JIT_STDIO_JWT: %v", err)
		}
		return claims
	}
	if verifier.IsOpen() {
		claims, _ := verifier.FromRequest(&http.Request{Header: http.Header{}})
		return claims
	}
	log.Fatalf("--stdio needs an identity: set $JIT_STDIO_JWT to a token (cmd/devtoken for local dev), or use zero-config mode (--mcp), which runs as a local identity")
	return authn.Claims{}
}
