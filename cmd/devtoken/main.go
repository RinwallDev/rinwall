// Command devtoken mints a dev-only signed identity JWT for local testing.
// DEV ONLY: a real deployment never mints its own delegated-identity
// tokens - an IdP (Okta/Auth0/etc.) does, and the proxy only verifies them.
// It exists so the JWT requirement doesn't block local curl testing.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/RinwallDev/rinwall/internal/authn"
)

func main() {
	user := flag.String("user", "", "delegated user, e.g. alex@example.com")
	role := flag.String("role", "", "delegated role, e.g. support, SalesManager, admin")
	ttl := flag.Duration("ttl", time.Hour, "token TTL")
	flag.Parse()

	if *user == "" || *role == "" {
		log.Fatal("devtoken: --user and --role are required")
	}

	secret := os.Getenv("JIT_JWT_SECRET")
	if secret == "" {
		secret = "dev-jwt-secret-change-me"
	}

	tok, err := authn.Mint(secret, *user, *role, *ttl)
	if err != nil {
		log.Fatalf("devtoken: %v", err)
	}
	fmt.Println(tok)
}
