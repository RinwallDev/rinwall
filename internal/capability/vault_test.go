package capability

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// TestVaultSeedMinter_MintSessionSeed_TimesOutOnHungServer proves the
// actual behavior the Vault-down fallback discussion asked for: a Vault
// that accepts a connection but never answers (a stuck request, a
// network partition specifically to Vault - not a clean "connection
// refused") must not hang the caller forever. It must fail within the
// caller's own context deadline, with an error a caller can recognize as
// Vault-specific via ErrVaultUnavailable.
func TestVaultSeedMinter_MintSessionSeed_TimesOutOnHungServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Accept but never reply and never close - a genuinely hung
			// backend, not a fast rejection.
			_ = conn
		}
	}()

	client, err := NewVaultClient("http://"+ln.Addr().String(), "irrelevant-token")
	if err != nil {
		t.Fatal(err)
	}
	minter := NewVaultSeedMinter(client, "irrelevant-key")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = minter.MintSessionSeed(ctx, "session-1")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error from a hung Vault connection")
	}
	if !errors.Is(err, ErrVaultUnavailable) {
		t.Fatalf("expected error to wrap ErrVaultUnavailable so callers can raise a distinguishable signal, got: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("expected the call to fail once its context deadline passed (~200ms), not hang - took %v", elapsed)
	}
}

// TestVaultKeyRingStore_Load_TimesOutOnHungServer covers the same
// hardening for the keyring's KV v2 calls, not just the seed minter's
// Transit call - both are real Vault network calls this package makes.
func TestVaultKeyRingStore_Load_TimesOutOnHungServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn
		}
	}()

	client, err := NewVaultClient("http://"+ln.Addr().String(), "irrelevant-token")
	if err != nil {
		t.Fatal(err)
	}
	store := NewVaultKeyRingStore(client, "secret", "jit/biscuit-keyring")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = store.Load(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error from a hung Vault connection")
	}
	if !errors.Is(err, ErrVaultUnavailable) {
		t.Fatalf("expected error to wrap ErrVaultUnavailable, got: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("expected Load to fail once its context deadline passed (~200ms), not hang - took %v", elapsed)
	}
}
