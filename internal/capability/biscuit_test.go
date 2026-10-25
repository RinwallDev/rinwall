package capability

import (
	"context"
	"testing"
	"time"
)

func testIssuer(t *testing.T) *BiscuitRootIssuer {
	t.Helper()
	issuer, err := NewBiscuitRootIssuer(context.Background(), &FakeKeyRingStore{}, FakeSeedMinter{})
	if err != nil {
		t.Fatal(err)
	}
	return issuer
}

// pubKeys is a small helper standing in for what a real verifier would get
// back from GET /biscuit-keys.
func pubKeys(t *testing.T, issuer *BiscuitRootIssuer) []string {
	t.Helper()
	hex, err := issuer.CurrentPublicKeyHex()
	if err != nil {
		t.Fatal(err)
	}
	return []string{hex}
}

func TestMintAttenuateVerify_HappyPath(t *testing.T) {
	issuer := testIssuer(t)
	root, err := issuer.MintRoot(context.Background(), "session-1", "alex@example.com", "support")
	if err != nil {
		t.Fatal(err)
	}
	token, err := root.Attenuate("update_customer_tier", "42", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(token.Value, pubKeys(t, issuer), "update_customer_tier", "42"); err != nil {
		t.Fatalf("expected a correctly-scoped token to verify, got: %v", err)
	}
}

func TestVerify_WrongToolRejected(t *testing.T) {
	issuer := testIssuer(t)
	root, _ := issuer.MintRoot(context.Background(), "session-1", "alex@example.com", "support")
	token, _ := root.Attenuate("update_customer_tier", "42", 10*time.Second)
	if err := Verify(token.Value, pubKeys(t, issuer), "delete_user", "42"); err == nil {
		t.Fatal("expected a token attenuated for a different tool to fail verification")
	}
}

func TestVerify_WrongResourceRejected(t *testing.T) {
	issuer := testIssuer(t)
	root, _ := issuer.MintRoot(context.Background(), "session-1", "alex@example.com", "support")
	token, _ := root.Attenuate("update_customer_tier", "42", 10*time.Second)
	if err := Verify(token.Value, pubKeys(t, issuer), "update_customer_tier", "43"); err == nil {
		t.Fatal("expected a token attenuated for a different resource to fail verification")
	}
}

func TestVerify_ExpiredRejected(t *testing.T) {
	issuer := testIssuer(t)
	root, _ := issuer.MintRoot(context.Background(), "session-1", "alex@example.com", "support")
	token, err := root.Attenuate("update_customer_tier", "42", 1*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if err := Verify(token.Value, pubKeys(t, issuer), "update_customer_tier", "42"); err == nil {
		t.Fatal("expected an expired token to fail verification")
	}
}

func TestVerify_TamperedBytesRejected(t *testing.T) {
	issuer := testIssuer(t)
	root, _ := issuer.MintRoot(context.Background(), "session-1", "alex@example.com", "support")
	token, _ := root.Attenuate("update_customer_tier", "42", 10*time.Second)

	// Flip the last character of the base64 payload - a byte-level bit flip
	// well inside the token, not just padding, so it lands in real content.
	tampered := []byte(token.Value)
	mid := len(tampered) / 2
	if tampered[mid] == 'A' {
		tampered[mid] = 'B'
	} else {
		tampered[mid] = 'A'
	}
	if err := Verify(string(tampered), pubKeys(t, issuer), "update_customer_tier", "42"); err == nil {
		t.Fatal("expected a tampered token to fail verification")
	}
}

func TestVerify_ForgedKeyRejected(t *testing.T) {
	realIssuer := testIssuer(t)
	forgedIssuer := testIssuer(t) // different random seed = different keypair

	root, err := forgedIssuer.MintRoot(context.Background(), "session-1", "attacker", "admin")
	if err != nil {
		t.Fatal(err)
	}
	token, err := root.Attenuate("delete_everything", "*", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// Verify against the REAL issuer's public key - a token signed by any
	// other key must never pass.
	if err := Verify(token.Value, pubKeys(t, realIssuer), "delete_everything", "*"); err == nil {
		t.Fatal("expected a token signed by a different keypair to fail verification against the real public key")
	}
}

func TestRotate_OldKeyStillVerifiesWithinGracePeriod(t *testing.T) {
	issuer := testIssuer(t)
	root, err := issuer.MintRoot(context.Background(), "session-1", "alex@example.com", "support")
	if err != nil {
		t.Fatal(err)
	}
	token, err := root.Attenuate("update_customer_tier", "42", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := issuer.Rotate(context.Background()); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// A verifier holding every currently-servable key (old + new) must
	// still accept a token signed before the rotation happened.
	keys, err := issuer.ServablePublicKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 servable keys right after a rotation (old + new), got %d", len(keys))
	}
	hexes := make([]string, len(keys))
	for i, k := range keys {
		hexes[i] = k.PublicKeyHex
	}
	if err := Verify(token.Value, hexes, "update_customer_tier", "42"); err != nil {
		t.Fatalf("expected a pre-rotation token to still verify against the post-rotation servable key set, got: %v", err)
	}
}

func TestRotate_NewMintsUseNewKeyOnly(t *testing.T) {
	issuer := testIssuer(t)
	oldKeyHex, err := issuer.CurrentPublicKeyHex()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := issuer.Rotate(context.Background()); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	root, err := issuer.MintRoot(context.Background(), "session-2", "alex@example.com", "support")
	if err != nil {
		t.Fatal(err)
	}
	token, err := root.Attenuate("update_customer_tier", "42", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// A verifier that only knows the OLD key must reject a token minted
	// after rotation - proves MintRoot actually switched to the new key,
	// not just that the old one still happens to work.
	if err := Verify(token.Value, []string{oldKeyHex}, "update_customer_tier", "42"); err == nil {
		t.Fatal("expected a post-rotation token to fail verification against only the pre-rotation key")
	}
}

func TestPrune_DropsFullyElapsedGracePeriodKey(t *testing.T) {
	issuer := testIssuer(t)
	oldKeyHex, err := issuer.CurrentPublicKeyHex()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.Rotate(context.Background()); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// Simulate the grace period having fully elapsed by pruning against a
	// time far in the future, rather than sleeping keyGracePeriod for real.
	issuer.mu.Lock()
	issuer.kr.Prune(time.Now().Add(keyGracePeriod * 2))
	issuer.mu.Unlock()

	keys, err := issuer.ServablePublicKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected the superseded key to be pruned, leaving 1 servable key, got %d", len(keys))
	}
	for _, k := range keys {
		if k.PublicKeyHex == oldKeyHex {
			t.Fatal("expected the fully-elapsed pre-rotation key to have been pruned")
		}
	}
}

func TestAttenuate_CannotExceedRootExpiry(t *testing.T) {
	issuer := testIssuer(t)
	root, err := issuer.MintRoot(context.Background(), "session-1", "alex@example.com", "support")
	if err != nil {
		t.Fatal(err)
	}
	// Ask for a much longer TTL than the root's own session lifetime -
	// Attenuate must clamp, never grant more time than the root actually has.
	token, err := root.Attenuate("get_user", "42", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if token.ExpiresAt.After(time.Now().Add(sessionRootTTL + time.Minute)) {
		t.Fatalf("expected attenuated token expiry to be clamped to the root's session TTL, got %v", token.ExpiresAt)
	}
}
