package validate

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/RinwallDev/rinwall/internal/registry"
)

func schema(spec registry.FieldSpec) map[string]registry.FieldSpec {
	return map[string]registry.FieldSpec{"field": spec}
}

func TestValidate_RequiredMissing(t *testing.T) {
	_, err := Validate(schema(registry.FieldSpec{Type: "string", Required: true}), map[string]any{})
	if err == nil {
		t.Fatal("expected error for missing required field, got nil")
	}
}

func TestValidate_UnknownFieldRejected(t *testing.T) {
	_, err := Validate(schema(registry.FieldSpec{Type: "string"}), map[string]any{"field": "x", "extra": "y"})
	if err == nil {
		t.Fatal("expected error for undeclared argument, got nil")
	}
}

func TestValidate_EnumViolation(t *testing.T) {
	_, err := Validate(schema(registry.FieldSpec{Type: "string", Enum: []string{"silver", "gold"}}), map[string]any{"field": "platinum"})
	if err == nil {
		t.Fatal("expected enum violation error, got nil")
	}
}

func TestValidate_PatternViolation(t *testing.T) {
	_, err := Validate(schema(registry.FieldSpec{Type: "string", Pattern: "^[0-9]+$"}), map[string]any{"field": "abc"})
	if err == nil {
		t.Fatal("expected pattern violation error, got nil")
	}
}

func TestValidate_MaxLengthViolation(t *testing.T) {
	_, err := Validate(schema(registry.FieldSpec{Type: "string", MaxLength: 3}), map[string]any{"field": "toolong"})
	if err == nil {
		t.Fatal("expected max_length violation error, got nil")
	}
}

func TestValidate_NumberMaxValue(t *testing.T) {
	max := 100.0
	s := schema(registry.FieldSpec{Type: "number", MaxValue: &max})
	if _, err := Validate(s, map[string]any{"field": 50.0}); err != nil {
		t.Fatalf("expected 50 under max_value 100 to pass, got %v", err)
	}
	if _, err := Validate(s, map[string]any{"field": 500.0}); err == nil {
		t.Fatal("expected 500 over max_value 100 to fail, got nil")
	}
}

// The core allowlist-canonicalization claim: an encoded payload that
// wouldn't trip a naive check on its outer shell is decoded first, then
// validated against the same rules as a plain value.
func TestValidate_Base64DecodedBeforeMaxLength(t *testing.T) {
	// The DECODED length is what gets checked against max_length, not the
	// (longer) encoded length - a naive check on the raw string would miss this.
	raw := "this is way more than five characters, encoded"
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))
	_, err := Validate(schema(registry.FieldSpec{Type: "string", MaxLength: 5}), map[string]any{"field": encoded})
	if err == nil {
		t.Fatal("expected decoded-then-checked value to violate max_length, got nil")
	}
	if !strings.Contains(err.Error(), "max_length") {
		t.Fatalf("expected a max_length error, got: %v", err)
	}
}

func TestValidate_OversizedAfterDecodeRejected(t *testing.T) {
	huge := strings.Repeat("a", maxStringBytes+100)
	encoded := base64.StdEncoding.EncodeToString([]byte(huge))
	_, err := Validate(schema(registry.FieldSpec{Type: "string"}), map[string]any{"field": encoded})
	if err == nil {
		t.Fatal("expected oversized decoded payload to be rejected, got nil")
	}
}

func TestValidate_BoolField(t *testing.T) {
	s := schema(registry.FieldSpec{Type: "bool"})
	if _, err := Validate(s, map[string]any{"field": true}); err != nil {
		t.Fatalf("expected bool to pass, got %v", err)
	}
	if _, err := Validate(s, map[string]any{"field": "true"}); err == nil {
		t.Fatal("expected string \"true\" to fail bool validation, got nil")
	}
}

// A validator that "decodes" an ordinary identifier into binary and then
// pattern-checks the garbage rejects every legitimate call - the first real
// API with hex or long numeric ids would have been 100% denials.
func TestValidate_LegitimateIDsAreNotMangledByCanonicalize(t *testing.T) {
	hexSchema := schema(registry.FieldSpec{Type: "string", Pattern: "^[0-9a-f]+$"})
	for _, id := range []string{"507f1f77bcf86cd799439011", "deadbeefdeadbeef", "0123456789abcdef0123456789abcdef"} {
		out, err := Validate(hexSchema, map[string]any{"field": id})
		if err != nil {
			t.Fatalf("hex id %q must survive canonicalization untouched, got: %v", id, err)
		}
		if out["field"] != id {
			t.Fatalf("hex id %q was altered to %q", id, out["field"])
		}
	}
	numSchema := schema(registry.FieldSpec{Type: "string", Pattern: "^[0-9]+$"})
	for _, id := range []string{"123456789012", "9876543210123456"} {
		if _, err := Validate(numSchema, map[string]any{"field": id}); err != nil {
			t.Fatalf("numeric id %q must survive canonicalization untouched, got: %v", id, err)
		}
	}
	if _, err := Validate(schema(registry.FieldSpec{Type: "string", Pattern: "^[a-z]+$"}), map[string]any{"field": "abcdefghijkl"}); err != nil {
		t.Fatalf("a plain slug that happens to be valid base64 must survive, got: %v", err)
	}
}

// The other direction still holds: genuinely encoded readable text is
// decoded before validation, so hiding a payload in base64 doesn't get it
// past a pattern the decoded value would fail.
func TestValidate_EncodedReadablePayloadIsStillDecoded(t *testing.T) {
	s := schema(registry.FieldSpec{Type: "string", Pattern: "^[0-9]+$"})
	for _, enc := range []string{
		base64.StdEncoding.EncodeToString([]byte("drop table users")),
		base64.URLEncoding.EncodeToString([]byte("drop table users -- and more")),
	} {
		if _, err := Validate(s, map[string]any{"field": enc}); err == nil {
			t.Fatalf("encoded payload %q should decode to text that fails the numeric pattern", enc)
		}
	}
}
