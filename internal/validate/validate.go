// Package validate implements allowlist-only payload validation: recursively
// canonicalize known encodings, then check the decoded value against a
// strict per-field schema. No denylist keyword matching anywhere in this
// file - that approach loses to encoding tricks by construction, per the
// plan's Intent Integrity Plane.
package validate

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/RinwallDev/rinwall/internal/registry"
)

const (
	maxDecodeDepth = 4
	maxStringBytes = 8192 // bound on any single field after full decode, to stop decompression-bomb-style abuse
)

// canonicalize repeatedly tries to decode a string as base64, hex, or a
// URL-encoded value, up to maxDecodeDepth times. If a string doesn't decode
// as any of those, it's returned as-is - this is not trying to detect
// "suspicious" content, only to stop an encoded payload from sailing through
// a validator that only ever looked at the outer encoded shell.
func canonicalize(s string) (string, error) {
	cur := s
	for i := 0; i < maxDecodeDepth; i++ {
		if len(cur) > maxStringBytes {
			return "", fmt.Errorf("value exceeds %d bytes after decoding depth %d", maxStringBytes, i)
		}
		next, changed := tryDecodeOnce(cur)
		if !changed {
			return cur, nil
		}
		cur = next
	}
	return "", fmt.Errorf("value nested more than %d encoding layers deep - rejected", maxDecodeDepth)
}

func tryDecodeOnce(s string) (string, bool) {
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil && looksLikeIntentionalEncoding(s, decoded) {
		return string(decoded), true
	}
	if decoded, err := base64.URLEncoding.DecodeString(s); err == nil && looksLikeIntentionalEncoding(s, decoded) {
		return string(decoded), true
	}
	if len(s) >= 2 && len(s)%2 == 0 {
		if decoded, err := hex.DecodeString(s); err == nil && looksLikeIntentionalEncoding(s, decoded) {
			return string(decoded), true
		}
	}
	if decoded, err := url.QueryUnescape(s); err == nil && decoded != s {
		return decoded, true
	}
	return s, false
}

// looksLikeIntentionalEncoding guards against treating an ordinary
// identifier as an encoded payload. Length alone is not enough: a 24-char
// hex ObjectId, a 12-digit numeric id, or a hex UUID all decode
// "successfully" as base64/hex - into binary garbage - and a validator that
// then pattern-checks the garbage rejects every legitimate call. The
// decoded bytes must themselves be plausible text; an encoded payload worth
// canonicalizing is one hiding readable structure, and binary noise is not
// that.
func looksLikeIntentionalEncoding(original string, decoded []byte) bool {
	return len(original) >= 12 && len(decoded) > 0 && isPlausibleText(decoded)
}

func isPlausibleText(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if r == 0x7f || (r < 0x20 && r != '\t' && r != '\n' && r != '\r') {
			return false
		}
	}
	return true
}

// Validate canonicalizes and checks a tool call's arguments against its
// registered schema. additionalProperties is implicitly false: any argument
// name not in the schema is rejected outright, never passed through.
func Validate(schema map[string]registry.FieldSpec, args map[string]any) (map[string]any, error) {
	clean := make(map[string]any, len(schema))

	for name, spec := range schema {
		val, present := args[name]
		if !present {
			if spec.Required {
				return nil, fmt.Errorf("missing required argument %q", name)
			}
			continue
		}
		checked, err := validateField(name, spec, val)
		if err != nil {
			return nil, err
		}
		clean[name] = checked
	}

	for name := range args {
		if _, known := schema[name]; !known {
			return nil, fmt.Errorf("argument %q is not declared in this tool's schema - rejected", name)
		}
	}

	return clean, nil
}

func validateField(name string, spec registry.FieldSpec, val any) (any, error) {
	switch spec.Type {
	case "string":
		s, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("argument %q must be a string", name)
		}
		canon, err := canonicalize(s)
		if err != nil {
			return nil, fmt.Errorf("argument %q: %w", name, err)
		}
		if spec.MaxLength > 0 && len(canon) > spec.MaxLength {
			return nil, fmt.Errorf("argument %q exceeds max_length %d", name, spec.MaxLength)
		}
		if spec.Pattern != "" {
			re, err := regexp.Compile(spec.Pattern)
			if err != nil {
				return nil, fmt.Errorf("argument %q: invalid pattern in schema: %w", name, err)
			}
			if !re.MatchString(canon) {
				return nil, fmt.Errorf("argument %q does not match required pattern %q", name, spec.Pattern)
			}
		}
		if len(spec.Enum) > 0 && !contains(spec.Enum, canon) {
			return nil, fmt.Errorf("argument %q must be one of %v", name, spec.Enum)
		}
		return canon, nil

	case "number":
		var f float64
		switch v := val.(type) {
		case float64:
			f = v
		case int:
			f = float64(v)
		case int64:
			f = float64(v)
		default:
			return nil, fmt.Errorf("argument %q must be a number", name)
		}
		if spec.MaxValue != nil && f > *spec.MaxValue {
			return nil, fmt.Errorf("argument %q=%v exceeds max_value %v", name, f, *spec.MaxValue)
		}
		return val, nil

	case "bool":
		b, ok := val.(bool)
		if !ok {
			return nil, fmt.Errorf("argument %q must be a bool", name)
		}
		return b, nil

	default:
		return nil, fmt.Errorf("argument %q: unsupported schema type %q", name, spec.Type)
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}
