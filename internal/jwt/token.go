// Package jwt parses signed compact JWTs without accepting token-provided trust.
package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

var (
	ErrMalformed = errors.New("malformed signed JWT")
	ErrAlgorithm = errors.New("unsupported JWT signing algorithm")
)

// Token retains the exact signed bytes and case-sensitive decoded claims.
// Parsing is not signature or claim validation.
type Token struct {
	Algorithm, KeyID, SigningInput string
	Signature                      []byte
	Claims                         map[string]json.RawMessage
}

// Parse accepts only algorithms selected by the owning authorization contract.
func Parse(raw string, acceptsAlgorithm func(string) bool) (Token, error) {
	bad := func() (Token, error) {
		return Token{}, ErrMalformed
	}
	if len(raw) > 20000 {
		return bad()
	}
	segments := strings.Split(raw, ".")
	if len(segments) != 3 {
		return bad()
	}
	decoded := make([][]byte, 3)
	for i, segment := range segments {
		if segment == "" {
			return bad()
		}
		data, err := base64.RawURLEncoding.Strict().DecodeString(segment)
		if err != nil {
			return bad()
		}
		decoded[i] = data
	}
	header, err := Object(decoded[0])
	if err != nil {
		return bad()
	}
	algorithm, ok := String(header, "alg")
	if !ok {
		return bad()
	}
	if !acceptsAlgorithm(algorithm) {
		return Token{}, ErrAlgorithm
	}
	keyID := ""
	if _, exists := header["kid"]; exists {
		keyID, ok = String(header, "kid")
		if !ok {
			return bad()
		}
	}
	if raw, exists := header["crit"]; exists {
		var critical []string
		if json.Unmarshal(raw, &critical) != nil || len(critical) != 0 {
			return bad()
		}
	}
	if raw, exists := header["b64"]; exists && string(raw) != "true" {
		return bad()
	}
	claims, err := Object(decoded[1])
	if err != nil {
		return bad()
	}
	// JOSE jku, x5u, jwk and x5c headers cannot introduce trust. Verification
	// selects only keys returned by the configured issuer's discovery.
	return Token{Algorithm: algorithm, KeyID: keyID, SigningInput: segments[0] + "." + segments[1], Signature: decoded[2], Claims: claims}, nil
}

// JWT member names are case-sensitive, including escaped JSON names. AWS uses
// the last member when names repeat. Every consumer uses this same decoded map;
// signature verification always covers the original, unmodified signed bytes.
func Object(data []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("JWT JSON is not UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 32 {
			return fmt.Errorf("JWT JSON nesting exceeds limit")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			for decoder.More() {
				token, err := decoder.Token()
				if err != nil {
					return err
				}
				if _, ok := token.(string); !ok {
					return fmt.Errorf("invalid JWT JSON member")
				}
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("invalid JWT JSON")
		}
		_, err = decoder.Token()
		return err
	}
	if err := visit(0); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JWT JSON")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil || object == nil {
		return nil, fmt.Errorf("JWT JSON must be an object")
	}
	return object, nil
}
func String(claims map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := claims[key]
	if !ok || bytes.Equal(raw, []byte("null")) {
		return "", false
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	return value, true
}
