package ssmcommands

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"

	api "stackd/internal/awsapi/ssm"
)

type cursor struct {
	Scope                Scope
	Action, Query, After string
}

// Continuations follow the existing SSM exclusive-key, query-scoped MAC pattern.
// Like Parameter Store cursors, they are invalidated by controller replacement.
func page[T any](s *Service, r Reader, action string, query any, rows []T, key func(T) string, size, maximum int, token *api.NextToken) ([]T, *api.NextToken, error) {
	if size < 1 || size > maximum {
		return nil, nil, failure("ValidationException", "MaxResults is outside the allowed range.")
	}
	selection, err := json.Marshal(query)
	if err != nil {
		return nil, nil, err
	}
	digest := sha256.Sum256(selection)
	expected := cursor{Scope: scopeFor(r.Context()), Action: action, Query: base64.RawURLEncoding.EncodeToString(digest[:])}
	after := ""
	if token != nil {
		encoded, signature, ok := strings.Cut(value(token), ".")
		body, bodyErr := base64.RawURLEncoding.DecodeString(encoded)
		sig, sigErr := base64.RawURLEncoding.DecodeString(signature)
		mac := hmac.New(sha256.New, s.tokenKey[:])
		_, _ = mac.Write(body)
		var current cursor
		if !ok || bodyErr != nil || sigErr != nil || !hmac.Equal(sig, mac.Sum(nil)) || json.Unmarshal(body, &current) != nil {
			return nil, nil, failure("InvalidNextToken", "The pagination token is invalid.")
		}
		after, current.After = current.After, ""
		if current != expected {
			return nil, nil, failure("InvalidNextToken", "The pagination token belongs to a different request.")
		}
	}
	slices.SortFunc(rows, func(a, b T) int { return strings.Compare(key(a), key(b)) })
	start := 0
	if token != nil {
		start, _ = slices.BinarySearchFunc(rows, after, func(row T, boundary string) int {
			if key(row) <= boundary {
				return -1
			}
			return 1
		})
	}
	end := min(start+size, len(rows))
	var next *api.NextToken
	if end < len(rows) {
		expected.After = key(rows[end-1])
		body, err := json.Marshal(expected)
		if err != nil {
			return nil, nil, err
		}
		mac := hmac.New(sha256.New, s.tokenKey[:])
		_, _ = mac.Write(body)
		next = new(api.NextToken(base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))))
	}
	return rows[start:end], next, nil
}
