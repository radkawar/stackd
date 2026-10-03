package organizations

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"

	api "stackd/internal/awsapi/organizations"
	"stackd/internal/awswire"
)

type paginationInput interface {
	Pagination() (*string, *int32)
}

type cursor struct{ Scope, After string }

func paginate[T any](s *operationState, items []T, in paginationInput, scope string, key func(T) string) ([]T, string, *awswire.Error) {
	scope = s.partition + "/" + s.caller + "/" + scope
	token, size := in.Pagination()
	limit := 20
	if size != nil {
		limit = int(*size)
	}
	after := ""
	if token != nil {
		data, sig, ok := strings.Cut(*token, ".")
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(data)
		signature, sigErr := base64.RawURLEncoding.DecodeString(sig)
		mac := hmac.New(sha256.New, s.tokenKey[:])
		mac.Write(decoded)
		var c cursor
		if !ok || decodeErr != nil || sigErr != nil || !hmac.Equal(mac.Sum(nil), signature) || json.Unmarshal(decoded, &c) != nil || c.Scope != scope {
			return nil, "", failure("InvalidInputException", "INVALID_NEXT_TOKEN: Invalid pagination token.")
		}
		after = c.After
	}
	slices.SortFunc(items, func(a, b T) int { return strings.Compare(key(a), key(b)) })
	start := 0
	for start < len(items) && key(items[start]) <= after {
		start++
	}
	end := min(start+limit, len(items))
	page := make([]T, end-start)
	copy(page, items[start:end])
	next := ""
	if end < len(items) {
		data, _ := json.Marshal(cursor{Scope: scope, After: key(items[end-1])})
		mac := hmac.New(sha256.New, s.tokenKey[:])
		mac.Write(data)
		next = base64.RawURLEncoding.EncodeToString(data) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}
	return page, next, nil
}

func nextToken(token string) *api.NextToken {
	if token == "" {
		return nil
	}
	return new(api.NextToken(token))
}
