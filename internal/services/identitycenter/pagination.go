package identitycenter

import (
	"encoding/base64"
	"encoding/json"
	"sort"
)

type pageToken struct{ Query, After string }

// key follows the existing list order and uniquely identifies a row.
func pageSlice[T any](values []T, token, scope string, limit int, key func(T) string) ([]T, string, error) {
	if limit == 0 {
		limit = 100
	}
	if limit < 1 || limit > 100 {
		return nil, "", bad("MaxResults must be between 1 and 100.")
	}
	start := 0
	if token != "" {
		var cursor pageToken
		raw, e := base64.RawURLEncoding.DecodeString(token)
		if e != nil || json.Unmarshal(raw, &cursor) != nil || cursor.After == "" {
			return nil, "", bad("Invalid pagination token.")
		}
		if cursor.Query != tokenHash(scope) {
			return nil, "", bad("Pagination token does not match this request.")
		}
		start = sort.Search(len(values), func(i int) bool { return key(values[i]) > cursor.After })
	}
	end := min(start+limit, len(values))
	next := ""
	if end < len(values) {
		raw, _ := json.Marshal(pageToken{Query: tokenHash(scope), After: key(values[end-1])})
		next = base64.RawURLEncoding.EncodeToString(raw)
	}
	return values[start:end], next, nil
}
func intValue[T ~int32 | ~int64](v *T) int {
	if v == nil {
		return 0
	}
	return int(*v)
}
