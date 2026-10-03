package autoscaling

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"

	api "stackd/internal/awsapi/autoscaling"
)

type pageToken struct {
	Query string `json:"q"`
	After string `json:"a"`
}

func listSelection[T ~string](values []T) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = string(v)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// A cursor is tied to the operation, tenant and canonical selection, but not
// page size. Keys, not offsets, keep continuations stable across deletions.
func pageRows[T any](scope Scope, operation string, filters any, maximum *api.MaxRecords, token *api.XmlString, rows []T, key func(T) string) ([]T, *api.XmlString, error) {
	limit := 50
	if maximum != nil {
		limit = int(*maximum)
	}
	if limit < 1 || limit > 100 {
		return nil, nil, invalid("MaxRecords must be between 1 and 100")
	}
	encoded, err := json.Marshal([]any{scope, operation, filters})
	if err != nil {
		return nil, nil, err
	}
	digest := sha256.Sum256(encoded)
	query := base64.RawURLEncoding.EncodeToString(digest[:])
	cursor := pageToken{Query: query}
	if token != nil {
		data, err := base64.RawURLEncoding.DecodeString(string(*token))
		if err != nil || json.Unmarshal(data, &cursor) != nil || cursor.Query != query || cursor.After == "" {
			return nil, nil, failure("InvalidNextToken", "The token is invalid.")
		}
	}
	slices.SortFunc(rows, func(a, b T) int { return strings.Compare(key(a), key(b)) })
	start := 0
	if cursor.After != "" {
		start, _ = slices.BinarySearchFunc(rows, cursor.After, func(row T, after string) int { return strings.Compare(key(row), after) })
		for start < len(rows) && key(rows[start]) <= cursor.After {
			start++
		}
	}
	rows = rows[start:]
	if len(rows) <= limit {
		return rows, nil, nil
	}
	cursor.After = key(rows[limit-1])
	data, err := json.Marshal(cursor)
	if err != nil {
		return nil, nil, err
	}
	return rows[:limit], new(api.XmlString(base64.RawURLEncoding.EncodeToString(data))), nil
}
