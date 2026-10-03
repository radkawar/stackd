package resourcegroups

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	api "stackd/internal/awsapi/resourcegroups"
)

type cursor struct {
	Scope        Scope
	Query, After string
}

func paginate[T any](ctx context.Context, action string, request any, token *api.NextToken, max *api.MaxResults, rows []T, key func(T) string) ([]T, *api.NextToken, error) {
	size := 50
	if max != nil {
		size = int(*max)
	}
	if size < 1 || size > 50 {
		return nil, nil, failure("BadRequestException", "MaxResults must be between 1 and 50.")
	}
	if value(token) == "" && len(rows) <= size {
		return rows, nil, nil
	}
	data, err := json.Marshal(request)
	if err != nil {
		return nil, nil, err
	}
	// Bound the cursor size independently of the query document's JSON encoding.
	hash := sha256.New()
	_, _ = hash.Write([]byte(action))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(data)
	var sum [sha256.Size]byte
	query := hex.EncodeToString(hash.Sum(sum[:0]))
	c := cursor{Scope: scopeFor(ctx), Query: query}
	if value(token) != "" {
		data, decodeErr := base64.StdEncoding.DecodeString(value(token))
		if decodeErr != nil {
			return nil, nil, failure("BadRequestException", "Pagination token not valid.")
		}
		if json.Unmarshal(data, &c) != nil || c.Scope != scopeFor(ctx) || c.Query != query || c.After == "" {
			return nil, nil, failure("BadRequestException", "Pagination token not valid.")
		}
	}
	start := 0
	for start < len(rows) && key(rows[start]) <= c.After {
		start++
	}
	end := min(start+size, len(rows))
	if end == len(rows) {
		return rows[start:end], nil, nil
	}
	c.After = key(rows[end-1])
	body, err := json.Marshal(c)
	if err != nil {
		return nil, nil, err
	}
	next := api.NextToken(base64.StdEncoding.EncodeToString(body))
	return rows[start:end], &next, nil
}
