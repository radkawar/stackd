package servicecatalogappregistry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"slices"
	api "stackd/internal/awsapi/servicecatalogappregistry"
	"strings"
)

type cursor struct {
	Scope                  Scope
	Action, Binding, After string
}

func paginate[T any](ctx context.Context, action, binding string, token *api.NextToken, max *api.MaxResults, rows []T, key func(T) string) ([]T, *api.NextToken, error) {
	size := 25
	if max != nil {
		size = int(*max)
	}
	if size < 1 || size > 100 {
		return nil, nil, failure("ValidationException", "maxResults must be between 1 and 100.")
	}
	slices.SortFunc(rows, func(a, b T) int { return strings.Compare(key(a), key(b)) })
	c := cursor{Scope: scopeFor(ctx), Action: action, Binding: binding}
	if value(token) != "" {
		b, err := base64.StdEncoding.DecodeString(value(token))
		if err != nil {
			return nil, nil, failure("ValidationException", "Invalid nextToken.")
		}
		if json.Unmarshal(b, &c) != nil || c.Scope != scopeFor(ctx) || c.Action != action || c.Binding != binding || c.After == "" {
			return nil, nil, failure("ValidationException", "Invalid nextToken.")
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
	b, err := json.Marshal(c)
	if err != nil {
		return nil, nil, err
	}
	return rows[start:end], new(api.NextToken(base64.StdEncoding.EncodeToString(b))), nil
}
