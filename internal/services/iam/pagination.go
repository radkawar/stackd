package iam

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"stackd/internal/awsapi"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

type pagination struct {
	IsTruncated bool
	Marker      string
}

type marker struct {
	Scope string `json:"s"`
	Last  string `json:"l"`
}

// Generated request types expose pagination controls separately from their
// typed selection. Callers may copy the input to bind effective filter defaults.
type paginationInput interface {
	Pagination() (token string, size *int32, selection any)
}

// page binds continuation markers to the partition, account, operation, and filters. Sorting
// by stable resource keys prevents map iteration order from changing page order.
func page[T any](ctx context.Context, items []T, key func(T) string, m awsctx.Metadata, input any) ([]T, pagination, *awswire.Error) {
	decoded, _ := awsapi.FromContext(ctx)
	action := string(decoded.Operation.Name)
	in, ok := input.(paginationInput)
	if !ok {
		return nil, pagination{}, requestBindingFailure()
	}
	token, size, selection := in.Pagination()
	n := 100
	if action == "GetServiceLastAccessedDetails" {
		n = 200
	}
	if size != nil {
		n = int(*size)
	}
	filters, err := json.Marshal(selection)
	if err != nil {
		return nil, pagination{}, requestBindingFailure()
	}
	hash := sha256.Sum256([]byte(m.Partition + "\x00" + m.AccountID + "\x00" + action + "\x00" + string(filters)))
	scope := hex.EncodeToString(hash[:])
	last := ""
	if token != "" {
		encoded, decodeErr := base64.RawURLEncoding.DecodeString(token)
		var mark marker
		if decodeErr != nil || json.Unmarshal(encoded, &mark) != nil || mark.Last == "" {
			if isLastAccessAction(action) {
				return nil, pagination{}, invalid("Invalid Marker.")
			}
			return nil, pagination{}, invalidInput("Invalid pagination marker.")
		}
		if mark.Scope != scope {
			return nil, pagination{}, invalidInput("Invalid pagination marker.")
		}
		last = mark.Last
	}
	slices.SortFunc(items, func(a, b T) int { return strings.Compare(key(a), key(b)) })
	start := 0
	for start < len(items) && key(items[start]) <= last {
		start++
	}
	items = items[start:]
	p := pagination{}
	if len(items) > n {
		items = items[:n]
		encoded, _ := json.Marshal(marker{Scope: scope, Last: key(items[len(items)-1])})
		p.IsTruncated = true
		p.Marker = base64.RawURLEncoding.EncodeToString(encoded)
	}
	return items, p, nil
}
