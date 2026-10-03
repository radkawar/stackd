package kms

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"

	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awswire"
)

type pageCursor struct{ Partition, Account, Region, Operation, Filter, After string }

// page binds cursors to their complete request scope and uses an exclusive key
// boundary, so mutations before the cursor do not duplicate earlier entries.
func (s *Service) page(ctx context.Context, operation, filter string, items []string, limit *kmsapi.LimitType, marker *kmsapi.MarkerType) ([]string, string, *awswire.Error) {
	sc := scopeFor(ctx)
	expected := pageCursor{Partition: sc.partition, Account: sc.account, Region: sc.region, Operation: operation, Filter: filter}
	size := 100
	if limit != nil {
		size = int(*limit)
	}
	if size < 1 || size > 1000 {
		return nil, "", failure("ValidationException", "Limit must be between 1 and 1000.")
	}
	start := 0
	if marker != nil {
		encoded, signature, ok := strings.Cut(string(*marker), ".")
		body, decodeErr := base64.RawURLEncoding.DecodeString(encoded)
		sig, sigErr := base64.RawURLEncoding.DecodeString(signature)
		mac := hmac.New(sha256.New, s.tokenKey[:])
		_, _ = mac.Write(body)
		var cursor pageCursor
		if !ok || decodeErr != nil || sigErr != nil || !hmac.Equal(sig, mac.Sum(nil)) || json.Unmarshal(body, &cursor) != nil {
			return nil, "", failure("InvalidMarkerException", "Invalid pagination marker.")
		}
		after := cursor.After
		cursor.After = ""
		if cursor != expected {
			return nil, "", failure("InvalidMarkerException", "Marker belongs to another request.")
		}
		start, _ = slices.BinarySearch(items, after)
		if start < len(items) && items[start] == after {
			start++
		}
	}
	end := min(start+size, len(items))
	next := ""
	if end < len(items) {
		expected.After = items[end-1]
		body, _ := json.Marshal(expected)
		mac := hmac.New(sha256.New, s.tokenKey[:])
		_, _ = mac.Write(body)
		next = base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}
	return items[start:end], next, nil
}
