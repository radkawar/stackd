package resourcegroupstaggingapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	api "stackd/internal/awsapi/resourcegroupstaggingapi"
)

type cursor struct {
	Scope        Scope
	Query, After string
	Expires      int64
}

func queryHash(action string, input any) string {
	data, _ := json.Marshal(input)
	sum := sha256.Sum256(append([]byte(action+"\x00"), data...))
	return hex.EncodeToString(sum[:])
}
func (s *Service) pageCursor(ctx context.Context, token, query string) (cursor, error) {
	if token == "" {
		return cursor{Scope: scopeFor(ctx), Query: query, Expires: s.clock.Now().Add(15 * time.Minute).UnixNano()}, nil
	}
	encoded, signature, ok := strings.Cut(token, ".")
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	signed, sigErr := base64.RawURLEncoding.DecodeString(signature)
	mac := hmac.New(sha256.New, s.tokenKey[:])
	_, _ = mac.Write(data)
	var c cursor
	if !ok || err != nil || sigErr != nil || !hmac.Equal(signed, mac.Sum(nil)) || json.Unmarshal(data, &c) != nil || c.Scope != scopeFor(ctx) || c.Query != query {
		return cursor{}, invalid("The pagination token is not valid for this request.")
	}
	if s.clock.Now().UnixNano() >= c.Expires {
		return cursor{}, failure("PaginationTokenExpiredException", "The pagination token has expired.")
	}
	return c, nil
}
func (s *Service) nextToken(c cursor, after string) *api.PaginationToken {
	c.After = after
	data, _ := json.Marshal(c)
	mac := hmac.New(sha256.New, s.tokenKey[:])
	_, _ = mac.Write(data)
	return new(api.PaginationToken(base64.RawURLEncoding.EncodeToString(data) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))))
}
func emptyToken() *api.PaginationToken { return new(api.PaginationToken("")) }
