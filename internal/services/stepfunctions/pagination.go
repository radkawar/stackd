package stepfunctions

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"

	api "stackd/internal/awsapi/stepfunctions"
	"stackd/internal/awsctx"
)

// A cursor binds an ordered position to the endpoint, caller, operation, filters,
// and resource incarnation. It never authorizes access to the next page.
type controlCursor struct {
	Collection string    `json:"collection"`
	After      string    `json:"after"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

func controlCollection(r Reader, action, resource, incarnation string) string {
	m := awsctx.FromContext(r.Context())
	data, _ := json.Marshal([]string{m.Partition, m.AccountID, m.Region, m.PrincipalARN, m.PrincipalID, action, resource, incarnation})
	hash := sha256.Sum256(data)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func controlPage(token *api.PageToken, size *api.PageSize, collection string, now time.Time) (int, string, error) {
	limit := 100
	if size != nil {
		if *size < 0 || *size > 1000 {
			return 0, "", invalid("maxResults must be between 0 and 1000.")
		}
		if *size > 0 {
			limit = int(*size)
		}
	}
	if token == nil {
		return limit, "", nil
	}
	data, err := base64.RawURLEncoding.DecodeString(value(token))
	var cursor controlCursor
	if err != nil || json.Unmarshal(data, &cursor) != nil || cursor.Collection != collection || cursor.After == "" || cursor.ExpiresAt.IsZero() || !now.Before(cursor.ExpiresAt) || cursor.ExpiresAt.After(now.Add(24*time.Hour)) {
		return 0, "", failure("InvalidToken", "Invalid Token: 'Invalid token'", 400)
	}
	return limit, cursor.After, nil
}

func controlNext(collection, after string, now time.Time) *api.PageToken {
	data, _ := json.Marshal(controlCursor{Collection: collection, After: after, ExpiresAt: now.Add(24 * time.Hour)})
	return new(api.PageToken(base64.RawURLEncoding.EncodeToString(data)))
}
