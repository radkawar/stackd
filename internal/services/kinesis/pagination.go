package kinesis

import (
	"encoding/base64"
	"encoding/json"
	"time"

	api "stackd/internal/awsapi/kinesis"
)

// pageCursor binds continuation to a caller scope and collection incarnation.
// After may carry an operation-specific JSON position for compound cursors.
type pageCursor struct {
	Collection string    `json:"collection"`
	After      string    `json:"after"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

func encodeCursor(collection, after string, now time.Time) *api.NextToken {
	data, _ := json.Marshal(pageCursor{Collection: collection, After: after, ExpiresAt: now.Add(5 * time.Minute)})
	return new(api.NextToken(base64.RawURLEncoding.EncodeToString(data)))
}

func decodeCursor(token *api.NextToken, collection string, now time.Time) (string, error) {
	if token == nil {
		return "", nil
	}
	data, err := base64.RawURLEncoding.DecodeString(value(token))
	var cursor pageCursor
	if err != nil || json.Unmarshal(data, &cursor) != nil || cursor.Collection != collection || cursor.After == "" || cursor.ExpiresAt.IsZero() {
		return "", failure("InvalidArgumentException", "Invalid NextToken.")
	}
	if !now.Before(cursor.ExpiresAt) {
		return "", failure("ExpiredNextTokenException", "The NextToken has expired.")
	}
	return cursor.After, nil
}
