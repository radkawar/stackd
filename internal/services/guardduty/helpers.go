package guardduty

import (
	"context"
	"encoding/base64"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/guardduty"
)

func newID() string { return strings.ReplaceAll(uuid.NewString(), "-", "") }
func stringTags(tags api.TagMap) map[string]string {
	out := make(map[string]string, len(tags))
	for k, v := range tags {
		out[string(k)] = string(v)
	}
	return out
}
func outputTags(tags map[string]string) api.TagMap {
	out := make(api.TagMap, len(tags))
	for k, v := range tags {
		out[api.TagKey(k)] = api.TagValue(v)
	}
	return out
}
func validateTags(tags map[string]string) error {
	if len(tags) > 200 {
		return invalid("A resource can have at most 200 tags")
	}
	for k, v := range tags {
		if k == "" || utf8.RuneCountInString(k) > 128 || utf8.RuneCountInString(v) > 256 || strings.HasPrefix(strings.ToLower(k), "aws:") {
			return invalid("Invalid tag key or value")
		}
	}
	return nil
}
func pagePrefix(ctx context.Context, kind string) string {
	sc := scopeFor(ctx)
	return sc.Partition + "\x00" + sc.AccountID + "\x00" + sc.Region + "\x00" + kind + "\x00"
}
func page(ctx context.Context, kind string, max *api.MaxResults, token string) (int, string, error) {
	limit := 50
	if max != nil {
		limit = int(*max)
	}
	if limit < 1 || limit > 50 {
		return 0, "", invalid("maxResults must be between 1 and 50")
	}
	if token == "" {
		return limit, "", nil
	}
	data, err := base64.RawURLEncoding.DecodeString(token)
	prefix := pagePrefix(ctx, kind)
	if err != nil || !strings.HasPrefix(string(data), prefix) {
		return 0, "", invalid("Invalid nextToken")
	}
	return limit, string(data[len(prefix):]), nil
}
func pageToken(ctx context.Context, kind, last string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(pagePrefix(ctx, kind) + last))
}
