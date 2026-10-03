package identitystore

import (
	"encoding/base64"
	"encoding/json"
	"sort"
	api "stackd/internal/awsapi/identitystore"
	"strings"
)

type pageToken struct{ Query, After string }

func page[T any](rows []T, query string, max *api.MaxResults, token *api.NextToken, id func(T) string) ([]T, *api.NextToken, error) {
	limit := 100
	if max != nil {
		limit = int(*max)
	}
	if limit < 1 || limit > 100 {
		return nil, nil, bad("MaxResults must be between 1 and 100.")
	}
	start := 0
	if token != nil {
		var cursor pageToken
		raw, e := base64.RawURLEncoding.DecodeString(string(*token))
		if e != nil || json.Unmarshal(raw, &cursor) != nil || cursor.Query != query || cursor.After == "" {
			return nil, nil, bad("Invalid NextToken.")
		}
		start = sort.Search(len(rows), func(i int) bool { return id(rows[i]) > cursor.After })
	}
	end := min(start+limit, len(rows))
	var next *api.NextToken
	if end < len(rows) {
		raw, _ := json.Marshal(pageToken{query, id(rows[end-1])})
		next = new(api.NextToken(base64.RawURLEncoding.EncodeToString(raw)))
	}
	return rows[start:end], next, nil
}
func queryKey(action, store, filter string) string {
	raw, _ := json.Marshal([]string{action, store, filter})
	return string(raw)
}
func filterName(filters api.Filters, path string) (string, error) {
	if len(filters) == 0 {
		return "", nil
	}
	if len(filters) != 1 || !strings.EqualFold(value(filters[0].AttributePath), path) {
		return "", bad("Only the " + path + " equality filter is supported.")
	}
	if value(filters[0].AttributeValue) == "" {
		return "", bad("Filter AttributeValue cannot be empty.")
	}
	return value(filters[0].AttributeValue), nil
}
func uniqueName(identifier *api.AlternateIdentifier, path string) (string, error) {
	if identifier == nil {
		return "", bad("AlternateIdentifier is required.")
	}
	// TODO: Comeback — externally provisioned identities and SCIM ExternalId lookup.
	if identifier.ExternalId != nil {
		return "", unsupported("ExternalId lookup requires external identity provisioning.")
	}
	if identifier.UniqueAttribute == nil || !strings.EqualFold(value(identifier.UniqueAttribute.AttributePath), path) {
		return "", bad("UniqueAttribute must select " + path + ".")
	}
	name, ok := identifier.UniqueAttribute.AttributeValue.(string)
	if !ok || name == "" {
		return "", bad("UniqueAttribute requires a non-empty string value.")
	}
	return name, nil
}
func reservedName(name string) bool {
	return strings.EqualFold(name, "Administrator") || strings.EqualFold(name, "AWSAdministrators")
}
func text(value string) *api.SensitiveStringType {
	if value == "" {
		return nil
	}
	return new(api.SensitiveStringType(value))
}
func memberID(v *api.MemberId) (string, error) {
	if v == nil || value(v.UserId) == "" {
		return "", bad("MemberId.UserId is required.")
	}
	return value(v.UserId), nil
}
