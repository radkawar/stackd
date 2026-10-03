package ssmdocuments

import (
	"cmp"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"

	api "stackd/internal/awsapi/ssm"
)

type documentFilter struct {
	Key    string
	Values []string
}

func filtersFor(in *api.ListDocumentsRequest) ([]documentFilter, error) {
	if len(in.Filters) > 0 && len(in.DocumentFilterList) > 0 {
		return nil, failure("InvalidFilterKey", "Use Filters or DocumentFilterList, not both.")
	}
	out := []documentFilter{}
	for _, f := range in.Filters {
		values := make([]string, 0, len(f.Values))
		for _, v := range f.Values {
			values = append(values, string(v))
		}
		out = append(out, documentFilter{value(f.Key), values})
	}
	for _, f := range in.DocumentFilterList {
		out = append(out, documentFilter{value(f.Key), []string{value(f.Value)}})
	}
	tags := 0
	for _, f := range out {
		if len(f.Values) == 0 {
			return nil, failure("InvalidFilterKey", "A filter requires values.")
		}
		if f.Key == "Owner" && len(f.Values) != 1 {
			return nil, failure("InvalidFilterKey", "Only one Owner filter value is supported.")
		}
		switch f.Key {
		case "Owner", "Name", "PlatformTypes", "DocumentType", "TargetType":
		default:
			if !strings.HasPrefix(f.Key, "tag:") || len(f.Key) == 4 {
				return nil, failure("InvalidFilterKey", "Unsupported document filter: "+f.Key)
			}
			tags++
		}
	}
	if tags > 1 {
		return nil, failure("InvalidFilterKey", "Only one tag filter is supported.")
	}
	return out, nil
}
func matchesDocument(d *api.DocumentDescription, record Record, filters []documentFilter, sc Scope) bool {
	for _, f := range filters {
		matched := false
		for _, want := range f.Values {
			switch f.Key {
			case "Owner":
				matched = want == value(d.Owner) || want == "Self" && record.Key.AccountID == sc.AccountID ||
					want == "Private" && record.Key.AccountID != sc.AccountID && record.Key.AccountID != "" && record.Shares["all"] == "" ||
					want == "Public" && (record.Key.AccountID == "" || record.Shares["all"] != "")
			case "Name":
				matched = strings.HasPrefix(record.Key.Name, want)
			case "PlatformTypes":
				matched = slices.Contains(d.PlatformTypes, api.PlatformType(want))
			case "DocumentType":
				matched = want == value(d.DocumentType)
			case "TargetType":
				matched = want == value(d.TargetType)
			default:
				actual, ok := record.Tags[strings.TrimPrefix(f.Key, "tag:")]
				matched = ok && actual == want
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}
func (s *Service) listDocuments(tx Transaction, in *api.ListDocumentsRequest) (*api.ListDocumentsResult, error) {
	if err := s.authorize(tx, "ListDocuments", Record{}, nil); err != nil {
		return nil, err
	}
	filters, err := filtersFor(in)
	if err != nil {
		return nil, err
	}
	sc := scopeFor(tx.Context())
	records, err := tx.Documents(sc)
	if err != nil {
		return nil, err
	}
	shared, err := tx.SharedDocuments(sc)
	if err != nil {
		return nil, err
	}
	records = append(records, shared...)
	builtinKey := Key{Scope: sc, Name: "AWS-RunShellScript"}
	builtinKey.AccountID = ""
	records = append(records, builtinRecord(builtinKey))
	identifiers := api.DocumentIdentifierList{}
	for _, r := range records {
		foreign := r.Key.AccountID != "" && r.Key.AccountID != sc.AccountID
		if foreign && s.authorize(tx, "ListDocuments", r, nil) != nil {
			continue
		}
		selector := "$DEFAULT"
		if foreign && sharedSelector(r, sc.AccountID) == "$LATEST" {
			selector = "$LATEST"
		}
		v, err := selectVersion(tx, r, selector, "")
		if err != nil {
			return nil, err
		}
		d, err := description(r, v)
		if err != nil {
			return nil, err
		}
		if foreign {
			d.Name = new(api.DocumentARN(documentARN(r.Key)))
		}
		if !matchesDocument(d, r, filters, sc) {
			continue
		}
		identifiers = append(identifiers, api.DocumentIdentifier{Name: d.Name, Owner: d.Owner, CreatedDate: d.CreatedDate, DocumentVersion: d.DocumentVersion, DocumentType: d.DocumentType, DocumentFormat: d.DocumentFormat, SchemaVersion: d.SchemaVersion, PlatformTypes: d.PlatformTypes, TargetType: d.TargetType, Tags: d.Tags, DisplayName: d.DisplayName, VersionName: d.VersionName})
	}
	size := 50
	if in.MaxResults != nil {
		size = int(*in.MaxResults)
	}
	rows, next, err := documentPage(s, tx, "ListDocuments", filters, identifiers, func(v api.DocumentIdentifier) string { return value(v.Name) }, size, in.NextToken)
	if err != nil {
		return nil, err
	}
	return &api.ListDocumentsResult{DocumentIdentifiers: rows, NextToken: next}, nil
}

// Tokens use the same scoped MAC/exclusive-key convention as Parameter Store.
type documentCursor[K cmp.Ordered] struct {
	Scope         Scope
	Action, Query string
	After         K
}

func documentPage[T any, K cmp.Ordered](s *Service, r Reader, action string, query any, rows []T, key func(T) K, size int, token *api.NextToken) ([]T, *api.NextToken, error) {
	return documentPageLimit(s, r, action, query, rows, key, size, 50, token)
}

func documentPageLimit[T any, K cmp.Ordered](s *Service, r Reader, action string, query any, rows []T, key func(T) K, size, maximum int, token *api.NextToken) ([]T, *api.NextToken, error) {
	if size < 1 || size > maximum {
		return nil, nil, failure("ValidationException", "MaxResults is outside the supported range.")
	}
	selection, err := json.Marshal(query)
	if err != nil {
		return nil, nil, err
	}
	digest := sha256.Sum256(selection)
	expected := documentCursor[K]{Scope: scopeFor(r.Context()), Action: action, Query: base64.RawURLEncoding.EncodeToString(digest[:])}
	var after K
	if token != nil {
		encoded, signature, ok := strings.Cut(value(token), ".")
		body, e := base64.RawURLEncoding.DecodeString(encoded)
		sig, se := base64.RawURLEncoding.DecodeString(signature)
		mac := hmac.New(sha256.New, s.tokenKey[:])
		_, _ = mac.Write(body)
		var cursor documentCursor[K]
		if !ok || e != nil || se != nil || !hmac.Equal(sig, mac.Sum(nil)) || json.Unmarshal(body, &cursor) != nil {
			return nil, nil, failure("InvalidNextToken", "Invalid pagination token.")
		}
		after, cursor.After = cursor.After, after
		if cursor != expected {
			return nil, nil, failure("InvalidNextToken", "Pagination token belongs to another query.")
		}
	}
	slices.SortFunc(rows, func(a, b T) int { return cmp.Compare(key(a), key(b)) })
	start := 0
	if token != nil {
		start, _ = slices.BinarySearchFunc(rows, after, func(row T, boundary K) int {
			if key(row) <= boundary {
				return -1
			}
			return 1
		})
	}
	end := min(start+size, len(rows))
	var next *api.NextToken
	if end < len(rows) {
		expected.After = key(rows[end-1])
		body, err := json.Marshal(expected)
		if err != nil {
			return nil, nil, err
		}
		mac := hmac.New(sha256.New, s.tokenKey[:])
		_, _ = mac.Write(body)
		next = new(api.NextToken(base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))))
	}
	return rows[start:end], next, nil
}
