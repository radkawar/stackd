package applicationautoscaling

import (
	"cmp"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"

	api "stackd/internal/awsapi/applicationautoscaling"
)

type pageCursor interface{ valid() bool }

func (c ListCursor) valid() bool     { return c.ResourceID != "" && c.Dimension != "" }
func (c ActivityCursor) valid() bool { return c.Sequence > 0 }

type listPageQuery struct {
	Operation string
	Key       TargetKey
	Resources []string
	Names     []string
}

type listPageToken[C pageCursor] struct {
	Scope   string `json:"s"`
	Filters string `json:"f"`
	Names   string `json:"n"`
	Cursor  *C     `json:"c"`
}

type listPage[C pageCursor] struct {
	limit     int
	readLimit int
	token     listPageToken[C]
}

// Selection sets are canonicalized, so filter order and duplicates do not change
// the query identity. MaxResults deliberately is not part of that identity.
func listSelection[T ~string](values []T) []string {
	out := listStrings(values)
	slices.Sort(out)
	return slices.Compact(out)
}

func listStrings[T ~string](values []T) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = string(value)
	}
	return out
}

func listQueryIdentity(parts ...any) string {
	data, _ := json.Marshal(parts)
	return string(data)
}

func newListPage[C pageCursor](query listPageQuery, max *api.MaxResults, text *api.XmlString) (listPage[C], error) {
	token := listPageToken[C]{
		Scope:   listQueryIdentity(query.Operation, query.Key),
		Filters: listQueryIdentity(listSelection(query.Resources)),
		Names:   listQueryIdentity(listSelection(query.Names)),
	}
	if text != nil {
		var supplied listPageToken[C]
		data, err := base64.RawURLEncoding.DecodeString(string(*text))
		if err != nil || json.Unmarshal(data, &supplied) != nil || supplied.Cursor == nil || !(*supplied.Cursor).valid() || supplied.Scope == "" || supplied.Filters == "" || supplied.Names == "" {
			return listPage[C]{}, failure("InvalidNextTokenException", "The NextToken value is not valid")
		}
		if supplied.Scope != token.Scope || supplied.Filters != token.Filters {
			return listPage[C]{}, failure("InvalidNextTokenException", "The NextToken value is not valid.")
		}
		if supplied.Names != token.Names {
			// Native policy-name filter changes on a valid continuation fail here,
			// unlike a resource change or a malformed token.
			if query.Operation == "DescribeScalingPolicies" {
				return listPage[C]{}, failure("InternalServiceException", "The service has encountered an internal error. We apologize for the inconvenience.")
			}
			return listPage[C]{}, failure("InvalidNextTokenException", "The NextToken value is not valid.")
		}
		token.Cursor = supplied.Cursor
	}
	limit, continuation, err := pageLimit(query.Operation, max)
	if err != nil {
		return listPage[C]{}, err
	}
	page := listPage[C]{limit: limit, readLimit: limit, token: token}
	if continuation {
		page.readLimit++
	}
	return page, nil
}

func (p listPage[C]) next(cursor C) *api.XmlString {
	p.token.Cursor = &cursor
	data, _ := json.Marshal(p.token)
	return new(api.XmlString(base64.RawURLEncoding.EncodeToString(data)))
}

func listCursor(key TargetKey, name string) ListCursor {
	return ListCursor{ResourceID: key.ResourceID, Dimension: key.Dimension, Name: name}
}

func compareListCursor(key TargetKey, name string, from *ListCursor) int {
	if from == nil {
		return 1
	}
	return cmp.Or(strings.Compare(key.ResourceID, from.ResourceID), strings.Compare(key.Dimension, from.Dimension), strings.Compare(name, from.Name))
}
