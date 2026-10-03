package apigatewayv2

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"stackd/internal/authorization"
)

func controlID() (string, error) {
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func controlARN(scope Scope, path string) string {
	return "arn:" + scope.Partition + ":apigateway:" + scope.Region + "::" + path
}
func (s *Service) authorize(r Reader, method, path string, current, requested map[string]string, keys []string) error {
	scope := scopeFor(r.Context())
	conditions := map[string][]string{}
	for k, v := range current {
		conditions["aws:ResourceTag/"+k] = []string{v}
	}
	for k, v := range requested {
		conditions["aws:RequestTag/"+k] = []string{v}
		keys = append(keys, k)
	}
	if keys != nil {
		slices.Sort(keys)
		conditions["aws:TagKeys"] = keys
	}
	if rejected := s.authorizer.Authorize(r.Context(), authorization.Request{Action: "apigateway:" + method, ResourceARN: controlARN(scope, path), ResourceAccountID: scope.AccountID, Context: conditions, ContextTypes: map[string]string{"aws:TagKeys": "stringList"}}); rejected != nil {
		return rejected
	}
	return nil
}
func (s *Service) passInvocationRole(r Reader, roleARN string) error {
	if roleARN == "" {
		return nil
	}
	now := s.clock.Now()
	if rejected := s.authorizer.Authorize(r.Context(), authorization.Request{
		Action: "iam:PassRole", ResourceARN: roleARN, EvaluationTime: &now,
		Context: map[string][]string{"iam:PassedToService": {"apigateway.amazonaws.com"}},
	}); rejected != nil {
		return rejected
	}
	return nil
}
func (s *Service) ownedAPI(r Reader, method, id, suffix string) (APIRecord, error) {
	key := APIKey{scopeFor(r.Context()), id}
	v, err := r.API(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return v, err
	}
	current := map[string]string(nil)
	if suffix == "" {
		current = v.Tags
	} else if stage, ok := strings.CutPrefix(suffix, "/stages/"); ok && !strings.Contains(stage, "/") {
		row, e := r.Stage(ResourceKey{key, stage})
		if e != nil && !errors.Is(e, ErrNotFound) {
			return v, e
		}
		current = row.Tags
	}
	// V2 does not inherit API tags onto children; V1 alone has that contract.
	if e := s.authorize(r, method, "/apis/"+id+suffix, current, nil, nil); e != nil {
		return v, e
	}
	return v, err
}

var tagCharacters = regexp.MustCompile(`^[\p{L}\p{N}\p{Z}_.:/=+\-@]*$`)

func validTags(tags map[string]string) error {
	if len(tags) > 50 {
		return bad("A resource may have at most 50 tags")
	}
	for k, v := range tags {
		if len(k) == 0 || utf8.RuneCountInString(k) > 128 || utf8.RuneCountInString(v) > 256 || !tagCharacters.MatchString(k) || !tagCharacters.MatchString(v) || strings.HasPrefix(strings.ToLower(k), "aws:") {
			return bad("Invalid tag")
		}
	}
	return nil
}

// Cursors use the existing Cognito owner/filter/last-key convention, rather than
// offsets that shift when a prior resource is deleted.
func page[T any](rows []T, maxResults, token, binding string, key func(T) string) ([]T, *string, error) {
	limit := 100
	if maxResults != "" {
		var err error
		limit, err = strconv.Atoi(maxResults)
		if err != nil || limit < 1 || limit > 1000 {
			return nil, nil, bad("MaxResults must be between 1 and 1000")
		}
	}
	cursor := ""
	if token != "" {
		raw, err := base64.RawURLEncoding.DecodeString(token)
		var parts []string
		if err != nil || json.Unmarshal(raw, &parts) != nil || len(parts) != 2 || parts[0] != binding || parts[1] == "" {
			return nil, nil, bad("Invalid pagination token")
		}
		cursor = parts[1]
	}
	start := 0
	for start < len(rows) && key(rows[start]) <= cursor {
		start++
	}
	end := min(start+limit, len(rows))
	out := rows[start:end]
	if end < len(rows) {
		raw, _ := json.Marshal([]string{binding, key(rows[end-1])})
		return out, new(base64.RawURLEncoding.EncodeToString(raw)), nil
	}
	return out, nil, nil
}
func pageBinding(r Reader, path string) string {
	sc := scopeFor(r.Context())
	return sc.Partition + ":" + sc.AccountID + ":" + sc.Region + ":" + path
}
