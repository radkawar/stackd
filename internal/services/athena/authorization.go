package athena

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/athena"
)

func (s *Service) authorize(ctx context.Context, action, arn string, tags map[string]string, conditions map[string][]string) error {
	if conditions == nil {
		conditions = map[string][]string{}
	}
	for k, v := range tags {
		conditions["aws:ResourceTag/"+k] = []string{v}
	}
	now := s.clock.Now()
	if rejected := s.authorizer.Authorize(ctx, authorization.Request{Action: "athena:" + action, ResourceARN: arn, Context: conditions, ContextTypes: map[string]string{"aws:TagKeys": "stringList"}, EvaluationTime: &now}); rejected != nil {
		return rejected
	}
	return nil
}
func (s *Service) loadWorkGroup(ctx context.Context, tx Transaction, name, action string) (WorkGroupRecord, error) {
	key := resourceFor(ctx, workGroupName(name))
	v, err := tx.WorkGroup(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return v, err
	}
	if rejected := s.authorize(ctx, action, key.ARN("workgroup"), v.Tags, nil); rejected != nil {
		return v, rejected
	}
	if errors.Is(err, ErrNotFound) && key.Name == "primary" {
		v = defaultWorkGroup(key, s.clock.Now())
		err = tx.PutWorkGroup(v)
	}
	return v, err
}
func (s *Service) loadCatalog(ctx context.Context, tx Transaction, name, action string) (CatalogRecord, error) {
	if name == "" || strings.EqualFold(name, "AwsDataCatalog") {
		name = "AwsDataCatalog"
	}
	key := resourceFor(ctx, name)
	v, err := tx.Catalog(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return v, err
	}
	if rejected := s.authorize(ctx, action, key.ARN("datacatalog"), v.Tags, nil); rejected != nil {
		return v, rejected
	}
	if errors.Is(err, ErrNotFound) && name == "AwsDataCatalog" {
		v = defaultCatalog(key)
		err = tx.PutCatalog(v)
	}
	return v, err
}
func (s *Service) loadQuery(ctx context.Context, tx Transaction, id, action string) (QueryRecord, error) {
	v, err := tx.Query(resourceFor(ctx, id))
	if err != nil {
		return v, err
	}
	_, err = s.loadWorkGroup(ctx, tx, value(v.Data.WorkGroup), action)
	return v, err
}
func requestTags(tags api.TagList) (map[string]string, error) {
	out := make(map[string]string, len(tags))
	for _, v := range tags {
		k := value(v.Key)
		if k == "" || strings.HasPrefix(strings.ToLower(k), "aws:") {
			return nil, invalidRequest("Tag key must be nonempty and must not use the aws: prefix.")
		}
		out[k] = value(v.Value)
	}
	if len(out) > 50 {
		return nil, invalidRequest("A resource cannot have more than 50 tags.")
	}
	return out, nil
}
func tagConditions(tags map[string]string) map[string][]string {
	out := map[string][]string{}
	for k, v := range tags {
		out["aws:RequestTag/"+k] = []string{v}
		out["aws:TagKeys"] = append(out["aws:TagKeys"], k)
	}
	return out
}

type pageCursor struct {
	Scope               Scope
	Kind, Parent, After string
}

func cursor(scope Scope, kind, parent string, token *api.Token) (string, error) {
	if token == nil {
		return "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(string(*token))
	if err != nil {
		return "", invalidRequest("Invalid pagination token.")
	}
	var v pageCursor
	if json.Unmarshal(raw, &v) != nil || v.Scope != scope || v.Kind != kind || v.Parent != parent || v.After == "" {
		return "", invalidRequest("Invalid pagination token.")
	}
	return v.After, nil
}
func nextToken(scope Scope, kind, parent, after string) *api.Token {
	b, _ := json.Marshal(pageCursor{scope, kind, parent, after})
	return new(api.Token(base64.RawURLEncoding.EncodeToString(b)))
}
func pageLimit[T ~int32](v *T, maximum int) (int, error) {
	if v == nil {
		return maximum, nil
	}
	if int(*v) < 1 || int(*v) > maximum {
		return 0, invalidRequest("MaxResults is outside the allowed range.")
	}
	return int(*v), nil
}
