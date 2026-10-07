package opensearch

import (
	"context"
	"maps"
	"slices"
	"strings"

	api "stackd/internal/awsapi/opensearch"
)

func keyFromARN(arn string) (Key, error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "es" || !strings.HasPrefix(parts[5], "domain/") {
		return Key{}, failure("ValidationException", "Invalid domain ARN.")
	}
	name := strings.TrimPrefix(parts[5], "domain/")
	if !domainName.MatchString(name) {
		return Key{}, failure("ValidationException", "Invalid domain ARN.")
	}
	return Key{Scope{parts[1], parts[4], parts[3]}, name}, nil
}
func (s *Service) tagDomain(ctx context.Context, tx Transaction, arn, action string, conditions map[string][]string) (Domain, error) {
	k, err := keyFromARN(arn)
	if err != nil {
		return Domain{}, err
	}
	if k.Scope != scopeFor(ctx) {
		return Domain{}, ErrNotFound
	}
	v, err := tx.Domain(k)
	if err != nil {
		return v, err
	}
	if cloudFormationForeign(ctx, v) {
		return Domain{}, ErrNotFound
	}
	if err = s.authorize(ctx, action, arn, v.Tags, conditions, nil); err != nil {
		return v, err
	}
	return v, nil
}
func (s *Service) addTags(ctx context.Context, tx Transaction, in *api.AddTagsRequest) (*api.Unit, error) {
	tags, err := requestTags(in.TagList)
	if err != nil {
		return nil, err
	}
	v, err := s.tagDomain(ctx, tx, value(in.ARN), "AddTags", tagConditions(tags))
	if err != nil {
		return nil, err
	}
	if v.Tags == nil {
		v.Tags = map[string]string{}
	}
	maps.Copy(v.Tags, tags)
	if len(v.Tags) > 50 {
		return nil, failure("ValidationException", "A domain cannot have more than 50 tags.")
	}
	return &api.Unit{}, tx.PutDomain(v)
}
func (s *Service) removeTags(ctx context.Context, tx Transaction, in *api.RemoveTagsRequest) (*api.Unit, error) {
	conditions := map[string][]string{"aws:TagKeys": nil}
	for _, k := range in.TagKeys {
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], string(k))
	}
	v, err := s.tagDomain(ctx, tx, value(in.ARN), "RemoveTags", conditions)
	if err != nil {
		return nil, err
	}
	for _, k := range in.TagKeys {
		delete(v.Tags, string(k))
	}
	return &api.Unit{}, tx.PutDomain(v)
}
func (s *Service) listTags(ctx context.Context, tx Transaction, in *api.ListTagsRequest) (*api.ListTagsResponse, error) {
	v, err := s.tagDomain(ctx, tx, value(in.ARN), "ListTags", nil)
	if err != nil {
		return nil, err
	}
	out := &api.ListTagsResponse{TagList: api.TagList{}}
	for _, k := range slices.Sorted(maps.Keys(v.Tags)) {
		out.TagList = append(out.TagList, api.Tag{Key: new(api.TagKey(k)), Value: new(api.TagValue(v.Tags[k]))})
	}
	return out, nil
}
