package athena

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"

	api "stackd/internal/awsapi/athena"
)

func registerTags(s *Service) {
	registerControl(s, "TagResource", s.tagResource)
	registerControl(s, "UntagResource", s.untagResource)
	registerControl(s, "ListTagsForResource", s.listTagsForResource)
}
func parseResource(ctx context.Context, arn string) (ResourceKey, string, error) {
	parts := strings.SplitN(arn, ":", 6)
	scope := scopeFor(ctx)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != scope.Partition || parts[2] != "athena" || parts[3] != scope.Region || parts[4] != scope.AccountID {
		return ResourceKey{}, "", invalidRequest("Invalid Athena resource ARN.")
	}
	kind, name, ok := strings.Cut(parts[5], "/")
	if !ok || name == "" || (kind != "workgroup" && kind != "datacatalog") {
		return ResourceKey{}, "", invalidRequest("Resource does not support Athena tags.")
	}
	return ResourceKey{Scope: scope, Name: name}, kind, nil
}
func (s *Service) resourceTags(ctx context.Context, tx Transaction, arn, action string, conditions map[string][]string) (map[string]string, func(map[string]string) error, error) {
	key, kind, err := parseResource(ctx, arn)
	if err != nil {
		return nil, nil, err
	}
	if kind == "workgroup" {
		v, err := tx.WorkGroup(key)
		if errors.Is(err, ErrNotFound) && key.Name == "primary" {
			v = defaultWorkGroup(key, s.clock.Now())
			err = nil
		}
		if err != nil {
			return nil, nil, err
		}
		if err := s.authorize(ctx, action, arn, v.Tags, conditions); err != nil {
			return nil, nil, err
		}
		return v.Tags, func(tags map[string]string) error { v.Tags = tags; return tx.PutWorkGroup(v) }, nil
	}
	v, err := tx.Catalog(key)
	if errors.Is(err, ErrNotFound) && key.Name == "AwsDataCatalog" {
		v = defaultCatalog(key)
		err = nil
	}
	if err != nil {
		return nil, nil, err
	}
	if err := s.authorize(ctx, action, arn, v.Tags, conditions); err != nil {
		return nil, nil, err
	}
	return v.Tags, func(tags map[string]string) error { v.Tags = tags; return tx.PutCatalog(v) }, nil
}
func (s *Service) tagResource(ctx context.Context, tx Transaction, in *api.TagResourceInput) (*api.TagResourceOutput, error) {
	tags, err := requestTags(in.Tags)
	if err != nil {
		return nil, err
	}
	current, put, err := s.resourceTags(ctx, tx, value(in.ResourceARN), "TagResource", tagConditions(tags))
	if err != nil {
		return nil, err
	}
	if current == nil {
		current = map[string]string{}
	}
	maps.Copy(current, tags)
	if len(current) > 50 {
		return nil, invalidRequest("A resource cannot have more than 50 tags.")
	}
	if err := put(current); err != nil {
		return nil, err
	}
	return &api.TagResourceOutput{}, nil
}
func (s *Service) untagResource(ctx context.Context, tx Transaction, in *api.UntagResourceInput) (*api.UntagResourceOutput, error) {
	var keys []string
	if len(in.TagKeys) > 0 {
		keys = make([]string, len(in.TagKeys))
		for i, k := range in.TagKeys {
			keys[i] = string(k)
		}
	}
	current, put, err := s.resourceTags(ctx, tx, value(in.ResourceARN), "UntagResource", map[string][]string{"aws:TagKeys": keys})
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		delete(current, k)
	}
	if err := put(current); err != nil {
		return nil, err
	}
	return &api.UntagResourceOutput{}, nil
}
func (s *Service) listTagsForResource(ctx context.Context, tx Transaction, in *api.ListTagsForResourceInput) (*api.ListTagsForResourceOutput, error) {
	tags, _, err := s.resourceTags(ctx, tx, value(in.ResourceARN), "ListTagsForResource", nil)
	if err != nil {
		return nil, err
	}
	limit, err := pageLimit(in.MaxResults, 50)
	if err != nil {
		return nil, err
	}
	after, err := cursor(scopeFor(ctx), "tags", value(in.ResourceARN), in.NextToken)
	if err != nil {
		return nil, err
	}
	keys := slices.Sorted(maps.Keys(tags))
	out := &api.ListTagsForResourceOutput{Tags: api.TagList{}}
	for _, key := range keys {
		if key <= after {
			continue
		}
		if len(out.Tags) == limit {
			last := value(out.Tags[len(out.Tags)-1].Key)
			out.NextToken = nextToken(scopeFor(ctx), "tags", value(in.ResourceARN), last)
			break
		}
		out.Tags = append(out.Tags, api.Tag{Key: new(api.TagKey(key)), Value: new(api.TagValue(tags[key]))})
	}
	return out, nil
}
