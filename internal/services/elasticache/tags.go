package elasticache

import (
	"context"
	"errors"
	"maps"
	api "stackd/internal/awsapi/elasticache"
	"strings"
)

func tagKey(ctx context.Context, raw string) (Key, error) {
	parts := strings.SplitN(raw, ":", 7)
	if len(parts) != 7 || parts[0] != "arn" || parts[2] != "elasticache" {
		return Key{}, failure("InvalidARN", "A valid ElastiCache ARN is required.")
	}
	sc := scopeFor(ctx)
	if parts[1] != sc.Partition || parts[3] != sc.Region || parts[4] != sc.AccountID {
		return Key{}, notFound(parts[5])
	}
	return resourceKey(ctx, parts[5], raw)
}
func resourceTags(tx Transaction, k Key) (map[string]string, func(map[string]string) error, error) {
	switch k.Kind {
	case "cluster", "replicationgroup":
		v, e := tx.Cluster(k)
		return v.Tags, func(tags map[string]string) error { v.Tags = tags; return tx.PutCluster(v) }, e
	case "snapshot":
		v, e := tx.Snapshot(k)
		return v.Tags, func(tags map[string]string) error { v.Tags = tags; return tx.PutSnapshot(v) }, e
	case "user":
		v, e := userRecord(tx, k)
		return v.Tags, func(tags map[string]string) error { v.Tags = tags; return tx.PutUser(v) }, e
	case "usergroup":
		v, e := tx.UserGroup(k)
		return v.Tags, func(tags map[string]string) error { v.Tags = tags; return tx.PutUserGroup(v) }, e
	case "parametergroup":
		v, e := parameterRecord(tx, k)
		return v.Tags, func(tags map[string]string) error {
			if builtinParameterFamily(k.Name) != "" {
				return stateError(k.Kind)
			}
			v.Tags = tags
			return tx.PutParameterGroup(v)
		}, e
	case "subnetgroup":
		v, e := tx.SubnetGroup(k)
		return v.Tags, func(tags map[string]string) error { v.Tags = tags; return tx.PutSubnetGroup(v) }, e
	}
	return nil, nil, ErrNotFound
}
func (s *Service) tagResource(ctx context.Context, tx Transaction, action, raw string, add map[string]string, remove []string) (*api.TagListMessage, error) {
	k, e := tagKey(ctx, raw)
	if e != nil {
		return nil, e
	}
	tags, save, e := resourceTags(tx, k)
	if errors.Is(e, ErrNotFound) {
		return nil, notFound(k.Kind)
	}
	if e != nil {
		return nil, e
	}
	requestTags := add
	if remove != nil {
		requestTags = map[string]string{}
		for _, key := range remove {
			requestTags[key] = ""
		}
	}
	if e = s.authorize(ctx, action, k, tags, requestTags); e != nil {
		return nil, e
	}
	if action != "ListTagsForResource" {
		tags = maps.Clone(tags)
		if tags == nil {
			tags = map[string]string{}
		}
		for key, v := range add {
			tags[key] = v
		}
		for _, key := range remove {
			delete(tags, key)
		}
		if len(tags) > 50 {
			return nil, failure("TagQuotaPerResourceExceeded", "At most 50 tags are permitted.")
		}
		if e = save(tags); e != nil {
			return nil, e
		}
	}
	return &api.TagListMessage{TagList: tagList(tags)}, nil
}
func (s *Service) addTags(ctx context.Context, tx Transaction, in *api.AddTagsToResourceMessage) (*api.TagListMessage, error) {
	tags, e := tagsFrom(in.Tags)
	if e != nil {
		return nil, e
	}
	if len(tags) == 0 {
		return nil, failure("InvalidParameterValue", "Tags must not be empty.")
	}
	return s.tagResource(ctx, tx, "AddTagsToResource", value(in.ResourceName), tags, nil)
}
func (s *Service) removeTags(ctx context.Context, tx Transaction, in *api.RemoveTagsFromResourceMessage) (*api.TagListMessage, error) {
	if len(in.TagKeys) == 0 {
		return nil, failure("InvalidParameterValue", "TagKeys must not be empty.")
	}
	keys := make([]string, 0, len(in.TagKeys))
	for _, key := range in.TagKeys {
		if key == "" || strings.HasPrefix(strings.ToLower(string(key)), "aws:") {
			return nil, failure("InvalidParameterValue", "Invalid tag key.")
		}
		keys = append(keys, string(key))
	}
	return s.tagResource(ctx, tx, "RemoveTagsFromResource", value(in.ResourceName), nil, keys)
}
func (s *Service) listTags(ctx context.Context, tx Transaction, in *api.ListTagsForResourceMessage) (*api.TagListMessage, error) {
	return s.tagResource(ctx, tx, "ListTagsForResource", value(in.ResourceName), nil, nil)
}
