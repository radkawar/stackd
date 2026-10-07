package docdb

import (
	"context"
	"errors"
	api "stackd/internal/awsapi/docdb"
	"strings"
)

func (s *Service) tagResource(ctx context.Context, tx Transaction, action, arn string, requestTags map[string]string, change func(map[string]string) (map[string]string, error)) (map[string]string, error) {
	parts := strings.SplitN(arn, ":", 7)
	if len(parts) != 7 {
		return nil, failure("InvalidParameterValue", "ResourceName must be a resource ARN.")
	}
	key, err := resourceKey(ctx, parts[5], arn)
	if err != nil {
		return nil, err
	}
	check := func(tags map[string]string, owner CloudFormationOwner, err error) error {
		if errors.Is(err, ErrNotFound) {
			return notFound(key.Kind)
		}
		if err != nil {
			return err
		}
		if err = checkCloudFormationOwner(ctx, key, owner); err != nil {
			return err
		}
		return s.authorize(ctx, action, key, tags, requestTags)
	}
	switch key.Kind {
	case "cluster":
		v, e := tx.Cluster(key)
		if e = check(v.Tags, v.Owner, e); e != nil {
			return nil, e
		}
		if change != nil {
			v.Tags, e = change(v.Tags)
			if e != nil {
				return nil, e
			}
			e = tx.PutCluster(v)
		}
		return v.Tags, e
	case "db":
		v, e := tx.Instance(key)
		if e = check(v.Tags, v.Owner, e); e != nil {
			return nil, e
		}
		if change != nil {
			v.Tags, e = change(v.Tags)
			if e != nil {
				return nil, e
			}
			e = tx.PutInstance(v)
		}
		return v.Tags, e
	case "cluster-snapshot":
		v, e := tx.Snapshot(key)
		if e = check(v.Tags, v.Owner, e); e != nil {
			return nil, e
		}
		if e = checkCloudFormationSnapshot(ctx, key, "cluster-"+v.SourceRuntimeID); e != nil {
			return nil, e
		}
		if change != nil {
			v.Tags, e = change(v.Tags)
			if e != nil {
				return nil, e
			}
			e = tx.PutSnapshot(v)
		}
		return v.Tags, e
	}
	return nil, failure("InvalidParameterValue", "Unsupported DocumentDB resource type.")
}
func (s *Service) addTags(ctx context.Context, tx Transaction, in *api.AddTagsToResourceInput) (*api.AddTagsToResourceOutput, error) {
	tags, e := tagsFrom(in.Tags)
	if e != nil {
		return nil, e
	}
	_, e = s.tagResource(ctx, tx, "AddTagsToResource", value(in.ResourceName), tags, func(current map[string]string) (map[string]string, error) {
		if current == nil {
			current = map[string]string{}
		}
		for k, v := range tags {
			current[k] = v
		}
		if len(current) > 50 {
			return nil, failure("InvalidParameterValue", "At most 50 customer tags are supported.")
		}
		return current, nil
	})
	return &api.AddTagsToResourceOutput{}, e
}
func (s *Service) removeTags(ctx context.Context, tx Transaction, in *api.RemoveTagsFromResourceInput) (*api.RemoveTagsFromResourceOutput, error) {
	_, e := s.tagResource(ctx, tx, "RemoveTagsFromResource", value(in.ResourceName), nil, func(current map[string]string) (map[string]string, error) {
		for _, k := range in.TagKeys {
			delete(current, string(k))
		}
		return current, nil
	})
	return &api.RemoveTagsFromResourceOutput{}, e
}
func (s *Service) listTags(ctx context.Context, tx Transaction, in *api.ListTagsForResourceInput) (*api.ListTagsForResourceOutput, error) {
	if len(in.Filters) > 0 {
		return nil, unsupported("Tag filters are not implemented.")
	}
	tags, e := s.tagResource(ctx, tx, "ListTagsForResource", value(in.ResourceName), nil, nil)
	if e != nil {
		return nil, e
	}
	return &api.ListTagsForResourceOutput{TagList: tagList(tags)}, nil
}
