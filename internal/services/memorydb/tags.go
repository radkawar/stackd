package memorydb

import (
	"context"
	"errors"
	"maps"
	api "stackd/internal/awsapi/memorydb"
	"strings"
)

func tagKey(ctx context.Context, arn string) (Key, error) {
	sc := scopeFor(ctx)
	prefix := "arn:" + sc.Partition + ":memorydb:" + sc.Region + ":" + sc.AccountID + ":"
	if !strings.HasPrefix(arn, prefix) {
		return Key{}, failure("InvalidARNFault", "The resource ARN is outside the current scope.")
	}
	parts := strings.SplitN(strings.TrimPrefix(arn, prefix), "/", 2)
	if len(parts) != 2 || parts[1] == "" {
		return Key{}, failure("InvalidARNFault", "Invalid resource ARN.")
	}
	return Key{Scope: sc, Kind: parts[0], Name: parts[1]}, nil
}
func resourceTags(r Reader, k Key) (map[string]string, error) {
	var tags map[string]string
	var e error
	switch k.Kind {
	case "cluster":
		var v Cluster
		v, e = r.Cluster(k)
		tags = v.Tags
	case "user":
		var v User
		v, e = r.User(k)
		tags = v.Tags
		if k.Name == "default" {
			tags = map[string]string{}
			e = nil
		}
	case "acl":
		var v ACL
		v, e = r.ACL(k)
		tags = v.Tags
		if k.Name == "open-access" {
			tags = map[string]string{}
			e = nil
		}
	case "parametergroup":
		var v ParameterGroup
		v, e = r.ParameterGroup(k)
		tags = v.Tags
		if _, ok := defaultParameterGroup(k.Scope, k.Name); ok {
			tags = map[string]string{}
			e = nil
		}
	case "subnetgroup":
		var v SubnetGroup
		v, e = r.SubnetGroup(k)
		tags = v.Tags
	case "snapshot":
		var v Snapshot
		v, e = r.Snapshot(k)
		tags = v.Tags
	default:
		return nil, failure("InvalidARNFault", "Invalid MemoryDB resource type.")
	}
	if errors.Is(e, ErrNotFound) {
		e = notFound(k.Kind)
	}
	return tags, e
}
func putTags(tx Transaction, k Key, tags map[string]string) error {
	switch k.Kind {
	case "cluster":
		v, e := tx.Cluster(k)
		if e != nil {
			return e
		}
		v.Tags = tags
		return tx.PutCluster(v)
	case "user":
		v, e := tx.User(k)
		if e != nil {
			return e
		}
		v.Tags = tags
		return tx.PutUser(v)
	case "acl":
		v, e := tx.ACL(k)
		if e != nil {
			return e
		}
		v.Tags = tags
		return tx.PutACL(v)
	case "parametergroup":
		v, e := tx.ParameterGroup(k)
		if e != nil {
			return e
		}
		v.Tags = tags
		return tx.PutParameterGroup(v)
	case "subnetgroup":
		v, e := tx.SubnetGroup(k)
		if e != nil {
			return e
		}
		v.Tags = tags
		return tx.PutSubnetGroup(v)
	case "snapshot":
		v, e := tx.Snapshot(k)
		if e != nil {
			return e
		}
		v.Tags = tags
		return tx.PutSnapshot(v)
	}
	return notFound(k.Kind)
}
func immutable(k Key) bool {
	return k.Kind == "user" && k.Name == "default" || k.Kind == "acl" && k.Name == "open-access" || k.Kind == "parametergroup" && strings.HasPrefix(k.Name, "default.")
}
func (s *Service) tagResource(ctx context.Context, tx Transaction, in *api.TagResourceRequest) (*api.TagResourceResponse, error) {
	k, e := tagKey(ctx, value(in.ResourceArn))
	if e != nil {
		return nil, e
	}
	tags, e := resourceTags(tx, k)
	if e != nil {
		return nil, e
	}
	requested, e := tagsFrom(in.Tags)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "TagResource", k, tags, requested); e != nil {
		return nil, e
	}
	if immutable(k) {
		return nil, invalid("Built-in resources cannot be tagged.")
	}
	if tags == nil {
		tags = map[string]string{}
	}
	maps.Copy(tags, requested)
	if len(tags) > 50 {
		return nil, failure("TagQuotaPerResourceExceeded", "At most 50 tags are allowed.")
	}
	if e = putTags(tx, k, tags); e != nil {
		return nil, e
	}
	return &api.TagResourceResponse{TagList: tagList(tags)}, nil
}
func (s *Service) untagResource(ctx context.Context, tx Transaction, in *api.UntagResourceRequest) (*api.UntagResourceResponse, error) {
	k, e := tagKey(ctx, value(in.ResourceArn))
	if e != nil {
		return nil, e
	}
	tags, e := resourceTags(tx, k)
	if e != nil {
		return nil, e
	}
	requestTags := map[string]string{}
	for _, name := range in.TagKeys {
		requestTags[string(name)] = ""
	}
	if e = s.authorize(ctx, "UntagResource", k, tags, requestTags); e != nil {
		return nil, e
	}
	if immutable(k) {
		return nil, invalid("Built-in resources cannot be tagged.")
	}
	for _, name := range in.TagKeys {
		delete(tags, string(name))
	}
	if e = putTags(tx, k, tags); e != nil {
		return nil, e
	}
	return &api.UntagResourceResponse{TagList: tagList(tags)}, nil
}
func (s *Service) listTags(ctx context.Context, tx Transaction, in *api.ListTagsRequest) (*api.ListTagsResponse, error) {
	k, e := tagKey(ctx, value(in.ResourceArn))
	if e != nil {
		return nil, e
	}
	tags, e := resourceTags(tx, k)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "ListTags", k, tags, nil); e != nil {
		return nil, e
	}
	return &api.ListTagsResponse{TagList: tagList(tags)}, nil
}
