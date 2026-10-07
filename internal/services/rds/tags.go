package rds

import (
	"context"
	"errors"
	"maps"
	"strings"

	api "stackd/internal/awsapi/rds"
)

func tagKey(ctx context.Context, arn string) (Key, error) {
	sc := scopeFor(ctx)
	prefix := "arn:" + sc.Partition + ":rds:" + sc.Region + ":" + sc.AccountID + ":"
	if !strings.HasPrefix(arn, prefix) {
		return Key{}, notFound("db")
	}
	kind, name, ok := strings.Cut(strings.TrimPrefix(arn, prefix), ":")
	if !ok {
		return Key{}, notFound("db")
	}
	switch kind {
	case "db", "cluster", "snapshot", "cluster-snapshot", "pg", "cluster-pg", "subgrp":
		return resourceKey(ctx, kind, name)
	}
	return Key{}, notFound(kind)
}

func readTags(tx Reader, k Key) (map[string]string, error) {
	var tags map[string]string
	var e error
	switch k.Kind {

	case "db", "cluster":
		v, err := tx.Database(k)
		tags, e = v.Tags, err
		if e == nil {
			e = checkCloudFormationOwner(tx.Context(), k, v.Owner)
		}
	case "snapshot", "cluster-snapshot":
		v, err := tx.Snapshot(k)
		tags, e = v.Tags, err
		if e == nil {
			e = checkCloudFormationOwner(tx.Context(), k, v.Owner)
		}
		id := "db-" + v.SourceRuntimeID
		if k.Kind == "cluster-snapshot" {
			id = "cluster-" + v.SourceRuntimeID
		}
		if e == nil {
			e = checkCloudFormationSnapshot(tx.Context(), k, id)
		}
	case "pg", "cluster-pg":
		v, err := tx.ParameterGroup(k)
		tags, e = v.Tags, err
		if e == nil {
			e = checkCloudFormationOwner(tx.Context(), k, v.Owner)
		}
	case "subgrp":
		v, err := tx.SubnetGroup(k)
		tags, e = v.Tags, err
		if e == nil {
			e = checkCloudFormationOwner(tx.Context(), k, v.Owner)
		}

	}
	if errors.Is(e, ErrNotFound) {
		e = notFound(k.Kind)
	}
	return tags, e
}

func writeTags(tx Transaction, k Key, tags map[string]string) error {
	switch k.Kind {

	case "db", "cluster":
		v, e := tx.Database(k)
		if e != nil {
			return e
		}
		v.Tags = tags
		v.Version++
		return tx.PutDatabase(v)
	case "snapshot", "cluster-snapshot":
		v, e := tx.Snapshot(k)
		if e != nil {
			return e
		}
		v.Tags = tags
		v.Version++
		return tx.PutSnapshot(v)
	case "pg", "cluster-pg":
		v, e := tx.ParameterGroup(k)
		if e != nil {
			return e
		}
		v.Tags = tags
		return tx.PutParameterGroup(v)
	case "subgrp":
		v, e := tx.SubnetGroup(k)
		if e != nil {
			return e
		}
		v.Tags = tags
		return tx.PutSubnetGroup(v)

	}
	return notFound(k.Kind)
}

func (s *Service) addTags(ctx context.Context, tx Transaction, in *api.AddTagsToResourceMessage) (*emptyResult, error) {
	k, e := tagKey(ctx, value(in.ResourceName))
	if e != nil {
		return nil, e
	}
	old, e := readTags(tx, k)
	if e != nil {
		return nil, e
	}
	added, e := tagsFrom(in.Tags)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "AddTagsToResource", k, old, added); e != nil {
		return nil, e
	}
	tags := maps.Clone(old)
	if tags == nil {
		tags = map[string]string{}
	}
	maps.Copy(tags, added)
	if len(tags) > 50 {
		return nil, failure("InvalidParameterValue", "At most 50 customer tags are supported.")
	}
	return &emptyResult{}, writeTags(tx, k, tags)
}

func (s *Service) removeTags(ctx context.Context, tx Transaction, in *api.RemoveTagsFromResourceMessage) (*emptyResult, error) {
	k, e := tagKey(ctx, value(in.ResourceName))
	if e != nil {
		return nil, e
	}
	tags, e := readTags(tx, k)
	if e != nil {
		return nil, e
	}
	requested := map[string]string{}
	for _, key := range in.TagKeys {
		requested[string(key)] = ""
	}
	if e = s.authorize(ctx, "RemoveTagsFromResource", k, tags, requested); e != nil {
		return nil, e
	}
	for _, key := range in.TagKeys {
		delete(tags, string(key))
	}
	return &emptyResult{}, writeTags(tx, k, tags)
}

func (s *Service) listTags(ctx context.Context, tx Transaction, in *api.ListTagsForResourceMessage) (*api.TagListMessage, error) {
	if len(in.Filters) > 0 {
		return nil, unsupported("Tag filters are not supported.")
	}
	k, e := tagKey(ctx, value(in.ResourceName))
	if e != nil {
		return nil, e
	}
	tags, e := readTags(tx, k)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "ListTagsForResource", k, tags, nil); e != nil {
		return nil, e
	}
	return &api.TagListMessage{TagList: tagList(tags)}, nil
}
