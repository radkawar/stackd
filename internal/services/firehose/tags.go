package firehose

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	api "stackd/internal/awsapi/firehose"
)

func requestTags(tags api.TagDeliveryStreamInputTagList) (map[string]string, error) {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if tag.Key == nil || value(tag.Key) == "" {
			return nil, failure("InvalidArgumentException", "Tag key must not be empty")
		}
		if tag.Value == nil {
			return nil, failure("InvalidArgumentException", "Tag value must not be null")
		}
		if err := mutableTagKey(value(tag.Key)); err != nil {
			return nil, err
		}
		out[value(tag.Key)] = value(tag.Value)
	}
	return out, nil
}

func mutableTagKey(key string) error {
	if strings.HasPrefix(strings.ToLower(key), "aws:") {
		return failure("InvalidArgumentException", "Tag keys beginning with aws: cannot be modified")
	}
	return nil
}

func requestTagConditions(tags map[string]string) map[string][]string {
	conditions := make(map[string][]string, len(tags)+1)
	keys := make([]string, 0, len(tags))
	for key, val := range tags {
		keys = append(keys, key)
		conditions["aws:RequestTag/"+key] = []string{val}
	}
	slices.Sort(keys)
	if len(keys) != 0 {
		conditions["aws:TagKeys"] = keys
	}
	return conditions
}

func mutableTags(stream StreamRecord) error {
	if stream.Status == "DELETING" {
		return failure("ResourceInUseException", fmt.Sprintf("Firehose %s under account %s is in the DELETING state.", stream.Key.Name, stream.Key.AccountID))
	}
	return nil
}

func (s *Service) tagDeliveryStream(ctx context.Context, tx Transaction, in *api.TagDeliveryStreamInput) (*api.TagDeliveryStreamOutput, error) {
	tags, err := requestTags(in.Tags)
	if err != nil {
		return nil, err
	}
	key := StreamKey{Scope: scopeFor(ctx), Name: value(in.DeliveryStreamName)}
	if err := s.authorize(ctx, tx, key, "TagDeliveryStream", requestTagConditions(tags)); err != nil {
		return nil, err
	}
	stream, err := findStream(tx, key)
	if err != nil {
		return nil, err
	}
	if err := mutableTags(stream); err != nil {
		return nil, err
	}
	merged := make(map[string]string, len(stream.Tags)+len(tags))
	maps.Copy(merged, stream.Tags)
	maps.Copy(merged, tags)
	if len(merged) > 50 {
		return nil, failure("InvalidArgumentException", "A delivery stream cannot have more than 50 tags")
	}
	stream.Tags = merged
	if err := tx.PutStream(stream); err != nil {
		return nil, err
	}
	return &api.TagDeliveryStreamOutput{}, nil
}

func (s *Service) untagDeliveryStream(ctx context.Context, tx Transaction, in *api.UntagDeliveryStreamInput) (*api.UntagDeliveryStreamOutput, error) {
	keys := make([]string, 0, len(in.TagKeys))
	for _, key := range in.TagKeys {
		if err := mutableTagKey(string(key)); err != nil {
			return nil, err
		}
		keys = append(keys, string(key))
	}
	key := StreamKey{Scope: scopeFor(ctx), Name: value(in.DeliveryStreamName)}
	if err := s.authorize(ctx, tx, key, "UntagDeliveryStream", map[string][]string{"aws:TagKeys": keys}); err != nil {
		return nil, err
	}
	stream, err := findStream(tx, key)
	if err != nil {
		return nil, err
	}
	if err := mutableTags(stream); err != nil {
		return nil, err
	}
	stream.Tags = maps.Clone(stream.Tags)
	for _, key := range keys {
		delete(stream.Tags, key)
	}
	if err := tx.PutStream(stream); err != nil {
		return nil, err
	}
	return &api.UntagDeliveryStreamOutput{}, nil
}

func (s *Service) listTagsForDeliveryStream(ctx context.Context, tx Transaction, in *api.ListTagsForDeliveryStreamInput) (*api.ListTagsForDeliveryStreamOutput, error) {
	stream, err := s.loadStream(ctx, tx, value(in.DeliveryStreamName), "ListTagsForDeliveryStream")
	if err != nil {
		return nil, err
	}
	limit := 50
	if in.Limit != nil {
		limit = int(*in.Limit)
	}
	if limit < 1 {
		return nil, failure("InvalidArgumentException", "Limit must be positive")
	}
	keys := slices.Sorted(maps.Keys(stream.Tags))
	out := &api.ListTagsForDeliveryStreamOutput{Tags: api.ListTagsForDeliveryStreamOutputTagList{}, HasMoreTags: new(api.BooleanObject(false))}
	for _, key := range keys {
		if key <= value(in.ExclusiveStartTagKey) {
			continue
		}
		if len(out.Tags) == limit {
			out.HasMoreTags = new(api.BooleanObject(true))
			break
		}
		out.Tags = append(out.Tags, api.Tag{Key: new(api.TagKey(key)), Value: new(api.TagValue(stream.Tags[key]))})
	}
	return out, nil
}
