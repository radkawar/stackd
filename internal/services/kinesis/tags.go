package kinesis

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	api "stackd/internal/awsapi/kinesis"
)

func requestTagConditions(tags api.TagMap) map[string][]string {
	conditions := map[string][]string{}
	keys := make([]string, 0, len(tags))
	for key, val := range tags {
		keys = append(keys, string(key))
		conditions["aws:RequestTag/"+string(key)] = []string{string(val)}
	}
	slices.Sort(keys)
	if len(keys) != 0 {
		conditions["aws:TagKeys"] = keys
	}
	return conditions
}

func validateTagKey(key string) error {
	if strings.HasPrefix(strings.ToLower(key), "aws:") {
		return failure("InvalidArgumentException", "Some tag keys in the request started with 'aws:'. System tags cannot be modified.")
	}
	if utf8.RuneCountInString(key) < 1 || utf8.RuneCountInString(key) > 128 {
		return failure("ValidationException", "Tag keys must contain between 1 and 128 characters")
	}
	return nil
}

func validateTags(tags api.TagMap) error {
	if len(tags) == 0 {
		return failure("ValidationException", "Tags must not be empty")
	}
	if len(tags) > 50 {
		return failure("InvalidArgumentException", "A resource cannot have more than 50 tags associated with it.")
	}
	for key, val := range tags {
		if err := validateTagKey(string(key)); err != nil {
			return err
		}
		if utf8.RuneCountInString(string(val)) > 256 {
			return failure("ValidationException", "Tag values must contain at most 256 characters")
		}
	}
	return nil
}

func sortedTags(tags api.TagMap) api.TagList {
	keys := make([]api.TagKey, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	out := make(api.TagList, 0, len(tags))
	for _, key := range keys {
		out = append(out, api.Tag{Key: new(key), Value: new(tags[key])})
	}
	return out
}

func resourceTags(r Reader, key ResourceKey) (api.TagList, error) {
	record, err := r.Tags(key)
	if errors.Is(err, ErrNotFound) {
		return api.TagList{}, nil
	}
	if err != nil {
		return nil, err
	}
	if record.Tags == nil {
		return api.TagList{}, nil
	}
	slices.SortFunc(record.Tags, func(a, b api.Tag) int { return strings.Compare(value(a.Key), value(b.Key)) })
	return record.Tags, nil
}

func (s *Service) mergeTags(tx Transaction, key ResourceKey, tags api.TagMap) error {
	current, err := resourceTags(tx, key)
	if err != nil {
		return err
	}
	merged := make(api.TagMap, len(current)+len(tags))
	for _, tag := range current {
		merged[*tag.Key] = api.TagValue(value(tag.Value))
	}
	for key, val := range tags {
		merged[key] = val
	}
	if len(merged) > 50 {
		return failure("InvalidArgumentException", fmt.Sprintf("Failed to add tags to resource %s under account %s because a given resource cannot have more than 50 tags associated with it.", key.ARN, key.AccountID))
	}
	return tx.PutTags(TagRecord{Key: key, Tags: sortedTags(merged)})
}

func removeTagConditions(keys api.TagKeyList) (map[string][]string, error) {
	if len(keys) == 0 || len(keys) > 50 {
		return nil, failure("ValidationException", "TagKeys must contain between 1 and 50 keys")
	}
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		if err := validateTagKey(string(key)); err != nil {
			return nil, err
		}
		values = append(values, string(key))
	}
	return map[string][]string{"aws:TagKeys": values}, nil
}

func removeResourceTags(tx Transaction, key ResourceKey, keys api.TagKeyList) error {
	current, err := resourceTags(tx, key)
	if err != nil {
		return err
	}
	result := make(api.TagList, 0, len(current))
	for _, tag := range current {
		if !slices.Contains(keys, *tag.Key) {
			result = append(result, tag)
		}
	}
	return tx.PutTags(TagRecord{Key: key, Tags: result})
}

func (s *Service) addTagsToStream(ctx context.Context, tx Transaction, in *api.AddTagsToStreamInput) (*api.AddTagsToStreamOutput, error) {
	if err := validateTags(in.Tags); err != nil {
		return nil, err
	}
	stream, err := streamKey(ctx, value(in.StreamName), value(in.StreamARN))
	if err != nil {
		return nil, err
	}
	key, err := s.resourceTarget(ctx, tx, stream.ARN(), "AddTagsToStream", requestTagConditions(in.Tags))
	if err != nil {
		return nil, err
	}
	if err = s.mergeTags(tx, key, in.Tags); err != nil {
		return nil, err
	}
	return &api.AddTagsToStreamOutput{}, nil
}

func (s *Service) tagResource(ctx context.Context, tx Transaction, in *api.TagResourceInput) (*api.TagResourceOutput, error) {
	if err := validateTags(in.Tags); err != nil {
		return nil, err
	}
	key, err := s.resourceTarget(ctx, tx, value(in.ResourceARN), "TagResource", requestTagConditions(in.Tags))
	if err != nil {
		return nil, err
	}
	if err = s.mergeTags(tx, key, in.Tags); err != nil {
		return nil, err
	}
	return &api.TagResourceOutput{}, nil
}

func (s *Service) removeTagsFromStream(ctx context.Context, tx Transaction, in *api.RemoveTagsFromStreamInput) (*api.RemoveTagsFromStreamOutput, error) {
	conditions, err := removeTagConditions(in.TagKeys)
	if err != nil {
		return nil, err
	}
	stream, err := streamKey(ctx, value(in.StreamName), value(in.StreamARN))
	if err != nil {
		return nil, err
	}
	key, err := s.resourceTarget(ctx, tx, stream.ARN(), "RemoveTagsFromStream", conditions)
	if err != nil {
		return nil, err
	}
	if err = removeResourceTags(tx, key, in.TagKeys); err != nil {
		return nil, err
	}
	return &api.RemoveTagsFromStreamOutput{}, nil
}

func (s *Service) untagResource(ctx context.Context, tx Transaction, in *api.UntagResourceInput) (*api.UntagResourceOutput, error) {
	conditions, err := removeTagConditions(in.TagKeys)
	if err != nil {
		return nil, err
	}
	key, err := s.resourceTarget(ctx, tx, value(in.ResourceARN), "UntagResource", conditions)
	if err != nil {
		return nil, err
	}
	if err = removeResourceTags(tx, key, in.TagKeys); err != nil {
		return nil, err
	}
	return &api.UntagResourceOutput{}, nil
}

func (s *Service) listTagsForResource(ctx context.Context, tx Transaction, in *api.ListTagsForResourceInput) (*api.ListTagsForResourceOutput, error) {
	key, err := s.resourceTarget(ctx, tx, value(in.ResourceARN), "ListTagsForResource", nil)
	if err != nil {
		return nil, err
	}
	tags, err := resourceTags(tx, key)
	if err != nil {
		return nil, err
	}
	return &api.ListTagsForResourceOutput{Tags: tags}, nil
}

func (s *Service) listTagsForStream(ctx context.Context, tx Transaction, in *api.ListTagsForStreamInput) (*api.ListTagsForStreamOutput, error) {
	stream, err := s.stream(ctx, tx, value(in.StreamName), value(in.StreamARN), "ListTagsForStream")
	if err != nil {
		return nil, err
	}
	tags, err := resourceTags(tx, ResourceKey{Scope: stream.Key.Scope, ARN: stream.Key.ARN()})
	if err != nil {
		return nil, err
	}
	limit := 50
	if in.Limit != nil {
		limit = int(*in.Limit)
	}
	if limit < 1 || limit > 10000 {
		return nil, failure("ValidationException", "Limit must be between 1 and 10000")
	}
	out := &api.ListTagsForStreamOutput{Tags: api.TagList{}, HasMoreTags: new(api.BooleanObject(false))}
	for _, tag := range tags {
		if value(tag.Key) <= value(in.ExclusiveStartTagKey) {
			continue
		}
		if len(out.Tags) == limit {
			out.HasMoreTags = new(api.BooleanObject(true))
			break
		}
		out.Tags = append(out.Tags, tag)
	}
	return out, nil
}
