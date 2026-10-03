package applicationautoscaling

import (
	"context"
	"maps"
	"slices"
	"strings"
	"unicode/utf8"

	api "stackd/internal/awsapi/applicationautoscaling"
)

func validateTagKey(key string) error {
	if n := utf8.RuneCountInString(key); n < 1 || n > 128 {
		return invalid("Tag keys must contain between 1 and 128 characters")
	}
	if strings.HasPrefix(strings.ToLower(key), "aws:") {
		return invalid("Caller is an end user and not allowed to mutate system tags")
	}
	return nil
}

func validateTags(tags api.TagMap) error {
	if len(tags) == 0 {
		return invalid("Tags cannot be empty")
	}
	for key, value := range tags {
		if err := validateTagKey(string(key)); err != nil {
			return err
		}
		if utf8.RuneCountInString(string(value)) > 256 {
			return invalid("Tag values cannot exceed 256 characters")
		}
	}
	if len(tags) > 50 {
		return failure("TooManyTagsException", "A scalable target cannot have more than 50 tags")
	}
	return nil
}

func (s *Service) listTagsForResource(ctx context.Context, tx Transaction, in *api.ListTagsForResourceInput) (*api.ListTagsForResourceOutput, error) {
	target, err := targetByARN(ctx, tx, value(in.ResourceARN))
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "ListTagsForResource", value(target.Data.ScalableTargetARN), targetConditions(TargetKey{}, target.Tags)); err != nil {
		return nil, err
	}
	tags := maps.Clone(target.Tags)
	if tags == nil {
		tags = api.TagMap{}
	}
	return &api.ListTagsForResourceOutput{Tags: tags}, nil
}

func (s *Service) tagResource(ctx context.Context, tx Transaction, in *api.TagResourceInput) (*api.TagResourceOutput, error) {
	if err := validateTags(in.Tags); err != nil {
		return nil, err
	}
	target, err := targetByARN(ctx, tx, value(in.ResourceARN))
	if err != nil {
		return nil, err
	}
	conditions := targetConditions(TargetKey{}, target.Tags)
	requestTagConditions(conditions, in.Tags)
	if err := s.authorize(ctx, "TagResource", value(target.Data.ScalableTargetARN), conditions); err != nil {
		return nil, err
	}
	count := len(target.Tags)
	for key := range in.Tags {
		if _, exists := target.Tags[key]; !exists {
			count++
		}
	}
	if count > 50 {
		return nil, failure("TooManyTagsException", "A scalable target cannot have more than 50 tags")
	}
	target.Tags = maps.Clone(target.Tags)
	if target.Tags == nil {
		target.Tags = make(api.TagMap, len(in.Tags))
	}
	for key, value := range in.Tags {
		target.Tags[key] = value
	}
	if err := tx.PutTarget(target); err != nil {
		return nil, err
	}
	return &api.TagResourceOutput{}, nil
}

func (s *Service) untagResource(ctx context.Context, tx Transaction, in *api.UntagResourceInput) (*api.UntagResourceOutput, error) {
	if len(in.TagKeys) == 0 {
		return nil, invalid("TagKeys cannot be null or empty")
	}
	keys := make([]string, len(in.TagKeys))
	for i, key := range in.TagKeys {
		if err := validateTagKey(string(key)); err != nil {
			return nil, err
		}
		keys[i] = string(key)
	}
	target, err := targetByARN(ctx, tx, value(in.ResourceARN))
	if err != nil {
		return nil, err
	}
	conditions := targetConditions(TargetKey{}, target.Tags)
	slices.Sort(keys)
	conditions["aws:TagKeys"] = slices.Compact(keys)
	if err := s.authorize(ctx, "UntagResource", value(target.Data.ScalableTargetARN), conditions); err != nil {
		return nil, err
	}
	target.Tags = maps.Clone(target.Tags)
	for _, key := range in.TagKeys {
		delete(target.Tags, key)
	}
	if err := tx.PutTarget(target); err != nil {
		return nil, err
	}
	return &api.UntagResourceOutput{}, nil
}
