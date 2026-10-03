package kms

import (
	"context"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awswire"
)

var tagPattern = regexp.MustCompile(`^[\p{L}\p{Z}\p{N}_.:/=+@-]*$`)

func (s *Service) registerTags() {
	register(s, "TagResource", s.tagResource)
	register(s, "UntagResource", s.untagResource)
	register(s, "ListResourceTags", s.listResourceTags)
}

func tagConditions(tags kmsapi.TagList) map[string][]string {
	conditions := make(map[string][]string)
	for _, tag := range tags {
		name := value(tag.TagKey)
		conditions["aws:RequestTag/"+name] = []string{value(tag.TagValue)}
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], name)
	}
	return conditions
}

func mergeTags(existing map[string]string, tags kmsapi.TagList) (map[string]string, *awswire.Error) {
	result := maps.Clone(existing)
	if result == nil {
		result = make(map[string]string)
	}
	seen := make(map[string]bool)
	for _, tag := range tags {
		name, val := value(tag.TagKey), value(tag.TagValue)
		if name == "" || utf8.RuneCountInString(name) > 128 || utf8.RuneCountInString(val) > 256 || !tagPattern.MatchString(name) || !tagPattern.MatchString(val) || strings.HasPrefix(strings.ToLower(name), "aws:") {
			return nil, failure("TagException", "Tag key or value is invalid, or uses the reserved aws: prefix.")
		}
		if seen[name] {
			return nil, failure("TagException", "Duplicate tag keys are not allowed.")
		}
		seen[name] = true
		result[name] = val
	}
	if len(result) > 50 {
		return nil, failure("LimitExceededException", "A key cannot have more than 50 tags.")
	}
	return result, nil
}

func (s *Service) tagResource(ctx context.Context, in *kmsapi.TagResourceInput) (*kmsapi.TagResourceOutput, *awswire.Error) {
	ctx = withConditions(ctx, tagConditions(in.Tags))
	k, err := s.resolveAuthorized(ctx, value(in.KeyId), false)
	if err != nil {
		return nil, err
	}
	if err := customerKey(k); err != nil {
		return nil, err
	}
	if k.state == "PendingDeletion" || k.state == "PendingReplicaDeletion" {
		return nil, failure("KMSInvalidStateException", "The key is pending deletion.")
	}
	tags, err := mergeTags(k.tags, in.Tags)
	if err != nil {
		return nil, err
	}
	k.tags = tags
	return &kmsapi.TagResourceOutput{}, nil
}

func (s *Service) untagResource(ctx context.Context, in *kmsapi.UntagResourceInput) (*kmsapi.UntagResourceOutput, *awswire.Error) {
	var names []string
	if len(in.TagKeys) > 0 {
		names = make([]string, 0, len(in.TagKeys))
		for _, name := range in.TagKeys {
			names = append(names, string(name))
		}
	}
	ctx = withConditions(ctx, map[string][]string{"aws:TagKeys": names})
	k, err := s.resolveAuthorized(ctx, value(in.KeyId), false)
	if err != nil {
		return nil, err
	}
	if err := customerKey(k); err != nil {
		return nil, err
	}
	if k.state == "PendingDeletion" || k.state == "PendingReplicaDeletion" {
		return nil, failure("KMSInvalidStateException", "The key is pending deletion.")
	}
	for _, name := range in.TagKeys {
		if strings.HasPrefix(strings.ToLower(string(name)), "aws:") {
			return nil, failure("TagException", "The aws: tag prefix is reserved.")
		}
	}
	for _, name := range in.TagKeys {
		delete(k.tags, string(name))
	}
	return &kmsapi.UntagResourceOutput{}, nil
}

func (s *Service) listResourceTags(ctx context.Context, in *kmsapi.ListResourceTagsInput) (*kmsapi.ListResourceTagsOutput, *awswire.Error) {
	k, err := s.resolveAuthorized(ctx, value(in.KeyId), false)
	if err != nil {
		return nil, err
	}
	names := slices.Sorted(maps.Keys(k.tags))
	page, next, err := s.page(ctx, "ListResourceTags", k.ID, names, in.Limit, in.Marker)
	if err != nil {
		return nil, err
	}
	out := &kmsapi.ListResourceTagsOutput{Tags: make(kmsapi.TagList, 0, len(page)), Truncated: ptr(kmsapi.BooleanType(next != ""))}
	if next != "" {
		out.NextMarker = ptr(kmsapi.MarkerType(next))
	}
	for _, name := range page {
		out.Tags = append(out.Tags, kmsapi.Tag{TagKey: ptr(kmsapi.TagKeyType(name)), TagValue: ptr(kmsapi.TagValueType(k.tags[name]))})
	}
	return out, nil
}
