package elbv2

import (
	"context"
	"slices"
	api "stackd/internal/awsapi/elbv2"
	"strings"
	"unicode/utf8"
)

func registerTags(s *Service) {
	register(s, "AddTags", s.addTags)
	register(s, "RemoveTags", s.removeTags)
	register(s, "DescribeTags", s.describeTags)
}
func validateTags(tags api.TagList) error {
	if len(tags) > 50 {
		return failure("TooManyTags", "A resource can have at most 50 tags")
	}
	seen := map[string]bool{}
	for _, t := range tags {
		k := value(t.Key)
		if k == "" || utf8.RuneCountInString(k) > 128 || utf8.RuneCountInString(value(t.Value)) > 256 || strings.HasPrefix(strings.ToLower(k), "aws:") {
			return invalid("Invalid tag key or value")
		}
		if seen[k] {
			return failure("DuplicateTagKeys", "A tag key was specified more than once")
		}
		seen[k] = true
	}
	return nil
}
func resourceTags(tx Reader, sc Scope, a string) (api.TagList, error) {
	switch {
	case strings.Contains(a, ":loadbalancer/"):
		v, e := loadBalancer(tx, sc, a)
		return v.Tags, e
	case strings.Contains(a, ":targetgroup/"):
		v, e := targetGroup(tx, sc, a)
		return v.Tags, e
	case strings.Contains(a, ":listener/"):
		v, e := listener(tx, sc, a)
		return v.Tags, e
	case strings.Contains(a, ":listener-rule/"):
		v, e := rule(tx, sc, a)
		return v.Tags, e
	default:
		return nil, invalid("Unsupported resource ARN")
	}
}
func putResourceTags(tx Transaction, sc Scope, a string, tags api.TagList) error {
	switch {
	case strings.Contains(a, ":loadbalancer/"):
		v, e := loadBalancer(tx, sc, a)
		if e != nil {
			return e
		}
		v.Tags = tags
		return tx.PutLoadBalancer(v)
	case strings.Contains(a, ":targetgroup/"):
		v, e := targetGroup(tx, sc, a)
		if e != nil {
			return e
		}
		v.Tags = tags
		return tx.PutTargetGroup(v)
	case strings.Contains(a, ":listener/"):
		v, e := listener(tx, sc, a)
		if e != nil {
			return e
		}
		v.Tags = tags
		return tx.PutListener(v)
	default:
		v, e := rule(tx, sc, a)
		if e != nil {
			return e
		}
		v.Tags = tags
		return tx.PutRule(v)
	}
}
func (s *Service) addTags(ctx context.Context, tx Transaction, in *api.AddTagsInput) (*api.AddTagsOutput, error) {
	if len(in.ResourceArns) < 1 || len(in.ResourceArns) > 20 {
		return nil, invalid("Specify between 1 and 20 resources")
	}
	if len(in.Tags) == 0 {
		return nil, invalid("Tags is required")
	}
	if e := validateTags(in.Tags); e != nil {
		return nil, e
	}
	sc := scopeFor(ctx)
	for _, a := range in.ResourceArns {
		old, e := resourceTags(tx, sc, string(a))
		if e != nil {
			return nil, e
		}
		if e = s.authorize(ctx, "AddTags", string(a), old, requestTags(in.Tags)); e != nil {
			return nil, e
		}
		byKey := map[string]api.Tag{}
		for _, t := range old {
			byKey[value(t.Key)] = t
		}
		for _, t := range in.Tags {
			byKey[value(t.Key)] = t
		}
		tags := make(api.TagList, 0, len(byKey))
		for _, t := range byKey {
			tags = append(tags, t)
		}
		if e = validateTags(tags); e != nil {
			return nil, e
		}
		slices.SortFunc(tags, func(a, b api.Tag) int { return strings.Compare(value(a.Key), value(b.Key)) })
		if e = putResourceTags(tx, sc, string(a), tags); e != nil {
			return nil, e
		}
	}
	return &api.AddTagsOutput{}, nil
}
func (s *Service) removeTags(ctx context.Context, tx Transaction, in *api.RemoveTagsInput) (*api.RemoveTagsOutput, error) {
	if len(in.ResourceArns) < 1 || len(in.ResourceArns) > 20 || len(in.TagKeys) == 0 {
		return nil, invalid("ResourceArns and TagKeys are required")
	}
	sc := scopeFor(ctx)
	for _, a := range in.ResourceArns {
		tags, e := resourceTags(tx, sc, string(a))
		if e != nil {
			return nil, e
		}
		if e = s.authorize(ctx, "RemoveTags", string(a), tags, map[string][]string{"aws:TagKeys": plainList(in.TagKeys)}); e != nil {
			return nil, e
		}
		out := api.TagList{}
		for _, t := range tags {
			if !slices.Contains(in.TagKeys, *t.Key) {
				out = append(out, t)
			}
		}
		if e = putResourceTags(tx, sc, string(a), out); e != nil {
			return nil, e
		}
	}
	return &api.RemoveTagsOutput{}, nil
}
func (s *Service) describeTags(ctx context.Context, tx Transaction, in *api.DescribeTagsInput) (*api.DescribeTagsOutput, error) {
	if len(in.ResourceArns) < 1 || len(in.ResourceArns) > 20 {
		return nil, invalid("Specify between 1 and 20 resources")
	}
	out := &api.DescribeTagsOutput{TagDescriptions: api.TagDescriptions{}}
	for _, a := range in.ResourceArns {
		tags, e := resourceTags(tx, scopeFor(ctx), string(a))
		if e != nil {
			return nil, e
		}
		if e = s.authorize(ctx, "DescribeTags", string(a), tags, nil); e != nil {
			return nil, e
		}
		d := api.TagDescription{Tags: tags}
		text(&d.ResourceArn, string(a))
		out.TagDescriptions = append(out.TagDescriptions, d)
	}
	return out, nil
}
