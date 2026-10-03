package eventbridge

import (
	"context"
	"slices"
	"strings"

	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/awswire"
)

func (s *Service) registerTags() {
	register(s, "TagResource", s.tagResource)
	register(s, "UntagResource", s.untagResource)
	register(s, "ListTagsForResource", s.listTags)
}
func resourceKey(ctx context.Context, arn string) (BusKey, *RuleKey, *awswire.Error) {
	p := strings.SplitN(arn, ":", 6)
	scope := scopeFor(ctx)
	if len(p) != 6 || p[1] != scope.Partition || p[2] != "events" || p[3] != scope.Region || len(p[4]) != 12 || strings.Trim(p[4], "0123456789") != "" {
		return BusKey{}, nil, failure("ValidationException", "Resource ARN must belong to the current partition and Region.")
	}
	scope.Account = p[4]
	if strings.HasPrefix(p[5], "event-bus/") {
		k, e := busKey(ctx, arn)
		return k, nil, e
	}
	if strings.HasPrefix(p[5], "rule/") {
		parts := strings.Split(strings.TrimPrefix(p[5], "rule/"), "/")
		bus := "default"
		name := parts[0]
		if len(parts) == 2 {
			bus, name = parts[0], parts[1]
		} else if len(parts) != 1 {
			return BusKey{}, nil, failure("ValidationException", "Invalid rule ARN.")
		}
		b := BusKey{scope, bus}
		r := RuleKey{b, name}
		return b, &r, nil
	}
	return BusKey{}, nil, failure("ValidationException", "Unsupported resource ARN.")
}
func (s *Service) tags(ctx context.Context, arn, action string, conditions map[string][]string, change func(map[string]string) error, completed func(context.Context, map[string]string) error) (map[string]string, *awswire.Error) {
	bus, rule, wire := resourceKey(ctx, arn)
	if wire != nil {
		return nil, wire
	}
	var tags map[string]string
	err := s.repository.Update(ctx, func(tx Transaction) error {
		var b BusRecord
		var r RuleRecord
		var err error
		if rule == nil {
			b, err = s.bus(tx, bus)
			tags = b.Tags
		} else {
			r, err = tx.Rule(*rule)
			tags = r.Tags
		}
		if err != nil {
			return err
		}
		if rule == nil {
			err = s.authorize(tx, action, arn, tags, conditions, b.Policy)
		} else {
			err = s.authorizeRule(tx, action, r, conditions)
		}
		if err != nil {
			return err
		}
		if tags == nil {
			tags = map[string]string{}
		}
		if change == nil {
			return completed(tx.Context(), tags)
		}
		if r.ManagedBy != "" {
			return managedRuleError(r, false)
		}
		if err := change(tags); err != nil {
			return err
		}
		if len(tags) > 50 {
			return failure("LimitExceededException", "A resource can have at most 50 tags.")
		}
		if rule == nil {
			b.Tags = tags
			if err := tx.PutBus(b); err != nil {
				return err
			}
		} else {
			r.Tags = tags
			if err := tx.PutRule(r); err != nil {
				return err
			}
		}
		return completed(tx.Context(), tags)
	})
	return tags, wireError(err)
}
func (s *Service) tagResource(ctx context.Context, in *api.TagResourceInput) (out *api.TagResourceOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "TagResource", in, &out, &rejected, false)
	out = &api.TagResourceOutput{}
	tags, conditions, wire := tagInput(in.Tags)
	if wire != nil {
		return nil, wire
	}
	_, wire = s.tags(ctx, value(in.ResourceARN), "TagResource", conditions, func(dst map[string]string) error {
		for k, v := range tags {
			dst[k] = v
		}
		return nil
	}, func(ctx context.Context, _ map[string]string) error {
		return s.recordCall(ctx, "TagResource", in, out, nil)
	})
	if wire != nil {
		return nil, wire
	}
	return out, nil
}
func (s *Service) untagResource(ctx context.Context, in *api.UntagResourceInput) (out *api.UntagResourceOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "UntagResource", in, &out, &rejected, false)
	out = &api.UntagResourceOutput{}
	conditions := map[string][]string{}
	for _, k := range in.TagKeys {
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], string(k))
	}
	_, wire := s.tags(ctx, value(in.ResourceARN), "UntagResource", conditions, func(tags map[string]string) error {
		for _, k := range in.TagKeys {
			delete(tags, string(k))
		}
		return nil
	}, func(ctx context.Context, _ map[string]string) error {
		return s.recordCall(ctx, "UntagResource", in, out, nil)
	})
	if wire != nil {
		return nil, wire
	}
	return out, nil
}
func (s *Service) listTags(ctx context.Context, in *api.ListTagsForResourceInput) (out *api.ListTagsForResourceOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "ListTagsForResource", in, &out, &rejected, false)
	_, wire := s.tags(ctx, value(in.ResourceARN), "ListTagsForResource", nil, nil, func(ctx context.Context, tags map[string]string) error {
		keys := make([]string, 0, len(tags))
		for k := range tags {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		out = &api.ListTagsForResourceOutput{Tags: api.TagList{}}
		for _, k := range keys {
			out.Tags = append(out.Tags, api.Tag{Key: str[api.TagKey](k), Value: str[api.TagValue](tags[k])})
		}
		return s.recordCall(ctx, "ListTagsForResource", in, out, nil)
	})
	if wire != nil {
		return nil, wire
	}
	return out, nil
}
