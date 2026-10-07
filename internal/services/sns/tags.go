package sns

import (
	"context"
	"errors"
	"maps"
	"slices"

	api "stackd/internal/awsapi/sns"
	"stackd/internal/awswire"
)

func (s *Service) registerTags() {
	register(s, "ListTagsForResource", s.listTags)
	register(s, "TagResource", s.tagResource)
	register(s, "UntagResource", s.untagResource)
}

func (s *Service) listTags(ctx context.Context, in *api.ListTagsForResourceInput) (out *api.ListTagsForResourceOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "ListTagsForResource", in, &out, &rejected, false)
	key, wire := topicKey(ctx, value(in.ResourceArn))
	if wire != nil {
		return nil, wire
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		topic, err := tx.Topic(key)
		if err != nil {
			return err
		}
		if err := s.authorize(tx, "ListTagsForResource", key.ARN(), topic.Tags, nil, topic.Policy); err != nil {
			return err
		}
		if err := checkCloudFormationTopicClaim(tx.Context(), topic); err != nil {
			return err
		}
		out = &api.ListTagsForResourceOutput{Tags: api.TagList{}}
		for _, k := range slices.Sorted(maps.Keys(topic.Tags)) {
			out.Tags = append(out.Tags, api.Tag{Key: str[api.TagKey](k), Value: str[api.TagValue](topic.Tags[k])})
		}
		return s.recordCall(tx.Context(), "ListTagsForResource", in, out, nil)
	})
	if errors.Is(err, ErrNotFound) {
		return nil, failure("ResourceNotFound", "The specified topic does not exist.", 404)
	}
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

func (s *Service) tagResource(ctx context.Context, in *api.TagResourceInput) (out *api.TagResourceOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "TagResource", in, &out, &rejected, false)
	key, wire := topicKey(ctx, value(in.ResourceArn))
	if wire != nil {
		return nil, wire
	}
	tags, conditions, wire := tagInput(in.Tags)
	if wire != nil {
		return nil, wire
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		topic, err := tx.Topic(key)
		if err != nil {
			return err
		}
		if err := s.authorize(tx, "TagResource", key.ARN(), topic.Tags, conditions, topic.Policy); err != nil {
			return err
		}
		if err := checkCloudFormationTopicClaim(tx.Context(), topic); err != nil {
			return err
		}
		merged := maps.Clone(topic.Tags)
		if merged == nil {
			merged = map[string]string{}
		}
		maps.Copy(merged, tags)
		if len(merged) > 50 {
			return failure("TagLimitExceeded", "A topic can have at most 50 tags.")
		}
		topic.Tags, topic.Updated = merged, s.clock.Now()
		if err := tx.PutTopic(topic); err != nil {
			return err
		}
		out = &api.TagResourceOutput{}
		return s.recordCall(tx.Context(), "TagResource", in, out, nil)
	})
	if errors.Is(err, ErrNotFound) {
		return nil, failure("ResourceNotFound", "The specified topic does not exist.", 404)
	}
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

func (s *Service) untagResource(ctx context.Context, in *api.UntagResourceInput) (out *api.UntagResourceOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "UntagResource", in, &out, &rejected, false)
	key, wire := topicKey(ctx, value(in.ResourceArn))
	if wire != nil {
		return nil, wire
	}
	conditions := map[string][]string{}
	for _, key := range in.TagKeys {
		if !validTagKey(string(key)) {
			return nil, failure("InvalidParameter", "Invalid tag key.")
		}
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], string(key))
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		topic, err := tx.Topic(key)
		if err != nil {
			return err
		}
		if err := s.authorize(tx, "UntagResource", key.ARN(), topic.Tags, conditions, topic.Policy); err != nil {
			return err
		}
		if err := checkCloudFormationTopicClaim(tx.Context(), topic); err != nil {
			return err
		}
		topic.Tags = maps.Clone(topic.Tags)
		for _, key := range in.TagKeys {
			delete(topic.Tags, string(key))
		}
		topic.Updated = s.clock.Now()
		if err := tx.PutTopic(topic); err != nil {
			return err
		}
		out = &api.UntagResourceOutput{}
		return s.recordCall(tx.Context(), "UntagResource", in, out, nil)
	})
	if errors.Is(err, ErrNotFound) {
		return nil, failure("ResourceNotFound", "The specified topic does not exist.", 404)
	}
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
