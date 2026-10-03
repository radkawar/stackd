package cloudtrail

import (
	"context"
	"slices"
	"strings"

	api "stackd/internal/awsapi/cloudtrail"
	"stackd/internal/awswire"
)

func tagValues(tags api.TagsList) (map[string]string, *awswire.Error) {
	out := map[string]string{}
	for _, tag := range tags {
		key := value(tag.Key)
		if strings.HasPrefix(strings.ToLower(key), "aws:") {
			return nil, failure("InvalidTagParameterException", "Tag keys beginning with aws: are reserved.")
		}
		out[key] = value(tag.Value)
	}
	if len(out) > 50 {
		return nil, failure("TagsLimitExceededException", "A trail can have at most 50 tags.")
	}
	return out, nil
}
func (s *Service) addTags(ctx context.Context, in *api.AddTagsInput) (*api.AddTagsOutput, *awswire.Error) {
	tags, wire := tagValues(in.TagsList)
	if wire != nil {
		return nil, wire
	}
	out := &api.AddTagsOutput{}
	err := s.update(ctx, out, func(tx Transaction) error {
		trail, err := s.resolveTrail(tx, value(in.ResourceId))
		if err != nil {
			return err
		}
		if wire := homeRegion(tx.Context(), trail); wire != nil {
			return wire
		}
		if wire := s.authorize(tx, "AddTags", trail, tags); wire != nil {
			return wire
		}
		if trail.Tags == nil {
			trail.Tags = map[string]string{}
		}
		for key, value := range tags {
			trail.Tags[key] = value
		}
		if len(trail.Tags) > 50 {
			return failure("TagsLimitExceededException", "A trail can have at most 50 tags.")
		}
		trail.Modified = s.clock.Now()
		return tx.PutTrail(trail)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
func (s *Service) removeTags(ctx context.Context, in *api.RemoveTagsInput) (*api.RemoveTagsOutput, *awswire.Error) {
	tags, wire := tagValues(in.TagsList)
	if wire != nil {
		return nil, wire
	}
	out := &api.RemoveTagsOutput{}
	err := s.update(ctx, out, func(tx Transaction) error {
		trail, err := s.resolveTrail(tx, value(in.ResourceId))
		if err != nil {
			return err
		}
		if wire := homeRegion(tx.Context(), trail); wire != nil {
			return wire
		}
		if wire := s.authorize(tx, "RemoveTags", trail, tags); wire != nil {
			return wire
		}
		for key := range tags {
			delete(trail.Tags, key)
		}
		trail.Modified = s.clock.Now()
		return tx.PutTrail(trail)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
func (s *Service) listTags(ctx context.Context, in *api.ListTagsInput) (*api.ListTagsOutput, *awswire.Error) {
	if in.NextToken != nil {
		return nil, failure("InvalidNextTokenException", "The pagination token is invalid.")
	}
	out := &api.ListTagsOutput{ResourceTagList: api.ResourceTagList{}}
	err := s.repository.View(ctx, func(r Reader) error {
		for _, resource := range in.ResourceIdList {
			trail, err := s.resolveTrail(r, string(resource))
			if err != nil {
				return err
			}
			if wire := s.authorize(r, "ListTags", trail, nil); wire != nil {
				return wire
			}
			keys := make([]string, 0, len(trail.Tags))
			for key := range trail.Tags {
				keys = append(keys, key)
			}
			slices.Sort(keys)
			tags := api.TagsList{}
			for _, key := range keys {
				tags = append(tags, api.Tag{Key: new(api.TagKey(key)), Value: new(api.TagValue(trail.Tags[key]))})
			}
			out.ResourceTagList = append(out.ResourceTagList, api.ResourceTag{ResourceId: str(trail.Key.ARN()), TagsList: tags})
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
