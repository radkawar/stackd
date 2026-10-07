package organizations

import (
	"maps"
	"net/http"
	"strings"

	api "stackd/internal/awsapi/organizations"
	"stackd/internal/awswire"
)

func (s *Service) registerTagOperations() {
	register(s, "TagResource", func(s *operationState, r *http.Request, in *api.TagResourceInput) (*api.TagResourceOutput, *awswire.Error) {
		o, err := s.organizationFor(r, true)
		if err != nil {
			return nil, err
		}
		if !o.taggable(inputString(in.ResourceId)) {
			return nil, failure("TargetNotFoundException", "The resource does not exist or does not support tags.")
		}
		if err := o.claimTagTarget(r, inputString(in.ResourceId), false); err != nil {
			return nil, err
		}
		tags, err := mergeTags(o.tags[inputString(in.ResourceId)], in.Tags)
		if err != nil {
			return nil, err
		}
		o.tags[inputString(in.ResourceId)] = tags
		return &api.TagResourceOutput{}, nil
	})
	register(s, "UntagResource", func(s *operationState, r *http.Request, in *api.UntagResourceInput) (*api.UntagResourceOutput, *awswire.Error) {
		o, err := s.organizationFor(r, true)
		if err != nil {
			return nil, err
		}
		if !o.taggable(inputString(in.ResourceId)) {
			return nil, failure("TargetNotFoundException", "The resource does not exist or does not support tags.")
		}
		if err := o.claimTagTarget(r, inputString(in.ResourceId), false); err != nil {
			return nil, err
		}
		for _, key := range in.TagKeys {
			if strings.HasPrefix(strings.ToLower(string(key)), "aws:") {
				return nil, failure("InvalidInputException", "Invalid tag key.")
			}
		}
		for _, key := range in.TagKeys {
			delete(o.tags[inputString(in.ResourceId)], string(key))
		}
		return &api.UntagResourceOutput{}, nil
	})
	register(s, "ListTagsForResource", func(s *operationState, r *http.Request, in *api.ListTagsForResourceInput) (*api.ListTagsForResourceOutput, *awswire.Error) {
		o, err := s.organizationFor(r, true)
		if err != nil {
			return nil, err
		}
		if !o.taggable(inputString(in.ResourceId)) {
			return nil, failure("TargetNotFoundException", "The resource does not exist or does not support tags.")
		}
		if err := o.claimTagTarget(r, inputString(in.ResourceId), true); err != nil {
			return nil, err
		}
		items := make([]api.Tag, 0, len(o.tags[inputString(in.ResourceId)]))
		for key, value := range o.tags[inputString(in.ResourceId)] {
			items = append(items, api.Tag{Key: new(api.TagKey(key)), Value: new(api.TagValue(value))})
		}
		items, next, err := paginate(s, items, in, o.organization.ID+"/tags/"+inputString(in.ResourceId), func(v api.Tag) string { return inputString(v.Key) })
		return &api.ListTagsForResourceOutput{Tags: items, NextToken: nextToken(next)}, err
	})
}

func (o *orgState) taggable(id string) bool {
	if o.resourcePolicy.ID != "" && id == o.resourcePolicy.ID {
		return true
	}
	if p, ok := o.policies[id]; ok {
		return !p.PolicySummary.AWSManaged
	}
	return o.targetExists(id)
}

func mergeTags(existing map[string]string, additions api.Tags) (map[string]string, *awswire.Error) {
	result := maps.Clone(existing)
	if result == nil {
		result = make(map[string]string)
	}
	seen := make(map[string]bool)
	for _, item := range additions {
		key, value := string(*item.Key), string(*item.Value)
		if strings.HasPrefix(strings.ToLower(key), "aws:") {
			return nil, failure("InvalidInputException", "Invalid tag key or value.")
		}
		if seen[key] {
			return nil, failure("InvalidInputException", "DUPLICATE_TAG_KEY: Tag keys must be unique within a request.")
		}
		seen[key] = true
		result[key] = value
	}
	if len(result) > 50 {
		return nil, failure("ConstraintViolationException", "MAX_TAG_LIMIT_EXCEEDED: A resource can have at most 50 tags.")
	}
	return result, nil
}
