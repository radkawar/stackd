package lambda

import (
	"context"
	"errors"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

func (s *Service) tagMapping(r Reader, key EventSourceMappingKey, action string, requested map[string]string, keys []string) (EventSourceMappingRecord, error) {
	v, err := r.EventSourceMapping(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return v, err
	}
	conditions := map[string][]string{}
	if len(keys) > 0 {
		conditions["aws:TagKeys"] = keys
	}
	if wire := s.authorize(r.Context(), action, key.ARN(), v.Tags, requested, conditions); wire != nil {
		return v, wire
	}
	return v, err
}
func (s *Service) listEventSourceMappingTags(ctx context.Context, in *api.ListTagsInput) (*api.ListTagsOutput, *awswire.Error) {
	key, wire := parseEventSourceMappingARN(ctx, value(in.Resource))
	if wire != nil {
		return nil, wire
	}
	out := &api.ListTagsOutput{Tags: api.Tags{}}
	err := s.repository.View(ctx, func(r Reader) error {
		v, err := s.tagMapping(r, key, "ListTags", nil, nil)
		if err != nil {
			return err
		}
		for k, val := range v.Tags {
			out.Tags[api.TagKey(k)] = api.TagValue(val)
		}
		return nil
	})
	if err != nil {
		return nil, mappingLookupError(err)
	}
	return out, nil
}
func (s *Service) tagEventSourceMapping(ctx context.Context, in *api.TagResourceInput) (*api.TagResourceOutput, *awswire.Error) {
	key, wire := parseEventSourceMappingARN(ctx, value(in.Resource))
	if wire != nil {
		return nil, wire
	}
	requested := make(map[string]string, len(in.Tags))
	for k, v := range in.Tags {
		requested[string(k)] = string(v)
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		v, err := s.tagMapping(tx, key, "TagResource", requested, nil)
		if err != nil {
			return err
		}
		if len(requested) == 0 {
			return tagParameterError("Tags must contain at least one entry.")
		}
		if wire := validateFunctionTags(requested); wire != nil {
			return wire
		}
		if v.Tags == nil {
			v.Tags = map[string]string{}
		}
		for key, val := range requested {
			v.Tags[key] = val
		}
		if wire := validateFunctionTags(v.Tags); wire != nil {
			return wire
		}
		if err := tx.PutEventSourceMapping(v); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "TagResource", in, nil, nil)
	})
	if err != nil {
		return nil, mappingLookupError(err)
	}
	return &api.TagResourceOutput{}, nil
}
func (s *Service) untagEventSourceMapping(ctx context.Context, in *api.UntagResourceInput) (*api.UntagResourceOutput, *awswire.Error) {
	key, wire := parseEventSourceMappingARN(ctx, value(in.Resource))
	if wire != nil {
		return nil, wire
	}
	keys := layerStrings(in.TagKeys)
	err := s.repository.Update(ctx, func(tx Transaction) error {
		v, err := s.tagMapping(tx, key, "UntagResource", nil, keys)
		if err != nil {
			return err
		}
		for _, key := range keys {
			if reservedTagKey(key) {
				return tagParameterError("Tag keys must not start with aws:.")
			}
			delete(v.Tags, key)
		}
		if err := tx.PutEventSourceMapping(v); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "UntagResource", in, nil, nil)
	})
	if err != nil {
		return nil, mappingLookupError(err)
	}
	return &api.UntagResourceOutput{}, nil
}
