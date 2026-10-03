package lambda

import (
	"context"
	"errors"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

func (s *Service) capacityTagTarget(r Reader, key CapacityProviderKey, action string, requested map[string]string, keys []string) (CapacityProviderRecord, error) {
	v, err := r.CapacityProvider(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return v, err
	}
	extra := map[string][]string{}
	if len(keys) > 0 {
		extra["aws:TagKeys"] = keys
	}
	if rejected := s.authorize(r.Context(), action, key.ARN(), v.Tags, requested, extra); rejected != nil {
		return v, rejected
	}
	return v, err
}
func (s *Service) listCapacityTags(ctx context.Context, in *api.ListTagsRequest) (*api.ListTagsResponse, *awswire.Error) {
	key, err := capacityKey(ctx, value(in.Resource))
	if err != nil {
		return nil, wireError(err)
	}
	out := &api.ListTagsResponse{Tags: api.Tags{}}
	err = s.repository.View(ctx, func(r Reader) error {
		v, err := s.capacityTagTarget(r, key, "ListTags", nil, nil)
		if err != nil {
			return err
		}
		for key, value := range v.Tags {
			out.Tags[api.TagKey(key)] = api.TagValue(value)
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
func (s *Service) tagCapacityProvider(ctx context.Context, in *api.TagResourceRequest) (*api.Unit, *awswire.Error) {
	key, err := capacityKey(ctx, value(in.Resource))
	if err != nil {
		return nil, wireError(err)
	}
	requested := map[string]string{}
	for key, value := range in.Tags {
		requested[string(key)] = string(value)
	}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		v, err := s.capacityTagTarget(tx, key, "TagResource", requested, nil)
		if err != nil {
			return err
		}
		if len(requested) == 0 {
			return tagParameterError("Tags must contain at least one entry.")
		}
		if v.Tags == nil {
			v.Tags = map[string]string{}
		}
		for key, value := range requested {
			v.Tags[key] = value
		}
		if rejected := validateFunctionTags(v.Tags); rejected != nil {
			return rejected
		}
		if err = tx.PutCapacityProvider(v); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "TagResource", in, nil, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return &api.Unit{}, nil
}
func (s *Service) untagCapacityProvider(ctx context.Context, in *api.UntagResourceRequest) (*api.Unit, *awswire.Error) {
	key, err := capacityKey(ctx, value(in.Resource))
	if err != nil {
		return nil, wireError(err)
	}
	keys := make([]string, len(in.TagKeys))
	for i, key := range in.TagKeys {
		keys[i] = string(key)
	}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		v, err := s.capacityTagTarget(tx, key, "UntagResource", nil, keys)
		if err != nil {
			return err
		}
		for _, key := range keys {
			if reservedTagKey(key) {
				return tagParameterError("Tag keys must not start with aws:.")
			}
			delete(v.Tags, key)
		}
		if err = tx.PutCapacityProvider(v); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "UntagResource", in, nil, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return &api.Unit{}, nil
}
