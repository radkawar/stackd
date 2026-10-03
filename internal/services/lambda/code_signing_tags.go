package lambda

import (
	"context"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

func (s *Service) listCodeSigningTags(ctx context.Context, in *api.ListTagsInput) (*api.ListTagsOutput, *awswire.Error) {
	key, wire := parseCodeSigningConfigARN(ctx, value(in.Resource))
	if wire != nil {
		return nil, wire
	}
	out := &api.ListTagsOutput{Tags: api.Tags{}}
	err := s.repository.View(ctx, func(r Reader) error {
		v, err := s.loadCodeSigningConfig(r, key, "ListTags", nil, nil)
		if err != nil {
			return err
		}
		for k, val := range v.Tags {
			out.Tags[api.TagKey(k)] = api.TagValue(val)
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

func (s *Service) tagCodeSigning(ctx context.Context, in *api.TagResourceInput) (*api.TagResourceOutput, *awswire.Error) {
	key, wire := parseCodeSigningConfigARN(ctx, value(in.Resource))
	if wire != nil {
		return nil, wire
	}
	requested := make(map[string]string, len(in.Tags))
	for k, val := range in.Tags {
		requested[string(k)] = string(val)
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		v, err := s.loadCodeSigningConfig(tx, key, "TagResource", requested, nil)
		if err != nil {
			return err
		}
		if len(requested) == 0 {
			return tagParameterError("Tags must contain at least one entry.")
		}
		if v.Tags == nil {
			v.Tags = map[string]string{}
		}
		for k, val := range requested {
			v.Tags[k] = val
		}
		if wire := validateFunctionTags(v.Tags); wire != nil {
			return wire
		}
		if err := tx.PutCodeSigningConfig(v); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "TagResource", in, nil, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return &api.TagResourceOutput{}, nil
}

func (s *Service) untagCodeSigning(ctx context.Context, in *api.UntagResourceInput) (*api.UntagResourceOutput, *awswire.Error) {
	key, wire := parseCodeSigningConfigARN(ctx, value(in.Resource))
	if wire != nil {
		return nil, wire
	}
	keys := layerStrings(in.TagKeys)
	err := s.repository.Update(ctx, func(tx Transaction) error {
		v, err := s.loadCodeSigningConfig(tx, key, "UntagResource", nil, map[string][]string{"aws:TagKeys": keys})
		if err != nil {
			return err
		}
		for _, k := range keys {
			if reservedTagKey(k) {
				return tagParameterError("Tag keys must not start with aws:.")
			}
			delete(v.Tags, k)
		}
		if err := tx.PutCodeSigningConfig(v); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "UntagResource", in, nil, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return &api.UntagResourceOutput{}, nil
}
