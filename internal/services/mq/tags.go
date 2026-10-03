package mq

import (
	"context"
	"errors"
	api "stackd/internal/awsapi/mq"
)

type taggedResource struct {
	broker        *BrokerRecord
	configuration *ConfigurationRecord
}

func (v taggedResource) tags() map[string]string {
	if v.broker != nil {
		return v.broker.Tags
	}
	return v.configuration.Tags
}
func (v taggedResource) put(t Transaction) error {
	if v.broker != nil {
		return t.PutBroker(*v.broker)
	}
	return t.PutConfiguration(*v.configuration)
}
func (s *Service) tagged(ctx context.Context, t Transaction, arn, action string, conditions map[string][]string) (taggedResource, error) {
	if isConfigurationARN(arn) {
		v, e := s.loadConfiguration(ctx, t, arn, action, conditions)
		if e != nil {
			if errors.Is(e, ErrNotFound) {
				return taggedResource{}, notFound("", "Resource was not found")
			}
			return taggedResource{}, e
		}
		return taggedResource{configuration: &v}, nil
	}
	v, e := s.load(ctx, t, arn, action, conditions)
	if e != nil {
		if errors.Is(e, ErrNotFound) {
			return taggedResource{}, notFound("", "Resource was not found")
		}
		return taggedResource{}, e
	}
	return taggedResource{broker: &v}, nil
}
func registerTags(s *Service) {
	register(s, "ListTags", func(ctx context.Context, t Transaction, in *api.ListTagsInput) (*api.ListTagsOutput, error) {
		v, e := s.tagged(ctx, t, value(in.ResourceArn), "ListTags", nil)
		if e != nil {
			return nil, e
		}
		o := &api.ListTagsOutput{}
		tagMap(&o.Tags, v.tags())
		return o, nil
	})
	register(s, "CreateTags", func(ctx context.Context, t Transaction, in *api.CreateTagsInput) (*api.CreateTagsOutput, error) {
		conditions := map[string][]string{}
		for k, x := range in.Tags {
			conditions["aws:RequestTag/"+string(k)] = []string{string(x)}
			conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], string(k))
		}
		v, e := s.tagged(ctx, t, value(in.ResourceArn), "CreateTags", conditions)
		if e != nil {
			return nil, e
		}
		for k, x := range in.Tags {
			v.tags()[string(k)] = string(x)
		}
		if e = validateTags(v.tags()); e != nil {
			return nil, e
		}
		return &api.CreateTagsOutput{}, v.put(t)
	})
	register(s, "DeleteTags", func(ctx context.Context, t Transaction, in *api.DeleteTagsInput) (*api.DeleteTagsOutput, error) {
		conditions := map[string][]string{"aws:TagKeys": listStrings(in.TagKeys)}
		v, e := s.tagged(ctx, t, value(in.ResourceArn), "DeleteTags", conditions)
		if e != nil {
			return nil, e
		}
		for _, k := range in.TagKeys {
			delete(v.tags(), string(k))
		}
		return &api.DeleteTagsOutput{}, v.put(t)
	})
}
