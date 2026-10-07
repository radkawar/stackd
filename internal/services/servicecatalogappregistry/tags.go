package servicecatalogappregistry

import (
	"context"
	"maps"
	"slices"
	api "stackd/internal/awsapi/servicecatalogappregistry"
	tagging "stackd/internal/services/resourcegroupstaggingapi"
	"strings"
)

func tagsInput(tags api.Tags) (map[string]string, error) {
	if len(tags) > 50 {
		return nil, failure("ValidationException", "A resource may have at most 50 tags.")
	}
	out := make(map[string]string, len(tags))
	for k, v := range tags {
		if strings.HasPrefix(strings.ToLower(string(k)), "aws:") {
			return nil, failure("ValidationException", "Tag keys beginning with aws: are reserved.")
		}
		out[string(k)] = string(v)
	}
	return out, nil
}
func tagsOutput(tags map[string]string) api.Tags {
	out := api.Tags{}
	for k, v := range tags {
		out[api.TagKey(k)] = api.TagValue(v)
	}
	return out
}
func (s *Service) listTagsForResource(tx Transaction, in *api.ListTagsForResourceRequest) (*api.ListTagsForResourceResponse, error) {
	arn := value(in.ResourceArn)
	tags, _, err := s.tagTarget(tx, arn, "ListTagsForResource", nil, nil)
	if err != nil {
		return nil, err
	}
	return &api.ListTagsForResourceResponse{Tags: tagsOutput(tags)}, nil
}

// The setter operates on the same detached owner record loaded for authorization.
func (s *Service) tagTarget(tx Transaction, arn, action string, requested map[string]string, keys []string) (map[string]string, func(map[string]string) error, error) {
	scope := scopeFor(tx.Context())
	a, found, err := tx.Application(scope, arn)
	if err != nil {
		return nil, nil, err
	}
	if found {
		if err := s.authorize(tx.Context(), action, arn, a.Tags, requested, keys); err != nil {
			return nil, nil, err
		}
		if err := fenceParent(tx.Context(), a.ID, a.ARN, a.CloudFormationClaim); err != nil {
			return nil, nil, err
		}
		return a.Tags, func(tags map[string]string) error { a.Tags = tags; return tx.PutApplication(a) }, nil
	}
	g, found, err := tx.AttributeGroup(scope, arn)
	if err != nil {
		return nil, nil, err
	}
	if err := s.authorize(tx.Context(), action, arn, g.Tags, requested, keys); err != nil {
		return nil, nil, err
	}
	if !found {
		return nil, nil, failure("ResourceNotFoundException", "Resource not found.")
	}
	if err := fenceParent(tx.Context(), g.ID, g.ARN, g.CloudFormationClaim); err != nil {
		return nil, nil, err
	}
	return g.Tags, func(tags map[string]string) error { g.Tags = tags; return tx.PutAttributeGroup(g) }, nil
}
func (s *Service) tagResource(tx Transaction, in *api.TagResourceRequest) (*api.TagResourceResponse, error) {
	requested, err := tagsInput(in.Tags)
	if err != nil {
		return nil, err
	}
	tags, save, err := s.tagTarget(tx, value(in.ResourceArn), "TagResource", requested, slices.Sorted(maps.Keys(requested)))
	if err != nil {
		return nil, err
	}
	if tags == nil {
		tags = map[string]string{}
	}
	maps.Copy(tags, requested)
	if len(tags) > 50 {
		return nil, failure("ValidationException", "A resource may have at most 50 tags.")
	}
	if err := save(tags); err != nil {
		return nil, err
	}
	return &api.TagResourceResponse{}, nil
}
func (s *Service) untagResource(tx Transaction, in *api.UntagResourceRequest) (*api.UntagResourceResponse, error) {
	var keys []string
	for _, k := range in.TagKeys {
		keys = append(keys, string(k))
	}
	tags, save, err := s.tagTarget(tx, value(in.ResourceArn), "UntagResource", nil, keys)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		delete(tags, k)
	}
	if err := save(tags); err != nil {
		return nil, err
	}
	return &api.UntagResourceResponse{}, nil
}
func (s *Service) ListTaggingResources(ctx context.Context) ([]tagging.Resource, error) {
	var out []tagging.Resource
	err := s.repository.View(ctx, func(r Reader) error {
		scope := scopeFor(ctx)
		apps, err := r.Applications(scope)
		if err != nil {
			return err
		}
		groups, err := r.AttributeGroups(scope)
		if err != nil {
			return err
		}
		for _, a := range apps {
			out = append(out, tagging.Resource{ARN: a.ARN, ResourceType: "servicecatalog:applications", Tags: a.Tags})
		}
		for _, g := range groups {
			out = append(out, tagging.Resource{ARN: g.ARN, ResourceType: "servicecatalog:attribute-groups", Tags: g.Tags})
		}
		return nil
	})
	return out, err
}
