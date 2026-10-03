package apigatewayv2

import (
	"errors"
	"maps"
	"net/url"
	api "stackd/internal/awsapi/apigatewayv2"
	"strings"
)

type taggedResource struct {
	api   *APIRecord
	stage *StageRecord
}

func (v taggedResource) tags() map[string]string {
	if v.api != nil {
		return v.api.Tags
	}
	if v.stage != nil {
		return v.stage.Tags
	}
	return nil
}
func (v taggedResource) put(tx Transaction, tags map[string]string) error {
	if v.api != nil {
		v.api.Tags = tags
		return tx.PutAPI(*v.api)
	}
	v.stage.Tags = tags
	return tx.PutStage(*v.stage)
}
func tagged(r Reader, arn string) (taggedResource, string, error) {
	prefix := controlARN(scopeFor(r.Context()), "/apis/")
	if !strings.HasPrefix(arn, prefix) {
		return taggedResource{}, "", ErrNotFound
	}
	parts := strings.Split(strings.TrimPrefix(arn, prefix), "/")
	key := APIKey{scopeFor(r.Context()), parts[0]}
	switch {
	case len(parts) == 1 && parts[0] != "":
		v, err := r.API(key)
		return taggedResource{api: &v}, "/apis/" + parts[0], err
	case len(parts) == 3 && parts[1] == "stages" && parts[2] != "":
		v, err := r.Stage(ResourceKey{key, parts[2]})
		return taggedResource{stage: &v}, "/apis/" + parts[0] + "/stages/" + parts[2], err
	default:
		return taggedResource{}, "", bad("Tags are supported on APIs and stages")
	}
}
func (s *Service) authorizeTags(r Reader, method, arn, path string, current, requested map[string]string, keys []string) error {
	if err := s.authorize(r, method, "/tags/"+url.QueryEscape(arn), current, requested, keys); err != nil {
		return err
	}
	targetMethod := "PATCH"
	if method == "GET" {
		targetMethod = "GET"
	}
	return s.authorize(r, targetMethod, path, current, requested, keys)
}
func (s *Service) getTags(tx Transaction, in *api.GetTagsInput) (*api.GetTagsOutput, error) {
	resource, path, err := tagged(tx, value(in.ResourceArn))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if e := s.authorizeTags(tx, "GET", value(in.ResourceArn), path, resource.tags(), nil, nil); e != nil {
		return nil, e
	}
	if err != nil {
		return nil, err
	}
	out := &api.GetTagsOutput{}
	stringMap(&out.Tags, resource.tags())
	return out, nil
}
func (s *Service) tagResource(tx Transaction, in *api.TagResourceInput) (*api.TagResourceOutput, error) {
	resource, path, err := tagged(tx, value(in.ResourceArn))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	requested := mapOf(in.Tags)
	if e := validTags(requested); e != nil {
		return nil, e
	}
	if e := s.authorizeTags(tx, "POST", value(in.ResourceArn), path, resource.tags(), requested, nil); e != nil {
		return nil, e
	}
	if err != nil {
		return nil, err
	}
	tags := maps.Clone(resource.tags())
	if tags == nil {
		tags = map[string]string{}
	}
	maps.Copy(tags, requested)
	if err := validTags(tags); err != nil {
		return nil, err
	}
	if err := resource.put(tx, tags); err != nil {
		return nil, err
	}
	return &api.TagResourceOutput{}, nil
}
func (s *Service) untagResource(tx Transaction, in *api.UntagResourceInput) (*api.UntagResourceOutput, error) {
	resource, path, err := tagged(tx, value(in.ResourceArn))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	keys := stringsOf(in.TagKeys)
	for _, key := range keys {
		if key == "" || strings.HasPrefix(strings.ToLower(key), "aws:") {
			return nil, bad("Invalid tag key")
		}
	}
	if e := s.authorizeTags(tx, "DELETE", value(in.ResourceArn), path, resource.tags(), nil, keys); e != nil {
		return nil, e
	}
	if err != nil {
		return nil, err
	}
	tags := maps.Clone(resource.tags())
	for _, key := range keys {
		delete(tags, key)
	}
	if err := resource.put(tx, tags); err != nil {
		return nil, err
	}
	return &api.UntagResourceOutput{}, nil
}
