package xray

import (
	"encoding/json"
	"errors"
	"maps"
	"strings"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/xray"
	"stackd/internal/awswire"
)

// taggedResource carries the existing typed row, so a tag-only write preserves
// configuration timestamps, group versions and sampling rate-boost state.
type taggedResource struct {
	group *GroupRecord
	rule  *SamplingRuleRecord
}

func readTaggedResource(r Reader, arn string) (taggedResource, error) {
	scope := scopeFor(r.Context())
	if strings.HasPrefix(arn, (GroupKey{Scope: scope}).ARN()) {
		row, err := resolveGroup(r, "", arn)
		return taggedResource{group: &row}, err
	}
	if strings.HasPrefix(arn, (SamplingRuleKey{Scope: scope}).ARN()) {
		key, err := samplingRuleKey(scope, "", arn)
		if err != nil {
			return taggedResource{}, err
		}
		row, err := samplingRule(r, key)
		return taggedResource{rule: &row}, err
	}
	// Never resolve a foreign account, region or partition through a local key.
	return taggedResource{}, ErrNotFound
}

func (resource taggedResource) tags() map[string]string {
	if resource.group != nil {
		return resource.group.Tags
	}
	if resource.rule != nil {
		return resource.rule.Tags
	}
	return nil
}

func (resource taggedResource) claim() string {
	if resource.group != nil {
		return resource.group.CFNOwner
	}
	if resource.rule != nil {
		return resource.rule.CFNOwner
	}
	return ""
}

func (resource taggedResource) putTags(tx Transaction, tags map[string]string) error {
	if resource.group != nil {
		resource.group.Tags = tags
		return tx.PutGroup(*resource.group)
	}
	resource.rule.Tags = tags
	return tx.PutSamplingRule(*resource.rule)
}

func missingTaggedResource(arn string) *awswire.Error {
	err := failure("ResourceNotFoundException", "Resource "+arn+" not found", 404)
	encoded, _ := json.Marshal(arn)
	err.Details = map[string]json.RawMessage{"ResourceName": encoded}
	return err
}

func (s *Service) tagResource(tx Transaction, in *api.TagResourceRequest) (*api.TagResourceResponse, error) {
	arn := value(in.ResourceARN)
	resource, err := readTaggedResource(tx, arn)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	tags, tagErr := validateTags(in.Tags)
	if tagErr != nil {
		return nil, tagErr
	}
	request := authorization.Request{Action: "xray:TagResource", ResourceARN: arn, Context: tagContext(resource.tags(), tags, nil), ContextTypes: map[string]string{"aws:TagKeys": "stringList"}}
	if authErr := s.authorizeResource(tx, request); authErr != nil {
		return nil, authErr
	}
	if err != nil {
		return nil, missingTaggedResource(arn)
	}
	if _, err := cloudFormationClaim(tx.Context(), resource.claim(), true); err != nil {
		return nil, err
	}
	merged := maps.Clone(resource.tags())
	if merged == nil {
		merged = make(map[string]string, len(tags))
	}
	maps.Copy(merged, tags)
	if len(merged) > 50 {
		return nil, failure("InvalidRequestException", "The resultant tag set must not have more than 50 user tags.")
	}
	if !maps.Equal(merged, resource.tags()) {
		if err := resource.putTags(tx, merged); err != nil {
			return nil, err
		}
	}
	return &api.TagResourceResponse{}, nil
}

func (s *Service) untagResource(tx Transaction, in *api.UntagResourceRequest) (*api.UntagResourceResponse, error) {
	arn := value(in.ResourceARN)
	resource, err := readTaggedResource(tx, arn)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	keys := make([]string, len(in.TagKeys))
	for i, key := range in.TagKeys {
		keys[i] = string(key)
		if strings.HasPrefix(strings.ToLower(string(key)), "aws:") {
			return nil, failure("InvalidRequestException", "Caller is an end user and not allowed to mutate system tags")
		}
	}
	request := authorization.Request{Action: "xray:UntagResource", ResourceARN: arn, Context: tagContext(resource.tags(), nil, keys), ContextTypes: map[string]string{"aws:TagKeys": "stringList"}}
	if authErr := s.authorizeResource(tx, request); authErr != nil {
		return nil, authErr
	}
	if err != nil {
		return nil, missingTaggedResource(arn)
	}
	if _, err := cloudFormationClaim(tx.Context(), resource.claim(), true); err != nil {
		return nil, err
	}
	tags := maps.Clone(resource.tags())
	for _, key := range keys {
		delete(tags, key)
	}
	if !maps.Equal(tags, resource.tags()) {
		if err := resource.putTags(tx, tags); err != nil {
			return nil, err
		}
	}
	return &api.UntagResourceResponse{}, nil
}

func (s *Service) listTagsForResource(tx Transaction, in *api.ListTagsForResourceRequest) (*api.ListTagsForResourceResponse, error) {
	arn := value(in.ResourceARN)
	resource, err := readTaggedResource(tx, arn)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if authErr := s.authorizeResource(tx, authorization.Request{Action: "xray:ListTagsForResource", ResourceARN: arn, Context: tagContext(resource.tags(), nil, nil)}); authErr != nil {
		return nil, authErr
	}
	if err != nil {
		return nil, missingTaggedResource(arn)
	}
	// Native ignores NextToken here and returns the complete bounded tag set.
	return &api.ListTagsForResourceResponse{Tags: tagList(resource.tags())}, nil
}
