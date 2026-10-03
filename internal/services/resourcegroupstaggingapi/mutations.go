package resourcegroupstaggingapi

import (
	"maps"
	"slices"
	"strings"
	"unicode/utf8"

	api "stackd/internal/awsapi/resourcegroupstaggingapi"
)

func validateKey(key string) error {
	if n := utf8.RuneCountInString(key); n < 1 || n > 128 {
		return invalid("Tag keys must contain 1 through 128 characters.")
	}
	if strings.HasPrefix(strings.ToLower(key), "aws:") {
		return invalid("The caller isn't allowed to modify system tags.")
	}
	return nil
}
func (s *Service) tagResources(tx Transaction, in *api.TagResourcesInput) (*api.TagResourcesOutput, error) {
	tags := make(map[string]string, len(in.Tags))
	for key, value := range in.Tags {
		tags[string(key)] = string(value)
	}
	keys := slices.Sorted(maps.Keys(tags))
	if err := s.authorize(tx.Context(), "TagResources", tags, keys); err != nil {
		return nil, err
	}
	if len(tags) < 1 || len(tags) > 50 {
		return nil, failure("ValidationException", "Tags must contain between 1 and 50 entries.")
	}
	for key, value := range tags {
		if err := validateKey(key); err != nil {
			return nil, err
		}
		if utf8.RuneCountInString(value) > 256 {
			return nil, invalid("Tag values may contain at most 256 characters.")
		}
	}
	failures, err := s.mutate(tx, in.ResourceARNList, tags, nil)
	if err != nil {
		return nil, err
	}
	return &api.TagResourcesOutput{FailedResourcesMap: failures}, nil
}
func (s *Service) untagResources(tx Transaction, in *api.UntagResourcesInput) (*api.UntagResourcesOutput, error) {
	keys := make([]string, 0, len(in.TagKeys))
	for _, key := range in.TagKeys {
		keys = append(keys, string(key))
	}
	if err := s.authorize(tx.Context(), "UntagResources", nil, keys); err != nil {
		return nil, err
	}
	if len(keys) < 1 || len(keys) > 50 {
		return nil, invalid("TagKeys must contain between 1 and 50 keys.")
	}
	for _, key := range keys {
		if err := validateKey(key); err != nil {
			return nil, err
		}
	}
	failures, err := s.mutate(tx, in.ResourceARNList, nil, keys)
	if err != nil {
		return nil, err
	}
	return &api.UntagResourcesOutput{FailedResourcesMap: failures}, nil
}
func (s *Service) mutate(tx Transaction, arns api.ResourceARNListForTagUntag, tags map[string]string, keys []string) (api.FailedResourcesMap, error) {
	if len(arns) < 1 || len(arns) > 20 {
		return nil, invalid("ResourceARNList must contain between 1 and 20 ARNs.")
	}
	if s.resources == nil {
		return nil, failure("InternalServiceException", "Resource owners are not configured.")
	}
	scope := scopeFor(tx.Context())
	// Malformed identities are batch admission errors, not an opportunity to
	// partially mutate before discovering a bad request's partition.
	for _, raw := range arns {
		p, err := parseARN(string(raw))
		if err != nil {
			return nil, err
		}
		if p[1] != scope.Partition {
			return nil, invalid("The ARN partition does not match the request partition.")
		}
		// Native GetResources accepts global dashboards, but the mutation router's
		// CloudWatch resource grammar accepts only regional alarm ARNs.
		if p[2] == "cloudwatch" && (p[3] == "" || !strings.HasPrefix(p[5], "alarm:")) {
			return nil, invalid(string(raw) + " is not a valid AmazonResourceName (ARN)")
		}
	}
	failures := make(api.FailedResourcesMap)
	for _, raw := range arns {
		arn := string(raw)
		p, _ := parseARN(arn)
		err := s.repository.Attempt(tx.Context(), func(attempt Transaction) error {
			if p[3] != "" && p[3] != scope.Region || p[4] != "" && p[4] != scope.AccountID {
				return invalid("The resource must belong to the calling account and Region.")
			}
			resource := Resource{ARN: arn, ResourceType: resourceType(arn)}
			if tags != nil {
				return s.resources.Tag(attempt.Context(), resource, tags)
			}
			return s.resources.Untag(attempt.Context(), resource, keys)
		})
		if err != nil {
			rejected := wireError(err)
			info := api.FailureInfo{ErrorCode: new(api.ErrorCode(rejected.Code)), StatusCode: new(api.StatusCode(rejected.StatusCode))}
			if rejected.Message != "" {
				info.ErrorMessage = new(api.ErrorMessage(rejected.Message))
			}
			failures[raw] = info
		}
	}
	return failures, nil
}
