package resourcegroupstaggingapi

import (
	"maps"
	"slices"

	api "stackd/internal/awsapi/resourcegroupstaggingapi"
)

// ListRequiredTags is an account policy reader, not an organization management
// operation. Required resource wildcards and CFN names come from the published
// Organizations resource catalog, never inferred capitalization of ARN types.
func (s *Service) listRequiredTags(tx Transaction, in *api.ListRequiredTagsInput) (*api.ListRequiredTagsOutput, error) {
	ctx := tx.Context()
	if err := s.authorize(ctx, "ListRequiredTags", nil, nil); err != nil {
		return nil, err
	}
	if in.MaxResults != nil && (*in.MaxResults < 1 || *in.MaxResults > 200) {
		return nil, invalid("MaxResults must be between 1 and 200.")
	}
	query := *in
	query.NextToken = nil
	cursor, err := s.pageCursor(ctx, value(in.NextToken), queryHash("ListRequiredTags", query))
	if err != nil {
		return nil, err
	}
	policy, err := s.effectivePolicy(ctx)
	if err != nil {
		return nil, err
	}
	required := map[string]map[string]bool{}
	for name, rule := range policy.Tags {
		key := rule.Key
		if key == "" {
			key = name
		}
		for _, kind := range rule.RequiredFor {
			if s.governance == nil {
				return nil, failure("InternalServiceException", "The Organizations resource catalog is not configured.")
			}
			types, err := s.governance.RequiredResourceTypes(kind)
			if err != nil {
				return nil, err
			}
			for _, resourceType := range types {
				if required[resourceType] == nil {
					required[resourceType] = map[string]bool{}
				}
				required[resourceType][key] = true
			}
		}
	}
	limit := 200
	if in.MaxResults != nil {
		limit = int(*in.MaxResults)
	}
	out := &api.ListRequiredTagsOutput{RequiredTags: make(api.RequiredTagsForListRequiredTags, 0, min(limit, len(required)))}
	last := ""
	for _, kind := range slices.Sorted(maps.Keys(required)) {
		if kind <= cursor.After {
			continue
		}
		if len(out.RequiredTags) == limit {
			out.NextToken = s.nextToken(cursor, last)
			break
		}
		aliases, err := s.governance.CloudFormationTypes(kind)
		if err != nil {
			return nil, err
		}
		aliases = slices.Clone(aliases)
		slices.Sort(aliases)
		aliases = slices.Compact(aliases)
		row := api.RequiredTag{ResourceType: new(api.ResourceType(kind)), CloudFormationResourceTypes: make(api.CloudFormationResourceTypes, 0, len(aliases)), ReportingTagKeys: make(api.ReportingTagKeys, 0, len(required[kind]))}
		for _, alias := range aliases {
			row.CloudFormationResourceTypes = append(row.CloudFormationResourceTypes, api.CloudFormationResourceType(alias))
		}
		for _, key := range slices.Sorted(maps.Keys(required[kind])) {
			row.ReportingTagKeys = append(row.ReportingTagKeys, api.TagKey(key))
		}
		out.RequiredTags = append(out.RequiredTags, row)
		last = kind
	}
	return out, nil
}
