package resourcegroupstaggingapi

import (
	"context"
	"maps"
	"slices"
	"strings"

	api "stackd/internal/awsapi/resourcegroupstaggingapi"
)

func readSupported(resource Resource) bool {
	// AWS documents these mutation-only resources as absent from Get* inventory.
	return resource.ResourceType != "iam:user" && resource.ResourceType != "iam:role" && !strings.HasPrefix(resource.ResourceType, "autoscaling:")
}
func (s *Service) list(ctx context.Context) ([]Resource, error) {
	if s.resources == nil {
		return nil, failure("InternalServiceException", "Resource owners are not configured.")
	}
	resources, err := s.resources.List(ctx, "")
	if err != nil {
		return nil, err
	}
	slices.SortFunc(resources, func(a, b Resource) int { return strings.Compare(a.ARN, b.ARN) })
	return slices.CompactFunc(resources, func(a, b Resource) bool { return a.ARN == b.ARN }), nil
}
func parseARN(raw string) ([]string, error) {
	p := strings.SplitN(raw, ":", 6)
	if len(p) != 6 || p[0] != "arn" || p[1] == "" || p[2] == "" || p[5] == "" || strings.ContainsAny(raw, "\r\n\t ") {
		return nil, invalid("The resource ARN is not valid.")
	}
	return p, nil
}
func resourceType(raw string) string {
	p, err := parseARN(raw)
	if err != nil {
		return ""
	}
	switch p[2] {
	case "s3":
		if !strings.Contains(p[5], "/") && !strings.Contains(p[5], ":") {
			return "s3:bucket"
		}
	case "sqs":
		return "sqs:queue"
	case "sns":
		return "sns:topic"
	}
	kind := strings.FieldsFunc(p[5], func(r rune) bool { return r == '/' || r == ':' })
	if len(kind) == 0 {
		return p[2]
	}
	return p[2] + ":" + kind[0]
}
func validateGet(in *api.GetResourcesInput, scope Scope) error {
	if in.ExcludeCompliantResources != nil && bool(*in.ExcludeCompliantResources) && !boolean(in.IncludeComplianceDetails) {
		return invalid("You must specify the IncludeComplianceDetails parameter and set it to true.")
	}
	if len(in.ResourceARNList) > 0 {
		if len(in.TagFilters) > 0 || len(in.ResourceTypeFilters) > 0 || in.ResourcesPerPage != nil || in.TagsPerPage != nil || value(in.PaginationToken) != "" {
			return invalid("ResourceARNList cannot be combined with filters or pagination parameters.")
		}
		if len(in.ResourceARNList) > 100 {
			return invalid("ResourceARNList can contain at most 100 ARNs.")
		}
		for _, arn := range in.ResourceARNList {
			p, err := parseARN(string(arn))
			if err != nil {
				return err
			}
			if p[1] != scope.Partition {
				return invalid("The ARN partition does not match the request partition.")
			}
		}
	}
	if in.ResourcesPerPage != nil && (*in.ResourcesPerPage < 1 || *in.ResourcesPerPage > 100) {
		return invalid("ResourcesPerPage must be between 1 and 100.")
	}
	if in.TagsPerPage != nil && (*in.TagsPerPage < 100 || *in.TagsPerPage > 500) {
		return invalid("TagsPerPage must be between 100 and 500.")
	}
	if len(in.ResourceTypeFilters) > 100 {
		return invalid("ResourceTypeFilters can contain at most 100 entries.")
	}
	for _, filter := range in.ResourceTypeFilters {
		if filter == "" || strings.Count(string(filter), ":") > 1 || strings.ContainsAny(string(filter), " \t\n") || strings.HasSuffix(string(filter), ":") {
			return invalid("Resource type filters must use service[:resourceType].")
		}
	}
	if len(in.TagFilters) > 50 {
		return invalid("TagFilters can contain at most 50 keys.")
	}
	for _, filter := range in.TagFilters {
		if value(filter.Key) == "" || len(filter.Values) > 20 {
			return invalid("Each tag filter requires a key and at most 20 values.")
		}
	}
	return nil
}
func matches(resource Resource, in *api.GetResourcesInput) bool {
	if len(in.ResourceARNList) > 0 && !slices.Contains(in.ResourceARNList, api.ResourceARN(resource.ARN)) {
		return false
	}
	if len(in.ResourceTypeFilters) > 0 {
		kind := resource.ResourceType
		if strings.HasPrefix(kind, "appconfig:") {
			// AppConfig policy/CFN kinds retain nested resource ownership,
			// but native GetResources filters use the ARN's first component.
			// See testdata/aws/resourcegroupstaggingapi/appconfig.json.
			kind = resourceType(resource.ARN)
		}
		matched := false
		for _, filter := range in.ResourceTypeFilters {
			if kind == string(filter) || !strings.Contains(string(filter), ":") && strings.HasPrefix(kind, string(filter)+":") {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for _, filter := range in.TagFilters {
		value, present := resource.Tags[value(filter.Key)]
		if !present || len(filter.Values) > 0 && !slices.Contains(filter.Values, api.TagValue(value)) {
			return false
		}
	}
	return true
}
func nativeTags(tags map[string]string) api.TagList {
	out := make(api.TagList, 0, len(tags))
	for _, key := range slices.Sorted(maps.Keys(tags)) {
		out = append(out, api.Tag{Key: new(api.TagKey(key)), Value: new(api.TagValue(tags[key]))})
	}
	return out
}
func (s *Service) getResources(tx Transaction, in *api.GetResourcesInput) (*api.GetResourcesOutput, error) {
	if err := s.authorize(tx.Context(), "GetResources", nil, nil); err != nil {
		return nil, err
	}
	if err := validateGet(in, scopeFor(tx.Context())); err != nil {
		return nil, err
	}
	query := *in
	query.PaginationToken = nil
	c, err := s.pageCursor(tx.Context(), value(in.PaginationToken), queryHash("GetResources", query))
	if err != nil {
		return nil, err
	}
	resources, err := s.list(tx.Context())
	if err != nil {
		return nil, err
	}
	memberships, err := inventoryMemberships(tx, scopeFor(tx.Context()), "")
	if err != nil {
		return nil, err
	}
	previous := make(map[string]bool, len(memberships))
	for _, m := range memberships {
		previous[m.ARN] = true
	}
	var policy tagPolicy
	if boolean(in.IncludeComplianceDetails) {
		policy, err = s.effectivePolicy(tx.Context())
		if err != nil {
			return nil, err
		}
	}
	limit, tagLimit := 100, 0
	if in.ResourcesPerPage != nil {
		limit = int(*in.ResourcesPerPage)
	}
	if in.TagsPerPage != nil {
		tagLimit = int(*in.TagsPerPage)
	}
	out := &api.GetResourcesOutput{PaginationToken: emptyToken(), ResourceTagMappingList: make(api.ResourceTagMappingList, 0)}
	tags, last := 0, c.After
	for _, resource := range resources {
		if resource.ARN <= c.After || !readSupported(resource) || len(resource.Tags) == 0 && !previous[resource.ARN] || !matches(resource, in) {
			continue
		}
		entry := api.ResourceTagMapping{ResourceARN: new(api.ResourceARN(resource.ARN)), Tags: nativeTags(resource.Tags)}
		if boolean(in.IncludeComplianceDetails) {
			entry.ComplianceDetails = policy.compliance(resource)
			if boolean(in.ExcludeCompliantResources) && boolean(entry.ComplianceDetails.ComplianceStatus) {
				continue
			}
		}
		count := max(1, len(resource.Tags))
		if len(out.ResourceTagMappingList) >= limit || tagLimit > 0 && tags+count > tagLimit && len(out.ResourceTagMappingList) > 0 {
			out.PaginationToken = s.nextToken(c, last)
			break
		}
		out.ResourceTagMappingList = append(out.ResourceTagMappingList, entry)
		tags += count
		last = resource.ARN
	}
	return out, nil
}
func (s *Service) tagVocabulary(tx Transaction, action, key, token string) ([]string, *api.PaginationToken, error) {
	if err := s.authorize(tx.Context(), action, nil, nil); err != nil {
		return nil, nil, err
	}
	c, err := s.pageCursor(tx.Context(), token, queryHash(action, key))
	if err != nil {
		return nil, nil, err
	}
	resources, err := s.list(tx.Context())
	if err != nil {
		return nil, nil, err
	}
	unique := map[string]bool{}
	for _, resource := range resources {
		if !readSupported(resource) {
			continue
		}
		if action == "GetTagKeys" {
			for key := range resource.Tags {
				unique[key] = true
			}
		} else if v, ok := resource.Tags[key]; ok {
			unique[v] = true
		}
	}
	all := slices.Sorted(maps.Keys(unique))
	next := emptyToken()
	out := make([]string, 0, min(1000, len(all)))
	for _, item := range all {
		// Empty tag values are legal; an initial empty cursor has not consumed one.
		if token != "" && item <= c.After {
			continue
		}
		if len(out) == 1000 {
			next = s.nextToken(c, out[len(out)-1])
			break
		}
		out = append(out, item)
	}
	return out, next, nil
}
func (s *Service) getTagKeys(tx Transaction, in *api.GetTagKeysInput) (*api.GetTagKeysOutput, error) {
	values, next, err := s.tagVocabulary(tx, "GetTagKeys", "", value(in.PaginationToken))
	if err != nil {
		return nil, err
	}
	out := &api.GetTagKeysOutput{PaginationToken: next, TagKeys: make(api.TagKeyList, 0, len(values))}
	for _, v := range values {
		out.TagKeys = append(out.TagKeys, api.TagKey(v))
	}
	return out, nil
}
func (s *Service) getTagValues(tx Transaction, in *api.GetTagValuesInput) (*api.GetTagValuesOutput, error) {
	if value(in.Key) == "" {
		return nil, invalid("Key is required.")
	}
	values, next, err := s.tagVocabulary(tx, "GetTagValues", value(in.Key), value(in.PaginationToken))
	if err != nil {
		return nil, err
	}
	out := &api.GetTagValuesOutput{PaginationToken: next, TagValues: make(api.TagValuesOutputList, 0, len(values))}
	for _, v := range values {
		out.TagValues = append(out.TagValues, api.TagValue(v))
	}
	return out, nil
}
