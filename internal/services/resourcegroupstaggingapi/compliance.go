package resourcegroupstaggingapi

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"strings"

	api "stackd/internal/awsapi/resourcegroupstaggingapi"
)

type tagRule struct {
	Key         string            `json:"tag_key"`
	Values      []json.RawMessage `json:"tag_value"`
	RequiredFor []string          `json:"report_required_tag_for"`
}
type tagPolicy struct {
	Tags map[string]tagRule `json:"tags"`
}

func (s *Service) effectivePolicy(ctx context.Context) (tagPolicy, error) {
	if s.policies == nil {
		return tagPolicy{}, failure("NotImplementedException", "Organizations effective tag-policy reader is not configured.")
	}
	document, err := s.policies.EffectiveTagPolicy(ctx)
	if err != nil {
		return tagPolicy{}, err
	}
	if document == "" {
		return tagPolicy{}, nil
	}
	var policy tagPolicy
	if err := json.Unmarshal([]byte(document), &policy); err != nil {
		return tagPolicy{}, err
	}
	return policy, nil
}
func tagValueMatches(pattern, value string) bool {
	before, after, wild := strings.Cut(pattern, "*")
	if !wild {
		return pattern == value
	}
	return len(value) >= len(before)+len(after) && strings.HasPrefix(value, before) && strings.HasSuffix(value, after)
}
func (p tagPolicy) compliance(resource Resource) *api.ComplianceDetails {
	out := &api.ComplianceDetails{ComplianceStatus: new(api.ComplianceStatus(true)), NoncompliantKeys: api.TagKeyList{}, KeysWithNoncompliantValues: api.TagKeyList{}, MissingTagKeys: api.TagKeyList{}}
	for _, name := range slices.Sorted(maps.Keys(p.Tags)) {
		rule := p.Tags[name]
		canonical := rule.Key
		if canonical == "" {
			canonical = name
		}
		found := false
		for _, key := range slices.Sorted(maps.Keys(resource.Tags)) {
			if !strings.EqualFold(key, name) {
				continue
			}
			found = true
			if key != canonical {
				out.NoncompliantKeys = append(out.NoncompliantKeys, api.TagKey(key))
			}
			allowed := len(rule.Values) == 0
			for _, raw := range rule.Values {
				var pattern string
				if json.Unmarshal(raw, &pattern) != nil {
					pattern = string(raw)
				}
				if tagValueMatches(pattern, resource.Tags[key]) {
					allowed = true
					break
				}
			}
			if !allowed {
				out.KeysWithNoncompliantValues = append(out.KeysWithNoncompliantValues, api.TagKey(key))
			}
		}
		if !found {
			for _, kind := range rule.RequiredFor {
				service, _, _ := strings.Cut(resource.ResourceType, ":")
				if kind == resource.ResourceType || kind == service+":ALL_SUPPORTED" {
					out.MissingTagKeys = append(out.MissingTagKeys, api.TagKey(canonical))
					break
				}
			}
		}
	}
	slices.Sort(out.NoncompliantKeys)
	slices.Sort(out.KeysWithNoncompliantValues)
	slices.Sort(out.MissingTagKeys)
	*out.ComplianceStatus = api.ComplianceStatus(len(out.NoncompliantKeys)+len(out.KeysWithNoncompliantValues)+len(out.MissingTagKeys) == 0)
	return out
}
