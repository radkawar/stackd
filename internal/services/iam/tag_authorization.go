package iam

import (
	"maps"
	"slices"
	"strings"

	iamapi "stackd/internal/awsapi/iam"
)

// Request conditions use the validated model input. Resource-owned tag rules
// (reserved prefixes, duplicate keys and accumulated quotas) run after permission
// evaluation in the mutation handler, matching AWS's denial precedence.
func requestTagConditions(input any, conditions map[string][]string) bool {
	var tags iamapi.TagListType
	if in, ok := input.(interface{ RequestTags() iamapi.TagListType }); ok {
		tags = in.RequestTags()
	}
	// AWS authorizes the last value supplied for an exactly repeated key;
	// an allowed request then fails the resource's duplicate-key rule.
	values := make(map[string]string, len(tags))
	for _, tag := range tags {
		values[inputString(tag.Key)] = inputString(tag.Value)
	}
	keys := slices.Sorted(maps.Keys(values))
	for _, key := range keys {
		condition := "aws:requesttag/" + strings.ToLower(key)
		conditions[condition] = append(conditions[condition], values[key])
	}
	if in, ok := input.(interface{ RequestTagKeys() iamapi.TagKeyListType }); ok {
		for _, key := range in.RequestTagKeys() {
			keys = append(keys, string(key))
		}
	}
	if len(keys) != 0 {
		slices.Sort(keys)
		conditions["aws:TagKeys"] = slices.Compact(keys)
	}
	return len(tags) != 0
}
