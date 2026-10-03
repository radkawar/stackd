package organizations

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// Required tags are limited across the entire inherited policy, rather than
// independently on each attached document.
func validateEffectiveTags(root *inheritedSetting, size int) []EffectivePolicyError {
	tags := root.children["tags"]
	if tags == nil {
		return nil
	}
	keys := make(map[string][]string)
	sources := make(map[string][]string)
	for _, key := range slices.Sorted(maps.Keys(tags.children)) {
		required := tags.children[key].children["report_required_tag_for"]
		if required == nil {
			continue
		}
		resources, _ := required.value.([]any)
		for _, resource := range resources {
			name := resource.(string)
			if slices.Contains(keys[name], key) {
				continue
			}
			keys[name] = append(keys[name], key)
			for _, id := range required.contributingPolicies() {
				if !slices.Contains(sources[name], id) {
					sources[name] = append(sources[name], id)
				}
			}
		}
	}
	var errors []EffectivePolicyError
	if size > 395000 {
		errors = append(errors, EffectivePolicyError{Code: "ELEMENTS_TOO_MANY", Message: fmt.Sprintf("Effective policy size is %d bytes, which exceeds the maximum limit of 395000 bytes", size), Path: "tags"})
	}
	for _, resource := range slices.Sorted(maps.Keys(keys)) {
		contributing := keys[resource]
		if len(contributing) <= 50 {
			continue
		}
		message := fmt.Sprintf("Resource type '%s' has %d tags for 'report_required_tag_for', which exceeds the maximum limit of 50. Contributing tag keys include: %s and %d more", resource, len(contributing), strings.Join(contributing[:5], ", "), len(contributing)-5)
		slices.Sort(sources[resource])
		errors = append(errors, EffectivePolicyError{Code: "ELEMENTS_TOO_MANY", Message: message, Path: "tags", ContributingPolicies: sources[resource]})
	}
	return errors
}
