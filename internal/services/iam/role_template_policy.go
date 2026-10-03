package iam

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
)

// Policy object formatting and unordered action/resource/principal lists do
// not constitute a role edit. Keep identifiers, conditions and statement Sids;
// this compares configuration, not the abstract set of permissions granted.
func templatePoliciesEqual(left, right string) bool {
	var a, b any
	if json.Unmarshal([]byte(left), &a) != nil || json.Unmarshal([]byte(right), &b) != nil {
		return false
	}
	return reflect.DeepEqual(templatePolicyValue(a), templatePolicyValue(b))
}

func templatePolicyValue(value any) any {
	switch value := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(value))
		for key, child := range value {
			out[key] = templatePolicyValue(child)
		}
		return out
	case []any:
		out := make([]any, len(value))
		for i, child := range value {
			out[i] = templatePolicyValue(child)
		}
		slices.SortFunc(out, func(a, b any) int {
			left, _ := json.Marshal(a)
			right, _ := json.Marshal(b)
			return strings.Compare(string(left), string(right))
		})
		if len(out) == 1 {
			return out[0]
		}
		return out
	default:
		return value
	}
}
