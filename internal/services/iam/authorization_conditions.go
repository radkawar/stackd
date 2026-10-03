package iam

import (
	"strings"

	"stackd/internal/awswire"
	"stackd/internal/iam/catalog"
)

// The service supplies only conditions applicable to the generated IAM action.
// Principal, session, transport and Organizations context is independently
// populated from verified sources by the central evaluator.
func filterActionConditions(action string, context map[string][]string) *awswire.Error {
	metadata, err := catalog.Load()
	if err != nil {
		return authorizationMetadataFailure()
	}
	definition, ok := metadata.LookupAction(action)
	if !ok || definition.Ambiguous {
		return authorizationMetadataFailure()
	}
	for key := range context {
		allowed := false
		for _, template := range definition.ConditionKeys {
			if conditionKeyMatches(template, key) {
				allowed = true
				break
			}
		}
		if !allowed {
			delete(context, key)
		}
	}
	return nil
}

func conditionKeyMatches(template, key string) bool {
	template, key = strings.ToLower(template), strings.ToLower(key)
	prefix, variable, dynamic := strings.Cut(template, "${")
	if !dynamic {
		return template == key
	}
	_, suffix, closed := strings.Cut(variable, "}")
	return closed && !strings.Contains(suffix, "${") && len(key) > len(prefix)+len(suffix) && strings.HasPrefix(key, prefix) && strings.HasSuffix(key, suffix)
}
