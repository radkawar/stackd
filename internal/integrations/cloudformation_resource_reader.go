package integrations

import (
	"strings"

	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

func cfnResourcePublicTags(tags map[string]string) []any {
	out := make([]any, 0, len(tags))
	for _, key := range cfnMessagingKeys(tags) {
		if !strings.HasPrefix(strings.ToLower(key), cfnComputeTagPrefix) {
			out = append(out, map[string]any{"Key": key, "Value": tags[key]})
		}
	}
	return out
}

// Cloud Control updates existing owner resources, not a new stack incarnation.
// Preserve ownership claims without exposing them or attaching a request's claim.
func cfnResourceMutationTags(r cloudformation.ResourceRequest, current, desired map[string]string) map[string]string {
	if !r.CloudControl {
		return desired
	}
	for key := range desired {
		if strings.HasPrefix(strings.ToLower(key), cfnComputeTagPrefix) {
			delete(desired, key)
		}
	}
	for key, value := range current {
		if strings.HasPrefix(strings.ToLower(key), cfnComputeTagPrefix) {
			desired[key] = value
		}
	}
	return desired
}

func cfnResourceCreateOwnedError(r cloudformation.ResourceRequest, err error) error {
	if err != nil && r.CloudControl {
		return &awswire.Error{Code: "AlreadyExistsException", Message: err.Error(), StatusCode: 400}
	}
	return err
}
