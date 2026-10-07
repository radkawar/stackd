package integrations

import (
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

func cfnResourcePublicTags(tags map[string]string) []any {
	out := make([]any, 0, len(tags))
	for _, key := range cfnMessagingKeys(tags) {
		out = append(out, map[string]any{"Key": key, "Value": tags[key]})
	}
	return out
}

func cfnResourceCreateOwnedError(r cloudformation.ResourceRequest, err error) error {
	if err != nil && r.CloudControl {
		return &awswire.Error{Code: "AlreadyExistsException", Message: err.Error(), StatusCode: 400}
	}
	return err
}
