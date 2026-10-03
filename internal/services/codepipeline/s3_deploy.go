package codepipeline

import (
	"fmt"

	api "stackd/internal/awsapi/codepipeline"
)

func validateS3Deploy(action api.ActionDeclaration) error {
	for _, key := range [...]api.ActionConfigurationKey{"BucketName", "Extract"} {
		if _, present := action.Configuration[key]; !present {
			return failure("InvalidActionDeclarationException", fmt.Sprintf("Action configuration for action '%s' is missing required configuration '%s'", text(action.Name), key))
		}
	}
	unknown := ""
	for key := range action.Configuration {
		switch key {
		case "BucketName", "Extract", "ObjectKey", "KMSEncryptionKeyARN", "CannedACL", "CacheControl":
		default:
			if unknown == "" || string(key) < unknown {
				unknown = string(key)
			}
		}
	}
	if unknown != "" {
		return failure("InvalidActionDeclarationException", fmt.Sprintf("Action configuration for action '%s' contains unknown configuration '%s'", text(action.Name), unknown))
	}
	// Native admission accepts nonempty Extract strings and an absent ObjectKey.
	// The execution owner validates their resolved values, after substitution.
	return nil
}
