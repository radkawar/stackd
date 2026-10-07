package integrations

import (
	"encoding/json"
	"fmt"
	"net/http"

	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

// CloudFormationStorageHandlers registers the additional S3, SQS and SSM
// resource types whose behavior is owned by existing typed service commands.
// Buckets, bucket policies, queues and queue policies remain in
// CloudFormationMessagingHandlers; parameters remain bootstrap handlers.
func CloudFormationStorageHandlers(commands StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	return map[string]cloudformation.ResourceHandler{
		"AWS::S3::AccessPoint":        cfnS3AccessPoint{commands},
		"AWS::SQS::QueueInlinePolicy": cfnSQSQueueInlinePolicy{commands},
		"AWS::SSM::Document":          cfnSSMDocument{commands},
		"AWS::SSM::ResourcePolicy":    cfnSSMResourcePolicy{commands},
		"AWS::SSM::ServiceSetting":    cfnSSMServiceSetting{commands},
	}
}

// cfnStorageDocument is a registry Json property whose schema admits either an
// object or its JSON text. Both forms yield the same object.
type cfnStorageDocument map[string]any

func (d *cfnStorageDocument) UnmarshalJSON(raw []byte) error {
	if len(raw) > 0 && raw[0] == '"' {
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return err
		}
		raw = []byte(text)
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return fmt.Errorf("expected a JSON object document")
	}
	*d = object
	return nil
}

// cfnStorageNotFound reports an absent owner resource with the handler error
// code Cloud Control maps to ResourceNotFoundException.
func cfnStorageNotFound(message string) *awswire.Error {
	return &awswire.Error{Code: "NotFound", Message: message, StatusCode: http.StatusNotFound}
}

// cfnStorageMissing normalizes owner-specific absence codes for Cloud Control.
func cfnStorageMissing(err error, codes ...string) error {
	if cfnMessagingMissing(err, codes...) {
		return cfnStorageNotFound(err.Error())
	}
	return err
}

func cfnStorageJSON(text string, out any) error {
	if err := json.Unmarshal([]byte(text), out); err != nil {
		return fmt.Errorf("owner returned an invalid JSON document: %w", err)
	}
	return nil
}
