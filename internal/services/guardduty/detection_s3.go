package guardduty

import (
	"bytes"
	"encoding/json"

	"stackd/journal"
)

// S3 records the submitted XML wrapper in CloudTrail parameters. A present,
// empty BucketLoggingStatus disables logging; missing audit input does not.
// This is a management-event finding and does not require S3 data protection.
func disabledBucketLoggingTarget(call journal.APICallCompleted, _ []DetectionTarget) (DetectionTarget, bool) {
	var request struct {
		Bucket string          `json:"bucketName"`
		Status json.RawMessage `json:"BucketLoggingStatus"`
	}
	if json.Unmarshal(call.RequestParameters, &request) != nil || request.Bucket == "" {
		return DetectionTarget{}, false
	}
	status := bytes.TrimSpace(request.Status)
	if bytes.Equal(status, []byte(`""`)) {
		// An empty XML element without namespace attributes projects as a string.
		return DetectionTarget{ResourceType: "AWS::S3::Bucket", ResourceName: request.Bucket}, true
	}
	if len(status) == 0 || status[0] != '{' {
		return DetectionTarget{}, false
	}
	var configuration struct {
		Enabled json.RawMessage `json:"LoggingEnabled"`
	}
	if json.Unmarshal(status, &configuration) != nil || len(configuration.Enabled) != 0 {
		return DetectionTarget{}, false
	}
	return DetectionTarget{ResourceType: "AWS::S3::Bucket", ResourceName: request.Bucket}, true
}
