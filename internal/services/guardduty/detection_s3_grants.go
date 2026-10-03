package guardduty

import (
	"encoding/json"
	"stackd/journal"
)

// TODO: Comeback extend S3-owned policy evidence to conditional grants and
// authenticated audiences; bounded proofs are not AWS Zelkova equivalence.
// https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html
func anonymousBucketGrantTarget(call journal.APICallCompleted, targets []DetectionTarget) (DetectionTarget, bool) {
	return bucketGrantTarget(call, targets, "Anonymous")
}
func authenticatedBucketGrantTarget(call journal.APICallCompleted, targets []DetectionTarget) (DetectionTarget, bool) {
	return bucketGrantTarget(call, targets, "Authenticated")
}
func bucketGrantTarget(call journal.APICallCompleted, targets []DetectionTarget, access string) (DetectionTarget, bool) {
	var request struct {
		Bucket string `json:"bucketName"`
	}
	if json.Unmarshal(call.RequestParameters, &request) != nil || request.Bucket == "" {
		return DetectionTarget{}, false
	}
	for _, target := range targets {
		if target.ResourceType == "AWS::S3::Bucket" && target.ResourceName == request.Bucket && target.PublicAccess == access {
			return target, true
		}
	}
	return DetectionTarget{}, false
}
