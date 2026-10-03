package guardduty

import (
	"encoding/json"

	"stackd/journal"
)

// PUT replaces all four settings; omitted settings become false. Require a
// recorded configuration so absent evidence is not treated as disabling.
// These predicates identify guardrail changes, not effective public access.
type publicAccessBlockRequest struct {
	Bucket        string `json:"bucketName"`
	Configuration *struct {
		BlockPublicACLs       *bool `json:"BlockPublicAcls"`
		IgnorePublicACLs      *bool `json:"IgnorePublicAcls"`
		BlockPublicPolicy     *bool `json:"BlockPublicPolicy"`
		RestrictPublicBuckets *bool `json:"RestrictPublicBuckets"`
	} `json:"PublicAccessBlockConfiguration"`
}

func (r publicAccessBlockRequest) disablesSetting() bool {
	c := r.Configuration
	if c == nil {
		return false
	}
	settings := [4]*bool{c.BlockPublicACLs, c.IgnorePublicACLs, c.BlockPublicPolicy, c.RestrictPublicBuckets}
	for _, setting := range settings {
		if setting == nil || !*setting {
			return true
		}
	}
	return false
}

func disabledBucketPublicAccessTarget(call journal.APICallCompleted, _ []DetectionTarget) (DetectionTarget, bool) {
	var request publicAccessBlockRequest
	if json.Unmarshal(call.RequestParameters, &request) != nil || request.Bucket == "" {
		return DetectionTarget{}, false
	}
	return DetectionTarget{ResourceType: "AWS::S3::Bucket", ResourceName: request.Bucket}, call.EventName == "DeleteBucketPublicAccessBlock" || request.disablesSetting()
}

func disabledAccountPublicAccessTarget(call journal.APICallCompleted, _ []DetectionTarget) (DetectionTarget, bool) {
	// S3 Control admits these operations only for the authenticated account;
	// successful account-control calls cannot target a different account.
	account := call.Identity.AccountID
	if account == "" {
		return DetectionTarget{}, false
	}
	if call.EventName == "DeleteAccountPublicAccessBlock" {
		return DetectionTarget{ResourceType: "AWS::Account", ResourceName: account}, true
	}
	var request publicAccessBlockRequest
	if json.Unmarshal(call.RequestParameters, &request) != nil {
		return DetectionTarget{}, false
	}
	return DetectionTarget{ResourceType: "AWS::Account", ResourceName: account}, request.disablesSetting()
}
