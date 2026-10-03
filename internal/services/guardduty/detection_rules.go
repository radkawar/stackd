package guardduty

import (
	"encoding/json"
	"slices"

	"stackd/journal"
)

// DetectionTarget identifies source-owned resource evidence in the API outcome's
// transaction. S3 names are bucket or bucket/key, not ARNs.
type DetectionTarget struct {
	ResourceType, ResourceName string
	// PublicAccess is an admitted bucket grant, not effective access after BPA.
	PublicAccess string
}

type credentialPredicate uint8

const (
	anyCallerCredential credentialPredicate = iota
	longTermRootCredential
	shortTermRootCredential
)

type detectionRule struct {
	findingType, title, description string
	severity                        float64
	source                          string // Empty matches every public API source.
	category                        journal.APICallCategory
	actions                         []string // Empty matches every API action.
	credential                      credentialPredicate
	requireSuccess                  bool
	requiredFeature, outputFeature  string
	target                          func(journal.APICallCompleted, []DetectionTarget) (DetectionTarget, bool)
}

// These are explicit local predicates, not a reconstruction of AWS's private
// detection algorithms. Each source/category path declares its own feature gate.
var apiDetectionRules = [...]detectionRule{
	{
		findingType: "Policy:IAMUser/RootCredentialUsage", title: "Root credentials used for an API call",
		description: "An API call used long-term root credentials.", severity: 2,
		category: journal.CategoryManagement, credential: longTermRootCredential,
		outputFeature: "CloudTrailManagementEvent", target: observedAPITarget,
	},
	{
		findingType: "Policy:IAMUser/ShortTermRootCredentialUsage", title: "Short-term root credentials used for an API call",
		description: "An API call used short-term root credentials.", severity: 2,
		category: journal.CategoryManagement, credential: shortTermRootCredential,
		outputFeature: "CloudTrailManagementEvent", target: observedAPITarget,
	},
	{
		findingType: "Policy:IAMUser/RootCredentialUsage", title: "Root credentials used for an API call",
		description: "An S3 data API call used long-term root credentials.", severity: 2,
		source: "s3.amazonaws.com", category: journal.CategoryData, credential: longTermRootCredential,
		requiredFeature: "S3_DATA_EVENTS", outputFeature: "S3DataEvent", target: observedAPITarget,
	},
	{
		findingType: "Policy:IAMUser/ShortTermRootCredentialUsage", title: "Short-term root credentials used for an API call",
		description: "An S3 data API call used short-term root credentials.", severity: 2,
		source: "s3.amazonaws.com", category: journal.CategoryData, credential: shortTermRootCredential,
		requiredFeature: "S3_DATA_EVENTS", outputFeature: "S3DataEvent", target: observedAPITarget,
	},
	{
		findingType: "Stealth:IAMUser/CloudTrailLoggingDisabled", title: "CloudTrail logging configuration changed",
		description: "An API call successfully stopped, deleted, or updated a named CloudTrail trail.", severity: 2,
		source: "cloudtrail.amazonaws.com", category: journal.CategoryManagement,
		actions: []string{"StopLogging", "DeleteTrail", "UpdateTrail"}, requireSuccess: true,
		outputFeature: "CloudTrailManagementEvent", target: namedTrailTarget,
	},
	{
		findingType: "Stealth:IAMUser/CloudTrailLoggingDisabled", title: "CloudTrail destination bucket deleted",
		description: "An API call successfully deleted an S3 bucket associated with a CloudTrail trail.", severity: 2,
		source: "s3.amazonaws.com", category: journal.CategoryManagement,
		actions: []string{"DeleteBucket"}, requireSuccess: true,
		outputFeature: "CloudTrailManagementEvent", target: associatedTrailBucketTarget,
	},
	{
		findingType: "Stealth:IAMUser/CloudTrailLoggingDisabled", title: "CloudTrail log object deleted",
		description: "An API call successfully deleted an S3 log object associated with a CloudTrail trail.", severity: 2,
		source: "s3.amazonaws.com", category: journal.CategoryData,
		actions: []string{"DeleteObject"}, requireSuccess: true,
		requiredFeature: "S3_DATA_EVENTS", outputFeature: "S3DataEvent", target: associatedTrailObjectTarget,
	},
	{
		findingType: "Stealth:S3/ServerAccessLoggingDisabled", title: "S3 server access logging disabled",
		description: "An API call successfully disabled server access logging for an S3 bucket.", severity: 2,
		source: "s3.amazonaws.com", category: journal.CategoryManagement,
		actions: []string{"PutBucketLogging"}, requireSuccess: true,
		outputFeature: "CloudTrailManagementEvent", target: disabledBucketLoggingTarget,
	},
	{
		findingType: "Policy:S3/BucketBlockPublicAccessDisabled", title: "S3 bucket public access blocking disabled",
		description: "An API call successfully removed or disabled an S3 bucket public access block setting.", severity: 2,
		source: "s3.amazonaws.com", category: journal.CategoryManagement,
		actions: []string{"PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock"}, requireSuccess: true,
		outputFeature: "CloudTrailManagementEvent", target: disabledBucketPublicAccessTarget,
	},
	{
		findingType: "Policy:S3/AccountBlockPublicAccessDisabled", title: "S3 account public access blocking disabled",
		description: "An API call successfully removed or disabled an S3 account public access block setting.", severity: 2,
		source: "s3.amazonaws.com", category: journal.CategoryManagement,
		actions: []string{"PutAccountPublicAccessBlock", "DeleteAccountPublicAccessBlock"}, requireSuccess: true,
		outputFeature: "CloudTrailManagementEvent", target: disabledAccountPublicAccessTarget,
	},
	{
		findingType: "Stealth:IAMUser/PasswordPolicyChange", title: "Account password policy change attempted",
		description: "An API call attempted to update or delete the account password policy.", severity: 2,
		source: "iam.amazonaws.com", category: journal.CategoryManagement,
		actions:       []string{"UpdateAccountPasswordPolicy", "DeleteAccountPasswordPolicy"},
		outputFeature: "CloudTrailManagementEvent", target: accountAPITarget,
	},
	{
		findingType: "Policy:S3/BucketAnonymousAccessGranted", title: "S3 bucket access granted to anonymous users",
		description: "A successful bucket ACL or policy change granted anonymous access.", severity: 8,
		source: "s3.amazonaws.com", category: journal.CategoryManagement,
		actions: []string{"PutBucketAcl", "PutBucketPolicy"}, requireSuccess: true,
		outputFeature: "CloudTrailManagementEvent", target: anonymousBucketGrantTarget,
	},
	{
		findingType: "Policy:S3/BucketPublicAccessGranted", title: "S3 bucket access granted to all AWS users",
		description: "A successful bucket ACL change granted access to the AuthenticatedUsers group.", severity: 8,
		source: "s3.amazonaws.com", category: journal.CategoryManagement,
		actions: []string{"PutBucketAcl"}, requireSuccess: true,
		outputFeature: "CloudTrailManagementEvent", target: authenticatedBucketGrantTarget,
	},
}

func detectAPICall(detector Detector, call journal.APICallCompleted, targets []DetectionTarget) []Observation {
	if !apiCallEligible(detector, call) {
		return nil
	}
	return detectAPIRules(call, detector, targets)
}

func detectAPIRules(call journal.APICallCompleted, detector Detector, targets []DetectionTarget) []Observation {
	var out []Observation
	for _, rule := range apiDetectionRules {
		if call.Category != rule.category || rule.source != "" && call.EventSource != rule.source ||
			len(rule.actions) != 0 && !slices.Contains(rule.actions, call.EventName) ||
			rule.requireSuccess && call.ErrorCode != "" || !rule.credential.matches(call.Identity) ||
			rule.requiredFeature != "" && !detectionFeatureEnabled(detector, rule.requiredFeature) {
			continue
		}
		target, ok := rule.target(call, targets)
		if !ok {
			continue
		}
		out = append(out, Observation{
			Type: rule.findingType, Title: rule.title, Description: rule.description, Severity: rule.severity,
			EventID: call.EventID, AccessKeyID: call.Identity.AccessKeyID, PrincipalID: call.Identity.PrincipalID,
			UserName: call.Identity.UserName, UserType: call.Identity.Type, API: call.EventName,
			ServiceName: call.EventSource, SourceIP: call.SourceIPAddress, ErrorCode: call.ErrorCode,
			ResourceType: target.ResourceType, ResourceName: target.ResourceName, FeatureName: rule.outputFeature,
		})
	}
	return out
}

func detectionFeatureEnabled(detector Detector, name string) bool {
	for _, feature := range detector.Features {
		if feature.Name == name {
			return feature.Status == "ENABLED"
		}
	}
	return false
}

func (predicate credentialPredicate) matches(identity journal.APIIdentity) bool {
	switch predicate {
	case anyCallerCredential:
		return true
	case longTermRootCredential:
		return identity.Type == "Root" && identity.SessionCreatedAt.IsZero()
	case shortTermRootCredential:
		// Session provenance, not an ASIA key prefix or root session issuer,
		// identifies temporary root credentials. An AssumedRole is never Root.
		return identity.Type == "Root" && !identity.SessionCreatedAt.IsZero()
	default:
		return false
	}
}

func observedAPITarget(call journal.APICallCompleted, _ []DetectionTarget) (DetectionTarget, bool) {
	for _, resource := range call.Resources {
		if resource.Type != "" && resource.Name != "" {
			return DetectionTarget{ResourceType: resource.Type, ResourceName: resource.Name}, true
		}
	}
	return DetectionTarget{}, true
}

func namedTrailTarget(call journal.APICallCompleted, _ []DetectionTarget) (DetectionTarget, bool) {
	var request struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(call.RequestParameters, &request) != nil || request.Name == "" {
		return DetectionTarget{}, false
	}
	return DetectionTarget{ResourceType: "AWS::CloudTrail::Trail", ResourceName: request.Name}, true
}

func associatedTrailBucketTarget(call journal.APICallCompleted, targets []DetectionTarget) (DetectionTarget, bool) {
	return associatedTrailS3Target(call, targets, false)
}

func associatedTrailObjectTarget(call journal.APICallCompleted, targets []DetectionTarget) (DetectionTarget, bool) {
	return associatedTrailS3Target(call, targets, true)
}

func associatedTrailS3Target(call journal.APICallCompleted, targets []DetectionTarget, object bool) (DetectionTarget, bool) {
	if len(targets) == 0 {
		return DetectionTarget{}, false
	}
	var request struct {
		Bucket string `json:"bucketName"`
		Key    string `json:"key"`
	}
	if json.Unmarshal(call.RequestParameters, &request) != nil || request.Bucket == "" {
		return DetectionTarget{}, false
	}
	wanted := DetectionTarget{ResourceType: "AWS::S3::Bucket", ResourceName: request.Bucket}
	if object {
		if request.Key == "" {
			return DetectionTarget{}, false
		}
		wanted = DetectionTarget{ResourceType: "AWS::S3::Object", ResourceName: request.Bucket + "/" + request.Key}
	}
	for _, target := range targets {
		if target == wanted {
			return target, true
		}
	}
	return DetectionTarget{}, false
}

func accountAPITarget(call journal.APICallCompleted, _ []DetectionTarget) (DetectionTarget, bool) {
	return DetectionTarget{ResourceType: "AWS::Account", ResourceName: call.Identity.AccountID}, call.Identity.AccountID != ""
}
