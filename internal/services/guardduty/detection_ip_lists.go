package guardduty

import (
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"

	"stackd/journal"
)

func apiCallEligible(detector Detector, call journal.APICallCompleted) bool {
	if detector.Status != "ENABLED" || !detectionFeatureEnabled(detector, "CLOUD_TRAIL") ||
		call.ServiceEvent || call.Identity.Type == "AWSService" || call.EventSource == "" || call.EventName == "" {
		return false
	}
	// Anonymous S3 requests are not authenticated CloudTrail data events.
	return call.EventSource != "s3.amazonaws.com" || call.Category != journal.CategoryData || call.Identity.AccessKeyID != ""
}

func detectAPICallWithLists(r Reader, detector Detector, call journal.APICallCompleted, targets []DetectionTarget) ([]Observation, error) {
	if !apiCallEligible(detector, call) {
		return nil, nil
	}
	var matches []IPList
	if address, ok := listSourceIPv4(call.SourceIPAddress); ok {
		var err error
		matches, err = r.MatchingIPLists(detector.Scope, detector.ID, address)
		if err != nil {
			return nil, err
		}
		for _, list := range matches {
			if list.Kind == TrustedIPList {
				// Trust overrides threat matches and the other implemented API rules.
				// Previously retained findings and explicit samples are untouched.
				return nil, nil
			}
		}
	}
	observed := detectAPIRules(call, detector, targets)
	if len(matches) == 0 || call.Identity.AccessKeyID == "" {
		return observed, nil
	}
	custom, ok := customIPObservation(detector, call)
	if !ok {
		return observed, nil
	}
	names := make([]string, 0, len(matches))
	for _, list := range matches {
		if list.Kind == ThreatIPList {
			names = append(names, list.Name)
		}
	}
	if len(names) == 0 {
		return observed, nil
	}
	slices.Sort(names)
	names = slices.Compact(names)
	custom.EventID, custom.AccessKeyID, custom.PrincipalID = call.EventID, call.Identity.AccessKeyID, call.Identity.PrincipalID
	custom.UserName, custom.UserType, custom.API = call.Identity.UserName, call.Identity.Type, call.EventName
	custom.ServiceName, custom.SourceIP, custom.ErrorCode = call.EventSource, call.SourceIPAddress, call.ErrorCode
	custom.ThreatListNames = names
	return append(observed, custom), nil
}

// Custom list findings use source-owned API outcomes and retained list matches.
// AWS documents invocation, not successful completion, so denied attempts retain
// their error evidence. These predicates do not infer a private anomaly model.
// https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html
// https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html
func customIPObservation(detector Detector, call journal.APICallCompleted) (Observation, bool) {
	if call.Category == journal.CategoryManagement {
		if strings.HasPrefix(call.EventName, "List") || strings.HasPrefix(call.EventName, "Describe") {
			return Observation{
				Type: "Recon:IAMUser/MaliciousIPCaller.Custom", Title: "API reconnaissance from a custom threat IP",
				Description: "An API operation that lists or describes AWS resources was invoked from an IP address in an active custom threat list.",
				Severity:    5, FeatureName: "CloudTrailManagementEvent",
			}, true
		}
		return Observation{
			Type: "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom", Title: "API invocation from a custom threat IP",
			Description: "An API operation was invoked from an IP address in an active custom threat list.",
			Severity:    5, FeatureName: "CloudTrailManagementEvent",
		}, true
	}
	if call.Category != journal.CategoryData || call.EventSource != "s3.amazonaws.com" ||
		!detectionFeatureEnabled(detector, "S3_DATA_EVENTS") {
		return Observation{}, false
	}
	// Use the S3 operations documented for these findings, not Get*/Put* name
	// heuristics. S3's producer normalizes ListObjectsV2 to ListObjects.
	var observed Observation
	switch call.EventName {
	case "GetObjectAcl", "ListObjects", "ListObjectsV2":
		observed.Type = "Discovery:S3/MaliciousIPCaller.Custom"
		observed.Title = "S3 discovery from a custom threat IP"
		observed.Description = "An S3 object discovery operation was invoked from an IP address in an active custom threat list."
	case "PutObject", "PutObjectAcl":
		observed.Type = "UnauthorizedAccess:S3/MaliciousIPCaller.Custom"
		observed.Title = "S3 access from a custom threat IP"
		observed.Description = "An S3 object write or ACL operation was invoked from an IP address in an active custom threat list."
	default:
		return Observation{}, false
	}
	bucket, arn, ok := customIPS3Bucket(detector, call)
	if !ok {
		return Observation{}, false
	}
	observed.Severity, observed.FeatureName = 8, "S3DataEvent"
	observed.ResourceType, observed.ResourceName, observed.ResourceARN = "AWS::S3::Bucket", bucket, arn
	return observed, true
}

// LookupResources and DetectionTargets are not native S3 event identities:
// the latter describe CloudTrail destinations. Require an actual bucket ARN
// from this S3 data event, agreeing with its request target and partition.
func customIPS3Bucket(detector Detector, call journal.APICallCompleted) (string, string, bool) {
	var request struct {
		Bucket string `json:"bucketName"`
	}
	if json.Unmarshal(call.RequestParameters, &request) != nil || request.Bucket == "" ||
		strings.ContainsAny(request.Bucket, ":/") {
		return "", "", false
	}
	arn := "arn:" + detector.Partition + ":s3:::" + request.Bucket
	for _, resource := range call.EventResources {
		if resource.Type == "AWS::S3::Bucket" && resource.ARN == arn {
			return request.Bucket, resource.ARN, true
		}
	}
	return "", "", false
}

// GuardDuty's legacy lists apply to public IPv4 origins, not private traffic or
// IPv6. Special-purpose ranges below follow the IANA IPv4 registry; the two
// globally reachable protocol-anycast addresses in 192.0.0/24 are exceptions.
var nonPublicIPv4 = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
}

func listSourceIPv4(source string) (uint32, bool) {
	address, err := netip.ParseAddr(source)
	if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() {
		return 0, false
	}
	bytes := address.As4()
	if bytes != [4]byte{192, 0, 0, 9} && bytes != [4]byte{192, 0, 0, 10} {
		for _, prefix := range nonPublicIPv4 {
			if prefix.Contains(address) {
				return 0, false
			}
		}
	}
	return binary.BigEndian.Uint32(bytes[:]), true
}
