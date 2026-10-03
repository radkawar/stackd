package guardduty

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	api "stackd/internal/awsapi/guardduty"
	"stackd/journal"
)

func rulesDetector(dataEvents bool) Detector {
	detector := Detector{Status: "ENABLED", Features: []Feature{{Name: "CLOUD_TRAIL", Status: "ENABLED"}}}
	if dataEvents {
		detector.Features = append(detector.Features, Feature{Name: "S3_DATA_EVENTS", Status: "ENABLED"})
	}
	return detector
}

func TestDetectionRootCredentialPredicates(t *testing.T) {
	session := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, test := range []struct {
		name     string
		identity journal.APIIdentity
		want     string
	}{
		{"long-term root", journal.APIIdentity{Type: "Root", AccessKeyID: "AKIAEXAMPLE"}, "Policy:IAMUser/RootCredentialUsage"},
		{"short-term root", journal.APIIdentity{Type: "Root", AccessKeyID: "ASIAEXAMPLE", SessionCreatedAt: session}, "Policy:IAMUser/ShortTermRootCredentialUsage"},
		{"session provenance not key prefix", journal.APIIdentity{Type: "Root", AccessKeyID: "LOCALKEY", SessionCreatedAt: session}, "Policy:IAMUser/ShortTermRootCredentialUsage"},
		{"key prefix not session provenance", journal.APIIdentity{Type: "Root", AccessKeyID: "ASIAEXAMPLE"}, "Policy:IAMUser/RootCredentialUsage"},
		{"IAM user", journal.APIIdentity{Type: "IAMUser", UserName: "root"}, ""},
		{"assumed root role", journal.APIIdentity{Type: "AssumedRole", IssuerARN: "arn:aws:iam::123456789012:root", IssuerUserName: "root", SessionCreatedAt: session}, ""},
		{"unknown identity", journal.APIIdentity{}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, code := range []string{"", "AccessDenied"} {
				call := journal.APICallCompleted{
					EventID: "root-event", EventSource: "ec2.amazonaws.com", EventName: "DescribeInstances",
					Category: journal.CategoryManagement, Identity: test.identity, ErrorCode: code,
				}
				got := detectAPICall(rulesDetector(false), call, nil)
				if test.want == "" {
					if len(got) != 0 {
						t.Fatalf("error %q: non-root identity produced %+v", code, got)
					}
					continue
				}
				if len(got) != 1 || got[0].Type != test.want || got[0].ErrorCode != code || got[0].AccessKeyID != test.identity.AccessKeyID || got[0].EventID != call.EventID {
					t.Fatalf("error %q: got %+v, want %s with actual credential and outcome", code, got, test.want)
				}
			}
		})
	}
}

func TestDetectionFoundationalGates(t *testing.T) {
	base := journal.APICallCompleted{EventSource: "iam.amazonaws.com", EventName: "ListUsers", Category: journal.CategoryManagement, Identity: journal.APIIdentity{Type: "Root"}}
	for _, test := range []struct {
		name   string
		change func(*Detector, *journal.APICallCompleted)
	}{
		{"disabled detector", func(d *Detector, _ *journal.APICallCompleted) { d.Status = "DISABLED" }},
		{"missing foundational feature", func(d *Detector, _ *journal.APICallCompleted) { d.Features = nil }},
		{"disabled foundational feature", func(d *Detector, _ *journal.APICallCompleted) { d.Features[0].Status = "DISABLED" }},
		{"service-generated outcome", func(_ *Detector, c *journal.APICallCompleted) { c.ServiceEvent = true }},
		{"missing category", func(_ *Detector, c *journal.APICallCompleted) { c.Category = "" }},
		{"unrelated data source", func(_ *Detector, c *journal.APICallCompleted) { c.Category = journal.CategoryData }},
		{"missing source", func(_ *Detector, c *journal.APICallCompleted) { c.EventSource = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			detector, call := rulesDetector(true), base
			test.change(&detector, &call)
			if got := detectAPICall(detector, call, nil); len(got) != 0 {
				t.Fatalf("gated event produced %+v", got)
			}
		})
	}
}

func TestDetectionCloudTrailLoggingPredicates(t *testing.T) {
	for _, action := range []string{"StopLogging", "DeleteTrail", "UpdateTrail"} {
		t.Run(action, func(t *testing.T) {
			base := journal.APICallCompleted{
				EventID: "trail-event", EventSource: "cloudtrail.amazonaws.com", EventName: action,
				Category: journal.CategoryManagement, Identity: journal.APIIdentity{Type: "IAMUser", UserName: "auditor"},
				RequestParameters: json.RawMessage(`{"name":"actual-trail"}`),
			}
			got := detectAPICall(rulesDetector(false), base, nil)
			if len(got) != 1 || got[0].Type != "Stealth:IAMUser/CloudTrailLoggingDisabled" || got[0].ResourceType != "AWS::CloudTrail::Trail" || got[0].ResourceName != "actual-trail" || got[0].API != action {
				t.Fatalf("named successful trail mutation: %+v", got)
			}
			for _, test := range []struct {
				name   string
				change func(*journal.APICallCompleted)
			}{
				{"denied", func(c *journal.APICallCompleted) { c.ErrorCode = "AccessDeniedException" }},
				{"unrelated source", func(c *journal.APICallCompleted) { c.EventSource = "ec2.amazonaws.com" }},
				{"unrelated action", func(c *journal.APICallCompleted) { c.EventName = "GetTrail" }},
				{"wrong category", func(c *journal.APICallCompleted) { c.Category = journal.CategoryData }},
				{"service outcome", func(c *journal.APICallCompleted) { c.ServiceEvent = true }},
				{"service identity", func(c *journal.APICallCompleted) { c.Identity.Type = "AWSService" }},
				{"missing trail", func(c *journal.APICallCompleted) { c.RequestParameters = json.RawMessage(`{}`) }},
				{"empty trail", func(c *journal.APICallCompleted) { c.RequestParameters = json.RawMessage(`{"name":""}`) }},
				{"wrong trail type", func(c *journal.APICallCompleted) { c.RequestParameters = json.RawMessage(`{"name":123}`) }},
				{"malformed request", func(c *journal.APICallCompleted) { c.RequestParameters = json.RawMessage(`{"name":`) }},
			} {
				t.Run(test.name, func(t *testing.T) {
					call := base
					test.change(&call)
					if got := detectAPICall(rulesDetector(true), call, nil); len(got) != 0 {
						t.Fatalf("unmatched logging event produced %+v", got)
					}
				})
			}
		})
	}
}

func TestDetectionAssociatedS3Targets(t *testing.T) {
	for _, test := range []struct {
		name, action, request, feature string
		category                       journal.APICallCategory
		target                         DetectionTarget
	}{
		{"bucket", "DeleteBucket", `{"bucketName":"trail-bucket"}`, "CloudTrailManagementEvent", journal.CategoryManagement, DetectionTarget{ResourceType: "AWS::S3::Bucket", ResourceName: "trail-bucket"}},
		{"object", "DeleteObject", `{"bucketName":"trail-bucket","key":"AWSLogs/account/log.gz"}`, "S3DataEvent", journal.CategoryData, DetectionTarget{ResourceType: "AWS::S3::Object", ResourceName: "trail-bucket/AWSLogs/account/log.gz"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			call := journal.APICallCompleted{EventSource: "s3.amazonaws.com", EventName: test.action, Category: test.category, Identity: journal.APIIdentity{Type: "IAMUser", AccessKeyID: "actual-key"}, RequestParameters: json.RawMessage(test.request)}
			targets := []DetectionTarget{test.target}
			got := detectAPICall(rulesDetector(true), call, targets)
			if len(got) != 1 || got[0].Type != "Stealth:IAMUser/CloudTrailLoggingDisabled" || got[0].ResourceName != test.target.ResourceName || got[0].ResourceType != test.target.ResourceType || got[0].FeatureName != test.feature {
				t.Fatalf("associated resource deletion: %+v", got)
			}
			for _, badTargets := range [][]DetectionTarget{nil, {{ResourceType: test.target.ResourceType, ResourceName: "unrelated"}}, {{ResourceType: "AWS::EC2::Instance", ResourceName: test.target.ResourceName}}} {
				if got := detectAPICall(rulesDetector(true), call, badTargets); len(got) != 0 {
					t.Fatalf("unassociated resource produced %+v", got)
				}
			}
			call.ErrorCode = "AccessDenied"
			if got := detectAPICall(rulesDetector(true), call, targets); len(got) != 0 {
				t.Fatalf("denied deletion produced %+v", got)
			}
			call.ErrorCode = ""
			call.EventSource = "other.amazonaws.com"
			if got := detectAPICall(rulesDetector(true), call, targets); len(got) != 0 {
				t.Fatalf("unrelated source produced %+v", got)
			}
		})
	}
}

func TestDetectionS3DataFeatureGate(t *testing.T) {
	for _, identity := range []journal.APIIdentity{
		{Type: "IAMUser", AccessKeyID: "actual-key"},
		{Type: "Root", AccessKeyID: "actual-key"},
		{Type: "Root", AccessKeyID: "actual-key", SessionCreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)},
	} {
		call := journal.APICallCompleted{EventSource: "s3.amazonaws.com", EventName: "DeleteObject", Category: journal.CategoryData, Identity: identity, RequestParameters: json.RawMessage(`{"bucketName":"trail","key":"log"}`)}
		targets := []DetectionTarget{{ResourceType: "AWS::S3::Object", ResourceName: "trail/log"}}
		for _, status := range []string{"", "DISABLED"} {
			detector := rulesDetector(false)
			if status != "" {
				detector.Features = append(detector.Features, Feature{Name: "S3_DATA_EVENTS", Status: status})
			}
			if got := detectAPICall(detector, call, targets); len(got) != 0 {
				t.Fatalf("identity %+v, feature %q produced %+v", identity, status, got)
			}
		}
		got := detectAPICall(rulesDetector(true), call, targets)
		wantTypes := []string{"Stealth:IAMUser/CloudTrailLoggingDisabled"}
		if identity.Type == "Root" {
			rootType := "Policy:IAMUser/RootCredentialUsage"
			if !identity.SessionCreatedAt.IsZero() {
				rootType = "Policy:IAMUser/ShortTermRootCredentialUsage"
			}
			wantTypes = append([]string{rootType}, wantTypes...)
		}
		var gotTypes []string
		for _, observation := range got {
			gotTypes = append(gotTypes, observation.Type)
			if observation.FeatureName != "S3DataEvent" {
				t.Fatalf("wrong data feature: %+v", observation)
			}
		}
		if !reflect.DeepEqual(gotTypes, wantTypes) {
			t.Fatalf("enabled data feature: got %v, want %v", gotTypes, wantTypes)
		}
		call.Identity.AccessKeyID = ""
		if got := detectAPICall(rulesDetector(true), call, targets); len(got) != 0 {
			t.Fatalf("unauthenticated S3 request produced findings: %+v", got)
		}
	}
}

func TestObservedFindingOutputUsesRetainedEvidence(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	finding := Finding{
		Scope:      Scope{Partition: "aws", AccountID: "123456789012", Region: "eu-west-1"},
		DetectorID: "actual-detector", ID: "actual-finding", Created: created, Updated: created.Add(time.Minute),
		Count: 3, Archived: true, Feedback: "NOT_USEFUL",
		Observation: Observation{
			Type: "Policy:IAMUser/RootCredentialUsage", Title: "Observed root API call", Description: "Retained API evidence", Severity: 2,
			EventID: "actual-event", AccessKeyID: "AKIAACTUAL", PrincipalID: "123456789012", UserName: "root", UserType: "Root",
			API: "DeleteBucket", ServiceName: "s3.amazonaws.com", SourceIP: "192.0.2.7", ErrorCode: "AccessDenied",
			ResourceType: "AWS::S3::Bucket", ResourceName: "actual-bucket", FeatureName: "CloudTrailManagementEvent",
		},
	}
	out := observedFindingOutput(finding)
	if value(out.AccountId) != finding.AccountID || value(out.Partition) != finding.Partition || value(out.Region) != finding.Region || value(out.Id) != finding.ID || value(out.Arn) != "arn:aws:guardduty:eu-west-1:123456789012:detector/actual-detector/finding/actual-finding" || value(out.SchemaVersion) != "2.0" {
		t.Fatalf("wrong finding identity: %+v", out)
	}
	if value(out.Type) != finding.Observation.Type || value(out.Title) != finding.Observation.Title || value(out.Description) != finding.Observation.Description || out.Severity == nil || *out.Severity != 2 {
		t.Fatalf("wrong observed classification: %+v", out)
	}
	if out.Resource == nil || value(out.Resource.ResourceType) != "AccessKey" || out.Resource.AccessKeyDetails == nil {
		t.Fatalf("missing actual access key resource: %+v", out.Resource)
	}
	key := out.Resource.AccessKeyDetails
	if value(key.AccessKeyId) != "AKIAACTUAL" || value(key.PrincipalId) != "123456789012" || value(key.UserName) != "root" || value(key.UserType) != "Root" {
		t.Fatalf("wrong caller evidence: %+v", key)
	}
	service := out.Service
	if service == nil || service.Action == nil || service.Action.AwsApiCallAction == nil {
		t.Fatal("missing observed API action")
	}
	action := service.Action.AwsApiCallAction
	if value(service.Action.ActionType) != "AWS_API_CALL" || value(action.Api) != "DeleteBucket" || value(action.ServiceName) != "s3.amazonaws.com" || value(action.ErrorCode) != "AccessDenied" || !reflect.DeepEqual(action.AffectedResources, api.AffectedResources{"AWS::S3::Bucket": "actual-bucket"}) {
		t.Fatalf("wrong API evidence: %+v", action)
	}
	remote := action.RemoteIpDetails
	if remote == nil || value(remote.IpAddressV4) != "192.0.2.7" || remote.IpAddressV6 != nil || remote.City != nil || remote.Country != nil || remote.GeoLocation != nil || remote.Organization != nil {
		t.Fatalf("fabricated or missing IP evidence: %+v", remote)
	}
	if value(service.DetectorId) != finding.DetectorID || value(service.ServiceName) != "guardduty" || value(service.FeatureName) != "CloudTrailManagementEvent" || service.Count == nil || *service.Count != 3 || service.Archived == nil || !*service.Archived || value(service.UserFeedback) != "NOT_USEFUL" {
		t.Fatalf("wrong retained service state: %+v", service)
	}
	if value(out.CreatedAt) != created.Format(time.RFC3339Nano) || value(out.UpdatedAt) != finding.Updated.Format(time.RFC3339Nano) || value(service.EventFirstSeen) != value(out.CreatedAt) || value(service.EventLastSeen) != value(out.UpdatedAt) {
		t.Fatal("retained occurrence timestamps were not projected")
	}
	if service.AdditionalInfo == nil {
		t.Fatal("missing source event evidence")
	}
	var additional map[string]any
	if err := json.Unmarshal([]byte(value(service.AdditionalInfo.Value)), &additional); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(additional, map[string]any{"eventId": "actual-event"}) {
		t.Fatalf("unexpected evidence or sample marker: %+v", additional)
	}
	finding.Observation.FeatureName = "S3DataEvent"
	finding.Observation.SourceIP = "2001:db8::7"
	out = observedFindingOutput(finding)
	if value(out.Service.FeatureName) != "S3DataEvent" || value(out.Service.Action.AwsApiCallAction.RemoteIpDetails.IpAddressV6) != "2001:db8::7" {
		t.Fatal("data feature or IPv6 evidence lost")
	}
	finding.Observation.SourceIP = "cloudtrail.amazonaws.com"
	out = observedFindingOutput(finding)
	if out.Service.Action.AwsApiCallAction.RemoteIpDetails != nil {
		t.Fatal("non-IP source fabricated IP details")
	}
}

func TestDetectionPasswordPolicyAttempts(t *testing.T) {
	for _, action := range []string{"UpdateAccountPasswordPolicy", "DeleteAccountPasswordPolicy"} {
		for _, outcome := range []string{"", "AccessDenied", "NoSuchEntity"} {
			t.Run(action+"/"+outcome, func(t *testing.T) {
				call := journal.APICallCompleted{
					EventID: "password-policy-event", EventSource: "iam.amazonaws.com", EventName: action,
					Category: journal.CategoryManagement, ErrorCode: outcome,
					Identity: journal.APIIdentity{Type: "IAMUser", AccountID: "123456789012", AccessKeyID: "actual-key"},
				}
				got := detectAPICall(rulesDetector(false), call, nil)
				if len(got) != 1 || got[0].Type != "Stealth:IAMUser/PasswordPolicyChange" ||
					got[0].ResourceType != "AWS::Account" || got[0].ResourceName != call.Identity.AccountID ||
					got[0].ErrorCode != outcome || got[0].AccessKeyID != "actual-key" || got[0].EventID != call.EventID {
					t.Fatalf("actual attempt evidence lost: %+v", got)
				}
				for _, mutate := range []func(*journal.APICallCompleted){
					func(c *journal.APICallCompleted) { c.EventName = "GetAccountPasswordPolicy" },
					func(c *journal.APICallCompleted) { c.EventSource = "s3.amazonaws.com" },
					func(c *journal.APICallCompleted) { c.Category = journal.CategoryData },
					func(c *journal.APICallCompleted) { c.Identity.AccountID = "" },
				} {
					other := call
					mutate(&other)
					if found := detectAPICall(rulesDetector(false), other, nil); len(found) != 0 {
						t.Fatalf("unrelated event detected: %+v", found)
					}
				}
			})
		}
	}
}
