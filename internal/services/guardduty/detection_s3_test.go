package guardduty

import (
	"encoding/json"
	"testing"

	"stackd/journal"
)

func TestDetectionS3ServerAccessLoggingRequest(t *testing.T) {
	for _, test := range []struct {
		name, request, errorCode string
		match                    bool
	}{
		{"disabled with namespace", `{"bucketName":"source","BucketLoggingStatus":{"xmlns":"http://s3.amazonaws.com/doc/2006-03-01/"}}`, "", true},
		{"disabled empty object", `{"bucketName":"source","BucketLoggingStatus":{}}`, "", true},
		{"disabled empty XML element", `{"bucketName":"source","BucketLoggingStatus":""}`, "", true},
		{"enabled", `{"bucketName":"source","BucketLoggingStatus":{"LoggingEnabled":{"TargetBucket":"destination","TargetPrefix":"logs/"}}}`, "", false},
		{"missing status", `{"bucketName":"source"}`, "", false},
		{"null status", `{"bucketName":"source","BucketLoggingStatus":null}`, "", false},
		{"present null enabled", `{"bucketName":"source","BucketLoggingStatus":{"LoggingEnabled":null}}`, "", false},
		{"missing bucket", `{"BucketLoggingStatus":{}}`, "", false},
		{"malformed", `{"bucketName":"source","BucketLoggingStatus":`, "", false},
		{"denied", `{"bucketName":"source","BucketLoggingStatus":{}}`, "AccessDenied", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			call := journal.APICallCompleted{EventSource: "s3.amazonaws.com", EventName: "PutBucketLogging", Category: journal.CategoryManagement, Identity: journal.APIIdentity{Type: "IAMUser", AccessKeyID: "caller-key"}, RequestParameters: json.RawMessage(test.request), ErrorCode: test.errorCode}
			got := detectAPICall(rulesDetector(false), call, nil)
			if !test.match {
				if len(got) != 0 {
					t.Fatalf("unmatched request produced %+v", got)
				}
				return
			}
			if len(got) != 1 || got[0].Type != "Stealth:S3/ServerAccessLoggingDisabled" || got[0].ResourceType != "AWS::S3::Bucket" || got[0].ResourceName != "source" || got[0].FeatureName != "CloudTrailManagementEvent" {
				t.Fatalf("incorrect bucket observation: %+v", got)
			}
			for _, mutation := range []func(*journal.APICallCompleted){
				func(c *journal.APICallCompleted) { c.Category = journal.CategoryData },
				func(c *journal.APICallCompleted) { c.EventName = "GetBucketLogging" },
				func(c *journal.APICallCompleted) { c.EventSource = "unrelated.amazonaws.com" },
			} {
				changed := call
				mutation(&changed)
				if rejected := detectAPICall(rulesDetector(false), changed, nil); len(rejected) != 0 {
					t.Fatalf("wrong operation source matched: %+v", rejected)
				}
			}
		})
	}
}
