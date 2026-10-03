package guardduty

import (
	"encoding/json"
	"fmt"
	"testing"

	"stackd/journal"
)

func TestDetectionS3PublicAccessBlock(t *testing.T) {
	for _, scope := range []struct{ name, resourceType, resourceName string }{
		{"Bucket", "AWS::S3::Bucket", "source"}, {"Account", "AWS::Account", "123456789012"},
	} {
		t.Run(scope.name, func(t *testing.T) {
			for _, tc := range []struct {
				name, operation, configuration, errorCode string
				want                                      bool
			}{
				{"enabled", "Put", `{"BlockPublicAcls":true,"IgnorePublicAcls":true,"BlockPublicPolicy":true,"RestrictPublicBuckets":true}`, "", false},
				{"acls disabled", "Put", `{"BlockPublicAcls":false,"IgnorePublicAcls":true,"BlockPublicPolicy":true,"RestrictPublicBuckets":true}`, "", true},
				{"ignore acls disabled", "Put", `{"BlockPublicAcls":true,"IgnorePublicAcls":false,"BlockPublicPolicy":true,"RestrictPublicBuckets":true}`, "", true},
				{"policy disabled", "Put", `{"BlockPublicAcls":true,"IgnorePublicAcls":true,"BlockPublicPolicy":false,"RestrictPublicBuckets":true}`, "", true},
				{"restrict buckets disabled", "Put", `{"BlockPublicAcls":true,"IgnorePublicAcls":true,"BlockPublicPolicy":true,"RestrictPublicBuckets":false}`, "", true},
				{"omitted settings reset", "Put", `{"BlockPublicAcls":true}`, "", true},
				{"all omitted settings reset", "Put", `{}`, "", true},
				{"null evidence", "Put", `null`, "", false},
				{"malformed evidence", "Put", `{"BlockPublicAcls":"false"}`, "", false},
				{"read only", "Get", `{"BlockPublicAcls":false}`, "", false},
				{"denied put", "Put", `{"BlockPublicAcls":false}`, "AccessDenied", false},
				{"delete", "Delete", `null`, "", true},
				{"denied delete", "Delete", `null`, "AccessDenied", false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					call := journal.APICallCompleted{EventSource: "s3.amazonaws.com", EventName: tc.operation + scope.name + "PublicAccessBlock", Category: journal.CategoryManagement, Identity: journal.APIIdentity{Type: "IAMUser", AccountID: "123456789012", AccessKeyID: "caller-key"}, ErrorCode: tc.errorCode, RequestParameters: json.RawMessage(fmt.Sprintf(`{"bucketName":"source","PublicAccessBlockConfiguration":%s}`, tc.configuration))}
					got := detectAPICall(rulesDetector(false), call, nil)
					if !tc.want {
						if len(got) != 0 {
							t.Fatalf("unexpected finding: %+v", got)
						}
						return
					}
					if len(got) != 1 || got[0].Type != "Policy:S3/"+scope.name+"BlockPublicAccessDisabled" || got[0].ResourceType != scope.resourceType || got[0].ResourceName != scope.resourceName || got[0].AccessKeyID != "caller-key" {
						t.Fatalf("incorrect finding: %+v", got)
					}
					for _, mutate := range []func(*journal.APICallCompleted){
						func(c *journal.APICallCompleted) { c.Category = journal.CategoryData },
						func(c *journal.APICallCompleted) { c.EventSource = "unrelated.amazonaws.com" },
						func(c *journal.APICallCompleted) { c.ServiceEvent = true },
						func(c *journal.APICallCompleted) {
							c.RequestParameters = json.RawMessage(`{}`)
							c.Identity.AccountID = ""
						},
					} {
						changed := call
						mutate(&changed)
						if found := detectAPICall(rulesDetector(false), changed, nil); len(found) != 0 {
							t.Fatalf("invalid source matched: %+v", found)
						}
					}
				})
			}
		})
	}
}
