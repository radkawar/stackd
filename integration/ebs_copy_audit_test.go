package stackd_test

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"

	"stackd"
	ebsdomain "stackd/internal/services/ebs"
	"stackd/journal"
	"stackd/storage"
)

// Compare the two native recipient views, not merely a successful SDK response.
// The rejected copy also proves its completed KMS dependency outcome survives the
// snapshot command rollback and repository reconstruction.
func TestEBSCopySnapshotNativeAudit(t *testing.T) {
	var native struct {
		ebsCopyFixture
		CloudTrail struct {
			Events []struct {
				Label string `json:"call_label"`
				Event map[string]any
			}
		}
	}
	awsReadFixture(t, "ebs/copy_data.json", &native)
	calls := map[string]ebsNativeCall{}
	for _, row := range native.Calls {
		calls[row.Label] = row
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var backends *storage.Backends
			r := newEBSCopyReplay(t, native.ebsCopyFixture, backend, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				backends = config.Storage
				return startPublicCloud(t, config)
			})
			for _, label := range []string{
				"owner-create-key", "member-create-key", "source-key-share-policy",
				"plain-source", "plain-source-put", "plain-source-complete",
				"encrypted-source", "encrypted-source-put", "encrypted-source-complete",
				"source-plain-state-0", "source-encrypted-state-1", "plain-share", "encrypted-share",
			} {
				row, ok := calls[label]
				if !ok {
					t.Fatalf("missing native copy audit prerequisite %q", label)
				}
				r.call(t, row)
				if row.Operation == "ModifySnapshotAttribute" {
					r.clock.Advance(ebsdomain.SharingDelay)
				}
			}
			for _, label := range []string{"member-plain", "authority-deny-describe"} {
				if !t.Run(label, func(t *testing.T) {
					call, ok := calls[label]
					if !ok {
						t.Fatalf("missing native audited copy %q", label)
					}
					// Botocore injected DestinationRegion on the captured wire;
					// replay that input rather than inventing it in audit output.
					for _, capture := range native.CloudTrail.Events {
						if capture.Label != label || capture.Event["eventName"] != "CopySnapshot" {
							continue
						}
						parameters, _ := capture.Event["requestParameters"].(map[string]any)
						if region, present := parameters["destinationRegion"]; present {
							var input map[string]any
							awsDecodeJSON(t, call.Input, &input)
							input["DestinationRegion"] = region
							inputJSON, err := json.Marshal(input)
							if err != nil {
								t.Fatal(err)
							}
							call.Input = inputJSON
						}
						break
					}
					caller, err := r.provider(t, call.Caller).Retrieve(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					before, err := backends.Journal.Read(t.Context(), 0, 1000)
					if err != nil {
						t.Fatal(err)
					}
					sequence := before[len(before)-1].Sequence
					ebsCopyCall(t, r, call)
					// Both success and rejection reopen through ebsCopyCall. Read the
					// reconstructed journal, then the signed public CloudTrail API.
					observed, err := backends.Journal.Read(t.Context(), sequence, 1000)
					if err != nil {
						t.Fatal(err)
					}
					actual := map[string]journal.Event{}
					for _, event := range observed {
						completed := event.APICallCompleted
						if completed == nil || completed.EventName != "CopySnapshot" && completed.EventName != "DescribeKey" {
							continue
						}
						key := completed.EventSource + "/" + completed.EventName + "/" + event.AccountID
						if _, exists := actual[key]; exists {
							t.Fatalf("duplicate completed copy audit outcome %s", key)
						}
						actual[key] = event
					}
					var paired []map[string]any
					var dependency map[string]any
					for _, capture := range native.CloudTrail.Events {
						want := capture.Event
						if capture.Label != label || want["eventName"] != "CopySnapshot" && want["eventName"] != "DescribeKey" {
							continue
						}
						account := r.bindings[want["recipientAccountId"].(string)]
						key := want["eventSource"].(string) + "/" + want["eventName"].(string) + "/" + account
						event, exists := actual[key]
						if !exists {
							t.Fatalf("missing durable native audit outcome %s", key)
						}
						delete(actual, key)
						client := cloudtrail.New(cloudtrail.Options{Region: event.Region, BaseEndpoint: aws.String(r.clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
						got := auditLookupRecord(t, client, event.RequestID, event.APICallCompleted.EventName)
						if got["eventID"] != event.APICallCompleted.EventID {
							t.Fatal("CloudTrail and durable journal disagree on copy outcome identity")
						}
						r.bind(t, want["requestID"].(string), event.RequestID)
						for _, field := range []string{"eventName", "eventSource", "awsRegion", "eventType", "eventCategory", "readOnly", "managementEvent", "errorCode", "resources"} {
							ec2NetworkCompare(t, label+"."+field, want[field], got[field], r.bindings)
						}
						for _, field := range []string{"requestParameters", "responseElements"} {
							body, err := json.Marshal(want[field])
							if err != nil {
								t.Fatal(err)
							}
							var expected any
							awsDecodeJSON(t, ec2AuditReplace(t, body, r.bindings), &expected)
							if fields, ok := expected.(map[string]any); ok && field == "requestParameters" {
								// Captures redact native bearer URLs. Locally credentials
								// must never enter retained audit documents at all.
								delete(fields, "presignedUrl")
							}
							if !reflect.DeepEqual(expected, got[field]) {
								t.Fatalf("%s %s = %#v, native %#v", key, field, got[field], expected)
							}
						}
						identity := got["userIdentity"].(map[string]any)
						wantIdentity := want["userIdentity"].(map[string]any)
						if identity["type"] != wantIdentity["type"] || identity["accountId"] != r.bindings[native.Member] || identity["invokedBy"] != wantIdentity["invokedBy"] {
							t.Fatalf("copy audit lost caller/service identity: %#v", identity)
						}
						if account == r.fixture.Account {
							if identity["arn"] != nil || identity["accessKeyId"] != nil || identity["sessionContext"] != nil {
								t.Fatalf("source owner received recipient credentials: %#v", identity)
							}
						} else if identity["accessKeyId"] != caller.AccessKeyID {
							t.Fatalf("copy audit changed original caller credentials: %#v", identity)
						}
						if want["eventName"] == "CopySnapshot" {
							paired = append(paired, got)
						} else {
							dependency = got
							if got["userAgent"] != want["userAgent"] {
								t.Fatalf("failed KMS dependency lost native invoking service: %#v", got)
							}
						}
					}
					if len(actual) != 0 || len(paired) != 2 {
						t.Fatalf("copy recipient audit mismatch: extra %v, paired %d", actual, len(paired))
					}
					if paired[0]["sharedEventID"] == nil || paired[0]["sharedEventID"] == "" || paired[0]["sharedEventID"] != paired[1]["sharedEventID"] || paired[0]["eventID"] == paired[1]["eventID"] || paired[0]["requestID"] != paired[1]["requestID"] {
						t.Fatalf("copy lost paired native correlation: %#v", paired)
					}
					if call.Code != "Success" && (dependency == nil || dependency["requestID"] != paired[0]["requestID"] || dependency["eventID"] == paired[0]["eventID"] || dependency["eventID"] == paired[1]["eventID"]) {
						t.Fatalf("failed copy lost its distinct completed KMS child outcome: %#v", dependency)
					}
				}) {
					return
				}
			}
		})
	}
}
