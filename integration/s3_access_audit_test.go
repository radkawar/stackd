package stackd_test

import (
	"encoding/json"
	"encoding/xml"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"stackd"
	"stackd/clock"
)

// Only request-correlated native records are delivery expectations. Bounded
// omissions (including the initial anonymous request) remain fixture notes,
// never assertions that CloudTrail permanently excludes those calls.
func TestS3AccessNativeAuditDelivery(t *testing.T) {
	runS3NativeAuditReplay(t, "s3/access_controls_audit_replay.json")
}

func TestS3CustomerEncryptionNativeAuditDelivery(t *testing.T) {
	runS3NativeAuditReplay(t, "s3/customer_encryption_audit_replay.json")
}

func runS3NativeAuditReplay(t *testing.T, path string) {
	t.Helper()
	var fixture struct {
		AuditBucket, AuditPrefix string
		TLS                      bool
		Payloads                 map[string][]s3MultipartPayload
		Setup, Trail             []s3KMSCall
		Verify                   []s3MultipartCall
		Calls                    []struct {
			s3MultipartCall
			Record       map[string]any
			CallerRecord map[string]any
			Raw          *s3MultipartEventCall
		}
	}
	awsReadFixture(t, path, &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 20, 11, 0, 0, 0, time.UTC))
			clients, reopen := retainedS3ReplayCloud(t, backend, stackd.Config{AccountID: "123456789012", Clock: source}, fixture.TLS)
			replay := newS3KMSReplay(clients)
			for _, row := range fixture.Setup {
				replay.call(t, row)
				if row.Session != "" {
					replay.values[row.Session+"Created"] = source.Now().UTC().Format(time.RFC3339)
				}
			}
			arn, key, secret := clients.user(t, "test", "Delegated")
			putUserPolicy(t, clients.iam("test", "test", ""), "Delegated", allow(`"s3:*"`, "*"))
			replay.sessions["audit-user"] = aws.Credentials{AccessKeyID: key, SecretAccessKey: secret}
			replay.values["auditUserARN"] = arn
			for _, row := range fixture.Trail {
				replay.call(t, row)
			}
			wires := map[string]*s3AttributesAuditWire{}
			ids, times := map[int]string{}, map[int]string{}
			for _, row := range fixture.Calls {
				t.Logf("Native sequence %d: %s", row.Sequence, row.Label)
				wire := &s3AttributesAuditWire{Client: replay.clients.server.Client()}
				replay.httpClient = wire
				if row.Raw != nil {
					credentials, ok := replay.sessions[row.Actor]
					if !ok {
						t.Fatalf("missing actor %q", row.Actor)
					}
					s3MultipartEventRequest(t, replay, credentials, *row.Raw, source.Now())
				} else if row.Service != "" && row.Service != "s3" {
					replay.call(t, row.s3KMSCall)
				} else {
					s3MultipartReplayCall(t, replay, fixture.Payloads, row.s3MultipartCall)
				}
				if row.Record != nil {
					id := wire.header.Get("x-amz-request-id")
					if id == "" || wires[id] != nil || wire.header.Get("x-amz-id-2") == "" {
						t.Fatalf("%s lost public request correlation", row.Label)
					}
					wires[id], ids[row.Sequence] = wire, id
					times[row.Sequence] = source.Now().UTC().Format(time.RFC3339)
				}
				advanceClock(t, source, time.Second)
			}
			// Both accepted delivery work and the final ownership/ACL/PAB state must
			// survive SQLite close/reopen before any log object is drained.
			replay.clients, replay.httpClient = reopen(), nil
			for _, row := range fixture.Verify {
				s3MultipartReplayCall(t, replay, fixture.Payloads, row)
			}
			advanceClock(t, source, 6*time.Minute)
			trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
			delivered := map[string]map[string]any{}
			pairedRequests := map[string]string{}
			for _, record := range trailNativeRecords(t, trailNativeObjects(t, replay.s3Client("caller"), fixture.AuditBucket, fixture.AuditPrefix)) {
				id, _ := record["requestID"].(string)
				if wires[id] == nil {
					continue
				}
				if prior := delivered[id]; prior != nil && !reflect.DeepEqual(prior, record) {
					t.Fatalf("redelivery changed request %s", id)
				}
				delivered[id] = record
			}
			for _, row := range fixture.Calls {
				if row.Record == nil {
					continue
				}
				t.Run(row.Label, func(t *testing.T) {
					id := ids[row.Sequence]
					got, wire := delivered[id], wires[id]
					if got == nil {
						t.Fatalf("%s: missing delivered gzip record from %s", row.Label, row.Source)
					}
					var want map[string]any
					if err := json.Unmarshal(replay.rebind(t, row.Record), &want); err != nil {
						t.Fatal(err)
					}
					want["eventTime"] = times[row.Sequence]
					want["requestParameters"].(map[string]any)["Host"] = wire.host
					var failure struct {
						Message string
						Error   struct{ Message string }
					}
					if wire.status >= 400 {
						if err := xml.Unmarshal(wire.body, &failure); err != nil {
							t.Fatal(err)
						}
						if failure.Message == "" {
							failure.Message = failure.Error.Message
						}
					}
					t.Logf("Comparing native sequence %d: %s", row.Sequence, row.Label)
					assertNativeAuditEvent(t, got, want, failure.Message)
					identity, _ := got["userIdentity"].(map[string]any)
					nativeIdentity := want["userIdentity"].(map[string]any)
					for _, field := range []string{"type", "userName", "accountId", "arn", "invokedBy"} {
						actual, present := identity[field]
						native, expected := nativeIdentity[field]
						if present != expected || !reflect.DeepEqual(actual, native) {
							t.Fatalf("%s changed caller %s: %#v", row.Label, field, identity)
						}
					}
					if nativeIdentity["type"] == "IAMUser" && identity["accessKeyId"] != key {
						t.Fatalf("%s changed authenticated caller: %#v", row.Label, identity)
					}
					if nativeIdentity["type"] == "AWSAccount" {
						if _, present := identity["accessKeyId"]; present {
							t.Fatalf("%s exposed cross-account access key: %#v", row.Label, identity)
						}
					}
					additional, _ := got["additionalEventData"].(map[string]any)
					nativeAdditional := want["additionalEventData"].(map[string]any)
					for _, field := range []string{"AuthenticationMethod", "SignatureVersion", "aclRequired", "objectSize", "SSEApplied"} {
						actual, present := additional[field]
						native, expected := nativeAdditional[field]
						if present != expected || !reflect.DeepEqual(actual, native) {
							t.Fatalf("%s changed %s presence/value: %#v", row.Label, field, additional)
						}
					}
					bytesIn, bytesOut := float64(wire.bytesIn), float64(len(wire.body))
					if nativeAdditional["bytesTransferredIn"] == float64(0) {
						// Admission can reject a write before consuming its body.
						bytesIn = 0
					}
					if nativeAdditional["bytesTransferredOut"] == float64(0) {
						// Native batch deletion reports no transferred response.
						bytesOut = 0
					}
					if additional["bytesTransferredIn"] != bytesIn || additional["bytesTransferredOut"] != bytesOut || additional["httpStatusCode"] != float64(wire.status) || additional["x-amz-id-2"] != wire.header.Get("x-amz-id-2") {
						t.Fatalf("%s lost native byte accounting/correlation: %#v; HTTP%d in%g out%g", row.Label, additional, wire.status, bytesIn, bytesOut)
					}
					if row.CallerRecord == nil {
						return
					}
					var callerWant map[string]any
					if err := json.Unmarshal(replay.rebind(t, row.CallerRecord), &callerWant); err != nil {
						t.Fatal(err)
					}
					callerWant["eventTime"] = times[row.Sequence]
					callerWant["requestParameters"].(map[string]any)["Host"] = wire.host
					callerAccount := callerWant["recipientAccountId"].(string)
					ownerAccount := want["recipientAccountId"].(string)
					region := callerWant["awsRegion"].(string)
					// History is read by each account's existing root credentials, not
					// by granting the S3 actor unrelated CloudTrail permissions.
					callerTrail := organizationsAuditClient(replay.clients, callerAccount, region)
					ownerTrail := organizationsAuditClient(replay.clients, ownerAccount, region)
					caller := auditLookupRecord(t, callerTrail, id, row.Operation)
					owner := auditLookupRecord(t, ownerTrail, id, row.Operation)
					assertNativeAuditEvent(t, caller, callerWant, failure.Message)
					if !reflect.DeepEqual(owner, got) {
						t.Fatalf("%s: owner history differs from delivered record", row.Label)
					}
					if !reflect.DeepEqual(identity, nativeIdentity) || !reflect.DeepEqual(caller["userIdentity"], callerWant["userIdentity"]) {
						t.Fatalf("%s: paired identities differ from native owner/caller fields: owner %#v caller %#v", row.Label, identity, caller["userIdentity"])
					}
					if !reflect.DeepEqual(caller["additionalEventData"], got["additionalEventData"]) {
						t.Fatalf("%s: paired records lost the same HTTP outcome", row.Label)
					}
					callerEvent, _ := caller["eventID"].(string)
					ownerEvent, _ := got["eventID"].(string)
					shared, _ := got["sharedEventID"].(string)
					if callerEvent == "" || ownerEvent == "" || callerEvent == ownerEvent || shared == "" || caller["sharedEventID"] != shared || got["requestID"] != id || caller["requestID"] != id {
						t.Fatalf("%s: paired records lost distinct event IDs or shared request correlation: owner %#v caller %#v", row.Label, got, caller)
					}
					if prior := pairedRequests[shared]; prior != "" && prior != id {
						t.Fatalf("%s: shared event ID %s correlates unrelated requests %s and %s", row.Label, shared, prior, id)
					}
					pairedRequests[shared] = id
					for account, foreignEvent := range map[string]string{callerAccount: ownerEvent, ownerAccount: callerEvent} {
						pages := cloudtrail.NewLookupEventsPaginator(organizationsAuditClient(replay.clients, account, region), &cloudtrail.LookupEventsInput{
							LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventId, AttributeValue: aws.String(foreignEvent)}},
						})
						for pages.HasMorePages() {
							page, err := pages.NextPage(t.Context())
							if err != nil {
								t.Fatal(err)
							}
							if len(page.Events) != 0 {
								t.Fatalf("%s: account %s exposed the other account's event %s", row.Label, account, foreignEvent)
							}
						}
					}
				})
			}
		})
	}
}
