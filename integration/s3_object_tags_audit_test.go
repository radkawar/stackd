package stackd_test

import (
	"encoding/json"
	"encoding/xml"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"stackd"
	"stackd/clock"
)

// The oracle contains delivered S3 gzip records, not LookupEvents history (which
// excludes data events). Unobserved records in the bounded native capture do not
// imply that those requests can never be delivered.
func TestS3ObjectTaggingNativeAuditDelivery(t *testing.T) {
	testS3NativeAuditDelivery(t, "s3/object_tagging_audit_replay.json.gz")
}

func TestS3CopyObjectNativeAuditDelivery(t *testing.T) {
	testS3NativeAuditDelivery(t, "s3/copy_audit_replay.json.gz")
}

func testS3NativeAuditDelivery(t *testing.T, fixturePath string) {
	t.Helper()
	var fixture struct {
		Cases []struct {
			Name, AuditBucket, AuditPrefix, Trail string
			NoTagValues                           []string
			Setup, Calls                          []s3KMSCall
			NoInternalSourceRead                  []int
			Records                               []struct {
				SourceSequence, AuditRecordIndex, DownloadSequence int
				FileKey                                            string
				InternalSourceRead                                 bool
				Record                                             map[string]any
			}
		}
	}
	awsReadFixture(t, fixturePath, &fixture)
	for _, scenario := range fixture.Cases {
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(scenario.Name+"/"+backend, func(t *testing.T) {
				source := clock.NewManual(time.Date(2026, 9, 20, 3, 22, 0, 0, time.UTC))
				clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012", Clock: source})
				replay := newS3KMSReplay(clients)
				for _, row := range scenario.Setup {
					replay.call(t, row)
				}
				// Preserve the native IAMUser identity with real SDK credentials;
				// only provisioning uses the root caller supplied by the runner.
				arn, key, secret := clients.user(t, "test", "Delegated")
				putUserPolicy(t, clients.iam("test", "test", ""), "Delegated", allow(`"s3:*"`, "*"))
				replay.sessions["audit-user"] = aws.Credentials{AccessKeyID: key, SecretAccessKey: secret}

				ids := map[int]string{}
				calls := map[string]s3KMSCall{}
				times := map[int]string{}
				errorsByID := map[string]string{}
				copyByExtendedID := map[string]int{}
				extendedIDs := map[int]string{}
				responseBytes := map[int]int{}
				endpoint, err := url.Parse(clients.server.URL)
				if err != nil {
					t.Fatal(err)
				}
				for _, row := range scenario.Calls {
					if !t.Run(row.Label, func(t *testing.T) {
						wire := &s3VersionHTTPClient{HTTPClient: replay.clients.server.Client()}
						replay.httpClient = wire
						out := replay.call(t, row)
						assertS3ErrorDetails(t, wire.body, row.ErrorDetails)
						id := wire.header.Get("x-amz-request-id")
						if id == "" || calls[id].Sequence != 0 {
							t.Fatalf("source sequence %d lost unique request correlation: %q", row.Sequence, id)
						}
						if row.Code == "Success" {
							if nativeAuditRequestID(t, out, nil) != id {
								t.Fatalf("source sequence %d SDK and wire request IDs differ", row.Sequence)
							}
						} else {
							var failure struct{ Message string }
							if err := xml.Unmarshal(wire.body, &failure); err != nil {
								t.Fatal(err)
							}
							errorsByID[id] = failure.Message
						}
						if row.Operation == "CopyObject" {
							extended := wire.header.Get("x-amz-id-2")
							if extended == "" || copyByExtendedID[extended] != 0 {
								t.Fatalf("source sequence %d lost unique extended request correlation: %q", row.Sequence, extended)
							}
							copyByExtendedID[extended], extendedIDs[row.Sequence] = row.Sequence, extended
							if row.Code == "Success" {
								size, err := strconv.Atoi(wire.header.Get("Content-Length"))
								if err != nil {
									t.Fatal(err)
								}
								responseBytes[row.Sequence] = size
							} else {
								responseBytes[row.Sequence] = len(wire.body)
							}
						}
						ids[row.Sequence], calls[id], times[row.Sequence] = id, row, source.Now().UTC().Format(time.RFC3339)
					}) {
						return
					}
				}

				// Accepted outcomes must survive a storage reopen before any batch
				// is flushed. This exercises retained SQLite as well as memory.
				replay.clients = reopen()
				replay.httpClient = nil
				advanceClock(t, source, 6*time.Minute)
				trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
				objects := trailNativeObjects(t, replay.s3Client("caller"), scenario.AuditBucket, scenario.AuditPrefix)
				delivered := map[string]map[string]any{}
				internal := map[int][]map[string]any{}
				allDelivered := map[string]map[string]any{}
				for _, got := range trailNativeRecords(t, objects) {
					id, _ := got["requestID"].(string)
					if id == "" {
						t.Fatalf("delivered record has no request ID: %#v", got)
					}
					if prior := allDelivered[id]; prior != nil {
						if !reflect.DeepEqual(prior, got) {
							t.Fatalf("redelivery changed request %s: %#v", id, got)
						}
						continue
					}
					allDelivered[id] = got
					identity, _ := got["userIdentity"].(map[string]any)
					row, ok := calls[id]
					sequence := row.Sequence
					if identity["invokedBy"] == "AWS Internal" {
						additional, _ := got["additionalEventData"].(map[string]any)
						extended, _ := additional["x-amz-id-2"].(string)
						sequence = copyByExtendedID[extended]
						if ok || sequence == 0 || got["eventName"] != "GetObject" {
							t.Fatalf("internal source read did not have a distinct CopyObject correlation: %#v", got)
						}
						internal[sequence] = append(internal[sequence], got)
					} else {
						if !ok || row.Operation == "PutBucketVersioning" {
							t.Fatalf("data selector admitted an unrelated or management request: %#v", got)
						}
						delivered[id] = got
					}
					for _, field := range []string{"requestParameters", "responseElements"} {
						projection, err := json.Marshal(got[field])
						if err != nil {
							t.Fatal(err)
						}
						for _, value := range scenario.NoTagValues {
							if strings.Contains(string(projection), strconv.Quote(value)) {
								t.Fatalf("source sequence %d leaked a tag value through %s", sequence, field)
							}
						}
					}
				}
				// These are bounded native controls, not claims about how long
				// AWS may delay a record. Inspect the entire locally drained batch.
				for _, sequence := range scenario.NoInternalSourceRead {
					if len(internal[sequence]) != 0 {
						t.Fatalf("source sequence %d unexpectedly read a rejected destination's source", sequence)
					}
				}
				expectedInternal := map[int]bool{}
				for _, expected := range scenario.Records {
					id := ids[expected.SourceSequence]
					records := []map[string]any{delivered[id]}
					if expected.InternalSourceRead {
						expectedInternal[expected.SourceSequence] = true
						records = internal[expected.SourceSequence]
						if len(records) == 0 {
							t.Fatalf("missing internal source read for sequence %d (native audit_records[%d])", expected.SourceSequence, expected.AuditRecordIndex)
						}
					}
					for _, got := range records {
						if got == nil {
							t.Fatalf("missing delivered source sequence %d (native audit_records[%d], download %d, %s)", expected.SourceSequence, expected.AuditRecordIndex, expected.DownloadSequence, expected.FileKey)
						}
						var want map[string]any
						if err := json.Unmarshal(replay.rebind(t, expected.Record), &want); err != nil {
							t.Fatal(err)
						}
						// Bind the real request host and manual event clock, not native
						// TLS/cipher details, CLI timing, or SDK/XML transfer byte counts.
						if !expected.InternalSourceRead {
							want["requestParameters"].(map[string]any)["Host"] = endpoint.Host
						}
						want["eventTime"] = times[expected.SourceSequence]
						assertNativeAuditEvent(t, got, want, errorsByID[id])
						additional, _ := got["additionalEventData"].(map[string]any)
						nativeAdditional := want["additionalEventData"].(map[string]any)
						if additional["httpStatusCode"] != nativeAdditional["httpStatusCode"] {
							t.Fatalf("source sequence %d audit status: got %#v, native %#v", expected.SourceSequence, additional, nativeAdditional)
						}
						if extended := extendedIDs[expected.SourceSequence]; extended != "" && additional["x-amz-id-2"] != extended {
							t.Fatalf("source sequence %d lost wire extended request correlation: %#v", expected.SourceSequence, additional)
						}
						if row := calls[id]; !expected.InternalSourceRead && row.Operation == "CopyObject" && additional["bytesTransferredOut"] != float64(responseBytes[expected.SourceSequence]) {
							t.Fatalf("source sequence %d audit lost actual copy response bytes: %#v", expected.SourceSequence, additional)
						}
						identity, _ := got["userIdentity"].(map[string]any)
						nativeIdentity := want["userIdentity"].(map[string]any)
						for _, field := range []string{"type", "userName", "accountId", "arn"} {
							if identity[field] != nativeIdentity[field] {
								t.Fatalf("source sequence %d changed native caller %s: %#v", expected.SourceSequence, field, identity)
							}
						}
						if expected.InternalSourceRead {
							if additional["objectSize"] != nativeAdditional["objectSize"] {
								t.Fatalf("internal source sequence %d changed native object size: got %#v, native %#v", expected.SourceSequence, additional, nativeAdditional)
							}
							if additional["bytesTransferredIn"] != float64(0) || additional["bytesTransferredOut"] != float64(0) {
								t.Fatalf("internal source sequence %d exposed customer-transfer bytes: %#v", expected.SourceSequence, additional)
							}
							for _, field := range []string{"sourceIPAddress", "userAgent"} {
								if got[field] != want[field] {
									t.Fatalf("internal source sequence %d changed %s: %#v", expected.SourceSequence, field, got)
								}
							}
							if identity["invokedBy"] != nativeIdentity["invokedBy"] || got["requestID"] == id {
								t.Fatalf("source sequence %d lost distinct AWS Internal identity: %#v", expected.SourceSequence, got)
							}
						} else if _, invoked := identity["invokedBy"]; invoked {
							t.Fatalf("explicit SDK source sequence %d became an internal read: %#v", expected.SourceSequence, got)
						}
						if identity["arn"] != arn || identity["accessKeyId"] != key || identity["principalId"] == nil || identity["principalId"] == "" || got["eventID"] == nil || got["eventID"] == "" {
							t.Fatalf("source sequence %d lost SDK principal/event identity: %#v", expected.SourceSequence, got)
						}
					}
				}
				for sequence := range internal {
					if !expectedInternal[sequence] {
						t.Fatalf("unobserved internal source read for sequence %d: %#v", sequence, internal[sequence])
					}
				}
			})
		}
	}
}
