package stackd_test

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"stackd"
	"stackd/clock"
)

type s3LockAuditCall struct {
	s3ObjectCall
	Record                                     map[string]any
	ModifiedFrom                               map[string]int
	DefaultRetentionFrom, DefaultRetentionDays int
	ErrorFromSequence                          int
}

// Only positively request-correlated delivered gzip records establish the native
// projections. The final reads are explicitly derived persistence checks, not
// claims that additional native requests were captured or others suppressed.
func TestS3ObjectLockNativeAuditDelivery(t *testing.T) {
	var fixture struct {
		Start                    time.Time
		AuditBucket, AuditPrefix string
		Setup, Sessions, Trail   []s3KMSCall
		Calls, Verify            []s3LockAuditCall
	}
	awsReadFixture(t, "s3/object_lock_audit_replay.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.Start)
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012", Clock: source})
			replay := newS3KMSReplay(clients)
			for _, row := range fixture.Setup {
				replay.call(t, row)
			}
			_, key, secret := clients.user(t, "test", "Delegated")
			putUserPolicy(t, clients.iam("test", "test", ""), "Delegated", allow(`"s3:*"`, "*"))
			replay.sessions["audit-user"] = aws.Credentials{AccessKeyID: key, SecretAccessKey: secret}
			for _, rows := range [][]s3KMSCall{fixture.Sessions, fixture.Trail} {
				for _, row := range rows {
					replay.call(t, row)
				}
			}

			wires := map[int]*s3AttributesAuditWire{}
			ids := map[string]int{}
			times := map[int]time.Time{}
			run := func(rows []s3LockAuditCall) {
				for _, row := range rows {
					t.Logf("Native sequence %d: %s (%s)", row.Sequence, row.Label, row.Source)
					if row.Reopen {
						replay.clients, replay.httpClient = reopen(), nil
					}
					advanceClock(t, source, row.At.Sub(source.Now()))
					times[row.Sequence] = source.Now()
					wire := &s3AttributesAuditWire{Client: replay.clients.server.Client()}
					replay.httpClient = wire
					out := replay.call(t, row.s3KMSCall)
					id := wire.header.Get("x-amz-request-id")
					if id == "" || ids[id] != 0 || wire.header.Get("x-amz-id-2") == "" {
						t.Fatalf("%s lost unique public request correlation", row.Label)
					}
					if row.Code == "Success" && nativeAuditRequestID(t, out, nil) != id {
						t.Fatalf("%s SDK and HTTP request IDs differ", row.Label)
					}
					ids[id], wires[row.Sequence] = row.Sequence, wire
					var headers map[string]string
					if err := json.Unmarshal(replay.rebind(t, row.Headers), &headers); err != nil {
						t.Fatal(err)
					}
					// Lock PUT version headers are not modeled in Smithy output.
					for name, want := range headers {
						if got := wire.header.Get(name); got != want {
							t.Fatalf("%s header %s = %q; native %q", row.Label, name, got, want)
						}
					}
					for _, name := range row.AbsentHeaders {
						if _, present := wire.header[http.CanonicalHeaderKey(name)]; present {
							t.Fatalf("%s exposed native-omitted header %s", row.Label, name)
						}
					}
				}
			}
			run(fixture.Calls)
			// Reopen both accepted queued audit work and the independently updated
			// lock components before observing their final persisted values.
			replay.clients, replay.httpClient = reopen(), nil
			run(fixture.Verify)
			replay.clients, replay.httpClient = reopen(), nil
			advanceClock(t, source, 6*time.Minute)
			trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
			delivered := map[int]map[string]any{}
			objects := trailNativeObjects(t, replay.s3Client("caller"), fixture.AuditBucket, fixture.AuditPrefix)
			for _, record := range trailNativeRecords(t, objects) {
				id, _ := record["requestID"].(string)
				sequence := ids[id]
				if sequence == 0 {
					continue
				}
				if prior := delivered[sequence]; prior != nil && !reflect.DeepEqual(prior, record) {
					t.Fatalf("redelivery changed request %s", id)
				}
				delivered[sequence] = record
			}
			for _, rows := range [][]s3LockAuditCall{fixture.Calls, fixture.Verify} {
				for _, row := range rows {
					got, wire := delivered[row.Sequence], wires[row.Sequence]
					if got == nil {
						t.Fatalf("%s: missing delivered gzip record (%s)", row.Label, row.Source)
					}
					var want map[string]any
					if err := json.Unmarshal(replay.rebind(t, row.Record), &want); err != nil {
						t.Fatal(err)
					}
					want["eventTime"] = times[row.Sequence].UTC().Format(time.RFC3339)
					want["requestParameters"].(map[string]any)["Host"] = wire.host
					errorWire := wire
					if row.ErrorFromSequence != 0 {
						errorWire = wires[row.ErrorFromSequence]
					}
					var failure struct{ Message string }
					if errorWire.status >= 400 {
						if err := xml.Unmarshal(errorWire.body, &failure); err != nil {
							t.Fatal(err)
						}
					}
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
					if identity["accessKeyId"] != replay.sessions[row.Actor].AccessKeyID || identity["principalId"] == nil || identity["principalId"] == "" || got["eventID"] == nil || got["eventID"] == "" {
						t.Fatalf("%s lost authenticated caller/event identity: %#v", row.Label, got)
					}
					additional, _ := got["additionalEventData"].(map[string]any)
					nativeAdditional := want["additionalEventData"].(map[string]any)
					if len(row.ModifiedFrom) != 0 {
						retention := nativeAdditional["objectRetentionInfo"].(map[string]any)
						for component, sequence := range row.ModifiedFrom {
							mutation, exists := times[sequence]
							if !exists {
								t.Fatalf("%s has unknown mutation origin %d", row.Label, sequence)
							}
							retention[component].(map[string]any)["lastModifiedTime"] = float64(mutation.UnixMilli())
						}
						if row.DefaultRetentionFrom != 0 {
							until := times[row.DefaultRetentionFrom].AddDate(0, 0, row.DefaultRetentionDays)
							retention["retentionInfo"].(map[string]any)["retainUntilTime"] = float64(until.UnixMilli())
						}
					}
					// Exact maps defend the native per-operation omissions as well as
					// independent mutation timestamps. Get/Head audit visibility is
					// deliberately broader than optional response-header authority.
					for _, field := range []string{"AuthenticationMethod", "SignatureVersion", "objectSize", "SSEApplied", "objectRetentionInfo"} {
						actual, present := additional[field]
						native, expected := nativeAdditional[field]
						if present != expected || !reflect.DeepEqual(actual, native) {
							t.Fatalf("%s changed %s presence/value: got %#v; native %#v", row.Label, field, actual, native)
						}
					}
					bytesIn, bytesOut := wire.bytesIn, len(errorWire.body)
					if row.Operation == "DeleteObjects" {
						// Native aggregate batch events account no transfer bytes,
						// even when the public result mixes deletions and errors.
						bytesIn, bytesOut = 0, 0
					}
					if additional["bytesTransferredIn"] != float64(bytesIn) || additional["bytesTransferredOut"] != float64(bytesOut) || additional["httpStatusCode"] != float64(wire.status) || additional["x-amz-id-2"] != wire.header.Get("x-amz-id-2") {
						t.Fatalf("%s lost measured HTTP accounting/correlation: %#v; HTTP%d in%d out%d", row.Label, additional, wire.status, bytesIn, bytesOut)
					}
				}
			}
		})
	}
}
