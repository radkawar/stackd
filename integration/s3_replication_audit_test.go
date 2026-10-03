package stackd_test

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"stackd"
	"stackd/clock"
)

// Native records are positive semantic controls, not evidence of exactly-once
// delivery or native execution latency. Every assertion reads delivered gzip
// objects; phase readbacks independently prove the replication actually worked.
func TestS3ReplicationNativeAuditDeliveryReplay(t *testing.T) {
	var fixture struct {
		Start                    time.Time
		AuditBucket, AuditPrefix string
		Setup                    []s3KMSCall
		Phases                   []struct {
			Label         string
			Calls, Checks []s3KMSCall
			Records       []struct {
				Source string
				Record map[string]any
			}
		}
	}
	awsReadFixture(t, "s3/replication_audit_replay.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.Start)
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012", Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return startPublicCloud(t, config)
			})
			replay := newS3KMSReplay(clients)
			_, key, secret := clients.user(t, "test", "Delegated")
			putUserPolicy(t, clients.iam("test", "test", ""), "Delegated", allow(`"*"`, "*"))
			replay.sessions["caller"] = aws.Credentials{AccessKeyID: key, SecretAccessKey: secret}
			for _, call := range fixture.Setup {
				replay.call(t, call)
			}
			advanceClock(t, source, time.Minute)
			trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
			seen := map[string]bool{}
			publicRequests := map[string]bool{}
			internalRequests := map[string]string{}
			for _, phase := range fixture.Phases {
				if !t.Run(phase.Label, func(t *testing.T) {
					for _, call := range phase.Calls {
						wire := &s3AttributesAuditWire{Client: replay.clients.server.Client()}
						replay.httpClient = wire
						replay.call(t, call)
						id := wire.header.Get("x-amz-request-id")
						if id == "" {
							t.Fatalf("%s omitted public request identity", call.Label)
						}
						publicRequests[id] = true
					}
					// Local persistence boundary: reopen accepted work before execution.
					replay.clients, replay.httpClient = reopen(), nil
					advanceClock(t, source, time.Minute)
					trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
					for _, call := range phase.Checks {
						replay.call(t, call)
					}
					advanceClock(t, source, 6*time.Minute)
					trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
					objects := trailNativeObjects(t, replay.s3Client("caller"), fixture.AuditBucket, fixture.AuditPrefix)
					records := trailNativeRecords(t, objects)
					for _, expected := range phase.Records {
						var want map[string]any
						if err := json.Unmarshal(replay.rebind(t, expected.Record), &want); err != nil {
							t.Fatal(err)
						}
						matched := false
						for _, got := range records {
							eventID, _ := got["eventID"].(string)
							if seen[eventID] || got["eventName"] != want["eventName"] || awsFixtureField(got, "userIdentity.invokedBy") != "s3.amazonaws.com" || awsFixtureField(got, "userIdentity.type") != "AssumedRole" {
								continue
							}
							if awsFixtureField(got, "requestParameters.bucketName") != awsFixtureField(want, "requestParameters.bucketName") || awsFixtureField(got, "requestParameters.key") != awsFixtureField(want, "requestParameters.key") {
								continue
							}
							s3NativeProjection(t, expected.Source, want, got)
							// Projection alone cannot defend native field omission.
							for _, field := range []string{"errorCode", "responseElements"} {
								actual, present := got[field]
								native, captured := want[field]
								if present != captured || !reflect.DeepEqual(actual, native) {
									t.Fatalf("%s changed %s presence/value: %#v", expected.Source, field, got)
								}
							}
							additional, _ := got["additionalEventData"].(map[string]any)
							nativeAdditional := want["additionalEventData"].(map[string]any)
							size, present := additional["objectSize"]
							nativeSize, captured := nativeAdditional["objectSize"]
							if present != captured || !reflect.DeepEqual(size, nativeSize) {
								t.Fatalf("%s changed native objectSize presence/value: %#v", expected.Source, additional)
							}
							message, hasMessage := got["errorMessage"].(string)
							if hasMessage != (want["errorCode"] != nil) || hasMessage && message == "" {
								t.Fatalf("%s lost error outcome: %#v", expected.Source, got)
							}
							requestID, _ := got["requestID"].(string)
							previous := internalRequests[requestID]
							if eventID == "" || requestID == "" || publicRequests[requestID] || previous != "" && previous != eventID {
								t.Fatalf("%s reused or omitted service request identity: %#v", expected.Source, got)
							}
							internalRequests[requestID] = eventID
							matched = true
						}
						if !matched {
							t.Fatalf("missing newly delivered native role record %s", expected.Source)
						}
					}
					for _, record := range records {
						id, _ := record["eventID"].(string)
						seen[id] = true
					}
				}) {
					return
				}
			}
		})
	}
}
