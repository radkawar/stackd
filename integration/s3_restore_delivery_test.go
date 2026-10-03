package stackd_test

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"stackd"
	"stackd/clock"
	"stackd/journal"
)

// Positive native deliveries only: bounded collection does not establish
// suppression, exactly-once delivery, or an AWS restore-completion latency SLA.
func TestS3RestoreNativeDeliveryReplay(t *testing.T) {
	var fixture struct {
		Start                    time.Time
		AuditBucket, AuditPrefix string
		Setup                    []s3KMSCall
		Calls                    []s3ObjectCall
		Notifications            []struct {
			s3NotifyDelivery
			CompletionFrom int
		}
		Records []struct {
			Sequence int
			Source   string
			Record   map[string]any
		}
	}
	awsReadFixture(t, "s3/restore_delivery_replay.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.Start)
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012", Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return startPublicCloud(t, config)
			})
			replay := newS3KMSReplay(clients)
			_, key, secret := clients.user(t, "test", "Delegated")
			putUserPolicy(t, clients.iam("test", "test", ""), "Delegated", allow(`"*"`, "*"))
			replay.sessions["owner"] = aws.Credentials{AccessKeyID: key, SecretAccessKey: secret}
			for _, row := range fixture.Setup {
				replay.call(t, row)
			}
			// Apply configured destinations before the original object mutations.
			advanceClock(t, source, time.Minute)
			trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
			readJournal := func() []journal.Event {
				t.Helper()
				var rows []journal.Event
				for after := int64(0); ; {
					page, err := replay.clients.server.Config.Handler.(*stackd.Stack).Events(t.Context(), after, 1000)
					if err != nil {
						t.Fatal(err)
					}
					if len(page) == 0 {
						return rows
					}
					rows = append(rows, page...)
					after = page[len(page)-1].Sequence
				}
			}
			var retained []journal.Event
			wires := map[int]*s3AttributesAuditWire{}
			requests := map[string]int{}
			calls := map[int]s3ObjectCall{}
			for _, row := range fixture.Calls {
				t.Logf("Native sequence %d: %s (%s)", row.Sequence, row.Label, row.Source)
				if row.Reopen {
					retained = readJournal()
					replay.clients, replay.httpClient = reopen(), nil
				}
				advanceClock(t, source, row.At.Sub(source.Now()))
				if row.Drain {
					trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
				}
				wire := &s3AttributesAuditWire{Client: replay.clients.server.Client()}
				replay.httpClient = wire
				out := replay.call(t, row.s3KMSCall)
				id := wire.header.Get("x-amz-request-id")
				if id == "" || requests[id] != 0 || wire.header.Get("x-amz-id-2") == "" {
					t.Fatalf("%s lost unique public request correlation", row.Label)
				}
				if row.Code == "Success" && nativeAuditRequestID(t, out, nil) != id {
					t.Fatalf("%s SDK and HTTP request IDs differ", row.Label)
				}
				requests[id], wires[row.Sequence], calls[row.Sequence] = row.Sequence, wire, row
				replay.values[fmt.Sprintf("request%d", row.Sequence)] = id
			}
			// Retain the completed state and all later 200 Post/audit publications
			// before their final delivery, without advancing to unmeasured expiry.
			replay.clients, replay.httpClient = reopen(), nil
			advanceClock(t, source, 6*time.Minute)
			trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
			rows := readJournal()
			if len(rows) < len(retained) || !reflect.DeepEqual(rows[:len(retained)], retained) {
				t.Fatal("reopen changed the committed journal prefix preceding restore completion")
			}
			api := map[int]journal.Event{}
			bridges := map[string]journal.Event{}
			for _, row := range rows {
				if call := row.APICallCompleted; call != nil && call.EventSource == "s3.amazonaws.com" {
					if sequence := requests[row.RequestID]; sequence != 0 && call.EventName == calls[sequence].Operation {
						api[sequence] = row
					}
				}
				if row.EventBridgeAccepted.EventID != "" {
					bridges[row.EventBridgeAccepted.WireEventID] = row
				}
			}
			receipts := map[string][]s3NotifyReceipt{}
			for _, channel := range []string{"classic", "eventbridge"} {
				s3NotifyCollect(t, replay, replay.values["queue_"+channel], receipts)
			}
			// Bind original Put sequencers, not whichever restore delivery happens
			// to arrive first. Completion identity is service-generated and shared
			// by the classic/direct envelopes, never the initiating HTTP ID.
			for _, receipt := range receipts[replay.values["queue_classic"]] {
				payload := receipt.payload
				key, _ := awsFixtureField(payload, "s3.object.key").(string)
				version := awsFixtureField(payload, "s3.object.versionId")
				if key == "" || version != replay.values["version_"+key] {
					continue
				}
				switch payload["eventName"] {
				case "ObjectCreated:Put":
					sequencer, _ := awsFixtureField(payload, "s3.object.sequencer").(string)
					owner, _ := awsFixtureField(payload, "s3.bucket.ownerIdentity.principalId").(string)
					if sequencer == "" || owner == "" {
						t.Fatalf("original Put lost object/owner identity: %#v", payload)
					}
					replay.values["sequencer_"+key], replay.values["owner_"+key] = sequencer, owner
				case "ObjectRestore:Completed":
					id := s3NotifyRequestID(payload)
					if id == "" || requests[id] != 0 {
						t.Fatalf("completion reused a public request identity: %#v", payload)
					}
					replay.values["completion_"+key] = id
				}
			}
			sequencers := map[string]string{}
			for _, expected := range fixture.Notifications {
				var want s3NotifyDelivery
				if err := json.Unmarshal(replay.rebind(t, expected.s3NotifyDelivery), &want); err != nil {
					t.Fatal(err)
				}
				found := -1
				for i, receipt := range receipts[want.Queue] {
					if s3NotifyIdentity(receipt.payload) == s3NotifyIdentity(want.Payload) {
						found = i
						break
					}
				}
				if found < 0 {
					t.Fatalf("missing native %s delivery from %s (producer %d)", want.Kind, want.Source, want.SourceSequence)
				}
				got := receipts[want.Queue][found]
				s3NotifyCompare(t, calls[want.SourceSequence].Label, want, got, sequencers)
				parent := api[want.SourceSequence]
				if parent.APICallCompleted == nil {
					t.Fatalf("producer %d lost its retained API outcome", want.SourceSequence)
				}
				if want.Kind == "eventbridge" {
					id, _ := got.payload["id"].(string)
					bridge := bridges[id]
					if bridge.EventBridgeAccepted.EventID == "" || bridge.ParentEventID != parent.APICallCompleted.EventID {
						t.Fatalf("%s lost API-to-EventBridge causality: parent %q, expected %s/%s %q", want.Source, bridge.ParentEventID, parent.APICallCompleted.EventSource, parent.APICallCompleted.EventName, parent.APICallCompleted.EventID)
					}
					if expected.CompletionFrom != 0 && bridge.Sequence <= parent.Sequence {
						t.Fatalf("completion preceded its retained origin: %#v", bridge)
					}
					accepted := false
					for _, row := range rows {
						if row.ParentEventID == bridge.EventBridgeAccepted.EventID && row.SQSMessageAccepted.QueueARN != "" && row.Sequence > bridge.Sequence {
							accepted = true
							break
						}
					}
					if !accepted {
						t.Fatalf("%s lost EventBridge-to-SQS retained causality", want.Source)
					}
				}
				receipts[want.Queue] = append(receipts[want.Queue][:found], receipts[want.Queue][found+1:]...)
			}
			// Leave unmatched receipts alone: these are positive native controls.
			delivered := map[int]map[string]any{}
			objects := trailNativeObjects(t, replay.s3Client("owner"), fixture.AuditBucket, fixture.AuditPrefix)
			for _, record := range trailNativeRecords(t, objects) {
				id, _ := record["requestID"].(string)
				if sequence := requests[id]; sequence != 0 {
					delivered[sequence] = record
				}
			}
			for _, expected := range fixture.Records {
				sequence := expected.Sequence
				got, wire, call := delivered[sequence], wires[sequence], calls[sequence]
				if got == nil {
					t.Fatalf("%s: missing request-correlated delivered gzip record from %s", call.Label, expected.Source)
				}
				var want map[string]any
				if err := json.Unmarshal(replay.rebind(t, expected.Record), &want); err != nil {
					t.Fatal(err)
				}
				want["eventTime"] = call.At.UTC().Format(time.RFC3339)
				want["requestParameters"].(map[string]any)["Host"] = wire.host
				var failure struct{ Message string }
				if wire.status >= 400 {
					if err := xml.Unmarshal(wire.body, &failure); err != nil {
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
						t.Fatalf("%s changed caller %s: %#v", call.Label, field, identity)
					}
				}
				origin := api[sequence]
				if origin.APICallCompleted == nil || got["eventID"] != origin.APICallCompleted.EventID || identity["accessKeyId"] != replay.sessions[call.Actor].AccessKeyID || identity["principalId"] != origin.APICallCompleted.Identity.PrincipalID {
					t.Fatalf("%s lost retained authenticated request/event identity: %#v", call.Label, got)
				}
				additional, _ := got["additionalEventData"].(map[string]any)
				nativeAdditional := want["additionalEventData"].(map[string]any)
				for _, field := range []string{"SignatureVersion", "AuthenticationMethod", "objectSize", "httpStatusCode"} {
					actual, present := additional[field]
					native, expected := nativeAdditional[field]
					if present != expected || !reflect.DeepEqual(actual, native) {
						t.Fatalf("%s changed native %s: got %#v; native %#v", call.Label, field, actual, native)
					}
				}
				if additional["bytesTransferredIn"] != float64(wire.bytesIn) || additional["bytesTransferredOut"] != float64(len(wire.body)) || additional["x-amz-id-2"] != wire.header.Get("x-amz-id-2") {
					t.Fatalf("%s lost measured HTTP accounting/correlation: %#v", call.Label, additional)
				}
			}
		})
	}
}
