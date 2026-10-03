package stackd_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"stackd"
	"stackd/clock"
)

// Replay positive native publications only. A bounded native collection without
// a particular event does not establish suppression or exactly-once delivery.
func TestS3ObjectLockNativeDeliveryReplay(t *testing.T) {
	var fixture struct {
		Start time.Time
		Setup []s3KMSCall
		Calls []struct {
			s3MultipartEventCall
			At time.Time
		}
	}
	awsReadFixture(t, "s3/object_lock_delivery_replay.json", &fixture)
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
			credentials := aws.Credentials{AccessKeyID: key, SecretAccessKey: secret}
			// Stabilize applied configuration using service time, not a native SLA.
			advanceClock(t, source, time.Minute)
			trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
			requests := make(map[string]int)
			for _, row := range fixture.Calls {
				if !t.Run(fmt.Sprintf("%d-%s", row.Sequence, row.Label), func(t *testing.T) {
					advanceClock(t, source, row.At.Sub(source.Now()))
					wire := s3MultipartEventRequest(t, replay, credentials, row.s3MultipartEventCall, source.Now())
					if wire.id == "" || requests[wire.id] != 0 || wire.extended == "" {
						t.Fatalf("lost unique public request correlation: %+v", wire)
					}
					requests[wire.id] = row.Sequence
					replay.values[fmt.Sprintf("request%d", row.Sequence)] = wire.id
					// Reopen after acceptance, before any job drain. Retention events
					// must retain this mutation's snapshot, not the final cleared state.
					if row.Reopen {
						replay.clients = reopen()
					}
				}) {
					return
				}
			}
			replay.clients = reopen()
			advanceClock(t, source, time.Minute)
			trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
			receipts := make(map[string][]s3NotifyReceipt)
			for _, channel := range []string{"classic", "eventbridge"} {
				s3NotifyCollect(t, replay, replay.values["queue_"+channel], receipts)
			}
			sequencers := make(map[string]string)
			for _, row := range fixture.Calls {
				if !t.Run(fmt.Sprintf("%d-%s-delivery", row.Sequence, row.Label), func(t *testing.T) {
					var expected []s3NotifyDelivery
					if err := json.Unmarshal(replay.rebind(t, row.Notifications), &expected); err != nil {
						t.Fatal(err)
					}
					for _, want := range expected {
						found := -1
						for i, receipt := range receipts[want.Queue] {
							if s3NotifyIdentity(receipt.payload) == s3NotifyIdentity(want.Payload) {
								found = i
								break
							}
						}
						if found < 0 {
							t.Fatalf("missing retained %s delivery from %s (source call %d): %#v", want.Kind, want.Source, want.SourceSequence, receipts[want.Queue])
						}
						// Full native equality preserves millisecond retention dates,
						// Unicode/form keys, size/eTag/version and omitted fields.
						s3NotifyCompare(t, row.Label, want, receipts[want.Queue][found], sequencers)
						receipts[want.Queue] = append(receipts[want.Queue][:found], receipts[want.Queue][found+1:]...)
					}
				}) {
					return
				}
			}
			// Do not reject remaining receipts: native positive controls do not
			// establish absence guarantees for implicit/default producer paths.
		})
	}
}
