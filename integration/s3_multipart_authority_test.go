package stackd_test

import (
	"testing"
	"time"

	"stackd"
	"stackd/clock"
)

// Authority fixtures retain their native source/sequence and execute with real
// assumed-role credentials. Reopening replaces only the server; credentials and
// issued resource identities remain the same across policy and key transitions.
func TestS3NativeMultipartAuthorityReplay(t *testing.T) {
	var fixture struct {
		Payloads  map[string][]s3MultipartPayload
		Scenarios []struct {
			Name  string
			Calls []s3MultipartCall
		}
	}
	awsReadFixture(t, "s3/multipart_authority_replay.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		for _, scenario := range fixture.Scenarios {
			t.Run(backend+"/"+scenario.Name, func(t *testing.T) {
				source := clock.NewManual(time.Date(2026, 9, 20, 9, 0, 0, 0, time.UTC))
				clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012", Clock: source})
				replay := newS3KMSReplay(clients)
				for _, row := range scenario.Calls {
					if row.Reopen {
						replay.clients = reopen()
					}
					if !t.Run(row.Label, func(t *testing.T) {
						if row.Service == "s3" {
							s3MultipartReplayCall(t, replay, fixture.Payloads, row)
						} else {
							replay.call(t, row.s3KMSCall)
						}
					}) {
						return
					}
					advanceClock(t, source, time.Second)
				}
			})
		}
	}
}
